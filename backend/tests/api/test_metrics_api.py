"""End-to-end-Tests der metrics-REST-API (v2) gegen app.py via TestClient (M.8).

Der HTTP-EBENEN-Beweis des Live-Schnitts: die drei Export-Endpunkte werden in der
v2-App (``app.py:create_app``) ueber ``ExportMetrics`` -> ``SqliteMetricsReader``
bedient. Echter Adapter auf einer tmp_path-DB via ``dependency_overrides`` (kein
echtes cernis.db). Belegt, was die wegfallende M.1-Charakterisierung NICHT abdeckte:
nicht "die modules.metrics-Funktion liefert X" (Altcode, isoliert), sondern "der
ENDPUNKT liefert ueber den v2-Pfad die geheilte Form" -- inkl. Response-Form
(PlainText vs. JSON) und Dependency-Verdrahtung.

Zwei Achsen wie der Reader-Test: DB MIT alive-Daten -> geheilte Form; leere DB ->
kein 500, valide leere/0-Ausgabe.

HINWEIS zum Live-Zustand: ``main:app`` (Altcode-Monolith) bedient die Endpunkte
real weiter ueber ``modules.metrics`` -- diese Tests pruefen die v2-App
(``create_app``), die der Einstiegspunkt-Wechsel (bzw. M.9) zum Live-Server macht.
Bis dahin bleiben ``modules/metrics.py`` + die M.1-Charakterisierer (sie sichern den
noch-live-Altcode-Pfad).
"""

import sqlite3
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.metrics import provide_export_metrics
from app import create_app
from application.metrics import ExportMetrics
from infrastructure.config import AppConfig
from infrastructure.metrics import SqliteMetricsReader


def _create_full_db(path: Path) -> None:
    """Vier Quell-Tabellen MIT frischen Daten inkl. rtt_history.alive (geheilt)."""
    now = time.time()
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE devices (mac TEXT, is_known INTEGER, last_seen TEXT);
        INSERT INTO devices (mac, is_known, last_seen) VALUES
            ('AA', 1, datetime('now')),
            ('BB', 0, datetime('now', '-2 hours'));

        CREATE TABLE rtt_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id TEXT, rtt_ms REAL, loss_pct REAL, ts REAL, alive INTEGER
        );

        CREATE TABLE sla_samples (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id TEXT, ts REAL, alive INTEGER, rtt_ms REAL
        );

        CREATE TABLE scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scanned_at TEXT DEFAULT (datetime('now')),
            cidr TEXT, host_count INTEGER, result_json TEXT
        );
        INSERT INTO scan_history (cidr, host_count) VALUES ('192.168.0.0/24', 12);
        """
    )
    conn.executemany(
        "INSERT INTO rtt_history (target_id, rtt_ms, loss_pct, ts, alive) VALUES (?, ?, ?, ?, ?)",
        [("wlan", 5.0, 0.0, now - 10, 1)],
    )
    conn.executemany(
        "INSERT INTO sla_samples (target_id, ts, alive, rtt_ms) VALUES (?, ?, ?, ?)",
        [("wlan", now - 100, 1, 5.0), ("wlan", now - 80, 1, 15.0)],
    )
    conn.commit()
    conn.close()


def _wired_app(db_path: Path) -> FastAPI:
    app = create_app(AppConfig())
    app.dependency_overrides[provide_export_metrics] = lambda: ExportMetrics(
        SqliteMetricsReader(db_path)
    )
    return app


@pytest.fixture
def full_client(tmp_path: Path) -> Iterator[TestClient]:
    db = tmp_path / "cernis.db"
    _create_full_db(db)
    with TestClient(_wired_app(db)) as client:
        yield client


@pytest.fixture
def empty_client(tmp_path: Path) -> Iterator[TestClient]:
    # Leere DB-Datei, KEINE Tabelle -> der Reader liest defensiv (0/[]).
    db = tmp_path / "cernis.db"
    sqlite3.connect(db).close()
    with TestClient(_wired_app(db)) as client:
        yield client


# ── /metrics (Prometheus, PlainText) ───────────────────────────────────────


def test_metrics_endpoint_healed_form(full_client: TestClient) -> None:
    resp = full_client.get("/metrics")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    body = resp.text
    assert "# ERROR" not in body
    assert "cernis_devices_total 2" in body
    # GEHEILT (v1: still weg): Monitor-Block via rtt_history.alive.
    assert 'cernis_monitor_rtt_ms{target="wlan"} 5.0' in body
    assert 'cernis_monitor_up{target="wlan"} 1' in body


def test_metrics_endpoint_empty_db_zeroed_not_error(empty_client: TestClient) -> None:
    resp = empty_client.get("/metrics")
    assert resp.status_code == 200
    assert "# ERROR" not in resp.text
    assert "cernis_devices_total 0" in resp.text


# ── /api/export/influxdb (Line-Protocol, PlainText) ────────────────────────


def test_influxdb_endpoint_healed_rtt_line(full_client: TestClient) -> None:
    resp = full_client.get("/api/export/influxdb")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    assert "cernis,source=devices total=2i,known=1i,active_24h=2i" in resp.text
    # GEHEILT (v1: ""): rtt-Zeile.
    assert "target=wlan rtt_ms=5.0,up=1i" in resp.text


def test_influxdb_endpoint_empty_db_device_line_only(empty_client: TestClient) -> None:
    resp = empty_client.get("/api/export/influxdb")
    assert resp.status_code == 200
    assert "total=0i" in resp.text


# ── /api/export/homeassistant (JSON) ───────────────────────────────────────


def test_homeassistant_endpoint_healed_state(full_client: TestClient) -> None:
    resp = full_client.get("/api/export/homeassistant")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")
    data = resp.json()
    # GEHEILT (v1: dauerhaft error-state): echter state-dict.
    assert "error" not in data["attributes"]
    assert data["attributes"]["devices_total"] == 2
    assert data["attributes"]["monitor"]["wlan"] == {"alive": True, "rtt_ms": 5.0}


def test_homeassistant_endpoint_empty_db_zero_state(empty_client: TestClient) -> None:
    resp = empty_client.get("/api/export/homeassistant")
    assert resp.status_code == 200
    data = resp.json()
    assert "error" not in data["attributes"]
    assert data["state"] == 0
    assert data["attributes"]["monitor"] == {}


# ── Verdrahtungs-Vertraege (explizit, nicht nur Nebeneffekt der 200-Tests) ──


def test_provide_export_metrics_placeholder_yields_500() -> None:
    """Ohne den Verdrahtungs-Override greift der NotImplementedError-Platzhalter -> 500.

    Wichtiger Verdrahtungs-Befund (in diesem Test festgehalten): ``create_app`` setzt
    den metrics-Override SELBST (app.py), anders als der scanning-Test, der ihn extern
    annahm. In der echten App ist der Platzhalter also nie live -- gut so. Um den
    Platzhalter-VERTRAG dennoch zu pruefen, wird der von ``create_app`` gesetzte
    Override hier gezielt ENTFERNT (simuliert einen Override-Key-Bruch / fehlende
    Verdrahtung). Dann muss ``provide_export_metrics`` greifen und hart fehlschlagen
    (NotImplementedError -> 500), NICHT still falsch laufen.
    """
    app = create_app(AppConfig())
    # Den von create_app gesetzten Override entfernen -> der Platzhalter wird live.
    del app.dependency_overrides[provide_export_metrics]
    # raise_server_exceptions=False: die NotImplementedError wird zur 500-Response,
    # statt in den Test durchzuschlagen.
    with TestClient(app, raise_server_exceptions=False) as client:
        resp = client.get("/metrics")
    assert resp.status_code == 500


def test_metrics_not_swallowed_by_spa(tmp_path: Path) -> None:
    """/metrics liefert Prometheus-Text, NICHT die SPA-index.html (Reihenfolge-Falle).

    Vertrag gegen das Verschieben des metrics-Blocks HINTER den ``mount("/")``: der
    SPA-Catch-all wuerde ``/metrics`` sonst verschlucken. Damit der Beweis etwas wert
    ist, wird der SPA-Mount DETERMINISTISCH aktiviert (erzwungenes ``frontend_dir``
    auf ein tmp-Verzeichnis mit Dummy-index.html) -- unabhaengig davon, ob ein echtes
    ``frontend/dist`` gebaut ist (sonst waere der "nicht-HTML"-Beweis wertlos, weil
    gar kein SPA-Mount da). Der Gegenpunkt-Assert (unbekannter Pfad -> SPA-HTML)
    belegt, dass der Mount WIRKLICH aktiv ist.
    """
    frontend = tmp_path / "frontend-dist"
    frontend.mkdir()
    (frontend / "index.html").write_text("<!doctype html><html><body>SPA</body></html>")

    db = tmp_path / "cernis.db"
    sqlite3.connect(db).close()
    app = create_app(AppConfig(frontend_dir=str(frontend)))
    app.dependency_overrides[provide_export_metrics] = lambda: ExportMetrics(
        SqliteMetricsReader(db)
    )
    with TestClient(app) as client:
        metrics = client.get("/metrics")
        spa = client.get("/irgendwas-unbekanntes")

    # /metrics: Prometheus-Text, NICHT vom SPA-Catch-all verschluckt.
    assert metrics.status_code == 200
    assert metrics.headers["content-type"].startswith("text/plain")
    assert "cernis_devices_total" in metrics.text
    assert "<html" not in metrics.text.lower()
    # Gegenpunkt: der SPA-Mount IST aktiv -- ein unbekannter Pfad liefert die index.html.
    assert spa.headers["content-type"].startswith("text/html")
    assert "SPA" in spa.text
