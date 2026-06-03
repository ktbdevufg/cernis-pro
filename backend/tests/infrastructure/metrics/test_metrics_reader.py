"""v2-Charakterisierer des metrics-Pfads (M.8): ``SqliteMetricsReader`` + ``ExportMetrics``.

Der ENDE-ZU-ENDE-Beweis, dass der M.4-``rtt_history.alive``-Fix durch den GANZEN
v2-Pfad traegt: Schema (mit alive) -> Reader (liest alive) -> MetricsSnapshot ->
reine Format-Funktion -> geheilte Export-Form. Das ist die Naht, die die M.1-
Charakterisierer (Altcode ``modules.metrics``, kaputt) NICHT abdecken -- sie froren
das tote v1 ein; diese Tests binden den geheilten v2-Pfad (analog der M.7-_SLA_STAT-
Naht).

Zwei Achsen:
* DB MIT Daten (inkl. rtt_history.alive, das v1 nie hatte) -> geheilte Form:
  cernis_monitor_* DA, influx-rtt DA, HA echter state-dict (kein error-state).
* LEERE DB (keine Tabelle) -> valide 0-Ausgabe, KEIN ERROR / KEIN error-state
  (leere-DB-Robustheit; der Reader legt NICHTS an, liest defensiv).

Der Reader macht bewusst KEIN _ensure_schema (reiner Konsument) -- darum legen die
Tests die Quell-Tabellen selbst an, exakt mit den Spalten/Zeitformen, die der Reader
liest: rtt_history/sla_samples mit epoch-float ``ts``, devices/scan_history mit
ISO-Text ``last_seen``/``scanned_at`` (DEFAULT datetime('now')).
"""

import sqlite3
import time
from pathlib import Path

import pytest

from application.metrics import ExportMetrics
from domain.metrics import MetricsSnapshot
from infrastructure.metrics import SqliteMetricsReader
from ports.metrics import MetricsReader


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "cernis.db"


def _create_full_db(path: Path) -> None:
    """Legt die vier Quell-Tabellen MIT frischen Daten an (inkl. rtt_history.alive).

    Zeitformen wie die schreibenden Adapter: devices/scan_history ISO-Text
    (datetime('now')), rtt_history/sla_samples epoch-float (time.time()).
    """
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
        INSERT INTO scan_history (cidr, host_count) VALUES ('10.0.0.0/24', 5);
        """
    )
    # rtt_history: zwei Targets, je die juengste Zeile ist die latest-per-target.
    # wlan: erreichbar (alive=1, rtt 5.0). gw: nicht erreichbar (alive=0, rtt -1.0).
    conn.executemany(
        "INSERT INTO rtt_history (target_id, rtt_ms, loss_pct, ts, alive) VALUES (?, ?, ?, ?, ?)",
        [
            ("wlan", 9.0, 0.0, now - 60, 1),  # aelter
            ("wlan", 5.0, 0.0, now - 10, 1),  # juenger -> latest
            ("gw", -1.0, 100.0, now - 5, 0),
        ],
    )
    # sla_samples wlan: 4 Samples, 3 alive -> uptime 75.0; rtts der alive>0 = [5,15]
    # -> avg 10.0.
    conn.executemany(
        "INSERT INTO sla_samples (target_id, ts, alive, rtt_ms) VALUES (?, ?, ?, ?)",
        [
            ("wlan", now - 100, 1, 5.0),
            ("wlan", now - 80, 1, 15.0),
            ("wlan", now - 60, 0, -1.0),
            ("wlan", now - 40, 1, 0.0),
        ],
    )
    conn.commit()
    conn.close()


# ── Port-Konformitaet ──────────────────────────────────────────────────────


def test_conforms_to_metrics_reader_protocol(db_path: Path) -> None:
    _: MetricsReader = SqliteMetricsReader(db_path)


# ── Reader gegen volle DB: die Aggregate stimmen ───────────────────────────


def test_snapshot_device_two_active_windows(db_path: Path) -> None:
    _create_full_db(db_path)
    snap = SqliteMetricsReader(db_path).snapshot()
    assert snap.device_total == 2
    assert snap.device_known == 1
    assert snap.device_unknown == 1
    # AA ist <1h -> active_1h=1; AA+? BB ist -2h -> nur AA in 1h, beide in 24h.
    assert snap.device_active_1h == 1
    assert snap.device_active_24h == 2


def test_snapshot_rtt_latest_per_target_with_alive(db_path: Path) -> None:
    # KERN des M.4-Beweises: alive wird gelesen, latest-per-target greift.
    _create_full_db(db_path)
    snap = SqliteMetricsReader(db_path).snapshot()
    points = {p.target_id: p for p in snap.rtt_points}
    assert set(points) == {"wlan", "gw"}
    # wlan: juengste Zeile (rtt 5.0, alive 1), NICHT die aeltere 9.0.
    assert points["wlan"].rtt_ms == 5.0
    assert points["wlan"].alive is True
    assert points["gw"].alive is False


def test_snapshot_sla_24h_aggregate(db_path: Path) -> None:
    _create_full_db(db_path)
    snap = SqliteMetricsReader(db_path).snapshot()
    sla = {p.target_id: p for p in snap.sla_points}
    assert sla["wlan"].uptime_pct == 75.0
    assert sla["wlan"].avg_rtt_ms == 10.0


def test_snapshot_scan_7d_aggregate(db_path: Path) -> None:
    _create_full_db(db_path)
    snap = SqliteMetricsReader(db_path).snapshot()
    assert snap.scans_7d == 2
    assert snap.scan_hosts_max == 12


# ── ExportMetrics gegen volle DB: GEHEILTE Form ────────────────────────────


def test_export_prometheus_healed_monitor_block(db_path: Path) -> None:
    _create_full_db(db_path)
    out = ExportMetrics(SqliteMetricsReader(db_path)).prometheus()
    assert "# ERROR" not in out
    assert "cernis_devices_total 2" in out
    # GEHEILT (v1: still weg): Monitor-Block via rtt_history.alive.
    assert 'cernis_monitor_rtt_ms{target="wlan"} 5.0' in out
    assert 'cernis_monitor_up{target="wlan"} 1' in out
    assert 'cernis_monitor_up{target="gw"} 0' in out
    # SLA-Block (24h-Aggregat).
    assert 'cernis_sla_uptime_pct{target="wlan"} 75.0' in out
    assert 'cernis_sla_avg_rtt_ms{target="wlan"} 10.0' in out


def test_export_influxdb_healed_rtt_lines(db_path: Path) -> None:
    _create_full_db(db_path)
    out = ExportMetrics(SqliteMetricsReader(db_path)).influxdb()
    assert "cernis,source=devices total=2i,known=1i,active_24h=2i" in out
    # GEHEILT (v1: ""): rtt-Zeilen pro Target.
    assert "target=wlan rtt_ms=5.0,up=1i" in out
    assert "target=gw rtt_ms=-1.0,up=0i" in out


def test_export_homeassistant_healed_real_state(db_path: Path) -> None:
    _create_full_db(db_path)
    out = ExportMetrics(SqliteMetricsReader(db_path)).homeassistant()
    # GEHEILT (v1: dauerhaft error-state, weil alive fehlte): echter state-dict.
    assert "error" not in out["attributes"]
    assert out["state"] == 1  # 1 device <1h
    assert out["attributes"]["devices_total"] == 2
    assert out["attributes"]["monitor"]["wlan"] == {"alive": True, "rtt_ms": 5.0}
    assert out["attributes"]["monitor"]["gw"] == {"alive": False, "rtt_ms": -1.0}


# ── Leere DB: valide 0-Ausgabe, KEIN ERROR / error-state ───────────────────


def test_snapshot_empty_db_is_null_snapshot(db_path: Path) -> None:
    # Keine Tabelle angelegt -> Reader liest defensiv -> Null-Snapshot.
    snap = SqliteMetricsReader(db_path).snapshot()
    assert snap == MetricsSnapshot()  # alle Zaehler 0, alle Listen leer


def test_export_prometheus_empty_db_zeroed_not_error(db_path: Path) -> None:
    out = ExportMetrics(SqliteMetricsReader(db_path)).prometheus()
    # GEHEILT (v1: "# ERROR generating metrics: no such table: devices"):
    assert "# ERROR" not in out
    assert "cernis_devices_total 0" in out
    assert "cernis_scans_last_7d 0" in out


def test_export_homeassistant_empty_db_zero_state_not_error(db_path: Path) -> None:
    out = ExportMetrics(SqliteMetricsReader(db_path)).homeassistant()
    # GEHEILT (v1: error-state): 0-state.
    assert "error" not in out["attributes"]
    assert out["state"] == 0
    assert out["attributes"]["monitor"] == {}
