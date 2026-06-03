"""Characterization-Contract der metrics-/export-Ausgaben (Altcode modules/metrics.py).

Gegen eine temporaere DB: ``metrics.DB_PATH`` am Modul-Namespace umgebogen (wie in
test_monitoring_storage, da beim Import gebunden). Die Helfer sind reine SQL-Leser
-- die Tabellen werden hier direkt per sqlite3 angelegt, exakt so wie die Queries
sie erwarten.

Eingefroren wird das ECHTE IST, samt der zwei bekannten kaputten Straenge -- NICHT
gefixt (das ist M.4/M.8-Entscheidung):

1) ``/metrics`` (generate_prometheus_metrics):
   - leere DB OHNE ``devices``-Tabelle -> der Device-Block steht NICHT in einem
     inneren try, also faengt der AEUSSERE try/except und die Ausgabe ist genau
     ``"# ERROR generating metrics: no such table: devices\n"``.
   - MIT ``devices``-Tabelle -> Device-Gauges erscheinen; der Monitor-Block liest
     ``rtt_history.alive`` -- diese Spalte EXISTIERT NICHT (rtt_history hat kein
     alive), der innere try/except schluckt still -> ``cernis_monitor_rtt_ms``
     fehlt geraeuschlos. Kein Knall.

2) ``/api/export/influxdb`` (generate_influxdb_lines): aeusserer try/except schluckt
   alles -> bei fehlender ``devices``-Tabelle ``""``.

3) ``/api/export/homeassistant`` (generate_homeassistant_state): laeuft im selben
   aeusseren try ueber ZWEI Tabellen -- ``devices`` UND ``rtt_history``. Fehlt
   EINE davon, ist das Ergebnis ``{"state": "error", "attributes": {"error":
   "no such table: <fehlende>"}}``. Bei leerer DB also ``no such table: devices``;
   mit devices aber ohne rtt_history ``no such table: rtt_history``. Erst MIT
   beiden Tabellen kommt der eigentliche State-Dict. AS-IS, kein Fix.
"""

import sqlite3
from pathlib import Path
from typing import Any

import pytest


@pytest.fixture
def metrics_mod(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    from modules import metrics

    db = str(tmp_path / "cernis.db")
    monkeypatch.setattr(metrics, "DB_PATH", db)
    # leere Datei-DB anlegen, ohne irgendeine Tabelle
    sqlite3.connect(db).close()
    return metrics


def _create_devices_table(db_path: str) -> None:
    """devices-Tabelle minimal, wie generate_prometheus_metrics sie liest."""
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE devices (
            mac TEXT, is_known INTEGER, last_seen TEXT
        );
        INSERT INTO devices (mac, is_known, last_seen) VALUES
            ('AA', 1, datetime('now')),
            ('BB', 0, datetime('now', '-2 hours'));
        """
    )
    conn.commit()
    conn.close()


def _create_rtt_history_without_alive(db_path: str) -> None:
    """rtt_history exakt wie monitor._init_monitor_db (OHNE alive-Spalte)."""
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE rtt_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id TEXT, rtt_ms REAL, loss_pct REAL, ts REAL
        );
        INSERT INTO rtt_history (target_id, rtt_ms, loss_pct, ts)
            VALUES ('wlan', 5.0, 0.0, strftime('%s','now'));
        """
    )
    conn.commit()
    conn.close()


# ── /metrics: leere DB -> ERROR-Zeile (Device-Block ohne inneres try) ──


def test_prometheus_empty_db_yields_error_line(metrics_mod: Any) -> None:
    out = metrics_mod.generate_prometheus_metrics()
    # AS-IS: der aeussere try/except faengt das fehlende devices-Table.
    assert out == "# ERROR generating metrics: no such table: devices\n"


# ── /metrics: mit devices -> Gauges, alive-Block still weg ──────


def test_prometheus_with_devices_emits_device_gauges(metrics_mod: Any) -> None:
    _create_devices_table(metrics_mod.DB_PATH)
    out = metrics_mod.generate_prometheus_metrics()

    # Device-Gauges sind da (Prometheus-Textform: HELP/TYPE/Sample).
    assert "# HELP cernis_devices_total Total devices in database" in out
    assert "# TYPE cernis_devices_total gauge" in out
    assert "cernis_devices_total 2" in out
    assert "cernis_devices_known 1" in out
    assert "cernis_devices_unknown 1" in out
    # KEINE ERROR-Zeile mehr -- es laeuft durch.
    assert "# ERROR generating metrics" not in out


def test_prometheus_alive_block_silently_absent(metrics_mod: Any) -> None:
    # devices + rtt_history (OHNE alive). Der Monitor-Block selektiert
    # `alive FROM rtt_history` -> OperationalError -> innerer try/except: pass.
    _create_devices_table(metrics_mod.DB_PATH)
    _create_rtt_history_without_alive(metrics_mod.DB_PATH)
    out = metrics_mod.generate_prometheus_metrics()

    # Device-Gauges erscheinen weiterhin (kein Knall) ...
    assert "cernis_devices_total 2" in out
    assert "# ERROR generating metrics" not in out
    # ... aber der alive-abhaengige Monitor-Block liefert NICHTS (toter Strang).
    assert "cernis_monitor_rtt_ms" not in out
    assert "cernis_monitor_up" not in out


# ── influxdb: still leer ───────────────────────────────────────


def test_influxdb_empty_db_yields_empty_string(metrics_mod: Any) -> None:
    # aeusserer try/except schluckt -> "" (AS-IS).
    assert metrics_mod.generate_influxdb_lines() == ""


def test_influxdb_with_devices_emits_device_line(metrics_mod: Any) -> None:
    _create_devices_table(metrics_mod.DB_PATH)
    out = metrics_mod.generate_influxdb_lines()
    # Line-Protocol: measurement,tags fields timestamp
    assert "cernis,source=devices " in out
    assert "total=2i" in out
    assert "known=1i" in out


# ── homeassistant: error-state bei leerer DB ───────────────────


def test_homeassistant_empty_db_yields_error_state(metrics_mod: Any) -> None:
    out = metrics_mod.generate_homeassistant_state()
    assert out == {
        "state": "error",
        "attributes": {"error": "no such table: devices"},
    }


def test_homeassistant_devices_without_rtt_history_still_error(metrics_mod: Any) -> None:
    # AS-IS schaerfer als naiv erwartet: generate_homeassistant_state liest im
    # SELBEN aeusseren try auch rtt_history. Mit devices, aber OHNE rtt_history,
    # knallt es auf rtt_history -> wieder error-state. Beide Tabellen noetig.
    _create_devices_table(metrics_mod.DB_PATH)
    out = metrics_mod.generate_homeassistant_state()
    assert out == {
        "state": "error",
        "attributes": {"error": "no such table: rtt_history"},
    }


def test_homeassistant_with_rtt_history_errors_on_missing_alive_column(
    metrics_mod: Any,
) -> None:
    # DRITTER (und schaerfster) toter Strang: die HA-monitor-Query selektiert
    # `alive FROM rtt_history` -- diese Spalte existiert in rtt_history NICHT
    # (monitor._init_monitor_db legt sie nie an). Im SELBEN aeusseren try -> der
    # ganze Aufruf kippt auf "no such column: alive". D.h.: mit dem ECHTEN
    # v1-Schema liefert /api/export/homeassistant IMMER error-state, weil der
    # alive-Strang nie befriedigt werden kann. AS-IS eingefroren, kein Fix (M.8).
    _create_devices_table(metrics_mod.DB_PATH)
    _create_rtt_history_without_alive(metrics_mod.DB_PATH)
    out = metrics_mod.generate_homeassistant_state()
    assert out == {
        "state": "error",
        "attributes": {"error": "no such column: alive"},
    }


def test_homeassistant_success_path_requires_nonexistent_schema(metrics_mod: Any) -> None:
    # Der erfolgreiche State-Dict-Pfad ist mit dem v1-Schema UNERREICHBAR -- er
    # setzt eine rtt_history.alive-Spalte voraus, die v1 nie anlegt. Wir belegen
    # das, indem wir die alive-Spalte KUENSTLICH hinzufuegen (kein v1-Zustand,
    # nur zur Charakterisierung des sonst toten Erfolgspfads). Das ist die
    # einzige Konstellation, in der HA NICHT error-state liefert.
    _create_devices_table(metrics_mod.DB_PATH)
    conn = sqlite3.connect(metrics_mod.DB_PATH)
    conn.executescript(
        """
        CREATE TABLE rtt_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id TEXT, rtt_ms REAL, loss_pct REAL, ts REAL, alive INTEGER
        );
        INSERT INTO rtt_history (target_id, rtt_ms, loss_pct, ts, alive)
            VALUES ('wlan', 5.0, 0.0, strftime('%s','now'), 1);
        """
    )
    conn.commit()
    conn.close()
    out = metrics_mod.generate_homeassistant_state()
    # Struktur (AS-IS, nur mit kuenstlichem alive-Schema erreichbar):
    assert out["state"] == out["attributes"]["devices_online"]
    assert out["attributes"]["devices_total"] == 2
    assert out["attributes"]["unit_of_measurement"] == "devices"
    assert out["attributes"]["friendly_name"] == "CERNIS PRO Network"
    assert out["attributes"]["icon"] == "mdi:lan"
    assert out["attributes"]["monitor"] == {"wlan": {"alive": True, "rtt_ms": 5.0}}
