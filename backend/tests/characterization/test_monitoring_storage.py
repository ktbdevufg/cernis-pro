"""Characterization-Contract der monitoring-DB-Round-trips (Altcode modules/).

Gegen eine temporaere DB (Muster wie test_scan_history_storage): ``DB_PATH`` wird
AM JEWEILIGEN MODUL-NAMESPACE umgebogen (``monkeypatch.setattr(monitor, "DB_PATH",
...)``), NICHT nur ``CERNIS_DATA_DIR`` -- denn ``modules.db_path.DB_PATH`` ist beim
Import bereits als String gebunden (``from modules.db_path import DB_PATH``), und
ein spaetes Setzen der Env-Var wuerde diesen Wert nicht mehr aendern.

Festgehalten wird, was die Schreib-Helfer in die Tabellen schreiben und wie die
Lese-Helfer es zurueckliefern:
    monitor:   _save_event/_save_rtt  ->  get_monitor_events/get_rtt_history
"""

import asyncio
from pathlib import Path
from typing import Any

import pytest

# ── monitor: monitor_events / rtt_history ─────────────────────


@pytest.fixture
def monitor_storage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    from modules import monitor

    monkeypatch.setattr(monitor, "DB_PATH", str(tmp_path / "cernis.db"))
    monitor._init_monitor_db()
    return monitor


def test_save_event_then_events_roundtrip(monitor_storage: Any) -> None:
    monitor = monitor_storage
    evt = monitor.MonitorEvent(
        target_id="wlan", label="WLAN", event="down", rtt_ms=-1.0, timestamp=1_700_000_000.0
    )
    monitor._save_event(evt)

    events = monitor.get_monitor_events()
    assert len(events) == 1
    row = events[0]
    # Spalten der monitor_events-Tabelle (AS-IS): id + die geschriebenen Felder.
    assert set(row.keys()) == {"id", "target_id", "label", "event", "rtt_ms", "ts", "datetime"}
    assert row["target_id"] == "wlan"
    assert row["label"] == "WLAN"
    assert row["event"] == "down"
    assert row["rtt_ms"] == -1.0
    assert row["ts"] == 1_700_000_000.0
    # datetime wird beim Schreiben aus ts als "%Y-%m-%d %H:%M:%S" formatiert.
    assert isinstance(row["datetime"], str)


def test_get_monitor_events_orders_newest_first(monitor_storage: Any) -> None:
    monitor = monitor_storage
    for i, ts in enumerate((100.0, 300.0, 200.0)):
        monitor._save_event(
            monitor.MonitorEvent(target_id=f"t{i}", label="L", event="up", rtt_ms=1.0, timestamp=ts)
        )
    events = monitor.get_monitor_events()
    # ORDER BY ts DESC
    assert [e["ts"] for e in events] == [300.0, 200.0, 100.0]


def test_get_monitor_events_empty_returns_empty_list(monitor_storage: Any) -> None:
    assert monitor_storage.get_monitor_events() == []


def test_save_rtt_then_history_roundtrip(monitor_storage: Any) -> None:
    monitor = monitor_storage
    result = monitor.PingResult(
        target_id="wlan",
        host="192.168.1.1",
        alive=True,
        rtt_ms=3.5,
        loss_pct=0.0,
        timestamp=1_700_000_000.0,
    )
    monitor._save_rtt(result)

    hist = monitor.get_rtt_history("wlan")
    assert len(hist) == 1
    row = hist[0]
    # get_rtt_history selektiert NUR rtt_ms, loss_pct, ts (keine alive-Spalte --
    # die existiert in rtt_history gar nicht; das ist der bekannte tote Strang).
    assert set(row.keys()) == {"rtt_ms", "loss_pct", "ts"}
    assert row["rtt_ms"] == 3.5
    assert row["loss_pct"] == 0.0
    assert row["ts"] == 1_700_000_000.0


def test_get_rtt_history_returns_chronological_oldest_first(monitor_storage: Any) -> None:
    monitor = monitor_storage
    for ts in (300.0, 100.0, 200.0):
        monitor._save_rtt(
            monitor.PingResult(
                target_id="wlan",
                host="h",
                alive=True,
                rtt_ms=ts / 100,
                loss_pct=0.0,
                timestamp=ts,
            )
        )
    hist = monitor.get_rtt_history("wlan")
    # Query holt DESC, Helfer dreht via reversed() -> aufsteigend zurueck.
    assert [r["ts"] for r in hist] == [100.0, 200.0, 300.0]


def test_get_rtt_history_filters_by_target(monitor_storage: Any) -> None:
    monitor = monitor_storage
    monitor._save_rtt(
        monitor.PingResult(
            target_id="wlan", host="h", alive=True, rtt_ms=1.0, loss_pct=0.0, timestamp=1.0
        )
    )
    monitor._save_rtt(
        monitor.PingResult(
            target_id="lan", host="h", alive=True, rtt_ms=2.0, loss_pct=0.0, timestamp=2.0
        )
    )
    assert len(monitor.get_rtt_history("wlan")) == 1
    assert monitor.get_rtt_history("wlan")[0]["rtt_ms"] == 1.0


# ── monitor: _ping_burst-Aggregation (RTT 0.0 vs. Sentinel -1.0) ──


def test_ping_burst_treats_zero_rtt_as_valid(monkeypatch: pytest.MonkeyPatch) -> None:
    # Windows-DWORD RoundTripTime rundet sub-ms-LAN-Latenz auf 0.0. Diese 0.0 ist
    # eine GUELTIGE Messung, kein Sentinel. Liefert _ping_once ausschliesslich
    # (True, 0.0), muss das aggregierte PingResult alive True, loss_pct 0.0 und
    # rtt_ms 0.0 melden -- NICHT den Sentinel -1.0.
    from modules import monitor

    async def fake_once(host: str, interface: str = "") -> tuple[bool, float]:
        return True, 0.0

    monkeypatch.setattr(monitor, "_ping_once", fake_once)

    result = asyncio.run(monitor._ping_burst("192.168.1.1", count=3))
    assert result.alive is True
    assert result.loss_pct == 0.0
    assert result.rtt_ms == 0.0


def test_ping_burst_sentinel_still_applies_when_unreachable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Gegenprobe: der Sentinel greift weiterhin. Liefert _ping_once ausschliesslich
    # (False, -1.0), ist das aggregierte PingResult alive False, loss_pct 100.0 und
    # rtt_ms -1.0 (kein gueltiger RTT-Wert vorhanden -> Rueckfall auf Sentinel).
    from modules import monitor

    async def fake_once(host: str, interface: str = "") -> tuple[bool, float]:
        return False, -1.0

    monkeypatch.setattr(monitor, "_ping_once", fake_once)

    result = asyncio.run(monitor._ping_burst("192.168.1.1", count=3))
    assert result.alive is False
    assert result.loss_pct == 100.0
    assert result.rtt_ms == -1.0
