"""Tests fuer ``SqliteMonitorEventRepository`` -- Round-trip, Reihenfolge, datetime-Format.

Getestet: (1) Port-Konformitaet, (2) save/recent-Round-trip inkl. StrEnum-Event-
Round-trip, (3) Reihenfolge ABSTEIGEND (Altcode ORDER BY ts DESC), (4) die
vorformatierte datetime-Spalte traegt das Altcode-Format "%Y-%m-%d %H:%M:%S".
"""

import sqlite3
from pathlib import Path

import pytest

from domain.monitoring import MonitorEvent, MonitorEventType
from infrastructure.monitoring.monitor_events import SqliteMonitorEventRepository
from ports.monitoring import MonitorEventRepository


@pytest.fixture
def repo(tmp_path: Path) -> SqliteMonitorEventRepository:
    return SqliteMonitorEventRepository(tmp_path / "cernis.db")


def _event(event_type: MonitorEventType, ts: float, label: str = "WLAN") -> MonitorEvent:
    return MonitorEvent(target_id="wlan", label=label, event=event_type, rtt_ms=3.0, timestamp=ts)


def test_conforms_to_event_repo_protocol(repo: SqliteMonitorEventRepository) -> None:
    _: MonitorEventRepository = repo


def test_save_then_recent_roundtrip(repo: SqliteMonitorEventRepository) -> None:
    repo.save(_event(MonitorEventType.DOWN, 100.0))
    recent = repo.recent(10)
    assert len(recent) == 1
    e = recent[0]
    assert e.target_id == "wlan"
    assert e.label == "WLAN"
    assert e.event is MonitorEventType.DOWN  # StrEnum-Round-trip
    assert e.rtt_ms == 3.0
    assert e.timestamp == 100.0


def test_recent_descending_newest_first(repo: SqliteMonitorEventRepository) -> None:
    repo.save(_event(MonitorEventType.UP, 100.0))
    repo.save(_event(MonitorEventType.DOWN, 300.0))
    repo.save(_event(MonitorEventType.UP, 200.0))
    recent = repo.recent(10)
    # Altcode get_monitor_events: ORDER BY ts DESC.
    assert [e.timestamp for e in recent] == [300.0, 200.0, 100.0]


def test_recent_respects_limit(repo: SqliteMonitorEventRepository) -> None:
    for ts in (1.0, 2.0, 3.0):
        repo.save(_event(MonitorEventType.UP, ts))
    assert len(repo.recent(2)) == 2
    assert repo.recent(0) == []


def test_recent_empty_returns_empty(repo: SqliteMonitorEventRepository) -> None:
    assert repo.recent(10) == []


def test_datetime_column_uses_altcode_format(repo: SqliteMonitorEventRepository) -> None:
    # Die vorformatierte datetime-Spalte traegt "%Y-%m-%d %H:%M:%S" (Altcode-DB-Format,
    # M.2-Format-Divergenz-Naht am Adapter-Rand). Wir lesen die Roh-Spalte direkt.
    from datetime import datetime

    ts = 1_700_000_000.0
    repo.save(_event(MonitorEventType.DOWN, ts))
    # Erwartetes Format aus demselben ts (TZ-lokal wie der Adapter via fromtimestamp).
    expected = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect(repo._db_path)  # Roh-Spalten-Check der datetime-Spalte
    row = conn.execute("SELECT datetime FROM monitor_events").fetchone()
    conn.close()
    assert row[0] == expected
    # Form: "YYYY-MM-DD HH:MM:SS" (10 + 1 + 8 Zeichen), NICHT das WS-Kurzformat.
    assert len(row[0]) == 19
    assert row[0][4] == "-" and row[0][13] == ":"
