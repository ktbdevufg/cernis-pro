"""Tests fuer ``SqliteLoggingEventRepository`` (B-I, Tabelle ``monitoring_log_events``).

Gegen eine echte temporaere sqlite (``tmp_path``), Muster wie ``test_monitor_events``.
Getestet: (1) Port-Konformitaet, (2) save->range-Round-trip (event_type roher str),
(3) range-Grenzen (since INKLUSIV, until EXKLUSIV), (4) Reihenfolge aufsteigend,
(5) range filtert nach task_id, (6) Leerzustand range -> [] (nicht None),
(7) delete_older_than loescht nur Aelteres + Rueckgabewert.
"""

from pathlib import Path

import pytest

from domain.monitoring import LoggingEventRow
from infrastructure.monitoring.logging_events import SqliteLoggingEventRepository
from ports.monitoring import LoggingEventRepository


@pytest.fixture
def repo(tmp_path: Path) -> SqliteLoggingEventRepository:
    return SqliteLoggingEventRepository(tmp_path / "cernis.db")


def test_conforms_to_logging_event_protocol(repo: SqliteLoggingEventRepository) -> None:
    _: LoggingEventRepository = repo


def test_save_then_range_roundtrip_raw_str_type(repo: SqliteLoggingEventRepository) -> None:
    repo.save("t1", event_type="latency_spike", rtt_ms=42.0, ts=100.0)
    rows = repo.range("t1", 0.0, 1000.0)
    assert rows == [LoggingEventRow(event_type="latency_spike", rtt_ms=42.0, ts=100.0)]
    # event_type ist ein roher str (kein MonitorEventType) -- s. Port-Docstring.
    assert isinstance(rows[0].event_type, str)


def test_range_preserves_sentinel(repo: SqliteLoggingEventRepository) -> None:
    repo.save("t1", event_type="unreachable", rtt_ms=-1.0, ts=10.0)
    assert repo.range("t1", 0.0, 1000.0)[0].rtt_ms == -1.0


def test_range_ascending_order(repo: SqliteLoggingEventRepository) -> None:
    for ts in (300.0, 100.0, 200.0):
        repo.save("t1", event_type="flap", rtt_ms=1.0, ts=ts)
    rows = repo.range("t1", 0.0, 1000.0)
    assert [r.ts for r in rows] == [100.0, 200.0, 300.0]


def test_range_since_inclusive_until_exclusive(repo: SqliteLoggingEventRepository) -> None:
    for ts in (100.0, 150.0, 200.0):
        repo.save("t1", event_type="flap", rtt_ms=1.0, ts=ts)
    rows = repo.range("t1", 100.0, 200.0)
    assert [r.ts for r in rows] == [100.0, 150.0]  # 100 inkl., 200 exkl.


def test_range_filters_by_task(repo: SqliteLoggingEventRepository) -> None:
    repo.save("t1", event_type="a", rtt_ms=1.0, ts=10.0)
    repo.save("t2", event_type="b", rtt_ms=2.0, ts=10.0)
    rows = repo.range("t1", 0.0, 1000.0)
    assert len(rows) == 1
    assert rows[0].event_type == "a"


def test_range_unknown_task_empty(repo: SqliteLoggingEventRepository) -> None:
    assert repo.range("nope", 0.0, 1000.0) == []  # [], nicht None


def test_delete_older_than_removes_only_older_and_returns_count(
    repo: SqliteLoggingEventRepository,
) -> None:
    for ts in (50.0, 100.0, 150.0):
        repo.save("t1", event_type="flap", rtt_ms=1.0, ts=ts)
    deleted = repo.delete_older_than(100.0)  # strikt aelter (< 100) -> nur 50 weg
    assert deleted == 1
    remaining = [r.ts for r in repo.range("t1", 0.0, 1000.0)]
    assert remaining == [100.0, 150.0]  # Grenze 100 bleibt


def test_delete_older_than_nothing_returns_zero(repo: SqliteLoggingEventRepository) -> None:
    repo.save("t1", event_type="flap", rtt_ms=1.0, ts=500.0)
    assert repo.delete_older_than(100.0) == 0
