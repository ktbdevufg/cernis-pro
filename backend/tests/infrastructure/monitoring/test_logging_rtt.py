"""Tests fuer ``SqliteLoggingRttRepository`` (B-I, Tabelle ``monitoring_log_rtt``).

Gegen eine echte temporaere sqlite (``tmp_path``), Muster wie ``test_rtt_history``.
Getestet: (1) Port-Konformitaet, (2) save->range-Round-trip inkl. alive/Sentinel,
(3) range-Grenzen (since INKLUSIV, until EXKLUSIV), (4) range-Reihenfolge aufsteigend,
(5) range filtert nach task_id, (6) Leerzustand range -> [] (nicht None),
(7) KEIN Trim (anders als rtt_history -- viele Zeilen bleiben),
(8) delete_older_than loescht nur Aelteres (Cutoff-Grenze) + Rueckgabewert, (9) count.
"""

from pathlib import Path

import pytest

from domain.monitoring import LoggingRttSample
from infrastructure.monitoring.logging_rtt import SqliteLoggingRttRepository
from ports.monitoring import LoggingRttRepository


@pytest.fixture
def repo(tmp_path: Path) -> SqliteLoggingRttRepository:
    return SqliteLoggingRttRepository(tmp_path / "cernis.db")


def test_conforms_to_logging_rtt_protocol(repo: SqliteLoggingRttRepository) -> None:
    _: LoggingRttRepository = repo


def test_save_then_range_roundtrip(repo: SqliteLoggingRttRepository) -> None:
    repo.save("t1", rtt_ms=3.5, loss_pct=0.0, alive=True, ts=100.0)
    rows = repo.range("t1", 0.0, 1000.0)
    assert rows == [LoggingRttSample(rtt_ms=3.5, loss_pct=0.0, alive=True, ts=100.0)]


def test_range_preserves_sentinel_and_alive_false(repo: SqliteLoggingRttRepository) -> None:
    repo.save("t1", rtt_ms=-1.0, loss_pct=100.0, alive=False, ts=10.0)
    s = repo.range("t1", 0.0, 1000.0)[0]
    assert s.alive is False
    assert s.rtt_ms == -1.0  # Sentinel bleibt


def test_range_ascending_order(repo: SqliteLoggingRttRepository) -> None:
    for ts in (300.0, 100.0, 200.0):
        repo.save("t1", rtt_ms=1.0, loss_pct=0.0, alive=True, ts=ts)
    rows = repo.range("t1", 0.0, 1000.0)
    assert [s.ts for s in rows] == [100.0, 200.0, 300.0]


def test_range_since_inclusive_until_exclusive(repo: SqliteLoggingRttRepository) -> None:
    for ts in (100.0, 150.0, 200.0):
        repo.save("t1", rtt_ms=1.0, loss_pct=0.0, alive=True, ts=ts)
    # Fenster [100, 200): 100 inklusiv, 200 exklusiv -> nur 100 + 150.
    rows = repo.range("t1", 100.0, 200.0)
    assert [s.ts for s in rows] == [100.0, 150.0]


def test_range_filters_by_task(repo: SqliteLoggingRttRepository) -> None:
    repo.save("t1", rtt_ms=1.0, loss_pct=0.0, alive=True, ts=10.0)
    repo.save("t2", rtt_ms=2.0, loss_pct=0.0, alive=True, ts=10.0)
    rows = repo.range("t1", 0.0, 1000.0)
    assert len(rows) == 1
    assert rows[0].rtt_ms == 1.0


def test_range_unknown_task_empty(repo: SqliteLoggingRttRepository) -> None:
    assert repo.range("nope", 0.0, 1000.0) == []  # [], nicht None


def test_no_trim_keeps_many_rows(repo: SqliteLoggingRttRepository) -> None:
    # rtt_history cappt auf 1000 -- HIER nicht (Retention statt Trim).
    for i in range(1100):
        repo.save("t1", rtt_ms=1.0, loss_pct=0.0, alive=True, ts=float(i))
    assert repo.count() == 1100


def test_delete_older_than_removes_only_older_and_returns_count(
    repo: SqliteLoggingRttRepository,
) -> None:
    for ts in (50.0, 100.0, 150.0):
        repo.save("t1", rtt_ms=1.0, loss_pct=0.0, alive=True, ts=ts)
    # Cutoff 100: strikt aelter (< 100) -> nur ts=50 weg; ts=100 bleibt (Grenze inkl.).
    deleted = repo.delete_older_than(100.0)
    assert deleted == 1
    remaining = [s.ts for s in repo.range("t1", 0.0, 1000.0)]
    assert remaining == [100.0, 150.0]


def test_delete_older_than_nothing_returns_zero(repo: SqliteLoggingRttRepository) -> None:
    repo.save("t1", rtt_ms=1.0, loss_pct=0.0, alive=True, ts=500.0)
    assert repo.delete_older_than(100.0) == 0  # nichts aelter als 100


def test_count_empty_is_zero(repo: SqliteLoggingRttRepository) -> None:
    assert repo.count() == 0


def test_all_for_returns_all_samples_ascending(repo: SqliteLoggingRttRepository) -> None:
    # C-3: all_for gibt ALLE Messpunkte eines Tasks chronologisch (kein Zeitfenster).
    for ts in (300.0, 100.0, 200.0):
        repo.save("t1", rtt_ms=1.0, loss_pct=0.0, alive=True, ts=ts)
    rows = repo.all_for("t1")
    assert [s.ts for s in rows] == [100.0, 200.0, 300.0]


def test_all_for_filters_by_task(repo: SqliteLoggingRttRepository) -> None:
    repo.save("t1", rtt_ms=1.0, loss_pct=0.0, alive=True, ts=10.0)
    repo.save("t2", rtt_ms=2.0, loss_pct=0.0, alive=True, ts=20.0)
    rows = repo.all_for("t1")
    assert len(rows) == 1
    assert rows[0].rtt_ms == 1.0


def test_all_for_unknown_task_empty(repo: SqliteLoggingRttRepository) -> None:
    assert repo.all_for("nope") == []  # [], nicht None
