"""Tests fuer ``SqliteRttHistoryRepository`` -- alive-Schema + Migrations-Guard.

Getestet: (1) Port-Konformitaet, (2) save/recent-Round-trip inkl. alive, (3)
Reihenfolge CHRONOLOGISCH AUFSTEIGEND (Altcode ORDER BY ts DESC + reversed), (4)
RTT-Sentinel -1.0 erhalten, (5) Filterung nach target_id, (6) 1000-Trim, und
(7) DER PFLICHT-MIGRATIONS-TEST: eine Alt-Tabelle OHNE alive (wie der Altcode-Loop
sie anlegt) wird durch _ensure_schema migriert -> save() mit alive knallt nicht,
recent() liefert Alt-Zeilen mit alive=False.
"""

import sqlite3
from pathlib import Path

import pytest

from domain.monitoring import PingSample
from infrastructure.monitoring.rtt_history import SqliteRttHistoryRepository
from ports.monitoring import RttHistoryRepository


@pytest.fixture
def repo(tmp_path: Path) -> SqliteRttHistoryRepository:
    return SqliteRttHistoryRepository(tmp_path / "cernis.db")


def _sample(target_id: str, ts: float, *, alive: bool = True, rtt: float = 3.0) -> PingSample:
    return PingSample(
        target_id=target_id, host="h", alive=alive, rtt_ms=rtt, loss_pct=0.0, timestamp=ts
    )


def test_conforms_to_rtt_history_protocol(repo: SqliteRttHistoryRepository) -> None:
    _: RttHistoryRepository = repo


def test_save_then_recent_roundtrip_with_alive(repo: SqliteRttHistoryRepository) -> None:
    repo.save(_sample("wlan", 100.0, alive=True, rtt=3.5))
    recent = repo.recent("wlan", 10)
    assert len(recent) == 1
    s = recent[0]
    assert s.target_id == "wlan"
    assert s.alive is True  # alive korrekt persistiert + rekonstruiert
    assert s.rtt_ms == 3.5
    assert s.loss_pct == 0.0
    assert s.timestamp == 100.0


def test_recent_chronological_ascending(repo: SqliteRttHistoryRepository) -> None:
    for ts in (300.0, 100.0, 200.0):
        repo.save(_sample("wlan", ts))
    recent = repo.recent("wlan", 10)
    # Altcode: ORDER BY ts DESC + reversed -> aufsteigend.
    assert [s.timestamp for s in recent] == [100.0, 200.0, 300.0]


def test_recent_preserves_rtt_sentinel(repo: SqliteRttHistoryRepository) -> None:
    repo.save(_sample("wlan", 1.0, alive=False, rtt=-1.0))
    s = repo.recent("wlan", 10)[0]
    assert s.alive is False
    assert s.rtt_ms == -1.0  # Sentinel bleibt


def test_recent_filters_by_target(repo: SqliteRttHistoryRepository) -> None:
    repo.save(_sample("wlan", 1.0))
    repo.save(_sample("lan", 2.0))
    assert len(repo.recent("wlan", 10)) == 1
    assert repo.recent("wlan", 10)[0].target_id == "wlan"


def test_recent_unknown_target_empty(repo: SqliteRttHistoryRepository) -> None:
    assert repo.recent("nope", 10) == []


def test_save_trims_to_1000_per_target(repo: SqliteRttHistoryRepository) -> None:
    # 1002 Samples -> nur die letzten 1000 bleiben (Adapter-Mechanik).
    for i in range(1002):
        repo.save(_sample("wlan", float(i)))
    recent = repo.recent("wlan", 5000)
    assert len(recent) == 1000
    # Die zwei aeltesten (ts 0, 1) sind weg, ts 2 ist nun das aelteste.
    assert recent[0].timestamp == 2.0


# ── DER PFLICHT-MIGRATIONS-TEST ─────────────────────────────────────────────


def _make_legacy_table_without_alive(db_path: Path) -> None:
    """Legt rtt_history OHNE alive an -- exakt wie der Altcode (_init_monitor_db)."""
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE rtt_history (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id TEXT,
            rtt_ms    REAL,
            loss_pct  REAL,
            ts        REAL
        )
        """
    )
    conn.execute(
        "INSERT INTO rtt_history (target_id, rtt_ms, loss_pct, ts) VALUES (?, ?, ?, ?)",
        ("wlan", 5.0, 0.0, 50.0),
    )
    conn.commit()
    conn.close()


def test_migration_adds_alive_to_legacy_table(tmp_path: Path) -> None:
    db = tmp_path / "cernis.db"
    # 1. Altcode-Box: rtt_history OHNE alive, mit einer Alt-Zeile.
    _make_legacy_table_without_alive(db)

    # 2. v2-Adapter aufbauen -> _ensure_schema migriert (ALTER ADD COLUMN alive).
    repo = SqliteRttHistoryRepository(db)

    # (a) save() mit alive knallt NICHT (Spalte existiert nach Migration).
    repo.save(_sample("wlan", 200.0, alive=True, rtt=3.0))

    # (b) recent() liefert die Alt-Zeile mit alive=False (Default 0) UND die neue.
    recent = repo.recent("wlan", 10)
    assert len(recent) == 2
    by_ts = {s.timestamp: s for s in recent}
    assert by_ts[50.0].alive is False  # Alt-Zeile: Default 0 -> False
    assert by_ts[50.0].rtt_ms == 5.0  # Altdaten erhalten
    assert by_ts[200.0].alive is True  # neue Zeile: alive geschrieben


def test_migration_is_idempotent(tmp_path: Path) -> None:
    # Zweimaliges Aufbauen auf derselben (schon migrierten) DB darf nicht knallen.
    db = tmp_path / "cernis.db"
    _make_legacy_table_without_alive(db)
    SqliteRttHistoryRepository(db)
    repo2 = SqliteRttHistoryRepository(db)  # zweiter _ensure_schema-Lauf
    repo2.save(_sample("wlan", 1.0))
    assert len(repo2.recent("wlan", 10)) == 2
