"""Tests fuer ``SqliteSlaSampleRepository`` (M.7) -- die SLA-Lese-Seite.

Getestet: (1) Port-Konformitaet, (2) samples_for-Round-trip mit der (alive, rtt_ms,
ts)-Spaltenreihenfolge, (3) Reihenfolge AUFSTEIGEND (Altcode ORDER BY ts), (4) der
since-Filter (ts > since, strikt), (5) Filterung nach target_id, (6) leere Tabelle /
unbekanntes Target -> [], (7) target_ids DISTINCT, (8) RTT-Sentinel -1.0 + alive=0
roh durchgereicht, (9) der BEFUND: sla_targets wird NICHT angelegt (toter
Altcode-DDL), (10) eine vom Altcode-init_sla_db angelegte Tabelle wird ohne Guard
gelesen (CREATE IF NOT EXISTS reicht -- keine fehlende Spalte wie in M.4).

KEIN Schreibpfad-Test -- der Adapter hat bewusst kein record() (s. ports/monitoring,
M.7b). Die Zeilen werden hier per direktem INSERT gesetzt, wie der (nie gerufene)
Altcode-record_sample sie schreiben WUERDE.
"""

import sqlite3
from pathlib import Path

import pytest

from infrastructure.monitoring.sla_samples import SqliteSlaSampleRepository
from ports.monitoring import SlaSampleRepository


@pytest.fixture
def repo(tmp_path: Path) -> SqliteSlaSampleRepository:
    return SqliteSlaSampleRepository(tmp_path / "cernis.db")


def _insert(
    repo: SqliteSlaSampleRepository, target_id: str, ts: float, *, alive: int = 1, rtt: float = 3.0
) -> None:
    """Schreibt eine Zeile direkt (wie der nie gerufene Altcode-record_sample)."""
    with repo._connect() as conn:
        conn.execute(
            "INSERT INTO sla_samples (target_id, ts, alive, rtt_ms) VALUES (?, ?, ?, ?)",
            (target_id, ts, alive, rtt),
        )


def test_conforms_to_sla_sample_protocol(repo: SqliteSlaSampleRepository) -> None:
    _: SlaSampleRepository = repo


def test_samples_for_roundtrip_column_order(repo: SqliteSlaSampleRepository) -> None:
    _insert(repo, "wlan", 100.0, alive=1, rtt=3.5)
    rows = repo.samples_for("wlan", 0.0)
    assert rows == [(1, 3.5, 100.0)]  # (alive, rtt_ms, ts) -- domain.SlaSample-Form


def test_samples_for_ascending_by_ts(repo: SqliteSlaSampleRepository) -> None:
    for ts in (300.0, 100.0, 200.0):
        _insert(repo, "wlan", ts)
    rows = repo.samples_for("wlan", 0.0)
    assert [r[2] for r in rows] == [100.0, 200.0, 300.0]  # ORDER BY ts aufsteigend


def test_samples_for_since_filter_is_strict(repo: SqliteSlaSampleRepository) -> None:
    _insert(repo, "wlan", 100.0)
    _insert(repo, "wlan", 200.0)
    # ts > since (strikt, wie Altcode WHERE ts > ?): 100.0 fliegt bei since=100.0 raus.
    rows = repo.samples_for("wlan", 100.0)
    assert [r[2] for r in rows] == [200.0]


def test_samples_for_filters_by_target(repo: SqliteSlaSampleRepository) -> None:
    _insert(repo, "wlan", 1.0)
    _insert(repo, "lan", 2.0)
    rows = repo.samples_for("wlan", 0.0)
    assert len(rows) == 1
    assert rows == [(1, 3.0, 1.0)]


def test_samples_for_unknown_target_empty(repo: SqliteSlaSampleRepository) -> None:
    assert repo.samples_for("nope", 0.0) == []  # Leer, nicht None


def test_samples_for_empty_table(repo: SqliteSlaSampleRepository) -> None:
    assert repo.samples_for("wlan", 0.0) == []


def test_preserves_sentinel_and_dead_sample(repo: SqliteSlaSampleRepository) -> None:
    # alive=0 + rtt=-1.0 roh durchgereicht (Domaene wertet alive truthy aus).
    _insert(repo, "wlan", 1.0, alive=0, rtt=-1.0)
    rows = repo.samples_for("wlan", 0.0)
    assert rows == [(0, -1.0, 1.0)]


def test_target_ids_distinct(repo: SqliteSlaSampleRepository) -> None:
    _insert(repo, "wlan", 1.0)
    _insert(repo, "wlan", 2.0)  # zweites Sample selber Target -> trotzdem 1x in DISTINCT
    _insert(repo, "lan", 3.0)
    assert sorted(repo.target_ids()) == ["lan", "wlan"]


def test_target_ids_empty_table(repo: SqliteSlaSampleRepository) -> None:
    assert repo.target_ids() == []


def test_sla_targets_table_not_created(repo: SqliteSlaSampleRepository) -> None:
    # BEFUND: der v2-Adapter legt die tote Altcode-Tabelle sla_targets NICHT an.
    with repo._connect() as conn:
        names = {
            row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
    assert "sla_samples" in names
    assert "sla_targets" not in names


# ── Altcode-Tabelle wird ohne Guard gelesen (kein Migrations-Bedarf wie M.4) ──


def _make_altcode_sla_table(db_path: Path) -> None:
    """Legt sla_samples + sla_targets an -- exakt wie der Altcode init_sla_db."""
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE sla_targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT, target_id TEXT UNIQUE,
            label TEXT, host TEXT, enabled INTEGER DEFAULT 1,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE sla_samples (
            id INTEGER PRIMARY KEY AUTOINCREMENT, target_id TEXT, ts REAL,
            alive INTEGER, rtt_ms REAL
        );
        """
    )
    conn.execute(
        "INSERT INTO sla_samples (target_id, ts, alive, rtt_ms) VALUES (?, ?, ?, ?)",
        ("wlan", 50.0, 1, 5.0),
    )
    conn.commit()
    conn.close()


def test_reads_altcode_table_without_guard(tmp_path: Path) -> None:
    # Box mit Altcode-sla_samples (exakt gleiche Spalten) -> CREATE IF NOT EXISTS ist
    # No-Op, die Alt-Zeile wird ohne Migration gelesen (anders als rtt_history.alive).
    db = tmp_path / "cernis.db"
    _make_altcode_sla_table(db)
    repo = SqliteSlaSampleRepository(db)
    assert repo.samples_for("wlan", 0.0) == [(1, 5.0, 50.0)]
    assert repo.target_ids() == ["wlan"]
