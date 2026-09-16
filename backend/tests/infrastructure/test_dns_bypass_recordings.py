"""Tests fuer den SQLite-Adapter ``SqliteDnsBypassRecordingRepository`` (E2).

Prueft die konkrete Implementierung gegen eine temporaere DB (``tmp_path``), nicht die
echte ``cernis.db`` (Muster ``test_outbound_log_recordings``). Kern der Behauptungen:

* save+get Round-trip inklusive Enum-Round-trip (state) und JSON-Round-trip
  (expected_servers).
* Upsert: zweimal ``save`` derselben ``id`` -> GENAU eine Zeile mit neuem ``state``.
* ``list_all`` sortiert nach ``created_at`` (aufsteigend).
* Nullable-Felder (effective_start/interface) sowie leere expected_servers ueberleben.
* ``delete`` ist idempotent; ``clear_all`` leert die Tabelle.
"""

import sqlite3
from pathlib import Path

import pytest

from domain.dns_bypass import (
    DnsBypassRecording,
    DnsBypassRecordingState,
)
from infrastructure.dns_bypass_recordings import SqliteDnsBypassRecordingRepository
from ports.dns_bypass import DnsBypassRecordingRepository


@pytest.fixture
def repo(tmp_path: Path) -> SqliteDnsBypassRecordingRepository:
    """Frisches Repository gegen eine temporaere DB."""
    return SqliteDnsBypassRecordingRepository(tmp_path / "cernis.db")


def _count_rows(db_path: Path) -> int:
    """Zaehlt die Zeilen der Tabelle direkt (Upsert-Beweis)."""
    conn = sqlite3.connect(db_path)
    try:
        return int(conn.execute("SELECT COUNT(*) FROM dns_bypass_recordings").fetchone()[0])
    finally:
        conn.close()


def _recording(
    rec_id: str,
    *,
    state: DnsBypassRecordingState = DnsBypassRecordingState.CREATED,
    created_at: float = 1.0,
    effective_start: float | None = None,
    interface: str | None = None,
    expected_servers: tuple[str, ...] = (),
) -> DnsBypassRecording:
    return DnsBypassRecording(
        id=rec_id,
        label=f"label-{rec_id}",
        purpose=f"purpose-{rec_id}",
        state=state,
        created_at=created_at,
        effective_start=effective_start,
        interface=interface,
        expected_servers=expected_servers,
    )


# ── Struktureller Vertrag ─────────────────────────────────────────────────


def test_conforms_to_protocol(repo: SqliteDnsBypassRecordingRepository) -> None:
    # Statische Vertragspruefung (mypy): erfuellt das Protocol strukturell.
    _: DnsBypassRecordingRepository = repo


# ── save + get Round-trip inkl. Enum + JSON ─────────────────────────────────


def test_save_then_get_roundtrips_enum_and_json(
    repo: SqliteDnsBypassRecordingRepository,
) -> None:
    rec = _recording(
        "r1",
        state=DnsBypassRecordingState.ACTIVE,
        effective_start=1_700_000_000.0,
        interface="eth0",
        expected_servers=("1.1.1.1", "8.8.8.8", "fe80::1"),
    )
    repo.save(rec)
    loaded = repo.get("r1")
    assert loaded == rec
    # state ist ein echtes Domaenen-Enum, kein roher String.
    assert loaded is not None
    assert isinstance(loaded.state, DnsBypassRecordingState)
    # expected_servers kommt als tuple zurueck (JSON-Round-trip).
    assert loaded.expected_servers == ("1.1.1.1", "8.8.8.8", "fe80::1")


def test_get_unknown_returns_none(repo: SqliteDnsBypassRecordingRepository) -> None:
    assert repo.get("fehlt") is None


def test_nullable_fields_and_empty_expected_roundtrip(
    repo: SqliteDnsBypassRecordingRepository,
) -> None:
    # effective_start/interface None -> als NULL abgelegt, None zurueck; leere
    # expected_servers -> leere Tuple (keine stille Umdeutung nach None).
    rec = _recording("r1")
    repo.save(rec)
    loaded = repo.get("r1")
    assert loaded is not None
    assert loaded.effective_start is None
    assert loaded.interface is None
    assert loaded.expected_servers == ()


# ── Upsert ──────────────────────────────────────────────────────────────────


def test_save_same_id_upserts_single_row_new_state(
    repo: SqliteDnsBypassRecordingRepository, tmp_path: Path
) -> None:
    repo.save(_recording("r1", state=DnsBypassRecordingState.CREATED))
    repo.save(_recording("r1", state=DnsBypassRecordingState.ACTIVE))
    # GENAU eine Zeile (Upsert ueber id), nicht zwei.
    assert _count_rows(tmp_path / "cernis.db") == 1
    loaded = repo.get("r1")
    assert loaded is not None
    assert loaded.state is DnsBypassRecordingState.ACTIVE


# ── list_all-Reihenfolge ────────────────────────────────────────────────────


def test_list_all_orders_by_created_at(repo: SqliteDnsBypassRecordingRepository) -> None:
    repo.save(_recording("b", created_at=30.0))
    repo.save(_recording("a", created_at=10.0))
    repo.save(_recording("c", created_at=20.0))
    ids = [r.id for r in repo.list_all()]
    assert ids == ["a", "c", "b"]


def test_list_all_empty(repo: SqliteDnsBypassRecordingRepository) -> None:
    assert repo.list_all() == []


# ── delete idempotent + clear_all ──────────────────────────────────────────


def test_delete_idempotent(repo: SqliteDnsBypassRecordingRepository) -> None:
    repo.save(_recording("r1"))
    repo.delete("r1")
    assert repo.get("r1") is None
    # Erneutes Loeschen (oder unbekannte id) ist kein Fehler.
    repo.delete("r1")
    repo.delete("nie_existiert")


def test_clear_all(repo: SqliteDnsBypassRecordingRepository) -> None:
    repo.save(_recording("a"))
    repo.save(_recording("b"))
    repo.clear_all()
    assert repo.list_all() == []
