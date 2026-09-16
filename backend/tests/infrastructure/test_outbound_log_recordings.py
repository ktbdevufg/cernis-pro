"""Tests fuer den SQLite-Adapter ``SqliteOutboundRecordingRepository`` (E2).

Prueft die konkrete Implementierung gegen eine temporaere DB (``tmp_path``), nicht die
echte ``cernis.db`` (Muster ``test_rogue_dhcp_repository``). Kern der Behauptungen:

* save+get Round-trip inklusive Enum-Round-trip (mode/depth/state).
* Upsert: zweimal ``save`` derselben ``id`` -> GENAU eine Zeile mit neuem ``state``.
* ``list_all`` sortiert nach ``created_at`` (aufsteigend).
* ``delete`` ist idempotent; ``clear_all`` leert die Tabelle.
"""

import sqlite3
from pathlib import Path

import pytest

from domain.outbound_log import (
    DetailDepth,
    OutboundRecording,
    RecordingMode,
    RecordingState,
)
from infrastructure.outbound_log_recordings import SqliteOutboundRecordingRepository
from ports.outbound_log import OutboundRecordingRepository


@pytest.fixture
def repo(tmp_path: Path) -> SqliteOutboundRecordingRepository:
    """Frisches Repository gegen eine temporaere DB."""
    return SqliteOutboundRecordingRepository(tmp_path / "cernis.db")


def _count_rows(db_path: Path) -> int:
    """Zaehlt die Zeilen der Tabelle direkt (Upsert-Beweis)."""
    conn = sqlite3.connect(db_path)
    try:
        return int(conn.execute("SELECT COUNT(*) FROM outbound_log_recordings").fetchone()[0])
    finally:
        conn.close()


def _recording(
    rec_id: str,
    *,
    state: RecordingState = RecordingState.CREATED,
    created_at: float = 1.0,
    mode: RecordingMode = RecordingMode.DETAIL,
    depth: DetailDepth = DetailDepth.ANONYMOUS,
    effective_start: float | None = None,
    max_duration_s: int | None = None,
) -> OutboundRecording:
    return OutboundRecording(
        id=rec_id,
        label=f"label-{rec_id}",
        purpose=f"purpose-{rec_id}",
        mode=mode,
        depth=depth,
        state=state,
        interval_s=60,
        created_at=created_at,
        effective_start=effective_start,
        max_duration_s=max_duration_s,
    )


# ── Struktureller Vertrag ─────────────────────────────────────────────────


def test_conforms_to_protocol(repo: SqliteOutboundRecordingRepository) -> None:
    # Statische Vertragspruefung (mypy): erfuellt das Protocol strukturell.
    _: OutboundRecordingRepository = repo


# ── save + get Round-trip inkl. Enums ──────────────────────────────────────


def test_save_then_get_roundtrips_enums(repo: SqliteOutboundRecordingRepository) -> None:
    rec = _recording(
        "r1",
        state=RecordingState.ACTIVE,
        mode=RecordingMode.DETAIL,
        depth=DetailDepth.APP_RESOLVED,
        effective_start=1_700_000_000.0,
        max_duration_s=3600,
    )
    repo.save(rec)
    loaded = repo.get("r1")
    assert loaded == rec
    # Enums sind echte Domaenen-Enums, kein roher String.
    assert loaded is not None
    assert isinstance(loaded.mode, RecordingMode)
    assert isinstance(loaded.depth, DetailDepth)
    assert isinstance(loaded.state, RecordingState)


def test_get_unknown_returns_none(repo: SqliteOutboundRecordingRepository) -> None:
    assert repo.get("fehlt") is None


def test_aggregate_recording_nullable_fields_roundtrip(
    repo: SqliteOutboundRecordingRepository,
) -> None:
    # AGGREGATE: effective_start/max_duration_s None -> als NULL abgelegt, None zurueck.
    rec = _recording("agg", mode=RecordingMode.AGGREGATE, depth=DetailDepth.ANONYMOUS)
    repo.save(rec)
    loaded = repo.get("agg")
    assert loaded is not None
    assert loaded.effective_start is None
    assert loaded.max_duration_s is None


# ── Upsert ──────────────────────────────────────────────────────────────────


def test_save_same_id_upserts_single_row_new_state(
    repo: SqliteOutboundRecordingRepository, tmp_path: Path
) -> None:
    repo.save(_recording("r1", state=RecordingState.CREATED))
    repo.save(_recording("r1", state=RecordingState.ACTIVE))
    # GENAU eine Zeile (Upsert ueber id), nicht zwei.
    assert _count_rows(tmp_path / "cernis.db") == 1
    loaded = repo.get("r1")
    assert loaded is not None
    assert loaded.state is RecordingState.ACTIVE


# ── list_all-Reihenfolge ────────────────────────────────────────────────────


def test_list_all_orders_by_created_at(repo: SqliteOutboundRecordingRepository) -> None:
    repo.save(_recording("b", created_at=30.0))
    repo.save(_recording("a", created_at=10.0))
    repo.save(_recording("c", created_at=20.0))
    ids = [r.id for r in repo.list_all()]
    assert ids == ["a", "c", "b"]


def test_list_all_empty(repo: SqliteOutboundRecordingRepository) -> None:
    assert repo.list_all() == []


# ── delete idempotent + clear_all ──────────────────────────────────────────


def test_delete_idempotent(repo: SqliteOutboundRecordingRepository) -> None:
    repo.save(_recording("r1"))
    repo.delete("r1")
    assert repo.get("r1") is None
    # Erneutes Loeschen (oder unbekannte id) ist kein Fehler.
    repo.delete("r1")
    repo.delete("nie_existiert")


def test_clear_all(repo: SqliteOutboundRecordingRepository) -> None:
    repo.save(_recording("a"))
    repo.save(_recording("b"))
    repo.clear_all()
    assert repo.list_all() == []
