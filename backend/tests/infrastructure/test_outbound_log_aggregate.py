"""Tests fuer den SQLite-Adapter ``SqliteOutboundAggregateRepository`` (E2).

Prueft die konkrete Implementierung gegen eine temporaere DB (``tmp_path``), nicht die
echte ``cernis.db`` (Muster ``test_rogue_dhcp_repository``). Kern der Behauptungen:

* ``upsert`` Neuanlage + Ueberschreiben: gleiche ``(recording_id, remote_ip)`` ->
  GENAU eine Zeile mit dem neuen Stand.
* ``get`` vorhanden / None.
* ``list_for`` sortiert ``total_count DESC, remote_ip ASC`` (lauteste zuerst, stabil).
* ``delete_for`` trifft nur die eine ``recording_id``.
* ``count`` / ``clear_all``.
"""

import sqlite3
from pathlib import Path

import pytest

from domain.outbound_log import AggregatedContact
from infrastructure.outbound_log_aggregate import SqliteOutboundAggregateRepository
from ports.outbound_log import OutboundAggregateRepository


@pytest.fixture
def repo(tmp_path: Path) -> SqliteOutboundAggregateRepository:
    """Frisches Repository gegen eine temporaere DB."""
    return SqliteOutboundAggregateRepository(tmp_path / "cernis.db")


def _count_rows(db_path: Path) -> int:
    conn = sqlite3.connect(db_path)
    try:
        return int(conn.execute("SELECT COUNT(*) FROM outbound_log_aggregate").fetchone()[0])
    finally:
        conn.close()


def _contact(
    remote_ip: str,
    *,
    total_count: int = 1,
    peak_count: int = 1,
    first_seen: float = 1.0,
    last_seen: float = 2.0,
    remote_port: int | None = 443,
) -> AggregatedContact:
    return AggregatedContact(
        remote_ip=remote_ip,
        first_seen=first_seen,
        last_seen=last_seen,
        total_count=total_count,
        peak_count=peak_count,
        remote_port=remote_port,
        hostname="host.example",
        country="DE",
        operator="ExampleOrg",
        asn="AS1234",
        app_name="firefox",
    )


# ── Struktureller Vertrag ─────────────────────────────────────────────────


def test_conforms_to_protocol(repo: SqliteOutboundAggregateRepository) -> None:
    _: OutboundAggregateRepository = repo


# ── upsert Neuanlage + Ueberschreiben ──────────────────────────────────────


def test_upsert_insert_then_get(repo: SqliteOutboundAggregateRepository) -> None:
    contact = _contact("8.8.8.8", total_count=5, peak_count=3)
    repo.upsert("r1", contact)
    assert repo.get("r1", "8.8.8.8") == contact


def test_upsert_same_key_overwrites_single_row(
    repo: SqliteOutboundAggregateRepository, tmp_path: Path
) -> None:
    repo.upsert("r1", _contact("8.8.8.8", total_count=1, peak_count=1, last_seen=2.0))
    repo.upsert("r1", _contact("8.8.8.8", total_count=9, peak_count=4, last_seen=99.0))
    # GENAU eine Zeile (PK recording_id, remote_ip), nicht zwei.
    assert _count_rows(tmp_path / "cernis.db") == 1
    loaded = repo.get("r1", "8.8.8.8")
    assert loaded is not None
    assert loaded.total_count == 9
    assert loaded.peak_count == 4
    assert loaded.last_seen == 99.0


def test_upsert_null_port_roundtrips_as_none(repo: SqliteOutboundAggregateRepository) -> None:
    repo.upsert("r1", _contact("8.8.8.8", remote_port=None))
    loaded = repo.get("r1", "8.8.8.8")
    assert loaded is not None
    assert loaded.remote_port is None


# ── get None ────────────────────────────────────────────────────────────────


def test_get_unknown_returns_none(repo: SqliteOutboundAggregateRepository) -> None:
    repo.upsert("r1", _contact("8.8.8.8"))
    assert repo.get("r1", "1.1.1.1") is None
    assert repo.get("rX", "8.8.8.8") is None


# ── list_for-Sortierung ─────────────────────────────────────────────────────


def test_list_for_orders_by_count_desc_then_ip_asc(
    repo: SqliteOutboundAggregateRepository,
) -> None:
    repo.upsert("r1", _contact("1.1.1.1", total_count=5))
    repo.upsert("r1", _contact("9.9.9.9", total_count=10))
    # Gleichstand bei total_count=5 -> stabil nach remote_ip ASC.
    repo.upsert("r1", _contact("2.2.2.2", total_count=5))
    ips = [c.remote_ip for c in repo.list_for("r1")]
    # 9.9.9.9 (10) zuerst, dann die beiden mit 5 nach IP aufsteigend.
    assert ips == ["9.9.9.9", "1.1.1.1", "2.2.2.2"]


def test_list_for_empty(repo: SqliteOutboundAggregateRepository) -> None:
    assert repo.list_for("fehlt") == []


# ── delete_for trifft nur die eine recording_id ────────────────────────────


def test_delete_for_only_affects_one_recording(
    repo: SqliteOutboundAggregateRepository,
) -> None:
    repo.upsert("r1", _contact("8.8.8.8"))
    repo.upsert("r1", _contact("1.1.1.1"))
    repo.upsert("r2", _contact("8.8.8.8"))
    repo.delete_for("r1")
    assert repo.list_for("r1") == []
    # r2 bleibt unberuehrt.
    assert [c.remote_ip for c in repo.list_for("r2")] == ["8.8.8.8"]
    # Idempotent: erneutes/unbekanntes delete_for kein Fehler.
    repo.delete_for("r1")
    repo.delete_for("nie_existiert")


# ── count + clear_all ───────────────────────────────────────────────────────


def test_count_and_clear_all(repo: SqliteOutboundAggregateRepository) -> None:
    assert repo.count() == 0
    repo.upsert("r1", _contact("8.8.8.8"))
    repo.upsert("r1", _contact("1.1.1.1"))
    repo.upsert("r2", _contact("8.8.8.8"))
    assert repo.count() == 3
    repo.clear_all()
    assert repo.count() == 0
