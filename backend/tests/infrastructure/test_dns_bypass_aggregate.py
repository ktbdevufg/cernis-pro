"""Tests fuer den SQLite-Adapter ``SqliteDnsBypassAggregateRepository`` (E2).

Prueft die konkrete Implementierung gegen eine temporaere DB (``tmp_path``), nicht die
echte ``cernis.db`` (Muster ``test_outbound_log_aggregate``). Kern der Behauptungen:

* ``upsert`` Neuanlage + Ueberschreiben: gleiche ``(recording_id, src_ip, dst_ip)`` ->
  GENAU eine Zeile mit dem neuen Stand.
* ``get`` vorhanden / None (auch: gleiche src_ip, andere dst_ip -> eigener Schluessel).
* ``list_for`` sortiert ``query_count DESC, src_ip ASC, dst_ip ASC`` (lauteste zuerst,
  stabil).
* ``sample_qnames`` (auch leer) ueberlebt den JSON-Round-trip in Reihenfolge.
* ``delete_for`` trifft nur die eine ``recording_id``.
* ``count`` / ``clear_all``.
"""

import sqlite3
from pathlib import Path

import pytest

from domain.dns_bypass import AggregatedBypass
from infrastructure.dns_bypass_aggregate import SqliteDnsBypassAggregateRepository
from ports.dns_bypass import DnsBypassAggregateRepository


@pytest.fixture
def repo(tmp_path: Path) -> SqliteDnsBypassAggregateRepository:
    """Frisches Repository gegen eine temporaere DB."""
    return SqliteDnsBypassAggregateRepository(tmp_path / "cernis.db")


def _count_rows(db_path: Path) -> int:
    conn = sqlite3.connect(db_path)
    try:
        return int(conn.execute("SELECT COUNT(*) FROM dns_bypass_aggregate").fetchone()[0])
    finally:
        conn.close()


def _aggregate(
    src_ip: str,
    dst_ip: str,
    *,
    query_count: int = 1,
    first_seen: float = 1.0,
    last_seen: float = 2.0,
    sample_qnames: tuple[str, ...] = ("a.example", "b.example"),
) -> AggregatedBypass:
    return AggregatedBypass(
        src_ip=src_ip,
        dst_ip=dst_ip,
        first_seen=first_seen,
        last_seen=last_seen,
        query_count=query_count,
        sample_qnames=sample_qnames,
    )


# ── Struktureller Vertrag ─────────────────────────────────────────────────


def test_conforms_to_protocol(repo: SqliteDnsBypassAggregateRepository) -> None:
    _: DnsBypassAggregateRepository = repo


# ── upsert Neuanlage + Ueberschreiben ──────────────────────────────────────


def test_upsert_insert_then_get(repo: SqliteDnsBypassAggregateRepository) -> None:
    aggregate = _aggregate("10.0.0.5", "8.8.8.8", query_count=5)
    repo.upsert("r1", aggregate)
    loaded = repo.get("r1", "10.0.0.5", "8.8.8.8")
    assert loaded == aggregate
    # sample_qnames kommt als tuple in stabiler Reihenfolge zurueck (JSON-Round-trip).
    assert loaded is not None
    assert loaded.sample_qnames == ("a.example", "b.example")


def test_upsert_same_key_overwrites_single_row(
    repo: SqliteDnsBypassAggregateRepository, tmp_path: Path
) -> None:
    repo.upsert("r1", _aggregate("10.0.0.5", "8.8.8.8", query_count=1, last_seen=2.0))
    repo.upsert("r1", _aggregate("10.0.0.5", "8.8.8.8", query_count=9, last_seen=99.0))
    # GENAU eine Zeile (PK recording_id, src_ip, dst_ip), nicht zwei.
    assert _count_rows(tmp_path / "cernis.db") == 1
    loaded = repo.get("r1", "10.0.0.5", "8.8.8.8")
    assert loaded is not None
    assert loaded.query_count == 9
    assert loaded.last_seen == 99.0


def test_empty_sample_qnames_roundtrips(repo: SqliteDnsBypassAggregateRepository) -> None:
    repo.upsert("r1", _aggregate("10.0.0.5", "8.8.8.8", sample_qnames=()))
    loaded = repo.get("r1", "10.0.0.5", "8.8.8.8")
    assert loaded is not None
    assert loaded.sample_qnames == ()


# ── get None + Schluessel-Trennung ──────────────────────────────────────────


def test_get_unknown_returns_none(repo: SqliteDnsBypassAggregateRepository) -> None:
    repo.upsert("r1", _aggregate("10.0.0.5", "8.8.8.8"))
    # gleiche src_ip, andere dst_ip -> eigener Schluessel (nicht getroffen).
    assert repo.get("r1", "10.0.0.5", "1.1.1.1") is None
    # gleiche dst_ip, andere src_ip -> eigener Schluessel (nicht getroffen).
    assert repo.get("r1", "10.0.0.9", "8.8.8.8") is None
    assert repo.get("rX", "10.0.0.5", "8.8.8.8") is None


# ── list_for-Sortierung ─────────────────────────────────────────────────────


def test_list_for_orders_by_count_desc_then_src_then_dst(
    repo: SqliteDnsBypassAggregateRepository,
) -> None:
    repo.upsert("r1", _aggregate("1.1.1.1", "8.8.8.8", query_count=5))
    repo.upsert("r1", _aggregate("9.9.9.9", "8.8.8.8", query_count=10))
    # Gleichstand bei query_count=5 -> stabil nach src_ip ASC.
    repo.upsert("r1", _aggregate("2.2.2.2", "8.8.8.8", query_count=5))
    # Gleichstand bei query_count=5 UND src_ip=2.2.2.2 -> stabil nach dst_ip ASC.
    repo.upsert("r1", _aggregate("2.2.2.2", "1.1.1.1", query_count=5))
    keys = [(a.src_ip, a.dst_ip) for a in repo.list_for("r1")]
    assert keys == [
        ("9.9.9.9", "8.8.8.8"),  # query_count=10 zuerst
        ("1.1.1.1", "8.8.8.8"),  # dann count=5, src_ip aufsteigend
        ("2.2.2.2", "1.1.1.1"),  # gleiche src_ip -> dst_ip aufsteigend
        ("2.2.2.2", "8.8.8.8"),
    ]


def test_list_for_empty(repo: SqliteDnsBypassAggregateRepository) -> None:
    assert repo.list_for("fehlt") == []


# ── delete_for trifft nur die eine recording_id ────────────────────────────


def test_delete_for_only_affects_one_recording(
    repo: SqliteDnsBypassAggregateRepository,
) -> None:
    repo.upsert("r1", _aggregate("10.0.0.5", "8.8.8.8"))
    repo.upsert("r1", _aggregate("10.0.0.6", "1.1.1.1"))
    repo.upsert("r2", _aggregate("10.0.0.5", "8.8.8.8"))
    repo.delete_for("r1")
    assert repo.list_for("r1") == []
    # r2 bleibt unberuehrt.
    assert [(a.src_ip, a.dst_ip) for a in repo.list_for("r2")] == [("10.0.0.5", "8.8.8.8")]
    # Idempotent: erneutes/unbekanntes delete_for kein Fehler.
    repo.delete_for("r1")
    repo.delete_for("nie_existiert")


# ── count + clear_all ───────────────────────────────────────────────────────


def test_count_and_clear_all(repo: SqliteDnsBypassAggregateRepository) -> None:
    assert repo.count() == 0
    repo.upsert("r1", _aggregate("10.0.0.5", "8.8.8.8"))
    repo.upsert("r1", _aggregate("10.0.0.6", "1.1.1.1"))
    repo.upsert("r2", _aggregate("10.0.0.5", "8.8.8.8"))
    assert repo.count() == 3
    repo.clear_all()
    assert repo.count() == 0
