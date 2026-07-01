"""Tests fuer den SQLite-Adapter ``SqliteDnsBypassDetailRepository`` (E2).

Prueft die konkrete Implementierung gegen eine temporaere DB (``tmp_path``), nicht die
echte ``cernis.db`` (Muster ``test_outbound_log_detail``). Kern der Behauptungen:

* Append mehrerer Zeilen; ``range`` liefert sie aufsteigend nach ``ts``.
* ``range`` ist halb-offen ``[since, until)`` -- since inklusiv, until exklusiv.
* ``delete_older_than`` ist strikt aelter (Punkt GENAU auf dem Cutoff bleibt),
  Rueckgabe = geloeschte Zeilenzahl.
* Leerer ``qname`` (``""``) ueberlebt als leerer String (kein NULL).
* ``count`` / ``clear_all``.
"""

from pathlib import Path

import pytest

from domain.dns_bypass import DnsBypassDetailRow
from infrastructure.dns_bypass_detail import SqliteDnsBypassDetailRepository
from ports.dns_bypass import DnsBypassDetailRepository


@pytest.fixture
def repo(tmp_path: Path) -> SqliteDnsBypassDetailRepository:
    """Frisches Repository gegen eine temporaere DB."""
    return SqliteDnsBypassDetailRepository(tmp_path / "cernis.db")


def _save(
    repo: SqliteDnsBypassDetailRepository,
    rec_id: str,
    ts: float,
    *,
    src_ip: str = "10.0.0.5",
    dst_ip: str = "8.8.8.8",
    l4: str = "udp",
    qname: str = "example.com",
) -> None:
    repo.save(rec_id, ts, src_ip, dst_ip, l4, qname)


# ── Struktureller Vertrag ─────────────────────────────────────────────────


def test_conforms_to_protocol(repo: SqliteDnsBypassDetailRepository) -> None:
    _: DnsBypassDetailRepository = repo


# ── Append + range-Reihenfolge ──────────────────────────────────────────────


def test_append_and_range_orders_by_ts(repo: SqliteDnsBypassDetailRepository) -> None:
    _save(repo, "r1", 30.0, src_ip="3.3.3.3")
    _save(repo, "r1", 10.0, src_ip="1.1.1.1")
    _save(repo, "r1", 20.0, src_ip="2.2.2.2")
    rows = repo.range("r1", 0.0, 100.0)
    assert [r.ts for r in rows] == [10.0, 20.0, 30.0]
    assert [r.src_ip for r in rows] == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]


def test_range_only_matching_recording(repo: SqliteDnsBypassDetailRepository) -> None:
    _save(repo, "r1", 10.0)
    _save(repo, "r2", 11.0)
    rows = repo.range("r1", 0.0, 100.0)
    assert len(rows) == 1
    assert rows[0].ts == 10.0


def test_range_empty(repo: SqliteDnsBypassDetailRepository) -> None:
    assert repo.range("fehlt", 0.0, 100.0) == []


# ── range halb-offen [since, until) ─────────────────────────────────────────


def test_range_half_open_window(repo: SqliteDnsBypassDetailRepository) -> None:
    for ts in (10.0, 20.0, 30.0):
        _save(repo, "r1", ts)
    # since INKLUSIV (10.0 dabei), until EXKLUSIV (30.0 NICHT dabei).
    rows = repo.range("r1", 10.0, 30.0)
    assert [r.ts for r in rows] == [10.0, 20.0]


# ── delete_older_than strikt aelter ─────────────────────────────────────────


def test_delete_older_than_strict_keeps_point_on_cutoff(
    repo: SqliteDnsBypassDetailRepository,
) -> None:
    for ts in (10.0, 20.0, 30.0):
        _save(repo, "r1", ts)
    deleted = repo.delete_older_than(20.0)
    # Strikt ts < 20.0 -> nur 10.0 weg; 20.0 bleibt (Punkt genau auf dem Cutoff).
    assert deleted == 1
    assert [r.ts for r in repo.range("r1", 0.0, 100.0)] == [20.0, 30.0]


def test_delete_older_than_nothing(repo: SqliteDnsBypassDetailRepository) -> None:
    _save(repo, "r1", 50.0)
    assert repo.delete_older_than(10.0) == 0


# ── leerer qname ueberlebt als "" ───────────────────────────────────────────


def test_empty_qname_roundtrips_as_empty_string(
    repo: SqliteDnsBypassDetailRepository,
) -> None:
    _save(repo, "r1", 10.0, qname="")
    rows = repo.range("r1", 0.0, 100.0)
    assert len(rows) == 1
    assert rows[0] == DnsBypassDetailRow(
        ts=10.0,
        src_ip="10.0.0.5",
        dst_ip="8.8.8.8",
        l4="udp",
        qname="",
    )


# ── count + clear_all ───────────────────────────────────────────────────────


def test_count_and_clear_all(repo: SqliteDnsBypassDetailRepository) -> None:
    assert repo.count() == 0
    _save(repo, "r1", 10.0)
    _save(repo, "r1", 11.0)
    _save(repo, "r2", 12.0)
    assert repo.count() == 3
    repo.clear_all()
    assert repo.count() == 0
