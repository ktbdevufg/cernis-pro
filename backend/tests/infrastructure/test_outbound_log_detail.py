"""Tests fuer den SQLite-Adapter ``SqliteOutboundDetailRepository`` (E2).

Prueft die konkrete Implementierung gegen eine temporaere DB (``tmp_path``), nicht die
echte ``cernis.db`` (Muster ``test_rogue_dhcp_repository``). Kern der Behauptungen:

* Append mehrerer Zeilen; ``range`` liefert sie aufsteigend nach ``ts``.
* ``range`` ist halb-offen ``[since, until)`` -- since inklusiv, until exklusiv.
* ``delete_older_than`` ist strikt aelter (Punkt GENAU auf dem Cutoff bleibt),
  Rueckgabe = geloeschte Zeilenzahl.
* NULL fuer ``remote_port``/``pid`` ueberlebt als ``None``.
* ``count`` / ``clear_all``.
"""

from pathlib import Path

import pytest

from domain.outbound_log import OutboundDetailRow
from infrastructure.outbound_log_detail import SqliteOutboundDetailRepository
from ports.outbound_log import OutboundDetailRepository


@pytest.fixture
def repo(tmp_path: Path) -> SqliteOutboundDetailRepository:
    """Frisches Repository gegen eine temporaere DB."""
    return SqliteOutboundDetailRepository(tmp_path / "cernis.db")


def _save(
    repo: SqliteOutboundDetailRepository,
    rec_id: str,
    ts: float,
    *,
    remote_ip: str = "1.2.3.4",
    remote_port: int | None = 443,
    pid: int | None = 1234,
    connection_count: int = 1,
) -> None:
    repo.save(
        rec_id,
        ts,
        remote_ip,
        remote_port,
        "host.example",
        "DE",
        "ExampleOrg",
        "AS1234",
        "firefox",
        pid,
        connection_count,
    )


# ── Struktureller Vertrag ─────────────────────────────────────────────────


def test_conforms_to_protocol(repo: SqliteOutboundDetailRepository) -> None:
    _: OutboundDetailRepository = repo


# ── Append + range-Reihenfolge ──────────────────────────────────────────────


def test_append_and_range_orders_by_ts(repo: SqliteOutboundDetailRepository) -> None:
    _save(repo, "r1", 30.0, remote_ip="3.3.3.3")
    _save(repo, "r1", 10.0, remote_ip="1.1.1.1")
    _save(repo, "r1", 20.0, remote_ip="2.2.2.2")
    rows = repo.range("r1", 0.0, 100.0)
    assert [r.ts for r in rows] == [10.0, 20.0, 30.0]
    assert [r.remote_ip for r in rows] == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]


def test_range_only_matching_recording(repo: SqliteOutboundDetailRepository) -> None:
    _save(repo, "r1", 10.0)
    _save(repo, "r2", 11.0)
    rows = repo.range("r1", 0.0, 100.0)
    assert len(rows) == 1
    assert rows[0].ts == 10.0


def test_range_empty(repo: SqliteOutboundDetailRepository) -> None:
    assert repo.range("fehlt", 0.0, 100.0) == []


# ── range halb-offen [since, until) ─────────────────────────────────────────


def test_range_half_open_window(repo: SqliteOutboundDetailRepository) -> None:
    for ts in (10.0, 20.0, 30.0):
        _save(repo, "r1", ts)
    # since INKLUSIV (10.0 dabei), until EXKLUSIV (30.0 NICHT dabei).
    rows = repo.range("r1", 10.0, 30.0)
    assert [r.ts for r in rows] == [10.0, 20.0]


# ── delete_older_than strikt aelter ─────────────────────────────────────────


def test_delete_older_than_strict_keeps_point_on_cutoff(
    repo: SqliteOutboundDetailRepository,
) -> None:
    for ts in (10.0, 20.0, 30.0):
        _save(repo, "r1", ts)
    deleted = repo.delete_older_than(20.0)
    # Strikt ts < 20.0 -> nur 10.0 weg; 20.0 bleibt (Punkt genau auf dem Cutoff).
    assert deleted == 1
    assert [r.ts for r in repo.range("r1", 0.0, 100.0)] == [20.0, 30.0]


def test_delete_older_than_nothing(repo: SqliteOutboundDetailRepository) -> None:
    _save(repo, "r1", 50.0)
    assert repo.delete_older_than(10.0) == 0


# ── NULL fuer remote_port/pid ───────────────────────────────────────────────


def test_null_port_and_pid_roundtrip_as_none(repo: SqliteOutboundDetailRepository) -> None:
    _save(repo, "r1", 10.0, remote_port=None, pid=None)
    rows = repo.range("r1", 0.0, 100.0)
    assert len(rows) == 1
    assert rows[0] == OutboundDetailRow(
        ts=10.0,
        remote_ip="1.2.3.4",
        remote_port=None,
        hostname="host.example",
        country="DE",
        operator="ExampleOrg",
        asn="AS1234",
        app_name="firefox",
        pid=None,
        connection_count=1,
    )


# ── count + clear_all ───────────────────────────────────────────────────────


def test_count_and_clear_all(repo: SqliteOutboundDetailRepository) -> None:
    assert repo.count() == 0
    _save(repo, "r1", 10.0)
    _save(repo, "r1", 11.0)
    _save(repo, "r2", 12.0)
    assert repo.count() == 3
    repo.clear_all()
    assert repo.count() == 0
