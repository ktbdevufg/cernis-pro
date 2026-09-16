"""Tests fuer den SQLite-Adapter ``SqliteRogueDhcpRepository`` (ADR 0038).

Prueft die konkrete Implementierung gegen eine temporaere DB (``tmp_path``), nicht die
echte ``cernis.db`` (Muster ``test_settings_repository``). Kern der Behauptungen:

* Schema-Init ist idempotent; ``load_latest`` liefert ``None`` bei leerem Speicher.
* ``save_latest`` UEBERSCHREIBT wirklich -- nach mehreren Speichern bleibt GENAU EIN
  Datensatz (Singleton-Row), und ``load_latest`` liefert den LETZTEN Stand.
* Die Server-Liste ueberlebt den Round-trip inkl. ``mac=None`` (kein erfundener Wert).
* Kaputtes JSON ist ein Fehler (kein stiller Fallback, S3).
"""

import sqlite3
from pathlib import Path

import pytest

from infrastructure.rogue_dhcp_repository import (
    CorruptRogueDhcpError,
    SqliteRogueDhcpRepository,
)
from ports.diagnostics import LatestRogueDhcp, RogueDhcpServerRecord, RogueDhcpStore


@pytest.fixture
def repo(tmp_path: Path) -> SqliteRogueDhcpRepository:
    """Frisches Repository gegen eine temporaere DB."""
    return SqliteRogueDhcpRepository(tmp_path / "cernis.db")


def _count_rows(db_path: Path) -> int:
    """Zaehlt die Zeilen der Singleton-Tabelle direkt (Singleton-Beweis)."""
    conn = sqlite3.connect(db_path)
    try:
        return int(conn.execute("SELECT COUNT(*) FROM rogue_dhcp_latest").fetchone()[0])
    finally:
        conn.close()


# ── Struktureller Vertrag ─────────────────────────────────────────────────


def test_conforms_to_rogue_dhcp_store_protocol(repo: SqliteRogueDhcpRepository) -> None:
    # Statische Vertragspruefung (mypy): erfuellt das Protocol strukturell.
    _: RogueDhcpStore = repo


# ── Leerer Speicher ────────────────────────────────────────────────────────


def test_load_latest_empty_returns_none(repo: SqliteRogueDhcpRepository) -> None:
    # Noch nie geprueft -> None (ehrliche Abwesenheit, kein Ersatz-Stand).
    assert repo.load_latest() is None


# ── Round-trip ─────────────────────────────────────────────────────────────


def test_save_then_load_roundtrips(repo: SqliteRogueDhcpRepository) -> None:
    repo.save_latest(
        [("192.168.1.1", "aa:bb:cc:dd:ee:ff", True), ("192.168.1.66", None, False)],
        ["192.168.1.1"],
        True,
        1_700_000_000.5,
    )
    assert repo.load_latest() == LatestRogueDhcp(
        servers=(
            RogueDhcpServerRecord(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:ff", is_expected=True),
            RogueDhcpServerRecord(ip="192.168.1.66", mac=None, is_expected=False),
        ),
        expected=("192.168.1.1",),
        has_unexpected=True,
        checked_ts=1_700_000_000.5,
    )


def test_mac_none_survives_roundtrip(repo: SqliteRogueDhcpRepository) -> None:
    # mac=None bleibt ehrlich None (JSON-null), kein erfundener Wert.
    repo.save_latest([("10.0.0.1", None, False)], [], True, 1.0)
    loaded = repo.load_latest()
    assert loaded is not None
    assert loaded.servers[0].mac is None


def test_empty_servers_and_expected_roundtrip(repo: SqliteRogueDhcpRepository) -> None:
    # Kein gefundener Server, keine Erwartung -> leere Tupel, has_unexpected False.
    repo.save_latest([], [], False, 42.0)
    assert repo.load_latest() == LatestRogueDhcp(
        servers=(), expected=(), has_unexpected=False, checked_ts=42.0
    )


# ── Singleton: save_latest ueberschreibt wirklich ──────────────────────────


def test_save_latest_overwrites_keeps_single_row(
    repo: SqliteRogueDhcpRepository, tmp_path: Path
) -> None:
    repo.save_latest([("192.168.1.1", None, True)], ["192.168.1.1"], False, 1.0)
    repo.save_latest([("10.9.9.9", None, False)], [], True, 2.0)
    repo.save_latest([("172.16.0.1", "11:22:33:44:55:66", False)], [], True, 3.0)
    # GENAU EIN Datensatz (Singleton-Row), egal wie oft gespeichert wurde.
    assert _count_rows(tmp_path / "cernis.db") == 1
    # Und es ist der LETZTE Stand.
    loaded = repo.load_latest()
    assert loaded is not None
    assert loaded.servers == (
        RogueDhcpServerRecord(ip="172.16.0.1", mac="11:22:33:44:55:66", is_expected=False),
    )
    assert loaded.checked_ts == 3.0


# ── Idempotenter Schema-Init ───────────────────────────────────────────────


def test_schema_init_idempotent(tmp_path: Path) -> None:
    # Ein zweites Repository auf derselben DB (erneuter _ensure_schema) ist kein Fehler
    # und sieht den zuvor gespeicherten Stand.
    db = tmp_path / "cernis.db"
    first = SqliteRogueDhcpRepository(db)
    first.save_latest([("192.168.1.1", None, True)], ["192.168.1.1"], False, 7.0)
    second = SqliteRogueDhcpRepository(db)
    loaded = second.load_latest()
    assert loaded is not None
    assert loaded.checked_ts == 7.0


# ── Kein stiller Fallback bei kaputtem JSON (S3) ───────────────────────────


def test_load_raises_on_corrupt_servers_json(
    repo: SqliteRogueDhcpRepository, tmp_path: Path
) -> None:
    # Direkt einen kaputten servers-Wert in die Singleton-Zeile schieben (Korruption
    # simulieren) -> load_latest wirft, statt still einen leeren Stand zu liefern.
    repo.save_latest([("192.168.1.1", None, True)], [], False, 1.0)
    conn = sqlite3.connect(tmp_path / "cernis.db")
    try:
        conn.execute("UPDATE rogue_dhcp_latest SET servers = ? WHERE id = 1", ("roh_kein_json",))
        conn.commit()
    finally:
        conn.close()
    with pytest.raises(CorruptRogueDhcpError) as exc_info:
        repo.load_latest()
    assert exc_info.value.column == "servers"
