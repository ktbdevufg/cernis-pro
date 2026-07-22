"""Tests fuer den SQLite-Adapter ``SqliteDnsTrustRepository`` (ADR 0043, E2).

Prueft die konkrete Implementierung gegen eine temporaere DB (``tmp_path``), nicht die
echte ``cernis.db`` (Muster ``test_dns_bypass_recordings``). Kern der Behauptungen:

* upsert+get Round-trip inklusive Enum-Round-trip (category/trust_state).
* Upsert: zweimal ``upsert`` derselben ``ip`` -> GENAU eine Zeile mit neuen Werten.
* ``list_all`` sortiert nach ``first_seen`` (aufsteigend); Leerzustand -> [].
* ``set_trust`` aendert NUR trust_state + last_seen (category/first_seen unberuehrt);
  unbekannte ip -> definierter No-Op (0 Zeilen).
* ``delete`` ist idempotent; ``clear_all`` leert die Tabelle.
"""

import sqlite3
from pathlib import Path

import pytest

from domain.dns_trust import (
    DnsServerCategory,
    DnsTrustState,
    TrustedDnsServer,
)
from infrastructure.dns_trust_repository import SqliteDnsTrustRepository
from ports.dns_trust import DnsTrustRepository


@pytest.fixture
def repo(tmp_path: Path) -> SqliteDnsTrustRepository:
    """Frisches Repository gegen eine temporaere DB."""
    return SqliteDnsTrustRepository(tmp_path / "cernis.db")


def _count_rows(db_path: Path) -> int:
    """Zaehlt die Zeilen der Tabelle direkt (Upsert-Beweis)."""
    conn = sqlite3.connect(db_path)
    try:
        return int(conn.execute("SELECT COUNT(*) FROM dns_trust_servers").fetchone()[0])
    finally:
        conn.close()


def _server(
    ip: str,
    *,
    category: DnsServerCategory = DnsServerCategory.PUBLIC_RESOLVER,
    first_seen: float = 1.0,
    last_seen: float = 1.0,
    trust_state: DnsTrustState = DnsTrustState.NEUTRAL,
    display_name: str = "",
    notes: str = "",
) -> TrustedDnsServer:
    return TrustedDnsServer(
        ip=ip,
        category=category,
        first_seen=first_seen,
        last_seen=last_seen,
        trust_state=trust_state,
        display_name=display_name,
        notes=notes,
    )


# ── Struktureller Vertrag ─────────────────────────────────────────────────


def test_conforms_to_protocol(repo: SqliteDnsTrustRepository) -> None:
    # Statische Vertragspruefung (mypy): erfuellt das Protocol strukturell.
    _: DnsTrustRepository = repo


# ── upsert + get Round-trip inkl. Enum ─────────────────────────────────────


def test_upsert_then_get_roundtrips_enums(repo: SqliteDnsTrustRepository) -> None:
    server = _server(
        "1.1.1.1",
        category=DnsServerCategory.GATEWAY,
        first_seen=100.0,
        last_seen=200.0,
        trust_state=DnsTrustState.TRUSTED,
        display_name="fritz.box",
        notes="Haus-Gateway",
    )
    repo.upsert(server)
    loaded = repo.get("1.1.1.1")
    assert loaded == server
    # category/trust_state sind echte Domaenen-Enums, keine rohen Strings.
    assert loaded is not None
    assert isinstance(loaded.category, DnsServerCategory)
    assert isinstance(loaded.trust_state, DnsTrustState)


def test_get_unknown_returns_none(repo: SqliteDnsTrustRepository) -> None:
    assert repo.get("9.9.9.9") is None


def test_platform_placeholder_flag_roundtrips(repo: SqliteDnsTrustRepository) -> None:
    # Das Platzhalter-Flag ueberlebt den Round-trip (INTEGER 0/1 <-> bool).
    server = TrustedDnsServer(
        ip="fec0:0:0:ffff::1",
        category=DnsServerCategory.UNKNOWN,
        first_seen=1.0,
        last_seen=1.0,
        is_platform_placeholder=True,
    )
    repo.upsert(server)
    loaded = repo.get("fec0:0:0:ffff::1")
    assert loaded is not None
    assert loaded.is_platform_placeholder is True
    # Default bleibt False, wenn nicht gesetzt.
    repo.upsert(_server("1.1.1.1"))
    plain = repo.get("1.1.1.1")
    assert plain is not None
    assert plain.is_platform_placeholder is False


# ── Additive Schema-Migration (bestehende DB ohne die neue Spalte) ─────────


def test_ensure_schema_adds_placeholder_column_to_legacy_table(tmp_path: Path) -> None:
    # Eine VOR der Platzhalter-Etappe angelegte Tabelle besitzt is_platform_placeholder
    # noch nicht -- CREATE TABLE IF NOT EXISTS legt sie dann NIE nach. Der Schema-Guard
    # (PRAGMA table_info + bedingtes ALTER) muss die Spalte beim Oeffnen nachruesten,
    # sonst scheitert jeder SELECT auf sie.
    db_path = tmp_path / "cernis.db"
    conn = sqlite3.connect(db_path)
    try:
        # ALTE Tabellenform: exakt wie das CREATE, aber OHNE is_platform_placeholder.
        conn.execute(
            """
            CREATE TABLE dns_trust_servers (
                ip           TEXT PRIMARY KEY,
                category     TEXT,
                trust_state  TEXT,
                first_seen   REAL,
                last_seen    REAL,
                display_name TEXT,
                notes        TEXT
            )
            """
        )
        conn.execute(
            "INSERT INTO dns_trust_servers "
            "(ip, category, trust_state, first_seen, last_seen, display_name, notes) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("1.1.1.1", "public_resolver", "neutral", 1.0, 1.0, "alt", ""),
        )
        conn.commit()
    finally:
        conn.close()

    # Oeffnen des Repositories fuehrt _ensure_schema aus und ruestet die Spalte nach.
    repo = SqliteDnsTrustRepository(db_path)

    # Die Spalte existiert nun.
    conn = sqlite3.connect(db_path)
    try:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(dns_trust_servers)")}
    finally:
        conn.close()
    assert "is_platform_placeholder" in cols

    # Und der bestehende Eintrag ist lesbar; die nachgeruestete Spalte traegt den Default.
    loaded = repo.get("1.1.1.1")
    assert loaded is not None
    assert loaded.is_platform_placeholder is False


# ── Upsert ──────────────────────────────────────────────────────────────────


def test_upsert_same_ip_replaces_single_row(repo: SqliteDnsTrustRepository, tmp_path: Path) -> None:
    repo.upsert(_server("1.1.1.1", category=DnsServerCategory.UNKNOWN, notes="alt"))
    repo.upsert(_server("1.1.1.1", category=DnsServerCategory.PUBLIC_RESOLVER, notes="neu"))
    # GENAU eine Zeile (Upsert ueber ip), nicht zwei.
    assert _count_rows(tmp_path / "cernis.db") == 1
    loaded = repo.get("1.1.1.1")
    assert loaded is not None
    assert loaded.category is DnsServerCategory.PUBLIC_RESOLVER
    assert loaded.notes == "neu"


# ── list_all-Reihenfolge + Leerzustand ─────────────────────────────────────


def test_list_all_orders_by_first_seen(repo: SqliteDnsTrustRepository) -> None:
    repo.upsert(_server("b", first_seen=30.0))
    repo.upsert(_server("a", first_seen=10.0))
    repo.upsert(_server("c", first_seen=20.0))
    ips = [s.ip for s in repo.list_all()]
    assert ips == ["a", "c", "b"]


def test_list_all_empty(repo: SqliteDnsTrustRepository) -> None:
    assert repo.list_all() == []


# ── set_trust: schmaler Schreibpfad ─────────────────────────────────────────


def test_set_trust_changes_only_state_and_last_seen(
    repo: SqliteDnsTrustRepository,
) -> None:
    repo.upsert(
        _server(
            "1.1.1.1",
            category=DnsServerCategory.GATEWAY,
            first_seen=100.0,
            last_seen=100.0,
            trust_state=DnsTrustState.NEUTRAL,
            display_name="gw",
            notes="notiz",
        )
    )
    repo.set_trust("1.1.1.1", DnsTrustState.TRUSTED, now=555.0)
    loaded = repo.get("1.1.1.1")
    assert loaded is not None
    # Nur Zustand + last_seen wandern.
    assert loaded.trust_state is DnsTrustState.TRUSTED
    assert loaded.last_seen == 555.0
    # Kategorie/first_seen/display_name/notes bleiben unberuehrt.
    assert loaded.category is DnsServerCategory.GATEWAY
    assert loaded.first_seen == 100.0
    assert loaded.display_name == "gw"
    assert loaded.notes == "notiz"


def test_set_trust_unknown_ip_is_noop(repo: SqliteDnsTrustRepository, tmp_path: Path) -> None:
    # Unbekannte ip -> 0 Zeilen betroffen, kein stilles Anlegen, kein Fehler.
    repo.set_trust("nie_existiert", DnsTrustState.REJECTED, now=1.0)
    assert repo.get("nie_existiert") is None
    assert _count_rows(tmp_path / "cernis.db") == 0


# ── set_rank: schmaler Schreibpfad (D4 E3) ──────────────────────────────────


def test_set_rank_changes_only_rank_and_last_seen(repo: SqliteDnsTrustRepository) -> None:
    repo.upsert(
        _server(
            "1.1.1.1",
            category=DnsServerCategory.GATEWAY,
            first_seen=100.0,
            last_seen=100.0,
            trust_state=DnsTrustState.TRUSTED,
            display_name="gw",
        )
    )
    repo.set_rank("1.1.1.1", 2, now=555.0)
    loaded = repo.get("1.1.1.1")
    assert loaded is not None
    # Nur Rang + last_seen wandern.
    assert loaded.expected_rank == 2
    assert loaded.last_seen == 555.0
    # Kategorie/first_seen/trust_state bleiben unberuehrt.
    assert loaded.category is DnsServerCategory.GATEWAY
    assert loaded.first_seen == 100.0
    assert loaded.trust_state is DnsTrustState.TRUSTED


def test_set_rank_unknown_ip_is_noop(repo: SqliteDnsTrustRepository, tmp_path: Path) -> None:
    # Unbekannte ip -> 0 Zeilen betroffen, kein stilles Anlegen, kein Fehler.
    repo.set_rank("nie_existiert", 1, now=1.0)
    assert repo.get("nie_existiert") is None
    assert _count_rows(tmp_path / "cernis.db") == 0


def test_expected_rank_roundtrips_via_upsert(repo: SqliteDnsTrustRepository) -> None:
    repo.upsert(
        TrustedDnsServer(
            ip="1.1.1.1",
            category=DnsServerCategory.PUBLIC_RESOLVER,
            first_seen=1.0,
            last_seen=1.0,
            expected_rank=3,
        )
    )
    loaded = repo.get("1.1.1.1")
    assert loaded is not None
    assert loaded.expected_rank == 3


def test_ensure_schema_adds_rank_column_to_legacy_table(tmp_path: Path) -> None:
    # Muster des placeholder-Migrationstests: eine VOR D4 E3 angelegte Tabelle besitzt
    # expected_rank noch nicht; der Schema-Guard muss die Spalte beim Oeffnen nachruesten.
    db_path = tmp_path / "cernis.db"
    conn = sqlite3.connect(db_path)
    try:
        # ALTE Tabellenform: mit is_platform_placeholder, aber OHNE expected_rank.
        conn.execute(
            """
            CREATE TABLE dns_trust_servers (
                ip           TEXT PRIMARY KEY,
                category     TEXT,
                trust_state  TEXT,
                first_seen   REAL,
                last_seen    REAL,
                display_name TEXT,
                notes        TEXT,
                is_platform_placeholder INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        conn.execute(
            "INSERT INTO dns_trust_servers "
            "(ip, category, trust_state, first_seen, last_seen, display_name, notes) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("1.1.1.1", "public_resolver", "neutral", 1.0, 1.0, "alt", ""),
        )
        conn.commit()
    finally:
        conn.close()

    repo = SqliteDnsTrustRepository(db_path)

    conn = sqlite3.connect(db_path)
    try:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(dns_trust_servers)")}
    finally:
        conn.close()
    assert "expected_rank" in cols

    # Bestehender Eintrag lesbar; die nachgeruestete Spalte traegt den Default 0.
    loaded = repo.get("1.1.1.1")
    assert loaded is not None
    assert loaded.expected_rank == 0


# ── delete idempotent + clear_all ──────────────────────────────────────────


def test_delete_idempotent(repo: SqliteDnsTrustRepository) -> None:
    repo.upsert(_server("1.1.1.1"))
    repo.delete("1.1.1.1")
    assert repo.get("1.1.1.1") is None
    # Erneutes Loeschen (oder unbekannte ip) ist kein Fehler.
    repo.delete("1.1.1.1")
    repo.delete("nie_existiert")


def test_clear_all(repo: SqliteDnsTrustRepository) -> None:
    repo.upsert(_server("a"))
    repo.upsert(_server("b"))
    repo.clear_all()
    assert repo.list_all() == []
