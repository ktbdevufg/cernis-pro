"""Tests fuer ``SqliteBlocklistEntryRepository`` -- gegen tmp_path-DB.

Belegt den atomaren Austausch (``replace_entries`` ersetzt vollstaendig), den
Domain-Suffix-Treffer (``lookup_domains``), den IP-Lookup (exakt + echtes CIDR-Netz),
``count_for``, ``delete_for`` und ``clear_all``. Muster der uebrigen
infrastructure-Repo-Tests (``tmp_path``-DB-Fixture).
"""

from pathlib import Path

import pytest

from infrastructure.blocklist_entries_db import SqliteBlocklistEntryRepository


@pytest.fixture
def repo(tmp_path: Path) -> SqliteBlocklistEntryRepository:
    return SqliteBlocklistEntryRepository(tmp_path / "cernis.db")


# ── replace_entries ersetzt vollstaendig ──────────────────────────────────────


def test_replace_entries_ersetzt_alte(repo: SqliteBlocklistEntryRepository) -> None:
    repo.replace_entries("src1", ["alt.example.com"], [])
    repo.replace_entries("src1", ["neu.example.com"], [])
    # Der alte Eintrag ist weg, nur der neue trifft.
    assert repo.lookup_domains(["alt.example.com"]) == []
    assert repo.lookup_domains(["neu.example.com"]) == [("src1", "neu.example.com")]


def test_replace_entries_count_domain_und_ip(repo: SqliteBlocklistEntryRepository) -> None:
    repo.replace_entries("src1", ["a.example.com", "b.example.com"], ["1.2.3.4", "10.0.0.0/8"])
    assert repo.count_for("src1") == 4


def test_replace_entries_isoliert_quellen(repo: SqliteBlocklistEntryRepository) -> None:
    repo.replace_entries("src1", ["a.example.com"], [])
    repo.replace_entries("src2", ["b.example.com"], [])
    # replace_entries einer Quelle laesst die andere unberuehrt.
    repo.replace_entries("src1", ["c.example.com"], [])
    assert repo.count_for("src2") == 1
    assert repo.lookup_domains(["b.example.com"]) == [("src2", "b.example.com")]


# ── lookup_domains Suffix-Treffer ─────────────────────────────────────────────


def test_lookup_domains_suffix_treffer(repo: SqliteBlocklistEntryRepository) -> None:
    # Liste fuehrt die Eltern-Domain; der Aufrufer reicht die Suffix-Kandidaten herein.
    repo.replace_entries("src1", ["example.com"], [])
    treffer = repo.lookup_domains(["sub.example.com", "example.com", "com"])
    assert treffer == [("src1", "example.com")]


def test_lookup_domains_kein_treffer(repo: SqliteBlocklistEntryRepository) -> None:
    repo.replace_entries("src1", ["example.com"], [])
    assert repo.lookup_domains(["other.org", "org"]) == []


def test_lookup_domains_leere_kandidaten(repo: SqliteBlocklistEntryRepository) -> None:
    repo.replace_entries("src1", ["example.com"], [])
    assert repo.lookup_domains([]) == []


def test_lookup_domains_trifft_keine_ip_eintraege(repo: SqliteBlocklistEntryRepository) -> None:
    # Ein IP-Eintrag mit gleichem Stringwert darf NICHT als Domain treffen (kind-Trennung).
    repo.replace_entries("src1", [], ["1.2.3.4"])
    assert repo.lookup_domains(["1.2.3.4"]) == []


# ── lookup_ips exakt + CIDR-Netz ──────────────────────────────────────────────


def test_lookup_ips_exakt(repo: SqliteBlocklistEntryRepository) -> None:
    repo.replace_entries("src1", [], ["1.2.3.4"])
    assert repo.lookup_ips("1.2.3.4") == [("src1", "1.2.3.4")]
    assert repo.lookup_ips("1.2.3.5") == []


def test_lookup_ips_exakt_mit_32_praefix(repo: SqliteBlocklistEntryRepository) -> None:
    # Eintrag explizit als /32 abgelegt -> die nackte IP muss ihn finden.
    repo.replace_entries("src1", [], ["9.9.9.9/32"])
    assert repo.lookup_ips("9.9.9.9") == [("src1", "9.9.9.9/32")]


def test_lookup_ips_cidr_netz(repo: SqliteBlocklistEntryRepository) -> None:
    repo.replace_entries("src1", [], ["10.0.0.0/8"])
    assert repo.lookup_ips("10.1.2.3") == [("src1", "10.0.0.0/8")]
    assert repo.lookup_ips("11.0.0.1") == []


def test_lookup_ips_exakt_und_netz_kein_doppeltreffer(
    repo: SqliteBlocklistEntryRepository,
) -> None:
    # IP liegt im Netz UND ist als exakter /32-Eintrag vorhanden -> genau zwei distinkte
    # Treffer (einer pro Eintrag), nicht der /32 doppelt.
    repo.replace_entries("src1", [], ["10.0.0.1/32", "10.0.0.0/8"])
    treffer = sorted(repo.lookup_ips("10.0.0.1"))
    assert treffer == [("src1", "10.0.0.0/8"), ("src1", "10.0.0.1/32")]


def test_lookup_ips_ipv6_netz(repo: SqliteBlocklistEntryRepository) -> None:
    repo.replace_entries("src1", [], ["2001:db8::/32"])
    assert repo.lookup_ips("2001:db8::1") == [("src1", "2001:db8::/32")]


# ── count_for / delete_for / clear_all ────────────────────────────────────────


def test_count_for_unbekannt_ist_null(repo: SqliteBlocklistEntryRepository) -> None:
    assert repo.count_for("gibtsnicht") == 0


def test_delete_for_entfernt_und_idempotent(repo: SqliteBlocklistEntryRepository) -> None:
    repo.replace_entries("src1", ["a.example.com"], ["1.2.3.4"])
    repo.delete_for("src1")
    assert repo.count_for("src1") == 0
    # Zweites delete_for wirft nicht.
    repo.delete_for("src1")


def test_clear_all_leert_alles(repo: SqliteBlocklistEntryRepository) -> None:
    repo.replace_entries("src1", ["a.example.com"], [])
    repo.replace_entries("src2", [], ["1.2.3.4"])
    repo.clear_all()
    assert repo.count_for("src1") == 0
    assert repo.count_for("src2") == 0
