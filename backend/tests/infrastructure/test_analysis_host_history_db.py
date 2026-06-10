"""Tests fuer ``SqliteHostHistoryRepository`` (C.1) -- gegen tmp_path-DB.

Belegt den ``record_seen`` <-> ``is_known``-Round-trip, die Behandlung der leeren MAC
(``is_known("")`` True, ``record_seen("")`` no-op -- ein Host ohne stabile Identitaet
kommt nicht in die Historie und gilt als bekannt), die Idempotenz von ``record_seen``
(``INSERT OR IGNORE``) und den Bulk-Lesepfad ``known_macs``. Muster der uebrigen
infrastructure-Repo-Tests (``tmp_path``-DB).
"""

from pathlib import Path

import pytest

from infrastructure.analysis_host_history_db import SqliteHostHistoryRepository


@pytest.fixture
def repo(tmp_path: Path) -> SqliteHostHistoryRepository:
    return SqliteHostHistoryRepository(tmp_path / "cernis.db")


# ── Round-trip ────────────────────────────────────────────────────────────────


def test_record_seen_dann_is_known(repo: SqliteHostHistoryRepository) -> None:
    repo.record_seen("aa:bb:cc:dd:ee:ff")
    assert repo.is_known("aa:bb:cc:dd:ee:ff") is True


def test_nicht_eingetragene_mac_ist_unbekannt(repo: SqliteHostHistoryRepository) -> None:
    repo.record_seen("aa:bb:cc:dd:ee:ff")
    assert repo.is_known("11:22:33:44:55:66") is False


# ── leere MAC ─────────────────────────────────────────────────────────────────


def test_leere_mac_gilt_als_bekannt(repo: SqliteHostHistoryRepository) -> None:
    # Ein Host ohne stabile Identitaet wird NICHT als neu gewertet -> is_known True.
    assert repo.is_known("") is True


def test_record_seen_leere_mac_ist_noop(repo: SqliteHostHistoryRepository) -> None:
    repo.record_seen("")
    assert repo.known_macs() == set()


# ── Idempotenz ────────────────────────────────────────────────────────────────


def test_record_seen_idempotent(repo: SqliteHostHistoryRepository) -> None:
    # Zweimal dieselbe MAC -> kein Fehler, genau ein Eintrag (INSERT OR IGNORE).
    repo.record_seen("aa:bb:cc:dd:ee:ff")
    repo.record_seen("aa:bb:cc:dd:ee:ff")
    assert repo.known_macs() == {"aa:bb:cc:dd:ee:ff"}


# ── known_macs (Bulk-Lesepfad) ────────────────────────────────────────────────


def test_known_macs_liefert_alle_eingetragenen(repo: SqliteHostHistoryRepository) -> None:
    repo.record_seen("aa:bb:cc:dd:ee:ff")
    repo.record_seen("11:22:33:44:55:66")
    assert repo.known_macs() == {"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"}


def test_known_macs_leer_bei_leerer_historie(repo: SqliteHostHistoryRepository) -> None:
    assert repo.known_macs() == set()
