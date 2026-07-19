"""Tests fuer ``SqliteHostHistoryRepository`` (C.1) -- gegen tmp_path-DB.

Belegt den ``record_seen`` <-> ``is_known``-Round-trip, die Behandlung der leeren MAC
(``is_known("")`` True, ``record_seen("")`` no-op -- ein Host ohne stabile Identitaet
kommt nicht in die Historie und gilt als bekannt), die Idempotenz von ``record_seen``
(``INSERT OR IGNORE``) und den Bulk-Lesepfad ``known_macs``. Muster der uebrigen
infrastructure-Repo-Tests (``tmp_path``-DB).
"""

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from infrastructure.analysis_host_history_db import SqliteHostHistoryRepository


class FakeClock:
    """Erfuellt das ``Clock``-Protocol strukturell; liefert einen festen Zeitpunkt.

    Timezone-aware UTC -- wie ``SystemClock``, damit ``.isoformat()`` einen Offset
    (``+00:00``) traegt und der Test deterministisch gegen den Erwartungswert prueft.
    """

    FIXED = datetime(2026, 7, 18, 13, 23, 45, 123456, tzinfo=UTC)

    def now(self) -> datetime:
        return self.FIXED


@pytest.fixture
def repo(tmp_path: Path) -> SqliteHostHistoryRepository:
    return SqliteHostHistoryRepository(tmp_path / "cernis.db", FakeClock())


# ── Round-trip ────────────────────────────────────────────────────────────────


def test_record_seen_dann_is_known(repo: SqliteHostHistoryRepository) -> None:
    repo.record_seen("aa:bb:cc:dd:ee:ff")
    assert repo.is_known("aa:bb:cc:dd:ee:ff") is True


def test_nicht_eingetragene_mac_ist_unbekannt(repo: SqliteHostHistoryRepository) -> None:
    repo.record_seen("aa:bb:cc:dd:ee:ff")
    assert repo.is_known("11:22:33:44:55:66") is False


def test_record_seen_setzt_first_seen_aus_clock_mit_tz_offset(
    repo: SqliteHostHistoryRepository, tmp_path: Path
) -> None:
    """``first_seen`` kommt aus der Clock: nicht leer, mit Zonen-Offset, exakter Wert.

    Belegt die A10-Etappe-2: der Zeitstempel wird explizit ueber den Clock-Port gesetzt
    (timezone-aware UTC, ISO-8601 mit +00:00) statt ueber den Schema-Default
    ``datetime('now')`` (UTC ohne Zonen-Kennzeichnung). Das Repository hat keinen Lesepfad
    fuer ``first_seen`` -- der Test liest die Spalte direkt aus der DB.
    """
    repo.record_seen("aa:bb:cc:dd:ee:ff")

    conn = sqlite3.connect(tmp_path / "cernis.db")
    first_seen = conn.execute(
        "SELECT first_seen FROM analysis_known_hosts WHERE mac = ?", ("aa:bb:cc:dd:ee:ff",)
    ).fetchone()[0]
    conn.close()

    assert first_seen.endswith("+00:00")  # traegt eine Zeitzonen-Kennzeichnung
    assert first_seen == FakeClock.FIXED.isoformat()  # exakt der Clock-Wert


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
