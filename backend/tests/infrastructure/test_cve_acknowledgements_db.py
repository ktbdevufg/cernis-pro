"""Tests fuer ``SqliteCveAcknowledgementRepository`` (ADR 0037) -- gegen tmp_path-DB.

Belegt das append-only ack/unack-Muster (ADR 0031, hier port-genau pro
(mac, cve_id, port)): record(ack) -> acknowledged_keys enthaelt das Tripel; unack
nimmt es wieder raus (juengster Eintrag gewinnt); Append-only (mehrfaches ack/unack);
Granularitaet (anderer Port/andere cve_id desselben Hosts unberuehrt).
"""

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from infrastructure.cve_acknowledgements_db import SqliteCveAcknowledgementRepository

MAC = "aa:bb:cc:dd:ee:ff"
CVE = "CVE-2024-0001"


class FakeClock:
    """Erfuellt das ``Clock``-Protocol strukturell; liefert einen festen Zeitpunkt.

    Timezone-aware UTC -- wie ``SystemClock``, damit ``.isoformat()`` einen Offset
    (``+00:00``) traegt und der Test deterministisch gegen den Erwartungswert prueft.
    """

    FIXED = datetime(2026, 7, 18, 13, 23, 45, 123456, tzinfo=UTC)

    def now(self) -> datetime:
        return self.FIXED


@pytest.fixture
def repo(tmp_path: Path) -> SqliteCveAcknowledgementRepository:
    return SqliteCveAcknowledgementRepository(tmp_path / "cernis.db", FakeClock())


def test_ack_dann_enthalten(repo: SqliteCveAcknowledgementRepository) -> None:
    repo.record(MAC, CVE, 22, "ack")
    assert (MAC, CVE, 22) in repo.acknowledged_keys()


def test_record_setzt_created_at_aus_clock_mit_tz_offset(
    repo: SqliteCveAcknowledgementRepository, tmp_path: Path
) -> None:
    """``created_at`` kommt aus der Clock: nicht leer, mit Zonen-Offset, exakter Wert.

    Belegt die A10-Etappe-2: der Zeitstempel wird explizit ueber den Clock-Port gesetzt
    (timezone-aware UTC, ISO-8601 mit +00:00) statt ueber den Schema-Default
    ``datetime('now')`` (UTC ohne Zonen-Kennzeichnung). Das Repository hat keinen Lesepfad
    fuer ``created_at`` -- der Test liest die Spalte direkt aus der DB.
    """
    repo.record(MAC, CVE, 22, "ack")

    conn = sqlite3.connect(tmp_path / "cernis.db")
    created_at = conn.execute("SELECT created_at FROM cve_acknowledgements").fetchone()[0]
    conn.close()

    assert created_at.endswith("+00:00")  # traegt eine Zeitzonen-Kennzeichnung
    assert created_at == FakeClock.FIXED.isoformat()  # exakt der Clock-Wert


def test_unack_nimmt_wieder_raus(repo: SqliteCveAcknowledgementRepository) -> None:
    repo.record(MAC, CVE, 22, "ack")
    repo.record(MAC, CVE, 22, "unack")
    assert (MAC, CVE, 22) not in repo.acknowledged_keys()


def test_juengster_eintrag_gewinnt(repo: SqliteCveAcknowledgementRepository) -> None:
    repo.record(MAC, CVE, 22, "ack")
    repo.record(MAC, CVE, 22, "unack")
    repo.record(MAC, CVE, 22, "ack")  # zuletzt wieder ack
    assert (MAC, CVE, 22) in repo.acknowledged_keys()


def test_granularitaet_port_genau(repo: SqliteCveAcknowledgementRepository) -> None:
    repo.record(MAC, CVE, 22, "ack")
    # Selbe cve_id, anderer Port -> NICHT quittiert.
    assert (MAC, CVE, 80) not in repo.acknowledged_keys()


def test_granularitaet_cve_genau(repo: SqliteCveAcknowledgementRepository) -> None:
    repo.record(MAC, CVE, 22, "ack")
    # Andere cve_id, selber Port -> NICHT quittiert.
    assert (MAC, "CVE-2024-9999", 22) not in repo.acknowledged_keys()


def test_ungueltige_action_bricht(repo: SqliteCveAcknowledgementRepository) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        repo.record(MAC, CVE, 22, "bogus")


def test_leeres_log(repo: SqliteCveAcknowledgementRepository) -> None:
    assert repo.acknowledged_keys() == set()
