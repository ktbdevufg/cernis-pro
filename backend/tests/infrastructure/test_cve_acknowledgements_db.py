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
MAC_UPPER = MAC.upper()
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
    # Schluessel kommen kanonisch GROSS heraus -- so treffen sie die (ebenfalls
    # grossgeschriebenen) Befund-Schluessel aus cve_findings.
    assert (MAC_UPPER, CVE, 22) in repo.acknowledged_keys()


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
    assert (MAC_UPPER, CVE, 22) in repo.acknowledged_keys()


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


# ── MAC-Vereinheitlichung (Finding 8) ────────────────────────────────────────


def test_ack_und_unack_ueber_beide_schreibweisen_sind_ein_strang(
    repo: SqliteCveAcknowledgementRepository,
) -> None:
    """ack klein, unack GROSS -> EIN Strang: die juengste Entscheidung gilt.

    Ohne Vereinheitlichung waeren das zwei konkurrierende Straenge gewesen, und das
    ``unack`` haette den Befund NICHT reaktiviert.
    """
    repo.record(MAC, CVE, 22, "ack")
    repo.record(MAC_UPPER, CVE, 22, "unack")
    assert (MAC_UPPER, CVE, 22) not in repo.acknowledged_keys()


def test_ack_gross_nach_unack_klein_gewinnt(
    repo: SqliteCveAcknowledgementRepository,
) -> None:
    """Gegenprobe in der anderen Richtung -- wieder gilt der juengste Eintrag."""
    repo.record(MAC, CVE, 22, "unack")
    repo.record(MAC_UPPER, CVE, 22, "ack")
    assert (MAC_UPPER, CVE, 22) in repo.acknowledged_keys()


def _roh_einfuegen(db: Path, mac: str, action: str) -> None:
    """Schreibt am Adapter VORBEI -- so entsteht der unmigrierte Altbestand."""
    conn = sqlite3.connect(db)
    with conn:
        conn.execute(
            "INSERT INTO cve_acknowledgements (mac, cve_id, port, action, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (mac, CVE, 22, action, FakeClock.FIXED.isoformat()),
        )
    conn.close()


def test_migration_hebt_altbestand_hoch(tmp_path: Path) -> None:
    """Ein kleingeschriebenes Alt-ack trifft nach dem naechsten Start den Befund."""
    db = tmp_path / "cernis.db"
    SqliteCveAcknowledgementRepository(db, FakeClock())  # Schema anlegen
    _roh_einfuegen(db, MAC, "ack")

    repo = SqliteCveAcknowledgementRepository(db, FakeClock())  # Migration
    assert (MAC_UPPER, CVE, 22) in repo.acknowledged_keys()


def test_migration_dubletten_sind_unschaedlich(tmp_path: Path) -> None:
    """mac ist kein Schluessel: beide Schreibweisen bleiben als Zeilen erhalten.

    Verlustfrei -- nichts wird geloescht. Fachlich richtig ist trotzdem EIN Ergebnis:
    nach dem Hochschreiben liegen beide in derselben Gruppe, die juengste (max(id))
    gewinnt -- hier das ``unack``.
    """
    db = tmp_path / "cernis.db"
    SqliteCveAcknowledgementRepository(db, FakeClock())
    _roh_einfuegen(db, MAC, "ack")
    _roh_einfuegen(db, MAC_UPPER, "unack")  # juenger (groessere id)

    repo = SqliteCveAcknowledgementRepository(db, FakeClock())
    assert (MAC_UPPER, CVE, 22) not in repo.acknowledged_keys()

    conn = sqlite3.connect(db)
    zeilen = conn.execute("SELECT count(*) FROM cve_acknowledgements").fetchone()[0]
    klein = conn.execute(
        "SELECT count(*) FROM cve_acknowledgements WHERE mac <> upper(mac)"
    ).fetchone()[0]
    conn.close()
    assert zeilen == 2  # kein Datenverlust (append-only bleibt append-only)
    assert klein == 0  # alle hochgeschrieben


def test_migration_ist_beim_zweiten_start_ein_no_op(tmp_path: Path) -> None:
    """Wiederholter Start aendert nichts mehr (Guard greift, Zahlen bleiben)."""
    db = tmp_path / "cernis.db"
    SqliteCveAcknowledgementRepository(db, FakeClock())
    _roh_einfuegen(db, MAC, "ack")

    erste = SqliteCveAcknowledgementRepository(db, FakeClock()).acknowledged_keys()
    zweite = SqliteCveAcknowledgementRepository(db, FakeClock()).acknowledged_keys()
    assert erste == zweite == {(MAC_UPPER, CVE, 22)}

    conn = sqlite3.connect(db)
    zeilen = conn.execute("SELECT count(*) FROM cve_acknowledgements").fetchone()[0]
    conn.close()
    assert zeilen == 1  # die Migration hat nichts vervielfaeltigt


def test_leeres_log(repo: SqliteCveAcknowledgementRepository) -> None:
    assert repo.acknowledged_keys() == set()
