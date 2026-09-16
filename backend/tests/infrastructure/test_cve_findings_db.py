"""Tests fuer ``SqliteCveFindingRepository`` (ADR 0037) -- gegen tmp_path-DB.

Belegt den Upsert-Round-trip (INSERT neu, UPDATE bekannter behaelt first_seen_ts),
die Identitaet je (mac, cve_id, port), und die Lese-Views (alle / pro Host) -- sowie
die MAC-Vereinheitlichung auf Grossschreibung (Finding 8): schreibweisen-unabhaengiges
Schreiben/Lesen und die kollisionssichere einmalige Bestands-Migration. Dazu
``replace_for_host`` (Befund 56): host-lokal, leere Sequenz erlaubt, transaktional.
Muster der uebrigen infrastructure-Repo-Tests (``tmp_path``-DB).
"""

import sqlite3
from pathlib import Path

import pytest

from domain.cve.models import CveFindingRecord
from infrastructure.cve_findings_db import SqliteCveFindingRepository

MAC = "aa:bb:cc:dd:ee:ff"
MAC_UPPER = MAC.upper()
OTHER = "11:22:33:44:55:66"


@pytest.fixture
def repo(tmp_path: Path) -> SqliteCveFindingRepository:
    return SqliteCveFindingRepository(tmp_path / "cernis.db")


def _finding(
    mac: str = MAC,
    cve_id: str = "CVE-2024-0001",
    port: int = 22,
    first: float = 100.0,
    last: float = 100.0,
    severity: str = "HIGH",
    score: float = 7.5,
) -> CveFindingRecord:
    return CveFindingRecord(
        mac=mac,
        cve_id=cve_id,
        port=port,
        severity=severity,
        cvss_score=score,
        description="desc",
        url="http://x",
        published="2024-01-01",
        first_seen_ts=first,
        last_seen_ts=last,
        ip="192.168.1.10",
        service="ssh",
    )


def test_upsert_dann_list_all(repo: SqliteCveFindingRepository) -> None:
    repo.upsert(_finding())
    rows = repo.list_all()
    assert len(rows) == 1
    assert rows[0].cve_id == "CVE-2024-0001"
    assert rows[0].first_seen_ts == 100.0


def test_upsert_bekannter_schluessel_behaelt_first_seen(repo: SqliteCveFindingRepository) -> None:
    repo.upsert(_finding(first=100.0, last=100.0))
    # Zweiter Upsert: gleicher (mac, cve_id, port), spaeterer last_seen, anderer first_seen-Wert
    # IM Record -- der DB-first_seen muss UNVERAENDERT bleiben (UPDATE-Zweig fasst ihn nicht an).
    repo.upsert(_finding(first=999.0, last=200.0, severity="CRITICAL", score=9.8))
    rows = repo.list_all()
    assert len(rows) == 1
    assert rows[0].first_seen_ts == 100.0  # unveraendert
    assert rows[0].last_seen_ts == 200.0  # aktualisiert
    assert rows[0].severity == "CRITICAL"  # NVD-Feld aktualisiert
    assert rows[0].cvss_score == 9.8


def test_verschiedene_ports_sind_verschiedene_befunde(repo: SqliteCveFindingRepository) -> None:
    repo.upsert(_finding(cve_id="CVE-2024-0001", port=22))
    repo.upsert(_finding(cve_id="CVE-2024-0001", port=80))
    assert len(repo.list_all()) == 2


def test_list_for_host_isoliert_macs(repo: SqliteCveFindingRepository) -> None:
    repo.upsert(_finding(mac=MAC))
    repo.upsert(_finding(mac=OTHER))
    assert len(repo.list_for_host(MAC)) == 1
    # Kanonisch grossgeschrieben zurueck -- die Befunde fuehren EINE Schreibweise.
    assert repo.list_for_host(MAC)[0].mac == MAC.upper()


def test_list_for_host_leere_mac(repo: SqliteCveFindingRepository) -> None:
    repo.upsert(_finding())
    assert repo.list_for_host("") == []


# ── MAC-Vereinheitlichung (Finding 8) ────────────────────────────────────────


def test_list_for_host_findet_unabhaengig_von_der_schreibweise(
    repo: SqliteCveFindingRepository,
) -> None:
    """DER Funktionsfehler: klein gespeichert, GROSS abgefragt -> lieferte faelschlich []."""
    repo.upsert(_finding(mac=MAC))
    assert len(repo.list_for_host(MAC_UPPER)) == 1
    assert len(repo.list_for_host(MAC)) == 1


def test_upsert_beide_schreibweisen_sind_ein_befund(
    repo: SqliteCveFindingRepository,
) -> None:
    """Derselbe Befund in zwei Schreibweisen erzeugt KEINE zwei Zeilen."""
    repo.upsert(_finding(mac=MAC, first=100.0, last=100.0))
    repo.upsert(_finding(mac=MAC_UPPER, first=100.0, last=200.0))
    rows = repo.list_all()
    assert len(rows) == 1
    assert rows[0].first_seen_ts == 100.0  # Upsert-Zweig, first_seen bleibt
    assert rows[0].last_seen_ts == 200.0


def _roh_einfuegen(
    db: Path,
    mac: str,
    cve_id: str = "CVE-2024-0001",
    port: int = 22,
    first: float = 100.0,
    last: float = 100.0,
    severity: str = "HIGH",
    score: float = 7.5,
) -> None:
    """Schreibt am Adapter VORBEI -- so entsteht der unmigrierte Altbestand."""
    conn = sqlite3.connect(db)
    with conn:
        conn.execute(
            "INSERT INTO cve_findings (mac, cve_id, port, severity, cvss_score, description, "
            "url, published, ip, service, first_seen_ts, last_seen_ts) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                mac,
                cve_id,
                port,
                severity,
                score,
                "desc",
                "http://x",
                "2024-01-01",
                "192.168.1.10",
                "ssh",
                first,
                last,
            ),
        )
    conn.close()


# ── replace_for_host: Zustandsanzeige statt Journal (Befund 56) ──────────────


def test_replace_for_host_ersetzt_nur_den_genannten_host(
    repo: SqliteCveFindingRepository,
) -> None:
    """Ersetzen ist HOST-LOKAL: der zweite Host bleibt vollstaendig unveraendert."""
    repo.upsert(_finding(mac=MAC, cve_id="CVE-ALT", port=22))
    repo.upsert(_finding(mac=OTHER, cve_id="CVE-FREMD", port=443, first=50.0, last=50.0))

    repo.replace_for_host(MAC, [_finding(mac=MAC, cve_id="CVE-NEU", port=80, first=200.0)])

    assert [(r.cve_id, r.port) for r in repo.list_for_host(MAC)] == [("CVE-NEU", 80)]
    fremd = repo.list_for_host(OTHER)
    assert len(fremd) == 1
    assert fremd[0].cve_id == "CVE-FREMD"
    assert fremd[0].first_seen_ts == 50.0  # unangetastet


def test_replace_for_host_leere_sequenz_raeumt_nur_diesen_host(
    repo: SqliteCveFindingRepository,
) -> None:
    """Leere Sequenz = der Host hat danach KEINE Befunde -- und nur er."""
    repo.upsert(_finding(mac=MAC, cve_id="CVE-1", port=22))
    repo.upsert(_finding(mac=MAC, cve_id="CVE-2", port=80))
    repo.upsert(_finding(mac=OTHER, cve_id="CVE-FREMD", port=443))

    repo.replace_for_host(MAC, [])

    assert repo.list_for_host(MAC) == []
    assert len(repo.list_for_host(OTHER)) == 1


def test_replace_for_host_ist_transaktional(repo: SqliteCveFindingRepository) -> None:
    """Bricht ein INSERT ab, darf auch das DELETE NICHT wirksam werden.

    Zwei Records mit demselben (cve_id, port) verletzen den PRIMARY KEY -- der zweite
    INSERT wirft. Ohne EINE Transaktionsklammer um DELETE + INSERTs staende der Host
    danach mit einem halben (oder leeren) Befundstand da; hier bleibt der ALTE Bestand.
    """
    repo.upsert(_finding(mac=MAC, cve_id="CVE-ALT", port=22, first=100.0, last=100.0))
    doppelt = [
        _finding(mac=MAC, cve_id="CVE-NEU", port=80, first=200.0),
        _finding(mac=MAC, cve_id="CVE-NEU", port=80, first=300.0),  # PK-Kollision
    ]

    with pytest.raises(sqlite3.IntegrityError):
        repo.replace_for_host(MAC, doppelt)

    rows = repo.list_for_host(MAC)
    assert len(rows) == 1
    assert rows[0].cve_id == "CVE-ALT"  # alter Bestand steht unveraendert
    assert rows[0].first_seen_ts == 100.0


def test_replace_for_host_ist_schreibweisen_unabhaengig(
    repo: SqliteCveFindingRepository,
) -> None:
    """Kleingeschriebene MAC im Aufruf trifft die (gross gespeicherten) Zeilen (Finding 8)."""
    repo.upsert(_finding(mac=MAC_UPPER, cve_id="CVE-ALT", port=22))

    repo.replace_for_host(MAC, [_finding(mac=MAC, cve_id="CVE-NEU", port=80)])

    rows = repo.list_all()
    assert len(rows) == 1  # keine Dublette in zweiter Schreibweise
    assert rows[0].cve_id == "CVE-NEU"
    assert rows[0].mac == MAC_UPPER


def test_migration_hebt_altbestand_hoch(tmp_path: Path) -> None:
    """Ein kleingeschriebener Altbefund ist nach dem naechsten Start erreichbar."""
    db = tmp_path / "cernis.db"
    SqliteCveFindingRepository(db)  # Schema anlegen
    _roh_einfuegen(db, MAC)

    repo = SqliteCveFindingRepository(db)  # zweiter Start -> Migration
    rows = repo.list_for_host(MAC_UPPER)
    assert len(rows) == 1
    assert rows[0].mac == MAC_UPPER
    assert len(repo.list_all()) == 1  # kein Datenverlust


def test_migration_kollision_bewahrt_aeltestes_first_seen(tmp_path: Path) -> None:
    """Kollision: EINE Zeile bleibt -- aeltestes first_seen, juengstes last_seen + NVD-Felder.

    Das aelteste ``first_seen_ts`` MUSS ueberleben: daran haengt die NEU-Kennzeichnung.
    Wuerde es juenger, floppte ein laengst bekannter Befund wieder als "neu" auf.
    """
    db = tmp_path / "cernis.db"
    SqliteCveFindingRepository(db)
    # aeltere Zeile: traegt das aelteste first_seen
    _roh_einfuegen(db, MAC, first=100.0, last=150.0, severity="HIGH", score=7.5)
    # juengere Zeile: traegt last_seen + den frischesten NVD-Stand
    _roh_einfuegen(db, MAC_UPPER, first=300.0, last=400.0, severity="CRITICAL", score=9.8)

    repo = SqliteCveFindingRepository(db)
    rows = repo.list_all()
    assert len(rows) == 1
    assert rows[0].mac == MAC_UPPER
    assert rows[0].first_seen_ts == 100.0  # aeltestes bewahrt
    assert rows[0].last_seen_ts == 400.0  # juengstes uebernommen
    assert rows[0].severity == "CRITICAL"  # NVD-Felder der juengsten Zeile
    assert rows[0].cvss_score == 9.8


def test_migration_kollision_nur_gleicher_schluessel_verschmilzt(tmp_path: Path) -> None:
    """Verschiedene (cve_id, port) bleiben getrennte Befunde -- kein Ueber-Verschmelzen."""
    db = tmp_path / "cernis.db"
    SqliteCveFindingRepository(db)
    _roh_einfuegen(db, MAC, cve_id="CVE-2024-0001", port=22, last=100.0)
    _roh_einfuegen(db, MAC_UPPER, cve_id="CVE-2024-0001", port=22, last=200.0)  # verschmilzt
    _roh_einfuegen(db, MAC, cve_id="CVE-2024-0002", port=22)  # eigener Befund
    _roh_einfuegen(db, MAC, cve_id="CVE-2024-0001", port=80)  # eigener Befund

    repo = SqliteCveFindingRepository(db)
    assert len(repo.list_all()) == 3
    assert len(repo.list_for_host(MAC_UPPER)) == 3


def test_migration_ist_beim_zweiten_start_ein_no_op(tmp_path: Path) -> None:
    """Wiederholter Start aendert nichts mehr (Guard greift, Zahlen bleiben)."""
    db = tmp_path / "cernis.db"
    SqliteCveFindingRepository(db)
    _roh_einfuegen(db, MAC, first=100.0, last=150.0)

    erste = SqliteCveFindingRepository(db).list_all()
    zweite = SqliteCveFindingRepository(db).list_all()
    assert len(erste) == len(zweite) == 1
    assert erste[0].mac == zweite[0].mac == MAC_UPPER
    assert erste[0].first_seen_ts == zweite[0].first_seen_ts == 100.0
    assert erste[0].last_seen_ts == zweite[0].last_seen_ts == 150.0
