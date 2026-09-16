"""Tests fuer ``SqliteCveCheckStateRepository`` (ADR 0037) -- gegen tmp_path-DB.

Belegt: get(None) fuer unbekannten Host, record->get-Round-trip, Upsert auf mac
(zweiter record ueberschreibt), Port-Set-(De-)Serialisierung inkl. leerem Set,
all_states -- sowie die MAC-Vereinheitlichung auf Grossschreibung (Finding 8):
Schreiben und Lesen sind schreibweisen-unabhaengig, der Bestand wird einmalig
kollisionssicher hochgeschrieben.
"""

import sqlite3
from pathlib import Path

import pytest

from infrastructure import cve_checkstate_db
from infrastructure.cve_checkstate_db import SqliteCveCheckStateRepository

MAC = "aa:bb:cc:dd:ee:ff"
MAC_UPPER = MAC.upper()


@pytest.fixture
def repo(tmp_path: Path) -> SqliteCveCheckStateRepository:
    return SqliteCveCheckStateRepository(tmp_path / "cernis.db")


def test_get_unbekannt_ist_none(repo: SqliteCveCheckStateRepository) -> None:
    assert repo.get(MAC) is None


def test_get_leere_mac_ist_none(repo: SqliteCveCheckStateRepository) -> None:
    assert repo.get("") is None


def test_record_dann_get_round_trip(repo: SqliteCveCheckStateRepository) -> None:
    repo.record(MAC, frozenset({22, 443, 80}), checked_ts=123.5)
    state = repo.get(MAC)
    assert state is not None
    # Kanonisch grossgeschrieben zurueck -- der Pruefstand fuehrt EINE Schreibweise.
    assert state.mac == MAC_UPPER
    assert state.last_checked_ts == 123.5
    assert state.checked_ports == frozenset({22, 80, 443})


def test_record_leeres_port_set(repo: SqliteCveCheckStateRepository) -> None:
    repo.record(MAC, frozenset(), checked_ts=10.0)
    state = repo.get(MAC)
    assert state is not None
    assert state.checked_ports == frozenset()


def test_record_upsert_ueberschreibt(repo: SqliteCveCheckStateRepository) -> None:
    repo.record(MAC, frozenset({22}), checked_ts=10.0)
    repo.record(MAC, frozenset({22, 443}), checked_ts=20.0)
    state = repo.get(MAC)
    assert state is not None
    assert state.last_checked_ts == 20.0
    assert state.checked_ports == frozenset({22, 443})
    assert len(repo.all_states()) == 1  # ein Stand je Host


def test_all_states(repo: SqliteCveCheckStateRepository) -> None:
    repo.record(MAC, frozenset({22}), checked_ts=10.0)
    repo.record("99:99:99:99:99:99", frozenset({80}), checked_ts=11.0)
    assert len(repo.all_states()) == 2


# ── MAC-Vereinheitlichung (Finding 8) ────────────────────────────────────────


def test_get_findet_unabhaengig_von_der_schreibweise(
    repo: SqliteCveCheckStateRepository,
) -> None:
    """Der Kern des Findings: klein geschrieben, GROSS gelesen -- und umgekehrt."""
    repo.record(MAC, frozenset({22}), checked_ts=5.0)
    assert repo.get(MAC_UPPER) is not None
    assert repo.get(MAC) is not None


def test_record_beide_schreibweisen_sind_ein_stand(
    repo: SqliteCveCheckStateRepository,
) -> None:
    """Zwei Schreibweisen derselben Adresse erzeugen KEINE zwei Pruefstaende."""
    repo.record(MAC, frozenset({22}), checked_ts=10.0)
    repo.record(MAC_UPPER, frozenset({22, 443}), checked_ts=20.0)
    assert len(repo.all_states()) == 1
    state = repo.get(MAC)
    assert state is not None
    assert state.last_checked_ts == 20.0


def test_leere_mac_bleibt_leer(repo: SqliteCveCheckStateRepository) -> None:
    """S3: eine leere MAC wird NICHT umgedeutet -- get liefert None, kein Krach."""
    assert repo.get("") is None


def _roh_einfuegen(db: Path, mac: str, ts: float, ports: str) -> None:
    """Schreibt am Adapter VORBEI -- so entsteht der unmigrierte Altbestand."""
    conn = sqlite3.connect(db)
    with conn:
        conn.execute(
            "INSERT INTO cve_check_state (mac, last_checked_ts, ports) VALUES (?, ?, ?)",
            (mac, ts, ports),
        )
    conn.close()


def test_migration_hebt_altbestand_hoch(tmp_path: Path) -> None:
    """Ein kleingeschriebener Altbestand ist nach dem naechsten Start erreichbar."""
    db = tmp_path / "cernis.db"
    SqliteCveCheckStateRepository(db)  # Schema anlegen
    _roh_einfuegen(db, MAC, 10.0, "22,80")

    repo = SqliteCveCheckStateRepository(db)  # zweiter Start -> Migration
    state = repo.get(MAC_UPPER)
    assert state is not None
    assert state.mac == MAC_UPPER
    assert state.checked_ports == frozenset({22, 80})
    assert len(repo.all_states()) == 1


def test_migration_kollision_juengster_stand_gewinnt(tmp_path: Path) -> None:
    """Beide Schreibweisen vorhanden -> EINE Zeile bleibt: die juengste samt ihren ports."""
    db = tmp_path / "cernis.db"
    SqliteCveCheckStateRepository(db)
    _roh_einfuegen(db, MAC, 10.0, "22")  # aelter
    _roh_einfuegen(db, MAC_UPPER, 20.0, "443,8443")  # juenger -> gewinnt

    repo = SqliteCveCheckStateRepository(db)
    states = repo.all_states()
    assert len(states) == 1  # kein Duplikat, kein Datenverlust ueber die Gruppe hinaus
    assert states[0].mac == MAC_UPPER
    assert states[0].last_checked_ts == 20.0
    # Die ports gehoeren zum juengsten Stand -- NICHT gemischt.
    assert states[0].checked_ports == frozenset({443, 8443})


def test_migration_ist_beim_zweiten_start_ein_no_op(tmp_path: Path) -> None:
    """Wiederholter Start aendert nichts mehr (Guard greift, Zahlen bleiben)."""
    db = tmp_path / "cernis.db"
    SqliteCveCheckStateRepository(db)
    _roh_einfuegen(db, MAC, 10.0, "22")

    erste = SqliteCveCheckStateRepository(db).all_states()
    zweite = SqliteCveCheckStateRepository(db).all_states()
    assert len(erste) == len(zweite) == 1
    assert erste[0].mac == zweite[0].mac == MAC_UPPER
    assert erste[0].last_checked_ts == zweite[0].last_checked_ts == 10.0


def test_migrations_fehlschlag_laesst_den_adapter_starten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Vorgabe: eine misslungene Migration wird geloggt, verhindert den Start aber NICHT.

    Ein toter Backend-Start waere der schlechtere Ausgang als ein unmigrierter
    Altbestand -- der Adapter bleibt benutzbar, nur die Alt-Zeilen sind es nicht.
    """
    db = tmp_path / "cernis.db"
    SqliteCveCheckStateRepository(db)
    _roh_einfuegen(db, MAC, 10.0, "22")

    def _kaputt(conn: object, table: str) -> int:
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(cve_checkstate_db, "migrate_macs_to_upper", _kaputt)

    repo = SqliteCveCheckStateRepository(db)  # darf NICHT werfen
    # Frisch geschriebene Staende funktionieren weiter (kanonisch gross).
    repo.record("11:22:33:44:55:66", frozenset({80}), checked_ts=50.0)
    assert repo.get("11:22:33:44:55:66") is not None
