"""Tests fuer ``SqliteCveAcknowledgementRepository`` (ADR 0037) -- gegen tmp_path-DB.

Belegt das append-only ack/unack-Muster (ADR 0031, hier port-genau pro
(mac, cve_id, port)): record(ack) -> acknowledged_keys enthaelt das Tripel; unack
nimmt es wieder raus (juengster Eintrag gewinnt); Append-only (mehrfaches ack/unack);
Granularitaet (anderer Port/andere cve_id desselben Hosts unberuehrt).
"""

from pathlib import Path

import pytest

from infrastructure.cve_acknowledgements_db import SqliteCveAcknowledgementRepository

MAC = "aa:bb:cc:dd:ee:ff"
CVE = "CVE-2024-0001"


@pytest.fixture
def repo(tmp_path: Path) -> SqliteCveAcknowledgementRepository:
    return SqliteCveAcknowledgementRepository(tmp_path / "cernis.db")


def test_ack_dann_enthalten(repo: SqliteCveAcknowledgementRepository) -> None:
    repo.record(MAC, CVE, 22, "ack")
    assert (MAC, CVE, 22) in repo.acknowledged_keys()


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
    import sqlite3

    with pytest.raises(sqlite3.IntegrityError):
        repo.record(MAC, CVE, 22, "bogus")


def test_leeres_log(repo: SqliteCveAcknowledgementRepository) -> None:
    assert repo.acknowledged_keys() == set()
