"""Tests fuer ``SqliteCveFindingRepository`` (ADR 0037) -- gegen tmp_path-DB.

Belegt den Upsert-Round-trip (INSERT neu, UPDATE bekannter behaelt first_seen_ts),
die Identitaet je (mac, cve_id, port), und die Lese-Views (alle / pro Host).
Muster der uebrigen infrastructure-Repo-Tests (``tmp_path``-DB).
"""

from pathlib import Path

import pytest

from domain.cve.models import CveFindingRecord
from infrastructure.cve_findings_db import SqliteCveFindingRepository

MAC = "aa:bb:cc:dd:ee:ff"
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
    assert repo.list_for_host(MAC)[0].mac == MAC


def test_list_for_host_leere_mac(repo: SqliteCveFindingRepository) -> None:
    repo.upsert(_finding())
    assert repo.list_for_host("") == []
