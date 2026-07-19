"""End-to-end-Test der cve-Routen (ADR 0037) via TestClient gegen eine Minimal-App.

Der cve-Router wird hier in eine eigene FastAPI-App gehaengt (NICHT ueber ``create_app``
-- die Lifespan-/Composition-Root-Anbindung kommt erst in Schnitt 3); die Dependencies
werden wie im Composition Root ueber ``dependency_overrides`` auf echte tmp_path-Repos
+ die echten Lese-Use-Cases verdrahtet. So wird der ganze Rand (Routing, Serializer,
Body-Validierung, Pass-Through) end-to-end geprueft. Die Zeit ist ueber ``now_provider``
fixiert (deterministisches is_new).
"""

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.cve import (
    provide_cve_acknowledge,
    provide_get_acknowledged_findings,
    provide_get_active_findings,
    provide_get_cve_status,
    router,
)
from application.cve import GetAcknowledgedFindings, GetActiveFindings, GetCveMonitorStatus
from domain.cve.models import CveFindingRecord
from infrastructure.clock import SystemClock
from infrastructure.cve_acknowledgements_db import SqliteCveAcknowledgementRepository
from infrastructure.cve_checkstate_db import SqliteCveCheckStateRepository
from infrastructure.cve_findings_db import SqliteCveFindingRepository
from ports.cve import InventoryHost, InventoryPort

MAC = "AA:BB:CC:DD:EE:01"
NOW = 1000.0


class _FakeInventory:
    def list_hosts(self) -> list[InventoryHost]:
        return [InventoryHost(mac=MAC, ip="1.2.3.4", ports=(InventoryPort(22, "ssh"),))]


Context = tuple[TestClient, SqliteCveFindingRepository]


@pytest.fixture
def context(tmp_path: Path) -> Iterator[Context]:
    db = tmp_path / "cernis.db"
    findings = SqliteCveFindingRepository(db)
    checkstate = SqliteCveCheckStateRepository(db)
    acks = SqliteCveAcknowledgementRepository(db, SystemClock())

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[provide_get_active_findings] = lambda: GetActiveFindings(
        findings, acks, now_provider=lambda: NOW
    )
    app.dependency_overrides[provide_get_acknowledged_findings] = lambda: GetAcknowledgedFindings(
        findings, acks, now_provider=lambda: NOW
    )
    app.dependency_overrides[provide_get_cve_status] = lambda: GetCveMonitorStatus(
        _FakeInventory(),
        checkstate,
        findings,
        acks,
        refresh_interval_provider=lambda: 24 * 3600.0,
        now_provider=lambda: NOW,
    )
    app.dependency_overrides[provide_cve_acknowledge] = lambda: acks.record
    yield TestClient(app), findings


def _seed(findings: SqliteCveFindingRepository, cve_id: str, port: int, first: float) -> None:
    findings.upsert(
        CveFindingRecord(
            mac=MAC,
            cve_id=cve_id,
            port=port,
            severity="HIGH",
            cvss_score=7.5,
            description="d",
            url="http://x",
            published="2024-01-01",
            first_seen_ts=first,
            last_seen_ts=first,
            ip="1.2.3.4",
            service="ssh",
        )
    )


def test_list_active_findings_mit_is_new(context: Context) -> None:
    client, findings = context
    _seed(findings, "CVE-1", 22, first=NOW)  # jetzt zuerst gesehen -> neu
    resp = client.get("/api/cve")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["cve_id"] == "CVE-1"
    assert data[0]["is_new"] is True
    assert data[0]["severity"] == "HIGH"
    assert data[0]["cvss_score"] == 7.5


def test_list_for_host(context: Context) -> None:
    client, findings = context
    _seed(findings, "CVE-1", 22, first=NOW)
    assert len(client.get(f"/api/cve/host/{MAC}").json()) == 1
    assert client.get("/api/cve/host/99:99:99:99:99:99").json() == []


def test_acknowledge_filtert_befund_raus(context: Context) -> None:
    client, findings = context
    _seed(findings, "CVE-1", 22, first=NOW)
    assert len(client.get("/api/cve").json()) == 1
    resp = client.post(
        "/api/cve/acknowledge",
        json={"mac": MAC, "cve_id": "CVE-1", "port": 22, "action": "ack"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    assert client.get("/api/cve").json() == []  # quittiert -> raus aus aktiv


def test_unack_reaktiviert(context: Context) -> None:
    client, findings = context
    _seed(findings, "CVE-1", 22, first=NOW)
    client.post(
        "/api/cve/acknowledge",
        json={"mac": MAC, "cve_id": "CVE-1", "port": 22, "action": "ack"},
    )
    client.post(
        "/api/cve/acknowledge",
        json={"mac": MAC, "cve_id": "CVE-1", "port": 22, "action": "unack"},
    )
    assert len(client.get("/api/cve").json()) == 1  # wieder aktiv


def test_acknowledged_endpunkt_zeigt_quittierte_nicht_in_aktiv(context: Context) -> None:
    client, findings = context
    _seed(findings, "CVE-1", 22, first=NOW)
    assert client.get("/api/cve/acknowledged").json() == []  # noch nichts quittiert
    client.post(
        "/api/cve/acknowledge",
        json={"mac": MAC, "cve_id": "CVE-1", "port": 22, "action": "ack"},
    )
    acked = client.get("/api/cve/acknowledged").json()
    assert len(acked) == 1
    assert acked[0]["cve_id"] == "CVE-1"
    assert acked[0]["severity"] == "HIGH"  # volle Daten, gleiche Wire-Form
    assert client.get("/api/cve").json() == []  # gleichzeitig NICHT mehr aktiv


def test_acknowledged_nach_unack_wieder_leer(context: Context) -> None:
    client, findings = context
    _seed(findings, "CVE-1", 22, first=NOW)
    client.post(
        "/api/cve/acknowledge",
        json={"mac": MAC, "cve_id": "CVE-1", "port": 22, "action": "ack"},
    )
    assert len(client.get("/api/cve/acknowledged").json()) == 1
    client.post(
        "/api/cve/acknowledge",
        json={"mac": MAC, "cve_id": "CVE-1", "port": 22, "action": "unack"},
    )
    assert client.get("/api/cve/acknowledged").json() == []  # raus aus ausgeblendet
    assert len(client.get("/api/cve").json()) == 1  # zurueck in aktiv


def test_acknowledge_ungueltige_action_422(context: Context) -> None:
    client, _ = context
    resp = client.post(
        "/api/cve/acknowledge",
        json={"mac": MAC, "cve_id": "CVE-1", "port": 22, "action": "loeschen"},
    )
    assert resp.status_code == 422


def test_status(context: Context) -> None:
    client, _ = context
    data = client.get("/api/cve/status").json()
    assert data["hosts_total"] == 1
    assert data["hosts_due"] == 1  # der Bestands-Host ist neu -> faellig
    assert data["sleeping"] is False
