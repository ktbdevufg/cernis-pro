"""End-to-end-Tests der scanning-REST-API (v2) gegen app.py via TestClient.

Echte Adapter auf Test-Backends via ``dependency_overrides``:
``SqliteScanHistoryRepository`` auf einer tmp_path-DB, ``VendorLookupAdapter``.
Kein echtes cernis.db. Belegt die REST-Shapes am S.1-Characterization-Contract
(``/api/history``, ``/api/history/{id}`` inkl. 404, ``/api/vendor/{mac}``).

``/api/arp`` ist bewusst NICHT dabei (S.7, braucht ArpTablePort) -- ein Test
darauf wuerde fehlschlagen, weil die Route absichtlich fehlt.
"""

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.scanning import (
    provide_get_scan_detail,
    provide_get_scan_history,
    provide_lookup_vendor,
)
from app import create_app
from application.scanning import GetScanDetail, GetScanHistory, LookupVendor
from domain.scanning import EnrichedHost, PortInfo
from infrastructure.config import AppConfig
from infrastructure.scanning.scan_history import SqliteScanHistoryRepository
from infrastructure.scanning.vendor_lookup import VendorLookupAdapter


@pytest.fixture
def repo(tmp_path: Path) -> SqliteScanHistoryRepository:
    return SqliteScanHistoryRepository(tmp_path / "cernis.db")


def _wired_app(repo: SqliteScanHistoryRepository) -> FastAPI:
    vendor = VendorLookupAdapter()
    app = create_app(AppConfig())
    app.dependency_overrides[provide_get_scan_history] = lambda: GetScanHistory(repo)
    app.dependency_overrides[provide_get_scan_detail] = lambda: GetScanDetail(repo)
    app.dependency_overrides[provide_lookup_vendor] = lambda: LookupVendor(vendor)
    return app


@pytest.fixture
def client(repo: SqliteScanHistoryRepository) -> Iterator[TestClient]:
    with TestClient(_wired_app(repo)) as test_client:
        yield test_client


# ── /api/history ─────────────────────────────────────────────────────────────


def test_history_lists_entries_without_blob(
    client: TestClient, repo: SqliteScanHistoryRepository
) -> None:
    repo.save("192.168.1.0/24", (EnrichedHost(ip="192.168.1.2", mac="AA:BB:CC:DD:EE:01"),))
    body = client.get("/api/history").json()
    assert len(body) == 1
    entry = body[0]
    assert entry["cidr"] == "192.168.1.0/24"
    assert entry["host_count"] == 1
    assert entry["scanned_at"]  # ISO-Zeitstempel, nicht leer
    assert set(entry.keys()) == {"id", "scanned_at", "cidr", "host_count"}  # kein Host-Blob


def test_history_empty_returns_empty_list(client: TestClient) -> None:
    assert client.get("/api/history").json() == []


# ── /api/history/{id} ────────────────────────────────────────────────────────


def test_history_detail_roundtrips_hosts(
    client: TestClient, repo: SqliteScanHistoryRepository
) -> None:
    host = EnrichedHost(
        ip="10.0.0.5",
        mac="AA:BB:CC:DD:EE:01",
        vendor="Acme",
        ports=(PortInfo(port=22, state="open", service="ssh"),),
        category="server",
    )
    repo.save("10.0.0.0/24", (host,))
    scan_id = repo.list(20)[0].scan_id

    body = client.get(f"/api/history/{scan_id}").json()
    assert body["cidr"] == "10.0.0.0/24"
    assert body["host_count"] == 1
    assert body["scanned_at"]
    assert len(body["hosts"]) == 1
    got = body["hosts"][0]
    assert got["ip"] == "10.0.0.5"
    assert got["vendor"] == "Acme"
    assert got["ports"] == [{"port": 22, "state": "open", "service": "ssh"}]
    assert got["category"] == "server"
    # tuples als JSON-Listen serialisiert:
    assert isinstance(got["tags"], list)
    assert isinstance(got["ipv6_all"], list)


def test_history_detail_unknown_returns_404(client: TestClient) -> None:
    assert client.get("/api/history/9999").status_code == 404


# ── /api/vendor/{mac} ────────────────────────────────────────────────────────


def test_vendor_returns_mac_and_vendor(client: TestClient) -> None:
    body = client.get("/api/vendor/AA:BB:CC:DD:EE:01").json()
    assert body["mac"] == "AA:BB:CC:DD:EE:01"
    assert "vendor" in body  # leer oder gefunden -- beides gueltig (OUI-DB-abhaengig)


# ── /api/arp bewusst NICHT vorhanden (S.7) ──────────────────────────────────


def test_arp_route_absent_until_s7(client: TestClient) -> None:
    # Kein ArpTablePort in S.6 -> die Route existiert nicht (404 vom Router/Mount).
    assert client.get("/api/arp").status_code == 404
