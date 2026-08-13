"""End-to-end-Tests der scanning-REST-API (v2) gegen app.py via TestClient.

Echte Adapter auf Test-Backends via ``dependency_overrides``:
``SqliteScanHistoryRepository`` auf einer tmp_path-DB, ``VendorLookupAdapter``.
Kein echtes cernis.db. Belegt die REST-Shapes am S.1-Characterization-Contract
(``/api/history``, ``/api/history/{id}`` inkl. 404, ``/api/vendor/{mac}``).

``/api/arp`` (S.7a) wird ueber einen Fake-``ArpTablePort`` verdrahtet -- kein
echter ``ip neigh``-Aufruf -- und liefert die rohe ``{ip: mac}``-Tabelle.
"""

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.scanning import (
    provide_get_arp_table,
    provide_get_scan_detail,
    provide_get_scan_history,
    provide_lookup_vendor,
)
from app import create_app
from application.scanning import GetArpTable, GetScanDetail, GetScanHistory, LookupVendor
from domain.scanning import EnrichedHost, PortInfo, PortInterception
from infrastructure.clock import SystemClock
from infrastructure.config import AppConfig
from infrastructure.scanning.scan_history import SqliteScanHistoryRepository
from infrastructure.scanning.vendor_lookup import VendorLookupAdapter


class _FakeArpTable:
    """Fake-``ArpTablePort`` mit fester Tabelle -- kein echter ``ip neigh``-Aufruf."""

    def __init__(self, table: dict[str, str]) -> None:
        self._table = table

    async def get_arp_table(self) -> dict[str, str]:
        return self._table


_ARP_TABLE = {"192.168.1.2": "AA:BB:CC:DD:EE:01", "192.168.1.3": "AA:BB:CC:DD:EE:02"}


@pytest.fixture
def repo(tmp_path: Path) -> SqliteScanHistoryRepository:
    return SqliteScanHistoryRepository(tmp_path / "cernis.db", SystemClock())


def _wired_app(repo: SqliteScanHistoryRepository) -> FastAPI:
    vendor = VendorLookupAdapter()
    app = create_app(AppConfig())
    app.dependency_overrides[provide_get_scan_history] = lambda: GetScanHistory(repo)
    app.dependency_overrides[provide_get_scan_detail] = lambda: GetScanDetail(repo)
    app.dependency_overrides[provide_lookup_vendor] = lambda: LookupVendor(vendor)
    app.dependency_overrides[provide_get_arp_table] = lambda: GetArpTable(_FakeArpTable(_ARP_TABLE))
    return app


@pytest.fixture
def client(repo: SqliteScanHistoryRepository) -> Iterator[TestClient]:
    with TestClient(_wired_app(repo)) as test_client:
        yield test_client


# ── /api/history ─────────────────────────────────────────────────────────────


def test_history_lists_entries_without_blob(
    client: TestClient, repo: SqliteScanHistoryRepository
) -> None:
    repo.save(
        "192.168.1.0/24",
        (EnrichedHost(ip="192.168.1.2", mac="AA:BB:CC:DD:EE:01"),),
        PortInterception(),
    )
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
        source="arp",  # nicht-Default -> beweist source-Durchstich ueber REST (S.7f)
    )
    repo.save("10.0.0.0/24", (host,), PortInterception())
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
    assert got["source"] == "arp"  # Quelle auch ueber die REST-History sichtbar (S.7f)
    # tuples als JSON-Listen serialisiert:
    assert isinstance(got["tags"], list)
    assert isinstance(got["ipv6_all"], list)


def test_history_detail_unknown_returns_404(client: TestClient) -> None:
    assert client.get("/api/history/9999").status_code == 404


def test_history_detail_exposes_interception(
    client: TestClient, repo: SqliteScanHistoryRepository
) -> None:
    """Das Gegenproben-Ergebnis (Befund 53) ist ueber die REST-Schnittstelle abrufbar."""
    repo.save(
        "10.0.0.0/24",
        (),
        PortInterception(
            checked=True,
            control_ips=("10.0.0.1", "10.0.0.85", "10.0.0.170"),
            intercepted_ports=(25, 143),
        ),
    )
    scan_id = repo.list(20)[0].scan_id

    got = client.get(f"/api/history/{scan_id}").json()["interception"]
    assert got == {
        "checked": True,
        "control_ips": ["10.0.0.1", "10.0.0.85", "10.0.0.170"],
        "intercepted_ports": [25, 143],
        "reason": "",
    }


def test_history_detail_distinguishes_not_checked_from_nothing_found(
    client: TestClient, repo: SqliteScanHistoryRepository
) -> None:
    """Ueber die Schnittstelle bleibt "nicht geprueft" von "nichts gefunden" trennbar."""
    repo.save("10.0.0.0/24", (), PortInterception(checked=False, reason="Zu wenige Adressen."))
    not_checked_id = repo.list(20)[0].scan_id
    repo.save("10.0.1.0/24", (), PortInterception(checked=True, control_ips=("10.0.1.1",)))
    checked_id = repo.list(20)[0].scan_id

    not_checked = client.get(f"/api/history/{not_checked_id}").json()["interception"]
    checked = client.get(f"/api/history/{checked_id}").json()["interception"]

    # Beide melden eine leere Portliste -- der Unterschied steckt in ``checked``.
    assert not_checked["intercepted_ports"] == checked["intercepted_ports"] == []
    assert not_checked["checked"] is False
    assert not_checked["reason"] == "Zu wenige Adressen."
    assert checked["checked"] is True


# ── /api/vendor/{mac} ────────────────────────────────────────────────────────


def test_vendor_returns_mac_and_vendor(client: TestClient) -> None:
    body = client.get("/api/vendor/AA:BB:CC:DD:EE:01").json()
    assert body["mac"] == "AA:BB:CC:DD:EE:01"
    assert "vendor" in body  # leer oder gefunden -- beides gueltig (OUI-DB-abhaengig)


# ── /api/arp (S.7a, roher ARP-Cache als {ip: mac}) ──────────────────────────


def test_arp_returns_raw_ip_mac_map(client: TestClient) -> None:
    # Shape am S.1-Characterization-Contract: das rohe {ip: mac}-dict, KEINE Liste.
    resp = client.get("/api/arp")
    assert resp.status_code == 200
    assert resp.json() == _ARP_TABLE


def test_arp_empty_returns_empty_object(repo: SqliteScanHistoryRepository) -> None:
    # Leerer ARP-Cache -> {} (vertraglicher Leer-Zustand, kein Fehler).
    app = _wired_app(repo)
    app.dependency_overrides[provide_get_arp_table] = lambda: GetArpTable(_FakeArpTable({}))
    with TestClient(app) as test_client:
        resp = test_client.get("/api/arp")
        assert resp.status_code == 200
        assert resp.json() == {}
