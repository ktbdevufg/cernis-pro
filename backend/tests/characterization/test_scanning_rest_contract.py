"""Characterization-Contract der scanning-nahen REST-Endpunkte (Altcode main.py).

Netzwerk-/DB-frei: die Endpunkt-Funktionen werden auf eine FRISCHE App gehaengt
(``add_api_route``, keine main-Lifespan), ihre I/O-Helfer sind am main-Namespace
gemockt. Festgehalten werden die Response-Shapes von ``/api/arp``,
``/api/vendor/{mac}``, ``/api/history`` und ``/api/history/{id}`` (inkl. 404).
"""

from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import main

_HISTORY_ENTRY = {
    "id": 1,
    "scanned_at": "2026-05-28T12:00:00",
    "cidr": "192.168.1.0/24",
    "host_count": 3,
}
_SCAN_DETAIL = {
    "id": 1,
    "scanned_at": "2026-05-28T12:00:00",
    "cidr": "192.168.1.0/24",
    "host_count": 1,
    "hosts": [{"ip": "192.168.1.2", "mac": "AA:BB:CC:DD:EE:01"}],
}


@pytest.fixture
def rest_client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setattr(main, "get_arp_table", lambda: {"192.168.1.2": "AA:BB:CC:DD:EE:01"})
    monkeypatch.setattr(main, "lookup_vendor", lambda mac: "TestVendor")
    monkeypatch.setattr(main, "get_scan_history", lambda limit=20: [_HISTORY_ENTRY])

    def fake_get_scan_by_id(scan_id: int) -> dict[str, Any] | None:
        return _SCAN_DETAIL if scan_id == 1 else None

    monkeypatch.setattr(main, "get_scan_by_id", fake_get_scan_by_id)

    fresh = FastAPI()
    fresh.add_api_route("/api/arp", main.api_arp, methods=["GET"])
    fresh.add_api_route("/api/vendor/{mac}", main.api_vendor, methods=["GET"])
    fresh.add_api_route("/api/history", main.api_history, methods=["GET"])
    fresh.add_api_route("/api/history/{scan_id}", main.api_history_detail, methods=["GET"])
    return TestClient(fresh)


def test_get_arp_returns_ip_mac_map(rest_client: TestClient) -> None:
    resp = rest_client.get("/api/arp")
    assert resp.status_code == 200
    assert resp.json() == {"192.168.1.2": "AA:BB:CC:DD:EE:01"}


def test_get_vendor_returns_mac_and_vendor(rest_client: TestClient) -> None:
    resp = rest_client.get("/api/vendor/AA:BB:CC:DD:EE:01")
    assert resp.status_code == 200
    assert resp.json() == {"mac": "AA:BB:CC:DD:EE:01", "vendor": "TestVendor"}


def test_get_history_lists_entries(rest_client: TestClient) -> None:
    resp = rest_client.get("/api/history")
    assert resp.status_code == 200
    assert resp.json() == [_HISTORY_ENTRY]


def test_get_history_detail_returns_full_scan(rest_client: TestClient) -> None:
    resp = rest_client.get("/api/history/1")
    assert resp.status_code == 200
    assert resp.json()["hosts"] == [{"ip": "192.168.1.2", "mac": "AA:BB:CC:DD:EE:01"}]


def test_get_history_detail_unknown_returns_404(rest_client: TestClient) -> None:
    resp = rest_client.get("/api/history/999")
    assert resp.status_code == 404
