"""Characterization-Contract des WebSocket ``/ws/scan`` (Altcode ``main.ws_scan``).

Schreibt das Frame-Protokoll fest -- Sicherheitsnetz fuer die scanning-Migration.
Netzwerk- und DB-frei: die I/O-Funktionen sind gemockt, und der Handler laeuft
auf einer FRISCHEN App (``add_api_websocket_route``), damit KEINE main-Lifespan
(init_db/Monitor/Scheduler gegen die echte cernis.db) feuert.

Bewusst NICHT Teil des Contracts (timing-/config-abhaengig): die Reihenfolge der
``host_found``-Frames und die optionalen Frames (``info``/fritzbox/arp/mdns) --
hier durch Config (mdns/ssdp/resolve/smb aus) und Mocks (Fritz/ARP leer)
ausgeschlossen. Der ``discover_subnet``-Fake kodiert bewusst den ``progress_cb``-
Vertrag des Altcodes mit: ``on_progress(completed, total, host)``.
"""

from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import main
from modules import discovery
from modules.discovery import DiscoveredHost

_CONFIG = {
    "cidr": "192.168.1.0/30",
    "port_scan": False,
    "mdns_scan": False,
    "ssdp_scan": False,
    "resolve_hostnames": False,
    "smb_scan": False,
}


@pytest.fixture
def ws_client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    async def fake_discover_subnet(
        cidr: str,
        max_concurrent: int = 64,
        timeout: float = 1.0,
        progress_cb: Any = None,
    ) -> list[Any]:
        # Kodiert den progress_cb-Vertrag des Altcodes mit: ein lebender Host,
        # genau ein on_progress(completed, total, host)-Aufruf.
        host = DiscoveredHost(ip="192.168.1.2", mac="AA:BB:CC:DD:EE:01", rtt_ms=1.0, is_alive=True)
        if progress_cb is not None:
            await progress_cb(1, 1, host)
        return [host]

    monkeypatch.setattr(main, "discover_subnet", fake_discover_subnet)
    monkeypatch.setattr(main, "get_known_devices", lambda: [])
    monkeypatch.setattr(main, "lookup_vendor", lambda mac: "TestVendor")
    monkeypatch.setattr(main, "get_setting", lambda key, default=None: None)
    monkeypatch.setattr(main, "decrypt", lambda value: "")
    monkeypatch.setattr(discovery, "get_arp_table", lambda: {})
    monkeypatch.setattr(main, "update_device_from_scan", lambda host: None)
    monkeypatch.setattr(main, "enrich_with_ipv6", lambda hosts: hosts)
    monkeypatch.setattr(main, "save_scan", lambda cidr, hosts: None)

    fresh = FastAPI()
    fresh.add_api_websocket_route("/ws/scan", main.ws_scan)
    return TestClient(fresh)


_EXPECTED_TYPES = [
    "scan_started",
    "phase",
    "host_found",
    "progress",
    "phase",
    "phase",
    "host_detail",
    "progress",
    "scan_complete",
]

_HOST_DETAIL_KEYS = {
    "type",
    "ip",
    "mac",
    "vendor",
    "rtt_ms",
    "hostname",
    "smb_name",
    "smb_domain",
    "os_guess",
    "os_accuracy",
    "scan_method",
    "ports",
    "mdns_services",
    "ssdp_services",
    "is_ndi",
    "is_unknown",
    "category",
    "label",
    "tags",
    "notes",
}


def test_ws_scan_frame_sequence_and_shapes(ws_client: TestClient) -> None:
    with ws_client.websocket_connect("/ws/scan") as ws:
        ws.send_json(_CONFIG)
        frames = [ws.receive_json() for _ in range(9)]

    assert [f["type"] for f in frames] == _EXPECTED_TYPES

    (
        scan_started,
        disc_running,
        host_found,
        disc_progress,
        disc_done,
        enrich_running,
        host_detail,
        enrich_progress,
        scan_complete,
    ) = frames

    assert scan_started == {"type": "scan_started", "cidr": "192.168.1.0/30", "total_hosts": 2}
    assert disc_running == {
        "type": "phase",
        "phase": "discovery",
        "status": "running",
        "total": 2,
    }
    assert host_found == {
        "type": "host_found",
        "ip": "192.168.1.2",
        "rtt_ms": 1.0,
        "mac": "AA:BB:CC:DD:EE:01",
        "vendor": "TestVendor",
        "is_unknown": True,
    }
    assert disc_progress == {
        "type": "progress",
        "phase": "discovery",
        "completed": 1,
        "total": 1,
        "pct": 100,
    }
    assert disc_done == {
        "type": "phase",
        "phase": "discovery",
        "status": "done",
        "alive_count": 1,
    }
    assert enrich_running == {
        "type": "phase",
        "phase": "enrich",
        "status": "running",
        "total": 1,
    }
    assert set(host_detail.keys()) == _HOST_DETAIL_KEYS
    assert host_detail["ip"] == "192.168.1.2"
    assert host_detail["mac"] == "AA:BB:CC:DD:EE:01"
    assert host_detail["vendor"] == "TestVendor"
    assert host_detail["ports"] == []
    assert host_detail["category"] == "unknown"
    assert host_detail["os_guess"] == ""
    assert host_detail["is_unknown"] is True
    assert enrich_progress == {
        "type": "progress",
        "phase": "enrich",
        "completed": 1,
        "total": 1,
        "pct": 100,
    }
    assert scan_complete == {"type": "scan_complete", "total_found": 1}


def test_ws_scan_invalid_json_yields_error(ws_client: TestClient) -> None:
    with ws_client.websocket_connect("/ws/scan") as ws:
        ws.send_text("kein json {")
        frame = ws.receive_json()
    assert frame["type"] == "error"
    assert "message" in frame


def test_ws_scan_invalid_cidr_yields_error(ws_client: TestClient) -> None:
    with ws_client.websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "nonsense"})
        frame = ws.receive_json()
    assert frame["type"] == "error"
    assert "Invalid CIDR" in frame["message"]
