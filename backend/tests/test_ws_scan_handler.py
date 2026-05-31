"""Tests fuer den ``/ws/scan``-Handler (S.6, Composition Root ``ws_scan.py``).

Der Handler wird mit einer Fake-``RunNetworkScan``-Factory auf eine FRISCHE
FastAPI-App gehaengt (``add_api_websocket_route``) -- KEINE app.py-Lifespan, kein
echtes Netz. Geprueft wird die Event->Frame-Uebersetzung (am S.1-Contract) und der
Fehlerpfad (NmapScanError/FritzAuthError -> error-Frame statt Abbruch).

``ws_scan.py`` liegt im Composition Root (darf domain/infrastructure importieren);
der Test darf das ebenfalls -- er ist kein Ring-Modul.
"""

from collections.abc import AsyncIterator
from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient

from domain.scanning import (
    EnrichedHost,
    HostEnriched,
    HostFound,
    PhaseChanged,
    PortInfo,
    Progress,
    ScanCompleted,
    ScanEvent,
    ScanStarted,
)
from infrastructure.scanning.fritz_hosts import FritzAuthError
from infrastructure.scanning.port_scanner import NmapScanError
from ws_scan import make_ws_scan


class _FakeRunNetworkScan:
    """Yieldet eine vorgegebene Event-Liste (oder wirft am Ende eine Exception)."""

    def __init__(self, events: list[ScanEvent], raise_at_end: Exception | None = None) -> None:
        self._events = events
        self._raise_at_end = raise_at_end

    async def run(self, config: Any) -> AsyncIterator[ScanEvent]:
        for event in self._events:
            yield event
        if self._raise_at_end is not None:
            raise self._raise_at_end


def _client(events: list[ScanEvent], raise_at_end: Exception | None = None) -> TestClient:
    app = FastAPI()
    app.add_api_websocket_route(
        "/ws/scan",
        make_ws_scan(lambda: _FakeRunNetworkScan(events, raise_at_end)),
    )
    return TestClient(app)


# ── Volle 9-Frame-Sequenz (S.1-Contract) ───────────────────────────────────


def test_full_frame_sequence_matches_s1_contract() -> None:
    host = EnrichedHost(
        ip="192.168.1.2",
        mac="AA:BB:CC:DD:EE:01",
        vendor="TestVendor",
        rtt_ms=1.0,
        is_unknown=True,
        category="unknown",
    )
    events: list[ScanEvent] = [
        ScanStarted(cidr="192.168.1.0/30", total_hosts=2),
        PhaseChanged(phase="discovery", status="running", total=2),
        HostFound(
            ip="192.168.1.2",
            mac="AA:BB:CC:DD:EE:01",
            vendor="TestVendor",
            rtt_ms=1.0,
            is_unknown=True,
            source="ping",
        ),
        Progress(phase="discovery", completed=1, total=1, pct=100),
        PhaseChanged(phase="discovery", status="done", alive_count=1),
        PhaseChanged(phase="enrich", status="running", total=1),
        HostEnriched(host=host),
        Progress(phase="enrich", completed=1, total=1, pct=100),
        ScanCompleted(total_found=1),
    ]
    with _client(events).websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "192.168.1.0/30"})
        frames = [ws.receive_json() for _ in range(9)]

    assert [f["type"] for f in frames] == [
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
    assert frames[0] == {"type": "scan_started", "cidr": "192.168.1.0/30", "total_hosts": 2}
    assert frames[1] == {"type": "phase", "phase": "discovery", "status": "running", "total": 2}
    # host_found OHNE source-Feld (S.1-Contract-Shape).
    assert frames[2] == {
        "type": "host_found",
        "ip": "192.168.1.2",
        "rtt_ms": 1.0,
        "mac": "AA:BB:CC:DD:EE:01",
        "vendor": "TestVendor",
        "is_unknown": True,
    }
    assert frames[4] == {
        "type": "phase",
        "phase": "discovery",
        "status": "done",
        "alive_count": 1,
    }
    assert frames[8] == {"type": "scan_complete", "total_found": 1}


def test_host_detail_frame_has_20_keys() -> None:
    host = EnrichedHost(
        ip="10.0.0.5",
        mac="AA:BB:CC:DD:EE:02",
        ports=(PortInfo(port=22, state="open", service="ssh"),),
        category="server",
    )
    with _client([HostEnriched(host=host)]).websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "10.0.0.0/30"})
        frame = ws.receive_json()

    assert frame["type"] == "host_detail"
    assert set(frame.keys()) == {
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
    assert frame["ports"] == [{"port": 22, "state": "open", "service": "ssh"}]
    assert frame["category"] == "server"


# ── Invalid-CIDR -> error-Frame (ScanConfig.__post_init__ wirft ValueError) ──


def test_invalid_cidr_yields_error_frame() -> None:
    with _client([]).websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "nonsense"})
        frame = ws.receive_json()
    assert frame["type"] == "error"
    assert "Invalid CIDR" in frame["message"]


# ── Adapter-Exceptions -> error-Frame statt Abbruch (S.6-Merkposten 2) ──────


def test_nmap_scan_error_yields_error_frame() -> None:
    # Erst ein paar Frames, dann wirft der Generator NmapScanError.
    events: list[ScanEvent] = [
        ScanStarted(cidr="10.0.0.0/30", total_hosts=2),
        PhaseChanged(phase="discovery", status="running", total=2),
    ]
    client = _client(events, raise_at_end=NmapScanError("10.0.0.5", "nmap_timeout"))
    with client.websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "10.0.0.0/30"})
        frames = [ws.receive_json() for _ in range(3)]  # 2 + error

    assert frames[0]["type"] == "scan_started"
    assert frames[2]["type"] == "error"
    assert "nmap_timeout" in frames[2]["message"]


def test_fritz_auth_error_yields_error_frame() -> None:
    client = _client([], raise_at_end=FritzAuthError("fritz.box"))
    with client.websocket_connect("/ws/scan") as ws:
        ws.send_json({"cidr": "10.0.0.0/30"})
        frame = ws.receive_json()
    assert frame["type"] == "error"
    assert "fritz.box" in frame["message"]
