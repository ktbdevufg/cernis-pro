"""End-to-end-Tests der capture-REST-API (v2, C.4+5) gegen den capture_router.

Frische ``FastAPI`` mit nur dem ``capture_router``; die ``provide_*`` werden per
``dependency_overrides`` mit Fakes/echten-Use-Cases-auf-Fake-Ports verdrahtet (kein
scapy, kein Raw-Socket). Belegt die v2-Wire-Shapes -- 1:1 zum C.0-Contract als
RegressionSSCHUTZ, AUSSER der EINEN Heilung:

* ``/api/pcap/save`` liefert bei vorhandener pcap jetzt 200 ``{ok, path, size}``
  (Altcode: 500 os-NameError). Der C.0-Test bleibt unangetastet (friert v1 ein);
  diese geheilte Form lebt HIER.

Alle anderen Routen muessen formgleich zum C.0-Contract bleiben (Regressionsnetz).
"""

from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.capture import (
    provide_build_topology,
    provide_capture_lldp,
    provide_capture_status,
    provide_get_lldp_neighbors,
    provide_pcap_path,
    provide_recent_packets,
    provide_save_dir,
    provide_start_capture,
    provide_start_capture_uc,
    provide_stop_capture,
)
from api.capture import router as capture_router
from application.capture import BuildTopology, CaptureLldp, GetLldpNeighbors, StartCapture
from domain.capture import LLDPNeighbor, PacketSummary

# ── Fakes ────────────────────────────────────────────────────────────────────


class _FakeSnifferForStart:
    """PacketSnifferPort-Fake fuer StartCapture -- nur ``is_available``/``check_permission``
    sind relevant; die uebrigen Port-Methoden sind Stubs (vollstaendiges Protocol fuer mypy)."""

    def __init__(self, available: bool = True, permission: str | None = None) -> None:
        self._available = available
        self._permission = permission

    def is_available(self) -> bool:
        return self._available

    def check_permission(self) -> str | None:
        return self._permission

    def stream(
        self, interface: str | None, bpf_filter: str, max_packets: int
    ) -> AsyncIterator[PacketSummary]:
        raise NotImplementedError

    def stop(self) -> None: ...

    def is_running(self) -> bool:
        return False

    def export_pcap(self, path: str) -> bool:
        return False


class _FakeLldpSniffer:
    """LldpSnifferPort-Fake fuer CaptureLldp: feste Runde oder Exception/Timeout."""

    def __init__(
        self, neighbors: list[LLDPNeighbor] | None = None, error: Exception | None = None
    ) -> None:
        self._neighbors = neighbors or []
        self._error = error

    async def capture(self, interface: str | None, duration: float) -> list[LLDPNeighbor]:
        if self._error is not None:
            raise self._error
        return self._neighbors


def _build_app() -> FastAPI:
    app = FastAPI()
    app.include_router(capture_router)
    return app


# ── pcap/available ────────────────────────────────────────────────────────────


def test_available_present_no_permission_error() -> None:
    app = _build_app()
    app.dependency_overrides[provide_start_capture_uc] = lambda: StartCapture(
        _FakeSnifferForStart(available=True, permission=None)
    )
    resp = TestClient(app).get("/api/pcap/available")
    assert resp.status_code == 200
    assert resp.json() == {"available": True, "permission_error": ""}


def test_available_present_with_permission_error() -> None:
    app = _build_app()
    app.dependency_overrides[provide_start_capture_uc] = lambda: StartCapture(
        _FakeSnifferForStart(available=True, permission="needs CAP_NET_RAW")
    )
    resp = TestClient(app).get("/api/pcap/available")
    assert resp.status_code == 200
    assert resp.json() == {"available": True, "permission_error": "needs CAP_NET_RAW"}


def test_available_scapy_missing() -> None:
    app = _build_app()
    app.dependency_overrides[provide_start_capture_uc] = lambda: StartCapture(
        _FakeSnifferForStart(available=False)
    )
    resp = TestClient(app).get("/api/pcap/available")
    assert resp.status_code == 200
    body = resp.json()
    assert body["available"] is False
    assert "libpcap" in body["permission_error"]


# ── pcap/start ────────────────────────────────────────────────────────────────


def test_start_success_appends_available_key() -> None:
    app = _build_app()
    app.dependency_overrides[provide_start_capture] = lambda: (
        lambda interface, bpf_filter, max_packets: {"ok": True, "error": ""}
    )
    app.dependency_overrides[provide_start_capture_uc] = lambda: StartCapture(
        _FakeSnifferForStart(available=True)
    )
    resp = TestClient(app).post("/api/pcap/start", json={})
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "error": "", "available": True}


def test_start_no_permission_returns_403_without_available_key() -> None:
    app = _build_app()
    app.dependency_overrides[provide_start_capture] = lambda: (
        lambda interface, bpf_filter, max_packets: {
            "ok": False,
            "error": "Permission denied -- needs CAP_NET_RAW",
        }
    )
    app.dependency_overrides[provide_start_capture_uc] = lambda: StartCapture(
        _FakeSnifferForStart(available=True)
    )
    resp = TestClient(app).post("/api/pcap/start", json={})
    assert resp.status_code == 403
    # KEIN angehaengter "available"-Key (exakt wie C.0).
    assert resp.json() == {"ok": False, "error": "Permission denied -- needs CAP_NET_RAW"}


def test_start_defaults_passed_through() -> None:
    spy: dict[str, Any] = {}

    def fake_start(interface: str | None, bpf_filter: str, max_packets: int) -> dict[str, Any]:
        spy["interface"] = interface
        spy["bpf_filter"] = bpf_filter
        spy["max_packets"] = max_packets
        return {"ok": True, "error": ""}

    app = _build_app()
    app.dependency_overrides[provide_start_capture] = lambda: fake_start
    app.dependency_overrides[provide_start_capture_uc] = lambda: StartCapture(
        _FakeSnifferForStart(available=True)
    )
    resp = TestClient(app).post("/api/pcap/start", json={})
    assert resp.status_code == 200
    # Leerer Body: interface ""->None, filter "", max_packets 5000.
    assert spy == {"interface": None, "bpf_filter": "", "max_packets": 5000}


# ── pcap/stop ─────────────────────────────────────────────────────────────────


def test_stop_always_ok_and_calls_stop() -> None:
    spy = {"called": False}
    app = _build_app()
    app.dependency_overrides[provide_stop_capture] = lambda: lambda: spy.__setitem__("called", True)
    resp = TestClient(app).post("/api/pcap/stop")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    assert spy["called"] is True


# ── pcap/status ───────────────────────────────────────────────────────────────


def test_status_fields_and_error_empty() -> None:
    status_payload = {
        "running": True,
        "packets": 42,
        "stats": {"total_packets": 42, "total_bytes": 1024},
        "pcap_available": True,
        "pcap_path": "/tmp/cernis_capture.pcap",
        "error": "",
    }
    app = _build_app()
    app.dependency_overrides[provide_capture_status] = lambda: lambda now: status_payload
    resp = TestClient(app).get("/api/pcap/status")
    assert resp.status_code == 200
    body = resp.json()
    assert set(body.keys()) == {
        "running",
        "packets",
        "stats",
        "pcap_available",
        "pcap_path",
        "error",
    }
    assert body["error"] == ""


# ── pcap/packets ──────────────────────────────────────────────────────────────


def test_packets_default_limit_and_wire_form() -> None:
    spy: dict[str, int] = {}

    def fake_recent(limit: int) -> list[PacketSummary]:
        spy["limit"] = limit
        return [PacketSummary(timestamp=1.0, protocol="TCP", dst_port=80)]

    app = _build_app()
    app.dependency_overrides[provide_recent_packets] = lambda: fake_recent
    resp = TestClient(app).get("/api/pcap/packets")
    assert resp.status_code == 200
    body = resp.json()
    assert spy["limit"] == 100
    # Wire-Form: voller PacketSummary-Feldsatz.
    assert body[0]["protocol"] == "TCP"
    assert body[0]["dst_port"] == 80
    assert set(body[0].keys()) == {
        "timestamp",
        "src_ip",
        "dst_ip",
        "src_mac",
        "dst_mac",
        "protocol",
        "src_port",
        "dst_port",
        "length",
        "info",
        "is_ipv6",
    }


def test_packets_limit_passed_through() -> None:
    spy: dict[str, int] = {}

    def fake_recent(limit: int) -> list[PacketSummary]:
        spy["limit"] = limit
        return []

    app = _build_app()
    app.dependency_overrides[provide_recent_packets] = lambda: fake_recent
    resp = TestClient(app).get("/api/pcap/packets", params={"limit": 250})
    assert resp.status_code == 200
    assert spy["limit"] == 250


def test_packets_limit_zero_rejected() -> None:
    app = _build_app()
    app.dependency_overrides[provide_recent_packets] = lambda: lambda limit: []
    resp = TestClient(app).get("/api/pcap/packets", params={"limit": 0})
    assert resp.status_code == 422


def test_packets_limit_too_large_rejected() -> None:
    app = _build_app()
    app.dependency_overrides[provide_recent_packets] = lambda: lambda limit: []
    resp = TestClient(app).get("/api/pcap/packets", params={"limit": 1001})
    assert resp.status_code == 422


# ── pcap/save (die GEHEILTE Route) ──────────────────────────────────────────────


def test_save_no_capture_file_returns_404() -> None:
    app = _build_app()
    app.dependency_overrides[provide_pcap_path] = lambda: lambda: None
    app.dependency_overrides[provide_save_dir] = lambda: lambda: Path("/tmp")
    resp = TestClient(app).post("/api/pcap/save")
    assert resp.status_code == 404
    assert resp.json() == {"error": "No capture file available. Start and stop a capture first."}


def test_save_with_capture_file_returns_200_healed(tmp_path: Path) -> None:
    # GEHEILT (C.0 fror hier 500 ein): vorhandene pcap -> 200 {ok, path, size}.
    src = tmp_path / "cernis_capture.pcap"
    src.write_bytes(b"\x00\x01\x02\x03")
    dest_dir = tmp_path / "Downloads"
    dest_dir.mkdir()

    app = _build_app()
    app.dependency_overrides[provide_pcap_path] = lambda: lambda: str(src)
    app.dependency_overrides[provide_save_dir] = lambda: lambda: dest_dir
    resp = TestClient(app).post("/api/pcap/save")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["path"] == str(dest_dir / "cernis_capture.pcap")
    assert body["size"] == 4
    # Datei wurde wirklich kopiert.
    assert (dest_dir / "cernis_capture.pcap").read_bytes() == b"\x00\x01\x02\x03"


# ── lldp/neighbors ──────────────────────────────────────────────────────────────


def test_lldp_neighbors_enriched_with_age_and_expired() -> None:
    # last_seen weit in der Vergangenheit -> expired True, age_secs > ttl.
    neighbor = LLDPNeighbor(
        source_mac="AA:BB:CC:DD:EE:01",
        chassis_id="switch-1",
        system_name="core-switch",
        ttl=120,
        last_seen=0.0,
    )
    capture_lldp = CaptureLldp(_FakeLldpSniffer())
    capture_lldp._neighbors["AA:BB:CC:DD:EE:01"] = neighbor

    app = _build_app()
    app.dependency_overrides[provide_get_lldp_neighbors] = lambda: GetLldpNeighbors(capture_lldp)
    resp = TestClient(app).get("/api/lldp/neighbors")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    entry = body[0]
    assert entry["source_mac"] == "AA:BB:CC:DD:EE:01"
    # age_secs/expired sind Teil des Vertrags (am Rand angereichert).
    assert "age_secs" in entry
    assert "expired" in entry
    assert entry["expired"] is True  # last_seen=0 -> uralt -> expired


# ── lldp/capture ────────────────────────────────────────────────────────────────


def test_lldp_capture_success_returns_neighbors() -> None:
    n = LLDPNeighbor(source_mac="AA:BB:CC:DD:EE:01", protocol="LLDP")
    capture_lldp = CaptureLldp(_FakeLldpSniffer(neighbors=[n]))
    app = _build_app()
    app.dependency_overrides[provide_capture_lldp] = lambda: capture_lldp
    resp = TestClient(app).post("/api/lldp/capture", json={})
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    assert body[0]["source_mac"] == "AA:BB:CC:DD:EE:01"
    assert body[0]["protocol"] == "LLDP"


def test_lldp_capture_interface_empty_to_none_and_duration() -> None:
    spy: dict[str, Any] = {}

    class _SpySniffer:
        async def capture(self, interface: str | None, duration: float) -> list[LLDPNeighbor]:
            spy["interface"] = interface
            spy["duration"] = duration
            return []

    app = _build_app()
    app.dependency_overrides[provide_capture_lldp] = lambda: CaptureLldp(_SpySniffer())
    resp = TestClient(app).post("/api/lldp/capture", json={"interface": "", "duration": 10})
    assert resp.status_code == 200
    assert spy == {"interface": None, "duration": 10.0}


def test_lldp_capture_error_returns_503() -> None:
    capture_lldp = CaptureLldp(_FakeLldpSniffer(error=RuntimeError("capture exploded")))
    app = _build_app()
    app.dependency_overrides[provide_capture_lldp] = lambda: capture_lldp
    resp = TestClient(app).post("/api/lldp/capture", json={})
    assert resp.status_code == 503
    assert resp.json() == {"error": "capture exploded"}


def test_lldp_capture_timeout_returns_503(monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    capture_lldp = CaptureLldp(_FakeLldpSniffer(neighbors=[]))
    app = _build_app()
    app.dependency_overrides[provide_capture_lldp] = lambda: capture_lldp

    async def boom_wait_for(awaitable: Any, timeout: float) -> Any:
        # awaitable schliessen (vermeidet "never awaited"-Warnung), dann Timeout werfen.
        if asyncio.iscoroutine(awaitable):
            awaitable.close()
        raise TimeoutError

    # String-Target: patcht ``wait_for`` am Modul-``asyncio`` von api.capture (das es
    # top-level importiert) -- mypy-sauber, kein Modul-Attribut-Zugriff im Test.
    monkeypatch.setattr("api.capture.asyncio.wait_for", boom_wait_for)
    resp = TestClient(app).post("/api/lldp/capture", json={})
    assert resp.status_code == 503
    assert "error" in resp.json()


# ── topology ──────────────────────────────────────────────────────────────────


def _topology_uc(
    hosts: list[dict[str, str]], neighbors: list[dict[str, str]], gateway_ip: str
) -> BuildTopology:
    """BuildTopology mit drei In-Memory-Providern (kein I/O, async-Gateway)."""

    async def _gateway() -> str:
        return gateway_ip

    return BuildTopology(lambda: hosts, lambda: neighbors, _gateway)


def _topology_factory(
    hosts: list[dict[str, str]], neighbors: list[dict[str, str]], gateway_ip: str
) -> object:
    """Factory-Override (Muster app.py): liefert quellen-UNABHAENGIG denselben
    Use-Case -- der ``source``-Param wird durchgereicht, aber im Test ignoriert
    (die Quelle-Unterscheidung lebt im Composition Root, nicht hier)."""
    uc = _topology_uc(hosts, neighbors, gateway_ip)
    return lambda _source: uc


def test_topology_empty_returns_empty_graph() -> None:
    app = _build_app()
    app.dependency_overrides[provide_build_topology] = lambda: _topology_factory(
        [], [], "192.168.1.1"
    )
    resp = TestClient(app).get("/api/topology")
    assert resp.status_code == 200
    assert resp.json() == {"nodes": [], "edges": []}


def test_topology_default_source_is_last_scan() -> None:
    """Ohne ``?source`` waehlt der Endpunkt ``last_scan`` -- die Factory bekommt
    genau diesen Wert hereingereicht (Default-Vertrag des Auftrags)."""
    app = _build_app()
    gesehen: list[str] = []

    def _factory() -> object:
        uc = _topology_uc([], [], "192.168.1.1")

        def _for(source: str) -> BuildTopology:
            gesehen.append(source)
            return uc

        return _for

    app.dependency_overrides[provide_build_topology] = _factory
    resp = TestClient(app).get("/api/topology")
    assert resp.status_code == 200
    assert gesehen == ["last_scan"]


def test_topology_explicit_all_known_source() -> None:
    """``?source=all_known`` wird an die Factory durchgereicht."""
    app = _build_app()
    gesehen: list[str] = []

    def _factory() -> object:
        uc = _topology_uc([], [], "192.168.1.1")

        def _for(source: str) -> BuildTopology:
            gesehen.append(source)
            return uc

        return _for

    app.dependency_overrides[provide_build_topology] = _factory
    resp = TestClient(app).get("/api/topology?source=all_known")
    assert resp.status_code == 200
    assert gesehen == ["all_known"]


def test_topology_invalid_source_returns_422() -> None:
    """Ein ungueltiger ``source`` -> 422 (FastAPI-``Literal``-Validierung)."""
    app = _build_app()
    app.dependency_overrides[provide_build_topology] = lambda: _topology_factory(
        [], [], "192.168.1.1"
    )
    resp = TestClient(app).get("/api/topology?source=bogus")
    assert resp.status_code == 422


def test_topology_marks_gateway_and_assumed_edges() -> None:
    hosts = [
        {"mac": "AA:AA:AA:AA:AA:01", "ip": "192.168.1.1", "hostname": "gw", "vendor": "AVM"},
        {"mac": "AA:AA:AA:AA:AA:02", "ip": "192.168.1.2", "hostname": "pc", "vendor": "Dell"},
    ]
    app = _build_app()
    app.dependency_overrides[provide_build_topology] = lambda: _topology_factory(
        hosts, [], "192.168.1.1"
    )
    resp = TestClient(app).get("/api/topology")
    assert resp.status_code == 200
    body = resp.json()
    by_id = {n["id"]: n for n in body["nodes"]}
    assert by_id["AA:AA:AA:AA:AA:01"]["type"] == "gateway"
    assert by_id["AA:AA:AA:AA:AA:02"]["type"] == "host"
    # Der Nicht-Gateway-Host bekommt eine gestrichelte (assumed) Sternkante.
    assert body["edges"] == [
        {"source": "AA:AA:AA:AA:AA:02", "target": "AA:AA:AA:AA:AA:01", "kind": "assumed"}
    ]


def test_topology_measured_edge_wire_shape() -> None:
    hosts = [
        {"mac": "AA:AA:AA:AA:AA:01", "ip": "192.168.1.1", "hostname": "gw", "vendor": ""},
        {"mac": "BB:BB:BB:BB:BB:02", "ip": "192.168.1.2", "hostname": "pc", "vendor": ""},
    ]
    neighbors = [
        {"source_mac": "BB:BB:BB:BB:BB:02", "chassis_id": "switch-1", "system_desc": "switch"}
    ]
    app = _build_app()
    app.dependency_overrides[provide_build_topology] = lambda: _topology_factory(
        hosts, neighbors, "192.168.1.1"
    )
    body = TestClient(app).get("/api/topology").json()
    kinds = {e["kind"] for e in body["edges"]}
    assert "measured" in kinds
    measured = next(e for e in body["edges"] if e["kind"] == "measured")
    assert measured == {"source": "BB:BB:BB:BB:BB:02", "target": "switch-1", "kind": "measured"}
    # Switch-Knoten traegt die Wire-Felder (description/port/protocol vorhanden).
    switch = next(n for n in body["nodes"] if n["id"] == "switch-1")
    assert switch["type"] == "switch"
    assert {"description", "port", "protocol"} <= switch.keys()
