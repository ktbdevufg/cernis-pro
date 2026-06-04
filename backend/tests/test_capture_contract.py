"""Characterization-Contract der capture-nahen REST-Endpunkte (Altcode main.py).

Nagelt das HEUTIGE Verhalten der vom Frontend genutzten REST-Routen fest, BEVOR
die capture-Domaene (pcap, lldp) migriert wird. scapy wird NICHT beruehrt: die
Endpunkt-Funktionen werden auf eine FRISCHE App gehaengt (``add_api_route``,
keine main-Lifespan), die dahinterliegenden Modulfunktionen sind am
main-Namespace gemockt (Aliase aus den Modul-Imports in main.py). Damit laufen
die Tests ohne Raw-Socket/CAP_NET_RAW und ohne echtes scapy.

Charakterisiert: ``/api/pcap/{available,start,stop,status,packets,save}`` und
``/api/lldp/{neighbors,capture}``. Die toten Routen ``/api/pcap/download`` und
``/api/lldp/topology`` sowie der kaputte WS ``/ws/pcap`` werden bewusst NICHT
festgenagelt (werden in der Migration gestrichen bzw. als Neubau ersetzt).
"""

import asyncio
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import main


def _build_app() -> FastAPI:
    """Frische App mit genau den charakterisierten capture-Routen."""
    fresh = FastAPI()
    fresh.add_api_route("/api/lldp/neighbors", main.api_lldp_neighbors, methods=["GET"])
    fresh.add_api_route("/api/lldp/capture", main.api_lldp_capture, methods=["POST"])
    fresh.add_api_route("/api/pcap/available", main.api_pcap_available, methods=["GET"])
    fresh.add_api_route("/api/pcap/start", main.api_pcap_start, methods=["POST"])
    fresh.add_api_route("/api/pcap/stop", main.api_pcap_stop, methods=["POST"])
    fresh.add_api_route("/api/pcap/status", main.api_pcap_status, methods=["GET"])
    fresh.add_api_route("/api/pcap/packets", main.api_pcap_packets, methods=["GET"])
    fresh.add_api_route("/api/pcap/save", main.api_pcap_save, methods=["POST"])
    return fresh


@pytest.fixture
def client() -> TestClient:
    return TestClient(_build_app())


# ── pcap/available ────────────────────────────────────────────


def test_available_scapy_present_no_permission_error(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(main, "pcap_available", lambda: True)
    monkeypatch.setattr(main, "pcap_check_permission", lambda: None)
    resp = client.get("/api/pcap/available")
    assert resp.status_code == 200
    assert resp.json() == {"available": True, "permission_error": ""}


def test_available_scapy_present_with_permission_error(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(main, "pcap_available", lambda: True)
    monkeypatch.setattr(
        main, "pcap_check_permission", lambda: "Permission denied — needs CAP_NET_RAW"
    )
    resp = client.get("/api/pcap/available")
    assert resp.status_code == 200
    assert resp.json() == {
        "available": True,
        "permission_error": "Permission denied — needs CAP_NET_RAW",
    }


def test_available_scapy_missing(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main, "pcap_available", lambda: False)
    resp = client.get("/api/pcap/available")
    assert resp.status_code == 200
    body = resp.json()
    assert body["available"] is False
    # Substring statt Volltext: der mehrzeilige Hinweistext ist plattformabhaengig
    # (Linux-Zweig) und soll kein Wartungsklotz sein.
    assert "libpcap-dev" in body["permission_error"]


# ── pcap/start ────────────────────────────────────────────────


def test_start_success_appends_available_key(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def fake_start(interface: Any, bpf_filter: str, max_packets: int) -> dict[str, Any]:
        return {"ok": True, "error": ""}

    monkeypatch.setattr(main, "pcap_start", fake_start)
    monkeypatch.setattr(main, "pcap_available", lambda: True)
    resp = client.post("/api/pcap/start", json={})
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "error": "", "available": True}


def test_start_no_permission_returns_403_without_available_key(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def fake_start(interface: Any, bpf_filter: str, max_packets: int) -> dict[str, Any]:
        return {"ok": False, "error": "Permission denied — needs CAP_NET_RAW"}

    monkeypatch.setattr(main, "pcap_start", fake_start)
    monkeypatch.setattr(main, "pcap_available", lambda: True)
    resp = client.post("/api/pcap/start", json={})
    assert resp.status_code == 403
    # Body unveraendert durchgereicht, KEIN angehaengter "available"-Key.
    assert resp.json() == {"ok": False, "error": "Permission denied — needs CAP_NET_RAW"}


def test_start_defaults_passed_through(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    spy: dict[str, Any] = {}

    async def fake_start(interface: Any, bpf_filter: str, max_packets: int) -> dict[str, Any]:
        spy["interface"] = interface
        spy["bpf_filter"] = bpf_filter
        spy["max_packets"] = max_packets
        return {"ok": True, "error": ""}

    monkeypatch.setattr(main, "pcap_start", fake_start)
    monkeypatch.setattr(main, "pcap_available", lambda: True)
    resp = client.post("/api/pcap/start", json={})
    assert resp.status_code == 200
    # Leerer Body: interface ""→None, filter "", max_packets 5000.
    assert spy == {"interface": None, "bpf_filter": "", "max_packets": 5000}


# ── pcap/stop ─────────────────────────────────────────────────


def test_stop_always_ok_and_calls_pcap_stop(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    spy: dict[str, bool] = {"called": False}

    def fake_stop() -> None:
        spy["called"] = True

    monkeypatch.setattr(main, "pcap_stop", fake_stop)
    resp = client.post("/api/pcap/stop")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    # Auch ohne laufenden Capture wird pcap_stop() gerufen und 200 geliefert
    # (der Handler prueft keinen Zustand).
    assert spy["called"] is True


# ── pcap/status ───────────────────────────────────────────────


def test_status_passed_through_with_field_names(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    status_payload = {
        "running": True,
        "packets": 42,
        "stats": {"total_packets": 42, "total_bytes": 1024},
        "pcap_available": True,
        "pcap_path": "/tmp/cernis_capture_1.pcap",
        "error": "",
    }
    monkeypatch.setattr(main, "get_capture_status", lambda: status_payload)
    resp = client.get("/api/pcap/status")
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
    # AS-IS: _capture_error wird im Altcode nie gesetzt, totes Feld, Phase-4-Kandidat.
    assert body["error"] == ""


# ── pcap/packets ──────────────────────────────────────────────


def test_packets_passed_through_with_default_limit(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    spy: dict[str, int] = {}

    def fake_recent(limit: int) -> list[dict[str, Any]]:
        spy["limit"] = limit
        return [{"timestamp": 1.0, "protocol": "TCP"}]

    monkeypatch.setattr(main, "get_recent_packets", fake_recent)
    resp = client.get("/api/pcap/packets")
    assert resp.status_code == 200
    assert resp.json() == [{"timestamp": 1.0, "protocol": "TCP"}]
    # Default-Limit 100.
    assert spy["limit"] == 100


def test_packets_limit_passed_through(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    spy: dict[str, int] = {}

    def fake_recent(limit: int) -> list[dict[str, Any]]:
        spy["limit"] = limit
        return []

    monkeypatch.setattr(main, "get_recent_packets", fake_recent)
    resp = client.get("/api/pcap/packets", params={"limit": 250})
    assert resp.status_code == 200
    assert spy["limit"] == 250


def test_packets_limit_zero_rejected(client: TestClient) -> None:
    # Query-Constraint ge=1.
    resp = client.get("/api/pcap/packets", params={"limit": 0})
    assert resp.status_code == 422


def test_packets_limit_too_large_rejected(client: TestClient) -> None:
    # Query-Constraint le=1000.
    resp = client.get("/api/pcap/packets", params={"limit": 1001})
    assert resp.status_code == 422


# ── pcap/save ─────────────────────────────────────────────────


def test_save_no_capture_file_returns_404(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(main, "get_pcap_path", lambda: None)
    resp = client.post("/api/pcap/save")
    assert resp.status_code == 404
    assert resp.json() == {"error": "No capture file available. Start and stop a capture first."}


def test_save_with_capture_file_crashes_500(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    # AS-IS kaputt: save-Handler referenziert os, das nicht am main-Namespace
    # gebunden ist (Z.1508) -> live NameError/500 sobald eine Capture-Datei
    # existiert. Migration (C.4+5) heilt den os-Import sichtbar.
    # Phase-4-/Heilungs-Kandidat.
    src = tmp_path / "cernis_capture_1.pcap"
    src.write_bytes(b"\x00\x01\x02\x03")
    monkeypatch.setattr(main, "get_pcap_path", lambda: str(src))

    # raise_server_exceptions=False: die unbehandelte NameError-Exception als
    # 500-Response beobachten statt sie in den Test durchzureichen.
    crash_client = TestClient(_build_app(), raise_server_exceptions=False)
    resp = crash_client.post("/api/pcap/save")
    assert resp.status_code == 500


# ── lldp/neighbors ────────────────────────────────────────────


def test_lldp_neighbors_passed_through(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    neighbor = {
        "source_mac": "AA:BB:CC:DD:EE:01",
        "chassis_id": "switch-1",
        "port_id": "Gi0/1",
        "system_name": "core-switch",
        "system_desc": "managed switch",
        "port_desc": "",
        "protocol": "LLDP",
        "vlans": [],
        "capabilities": [],
        "mgmt_ip": "",
        "ttl": 120,
        "last_seen": 1000.0,
        "age_secs": 5,
        "expired": False,
    }
    monkeypatch.setattr(main, "lldp_neighbors", lambda: [neighbor])
    resp = client.get("/api/lldp/neighbors")
    assert resp.status_code == 200
    body = resp.json()
    assert body == [neighbor]
    # age_secs/expired werden von get_neighbors() ergaenzt und sind Teil des Vertrags.
    assert "age_secs" in body[0]
    assert "expired" in body[0]


# ── lldp/capture ──────────────────────────────────────────────


def test_lldp_capture_success_and_timeout_arg(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    neighbors = [{"source_mac": "AA:BB:CC:DD:EE:01", "protocol": "LLDP"}]

    async def fake_capture(interface: Any, duration: float) -> list[dict[str, Any]]:
        return neighbors

    monkeypatch.setattr(main, "lldp_capture", fake_capture)

    # asyncio.wait_for umhuellen, um timeout=duration+5 als Vertrag zu pruefen.
    spy: dict[str, Any] = {}
    real_wait_for = asyncio.wait_for

    async def spy_wait_for(awaitable: Any, timeout: float) -> Any:
        spy["timeout"] = timeout
        return await real_wait_for(awaitable, timeout=timeout)

    monkeypatch.setattr(main.asyncio, "wait_for", spy_wait_for)

    resp = client.post("/api/lldp/capture", json={})
    assert resp.status_code == 200
    assert resp.json() == neighbors
    # Defaults leerer Body: duration 30.0 → timeout 35.0.
    assert spy["timeout"] == 35.0


def test_lldp_capture_passes_interface_and_duration(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    spy: dict[str, Any] = {}

    async def fake_capture(interface: Any, duration: float) -> list[dict[str, Any]]:
        spy["interface"] = interface
        spy["duration"] = duration
        return []

    monkeypatch.setattr(main, "lldp_capture", fake_capture)
    resp = client.post("/api/lldp/capture", json={"interface": "", "duration": 10})
    assert resp.status_code == 200
    # interface ""→None, duration float-gecastet.
    assert spy == {"interface": None, "duration": 10.0}


def test_lldp_capture_error_returns_503(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def fake_capture(interface: Any, duration: float) -> list[dict[str, Any]]:
        raise RuntimeError("capture exploded")

    monkeypatch.setattr(main, "lldp_capture", fake_capture)
    resp = client.post("/api/lldp/capture", json={})
    assert resp.status_code == 503
    assert resp.json() == {"error": "capture exploded"}


def test_lldp_capture_timeout_returns_503(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def fake_capture(interface: Any, duration: float) -> list[dict[str, Any]]:
        return []

    monkeypatch.setattr(main, "lldp_capture", fake_capture)

    # wait_for synthetisch TimeoutError werfen lassen — KEIN reales Warten.
    async def boom_wait_for(awaitable: Any, timeout: float) -> Any:
        # Awaitable schliessen, um "never awaited"-Warnungen zu vermeiden.
        if asyncio.iscoroutine(awaitable):
            awaitable.close()
        raise TimeoutError

    monkeypatch.setattr(main.asyncio, "wait_for", boom_wait_for)
    resp = client.post("/api/lldp/capture", json={})
    assert resp.status_code == 503
    body = resp.json()
    assert "error" in body
