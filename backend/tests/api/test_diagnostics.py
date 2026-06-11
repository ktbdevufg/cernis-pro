"""End-to-end-Tests des diagnostics-Routers (1a) gegen app.py via TestClient.

Belegt: ``GET /api/diagnostics/dns`` serialisiert das ``DnsResult`` (mit wiederholbarem
``types``-Default), ``GET /api/diagnostics/traceroute`` das ``TracerouteResult`` (inkl.
nicht-antwortendem Hop als ``null``-Luecke), ``privileged`` ist Pflicht -> fehlend ergibt
422. ``GET /api/diagnostics/traceroute/permission`` liefert die ``{ok, error}``-Naht. Die
Tool-fehlt-Naht (``DiagnosticsToolMissing`` -> 503) wird ueber einen Fake-Runner belegt,
der die infra-Exception wirft (der globale exception_handler im Composition Root mappt).
Runner via ``dependency_overrides`` durch Fakes ersetzt -- kein echtes dig/traceroute.
"""

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.diagnostics import (
    provide_check_dhcp_permission,
    provide_check_external,
    provide_check_tools,
    provide_check_traceroute_permission,
    provide_detect_rogue_dhcp,
    provide_grab_banner,
    provide_resolve_dns,
    provide_run_traceroute,
)
from app import create_app
from application.diagnostics import RogueDhcpPermissionError
from domain.diagnostics import (
    BannerResult,
    DhcpServer,
    DnsRecord,
    DnsResult,
    ExternalCheckResult,
    ExternalPortResult,
    RogueDhcpResult,
    ToolReport,
    ToolStatus,
    TracerouteHop,
    TracerouteResult,
)
from infrastructure.config import AppConfig
from infrastructure.diagnostics_linux import DiagnosticsToolMissing, ExternalCheckFailed


@pytest.fixture
def app() -> Iterator[FastAPI]:
    yield create_app(AppConfig())


class _FakePermission:
    """In-Memory-Stand-in fuer CheckTraceroutePermission ({ok, error}-Naht)."""

    def __init__(self, ok: bool, error: str) -> None:
        self._ok = ok
        self._error = error

    def __call__(self) -> dict[str, object]:
        return {"ok": self._ok, "error": self._error}


# ── DNS ──────────────────────────────────────────────────────────────────────


def test_dns_wire_form_default_types(app: FastAPI) -> None:
    """Ohne ``types`` greift der Default; die Records erscheinen serialisiert."""

    result = DnsResult(
        query="example.com",
        requested_types=("A", "AAAA", "PTR"),
        records=(DnsRecord(record_type="A", value="1.2.3.4"),),
    )
    seen: dict[str, Any] = {}

    async def _fake_resolve(query: str, types: list[str]) -> Any:
        seen["query"] = query
        seen["types"] = types
        return result

    app.dependency_overrides[provide_resolve_dns] = lambda: _fake_resolve

    with TestClient(app) as client:
        response = client.get("/api/diagnostics/dns", params={"query": "example.com"})

    assert response.status_code == 200
    # Default-Typen kamen am Runner an (wiederholbarer Query-Param, Default A/AAAA/PTR).
    assert seen["types"] == ["A", "AAAA", "PTR"]
    body = response.json()
    assert body == {
        "query": "example.com",
        "requested_types": ["A", "AAAA", "PTR"],
        "records": [{"record_type": "A", "value": "1.2.3.4"}],
    }


def test_dns_repeatable_types(app: FastAPI) -> None:
    """``?types=A&types=MX`` kommt als Liste am Runner an."""

    result = DnsResult(query="example.com", requested_types=("A", "MX"), records=())
    seen: dict[str, Any] = {}

    async def _fake_resolve(query: str, types: list[str]) -> Any:
        seen["types"] = types
        return result

    app.dependency_overrides[provide_resolve_dns] = lambda: _fake_resolve

    with TestClient(app) as client:
        response = client.get(
            "/api/diagnostics/dns",
            params=[("query", "example.com"), ("types", "A"), ("types", "MX")],
        )

    assert response.status_code == 200
    assert seen["types"] == ["A", "MX"]
    # Leere Antwort ist kein Fehler -- records []
    assert response.json()["records"] == []


def test_dns_tool_missing_maps_to_503(app: FastAPI) -> None:
    """Fehlt ``dig``, wirft der Runner DiagnosticsToolMissing -> 503 (globaler Handler)."""

    async def _fake_resolve(query: str, types: list[str]) -> Any:
        raise DiagnosticsToolMissing("dig")

    app.dependency_overrides[provide_resolve_dns] = lambda: _fake_resolve

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/api/diagnostics/dns", params={"query": "example.com"})

    assert response.status_code == 503
    assert "dig" in response.json()["detail"]


# ── traceroute ───────────────────────────────────────────────────────────────


def test_traceroute_wire_form_with_timeout_hop(app: FastAPI) -> None:
    """``privileged=true`` + nicht-antwortender Hop als ``null``-Luecke im Wire."""

    result = TracerouteResult(
        target="example.com",
        privileged=True,
        hops=(
            TracerouteHop(hop=1, address="172.18.0.1", rtt_ms=0.6),
            TracerouteHop(hop=2, address=None, rtt_ms=None),
        ),
    )
    seen: dict[str, Any] = {}

    async def _fake_run(target: str, privileged: bool) -> Any:
        seen["privileged"] = privileged
        return result

    app.dependency_overrides[provide_run_traceroute] = lambda: _fake_run

    with TestClient(app) as client:
        response = client.get(
            "/api/diagnostics/traceroute",
            params={"target": "example.com", "privileged": "true"},
        )

    assert response.status_code == 200
    assert seen["privileged"] is True
    body = response.json()
    assert body["target"] == "example.com"
    assert body["privileged"] is True
    assert body["hops"] == [
        {"hop": 1, "address": "172.18.0.1", "rtt_ms": 0.6},
        {"hop": 2, "address": None, "rtt_ms": None},
    ]


def test_traceroute_privileged_required(app: FastAPI) -> None:
    """Fehlender Pflichtparameter ``privileged`` -> 422 (kein Raten)."""

    async def _fake_run(target: str, privileged: bool) -> Any:
        return TracerouteResult(target=target, privileged=privileged, hops=())

    app.dependency_overrides[provide_run_traceroute] = lambda: _fake_run

    with TestClient(app) as client:
        response = client.get("/api/diagnostics/traceroute", params={"target": "example.com"})

    assert response.status_code == 422


def test_traceroute_tool_missing_maps_to_503(app: FastAPI) -> None:
    async def _fake_run(target: str, privileged: bool) -> Any:
        raise DiagnosticsToolMissing("traceroute")

    app.dependency_overrides[provide_run_traceroute] = lambda: _fake_run

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get(
            "/api/diagnostics/traceroute",
            params={"target": "example.com", "privileged": "false"},
        )

    assert response.status_code == 503
    assert "traceroute" in response.json()["detail"]


# ── traceroute/permission ────────────────────────────────────────────────────


def test_traceroute_permission_privileged_available(app: FastAPI) -> None:
    app.dependency_overrides[provide_check_traceroute_permission] = lambda: _FakePermission(
        True, ""
    )

    with TestClient(app) as client:
        response = client.get("/api/diagnostics/traceroute/permission")

    assert response.status_code == 200
    assert response.json() == {"ok": True, "error": ""}


def test_traceroute_permission_only_unprivileged(app: FastAPI) -> None:
    msg = "Die genauere (privilegierte) traceroute-Methode benoetigt Root."
    app.dependency_overrides[provide_check_traceroute_permission] = lambda: _FakePermission(
        False, msg
    )

    with TestClient(app) as client:
        response = client.get("/api/diagnostics/traceroute/permission")

    assert response.status_code == 200
    assert response.json() == {"ok": False, "error": msg}


# ── tools (1b) ────────────────────────────────────────────────────────────────


def test_tools_without_param_checks_all(app: FastAPI) -> None:
    """Ohne ``tools`` kommt ``None`` am Runner an (Erstinstallation: alle pruefen)."""

    report = ToolReport(
        manager="apt",
        statuses=(
            ToolStatus(name="dig", available=True),
            ToolStatus(name="traceroute", available=True),
        ),
        install_command=None,
    )
    seen: dict[str, Any] = {}

    def _fake_check(tools: list[str] | None) -> Any:
        seen["tools"] = tools
        return report

    app.dependency_overrides[provide_check_tools] = lambda: _fake_check

    with TestClient(app) as client:
        response = client.get("/api/diagnostics/tools")

    assert response.status_code == 200
    assert seen["tools"] is None  # ohne Param -> None (alle)
    assert response.json() == {
        "manager": "apt",
        "statuses": [
            {"name": "dig", "available": True},
            {"name": "traceroute", "available": True},
        ],
        "install_command": None,
    }


def test_tools_with_repeatable_param_checks_subset(app: FastAPI) -> None:
    """``?tools=dig`` kommt als Liste am Runner an; install_command im Wire serialisiert."""

    report = ToolReport(
        manager="apt",
        statuses=(ToolStatus(name="dig", available=False),),
        install_command="sudo apt install dnsutils",
    )
    seen: dict[str, Any] = {}

    def _fake_check(tools: list[str] | None) -> Any:
        seen["tools"] = tools
        return report

    app.dependency_overrides[provide_check_tools] = lambda: _fake_check

    with TestClient(app) as client:
        response = client.get("/api/diagnostics/tools", params=[("tools", "dig")])

    assert response.status_code == 200
    assert seen["tools"] == ["dig"]
    body = response.json()
    assert body["install_command"] == "sudo apt install dnsutils"
    assert body["statuses"] == [{"name": "dig", "available": False}]


def test_tools_manager_none_serializes_null(app: FastAPI) -> None:
    """Kein Manager erkannt -> manager + install_command sind ehrlich ``null`` im Wire."""

    report = ToolReport(
        manager=None,
        statuses=(ToolStatus(name="dig", available=False),),
        install_command=None,
    )

    app.dependency_overrides[provide_check_tools] = lambda: lambda _tools: report

    with TestClient(app) as client:
        response = client.get("/api/diagnostics/tools", params=[("tools", "dig")])

    assert response.status_code == 200
    body = response.json()
    assert body["manager"] is None
    assert body["install_command"] is None


# ── banner (2a) ────────────────────────────────────────────────────────────────


def test_banner_wire_form_ok(app: FastAPI) -> None:
    """200-Pfad: target/port kommen am Runner an, BannerResult wird serialisiert."""

    result = BannerResult(
        target="example.com", port=22, probe="passive", banner="SSH-2.0-OpenSSH", state="ok"
    )
    seen: dict[str, Any] = {}

    async def _fake_grab(target: str, port: int) -> Any:
        seen["target"] = target
        seen["port"] = port
        return result

    app.dependency_overrides[provide_grab_banner] = lambda: _fake_grab

    with TestClient(app) as client:
        response = client.get(
            "/api/diagnostics/banner", params={"target": "example.com", "port": 22}
        )

    assert response.status_code == 200
    assert seen == {"target": "example.com", "port": 22}
    assert response.json() == {
        "target": "example.com",
        "port": 22,
        "probe": "passive",
        "banner": "SSH-2.0-OpenSSH",
        "state": "ok",
    }


def test_banner_no_banner_serializes_null(app: FastAPI) -> None:
    """``banner`` ist ehrlich ``null`` im Wire, wenn nichts kam (kein erfundener Wert)."""

    result = BannerResult(
        target="example.com", port=443, probe="passive", banner=None, state="no_banner"
    )

    async def _fake_grab(target: str, port: int) -> Any:
        return result

    app.dependency_overrides[provide_grab_banner] = lambda: _fake_grab

    with TestClient(app) as client:
        response = client.get(
            "/api/diagnostics/banner", params={"target": "example.com", "port": 443}
        )

    assert response.status_code == 200
    body = response.json()
    assert body["banner"] is None
    assert body["state"] == "no_banner"


def test_banner_port_required(app: FastAPI) -> None:
    """Fehlender Pflichtparameter ``port`` -> 422 (kein Raten)."""

    async def _fake_grab(target: str, port: int) -> Any:
        return BannerResult(
            target=target, port=port, probe="passive", banner=None, state="no_banner"
        )

    app.dependency_overrides[provide_grab_banner] = lambda: _fake_grab

    with TestClient(app) as client:
        response = client.get("/api/diagnostics/banner", params={"target": "example.com"})

    assert response.status_code == 422


def test_banner_target_required(app: FastAPI) -> None:
    """Fehlender Pflichtparameter ``target`` -> 422."""

    async def _fake_grab(target: str, port: int) -> Any:
        return BannerResult(
            target=target, port=port, probe="passive", banner=None, state="no_banner"
        )

    app.dependency_overrides[provide_grab_banner] = lambda: _fake_grab

    with TestClient(app) as client:
        response = client.get("/api/diagnostics/banner", params={"port": 22})

    assert response.status_code == 422


def test_banner_port_out_of_range(app: FastAPI) -> None:
    """``port`` ausserhalb 1..65535 -> 422 (FastAPI-Grenze)."""

    async def _fake_grab(target: str, port: int) -> Any:
        return BannerResult(
            target=target, port=port, probe="passive", banner=None, state="no_banner"
        )

    app.dependency_overrides[provide_grab_banner] = lambda: _fake_grab

    with TestClient(app) as client:
        response = client.get(
            "/api/diagnostics/banner", params={"target": "example.com", "port": 70000}
        )

    assert response.status_code == 422


# ── external (2b) ──────────────────────────────────────────────────────────────


def test_external_ip_not_configured_wire(app: FastAPI) -> None:
    """configured=False-Pfad: ip/family null, error traegt den neutralen Hinweis."""

    result = ExternalCheckResult(
        configured=False,
        checked_ip=None,
        family=None,
        ports=(),
        error="Externer Check nicht konfiguriert: bitte cpnetcheck-URL und Token setzen.",
    )
    seen: dict[str, Any] = {}

    async def _fake_check(ports: list[int] | None) -> Any:
        seen["ports"] = ports
        return result

    app.dependency_overrides[provide_check_external] = lambda: _fake_check

    with TestClient(app) as client:
        response = client.get("/api/diagnostics/external/ip")

    assert response.status_code == 200
    # Reiner IP-Check -> ports None am Runner.
    assert seen["ports"] is None
    body = response.json()
    assert body == {
        "configured": False,
        "ip": None,
        "family": None,
        "error": result.error,
    }


def test_external_ip_configured_wire(app: FastAPI) -> None:
    """configured=True-Pfad (IP): ip/family serialisiert, error null."""

    result = ExternalCheckResult(
        configured=True,
        checked_ip="203.0.113.7",
        family="ipv4",
        ports=(),
        error=None,
    )

    async def _fake_check(ports: list[int] | None) -> Any:
        return result

    app.dependency_overrides[provide_check_external] = lambda: _fake_check

    with TestClient(app) as client:
        response = client.get("/api/diagnostics/external/ip")

    assert response.status_code == 200
    assert response.json() == {
        "configured": True,
        "ip": "203.0.113.7",
        "family": "ipv4",
        "error": None,
    }


def test_external_ports_configured_wire(app: FastAPI) -> None:
    """configured=True-Pfad (Ports): ports kommen am Runner an, results serialisiert."""

    result = ExternalCheckResult(
        configured=True,
        checked_ip="203.0.113.7",
        family="ipv4",
        ports=(
            ExternalPortResult(port=80, reachable=True, state="open"),
            ExternalPortResult(port=443, reachable=False, state="filtered"),
        ),
        error=None,
    )
    seen: dict[str, Any] = {}

    async def _fake_check(ports: list[int] | None) -> Any:
        seen["ports"] = ports
        return result

    app.dependency_overrides[provide_check_external] = lambda: _fake_check

    with TestClient(app) as client:
        response = client.get(
            "/api/diagnostics/external/ports", params=[("ports", "80"), ("ports", "443")]
        )

    assert response.status_code == 200
    assert seen["ports"] == [80, 443]
    assert response.json() == {
        "configured": True,
        "checked_ip": "203.0.113.7",
        "family": "ipv4",
        "results": [
            {"port": 80, "reachable": True, "state": "open"},
            {"port": 443, "reachable": False, "state": "filtered"},
        ],
        "error": None,
    }


def test_external_ports_not_configured_wire(app: FastAPI) -> None:
    """configured=False-Pfad (Ports): results leer, checked_ip null, error gesetzt."""

    result = ExternalCheckResult(
        configured=False,
        checked_ip=None,
        family=None,
        ports=(),
        error="Externer Check nicht konfiguriert.",
    )

    async def _fake_check(ports: list[int] | None) -> Any:
        return result

    app.dependency_overrides[provide_check_external] = lambda: _fake_check

    with TestClient(app) as client:
        response = client.get("/api/diagnostics/external/ports", params=[("ports", "80")])

    assert response.status_code == 200
    body = response.json()
    assert body["configured"] is False
    assert body["checked_ip"] is None
    assert body["results"] == []
    assert body["error"] == "Externer Check nicht konfiguriert."


def test_external_ports_required(app: FastAPI) -> None:
    """Fehlender Pflichtparameter ``ports`` -> 422 (kein Raten)."""

    async def _fake_check(ports: list[int] | None) -> Any:
        raise AssertionError("darf bei 422 nicht gerufen werden")

    app.dependency_overrides[provide_check_external] = lambda: _fake_check

    with TestClient(app) as client:
        response = client.get("/api/diagnostics/external/ports")

    assert response.status_code == 422


def test_external_ports_invalid_value_422(app: FastAPI) -> None:
    """``ports`` ausserhalb 1..65535 -> 422 (FastAPI-Grenze, kein Use-Case-Aufruf)."""

    async def _fake_check(ports: list[int] | None) -> Any:
        raise AssertionError("darf bei 422 nicht gerufen werden")

    app.dependency_overrides[provide_check_external] = lambda: _fake_check

    with TestClient(app) as client:
        response = client.get("/api/diagnostics/external/ports", params=[("ports", "70000")])

    assert response.status_code == 422


def test_external_ip_service_error_maps_to_502(app: FastAPI) -> None:
    """Dienstfehler (ExternalCheckFailed) -> 502 (globaler Handler), Token nie im Body."""

    async def _fake_check(ports: list[int] | None) -> Any:
        raise ExternalCheckFailed("Der externe Erreichbarkeits-Dienst ist nicht erreichbar.")

    app.dependency_overrides[provide_check_external] = lambda: _fake_check

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/api/diagnostics/external/ip")

    assert response.status_code == 502
    detail = response.json()["detail"]
    assert "erreichbar" in detail


def test_external_ports_service_error_maps_to_502(app: FastAPI) -> None:
    """Auch der Port-Pfad mappt ExternalCheckFailed auf 502."""

    async def _fake_check(ports: list[int] | None) -> Any:
        raise ExternalCheckFailed("Authentifizierung am externen Dienst fehlgeschlagen.")

    app.dependency_overrides[provide_check_external] = lambda: _fake_check

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/api/diagnostics/external/ports", params=[("ports", "443")])

    assert response.status_code == 502


# ── Rogue-DHCP (3) ─────────────────────────────────────────────────────────────


def test_dhcp_wire_form_with_unexpected(app: FastAPI) -> None:
    """``GET /api/diagnostics/dhcp`` serialisiert das RogueDhcpResult (mit unexpected)."""

    result = RogueDhcpResult(
        servers=(
            DhcpServer(ip="192.168.1.1", mac=None, is_expected=True),
            DhcpServer(ip="192.168.1.66", mac="de:ad:be:ef:00:01", is_expected=False),
        ),
        expected=("192.168.1.1",),
        has_unexpected=True,
    )

    async def _fake_detect() -> Any:
        return result

    app.dependency_overrides[provide_detect_rogue_dhcp] = lambda: _fake_detect

    with TestClient(app) as client:
        response = client.get("/api/diagnostics/dhcp")

    assert response.status_code == 200
    assert response.json() == {
        "servers": [
            {"ip": "192.168.1.1", "mac": None, "is_expected": True},
            {"ip": "192.168.1.66", "mac": "de:ad:be:ef:00:01", "is_expected": False},
        ],
        "expected": ["192.168.1.1"],
        "has_unexpected": True,
    }


def test_dhcp_wire_form_no_unexpected(app: FastAPI) -> None:
    """Alle erwartet -> has_unexpected false, mac ehrlich null."""

    result = RogueDhcpResult(
        servers=(DhcpServer(ip="192.168.1.1", mac=None, is_expected=True),),
        expected=("192.168.1.1",),
        has_unexpected=False,
    )

    async def _fake_detect() -> Any:
        return result

    app.dependency_overrides[provide_detect_rogue_dhcp] = lambda: _fake_detect

    with TestClient(app) as client:
        response = client.get("/api/diagnostics/dhcp")

    assert response.status_code == 200
    body = response.json()
    assert body["has_unexpected"] is False
    assert body["servers"][0]["mac"] is None


def test_dhcp_without_root_maps_to_403(app: FastAPI) -> None:
    """Ohne Root wirft der Use-Case RogueDhcpPermissionError -> globaler Handler 403."""

    async def _fake_detect() -> Any:
        raise RogueDhcpPermissionError("Rogue-DHCP-Erkennung benoetigt Root.")

    app.dependency_overrides[provide_detect_rogue_dhcp] = lambda: _fake_detect

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/api/diagnostics/dhcp")

    assert response.status_code == 403
    assert "Root" in response.json()["detail"]


def test_dhcp_permission_ok_wire_form(app: FastAPI) -> None:
    """``GET /api/diagnostics/dhcp/permission`` liefert die {ok, error}-Naht."""

    app.dependency_overrides[provide_check_dhcp_permission] = lambda: _FakePermission(
        ok=True, error=""
    )

    with TestClient(app) as client:
        response = client.get("/api/diagnostics/dhcp/permission")

    assert response.status_code == 200
    assert response.json() == {"ok": True, "error": ""}


def test_dhcp_permission_blocked_wire_form(app: FastAPI) -> None:
    """ok=false + Begruendung, wenn kein Root / nmap fehlt."""

    app.dependency_overrides[provide_check_dhcp_permission] = lambda: _FakePermission(
        ok=False, error="braucht Root"
    )

    with TestClient(app) as client:
        response = client.get("/api/diagnostics/dhcp/permission")

    assert response.status_code == 200
    assert response.json() == {"ok": False, "error": "braucht Root"}
