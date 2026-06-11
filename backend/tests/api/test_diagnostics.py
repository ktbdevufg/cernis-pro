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
    provide_check_tools,
    provide_check_traceroute_permission,
    provide_resolve_dns,
    provide_run_traceroute,
)
from app import create_app
from domain.diagnostics import (
    DnsRecord,
    DnsResult,
    ToolReport,
    ToolStatus,
    TracerouteHop,
    TracerouteResult,
)
from infrastructure.config import AppConfig
from infrastructure.diagnostics_linux import DiagnosticsToolMissing


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
