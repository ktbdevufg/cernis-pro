"""v2-Vertrag des agent-REST-Rands (``api/agent.py``).

Gegenstueck zum eingefrorenen A.0-Characterizer ``test_agent_rest_contract`` (der
friert die v1-``main.py``-Routen ein). HIER wird der v2-Rand selbst gegen
dieselbe Wire-Form genagelt: eine frische ``FastAPI``-App mit dem
``agent_router``, die Use-Cases ueber ``dependency_overrides`` durch Fakes
ersetzt (kein DB/Netzwerk/Keystore). Muster ``test_capture_api`` neben
``test_capture_contract``.

Festgehalten:
* ``GET`` liefert EXAKT die A.0-Wire-Form: Token-Maske ``"••••••••"`` (am Rand,
  nicht aus domain), tote Felder ``last_seen``/``version``/``platform`` leer,
  ``enabled`` als ``int``, ``cidrs`` als Liste.
* ``_ping_to_wire`` KONDITIONAL: reachable=True OHNE ``error``-Key,
  reachable=False MIT ``error``.
* ``POST`` mit fehlendem Pflichtfeld -> 500 (roher dict-Body, kein BaseModel).
* ``POST``-Erfolg reicht PRIMITIVE + Token an ``SaveAgent`` (Spy) -- der Rand baut
  kein ``domain``-Objekt, das ``RemoteAgent`` entsteht im Use-Case.
* ``DELETE`` idempotent (immer 200 ``{ok: True}``).
* ``ping``/``scan`` auf unbekannten Agenten -> 404.
* ``scan``-Exception -> 503; ``scan`` nutzt ``wait_for(timeout=300.0)`` (Spy).
"""

from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.agent import (
    provide_delete_agent,
    provide_list_agents,
    provide_ping_agent,
    provide_save_agent,
    provide_scan_via_agent,
)
from api.agent import (
    router as agent_router,
)
from application.agent import AgentNotFoundError
from domain.agent import AgentPingResult, RemoteAgent


def _fresh_app() -> FastAPI:
    """Frische App nur mit dem agent_router (ohne create_app/Composition Root)."""
    app = FastAPI()
    app.include_router(agent_router)
    return app


# ── GET /api/agents ──────────────────────────────────────────────────────────────


def test_get_agents_returns_masked_altcode_wire_form() -> None:
    agent = RemoteAgent(
        id="agent-1",
        name="VPS Netcup",
        url="http://vps.example.de:8766",
        enabled=True,
        cidrs=("10.0.0.0/24",),
    )
    app = _fresh_app()
    app.dependency_overrides[provide_list_agents] = lambda: lambda: [agent]

    resp = TestClient(app).get("/api/agents")
    assert resp.status_code == 200
    # Exakt die A.0-Wire-Form: Maske, tote Felder leer, enabled int, cidrs Liste.
    assert resp.json() == [
        {
            "id": "agent-1",
            "name": "VPS Netcup",
            "url": "http://vps.example.de:8766",
            "token": "••••••••",
            "enabled": 1,
            "last_seen": "",
            "version": "",
            "platform": "",
            "cidrs": ["10.0.0.0/24"],
        }
    ]


def test_get_agents_empty_returns_empty_list() -> None:
    app = _fresh_app()
    app.dependency_overrides[provide_list_agents] = lambda: lambda: []
    resp = TestClient(app).get("/api/agents")
    assert resp.status_code == 200
    assert resp.json() == []


# ── POST /api/agents ─────────────────────────────────────────────────────────────


def test_post_agent_passes_primitives_and_token_and_returns_ok() -> None:
    spy: dict[str, Any] = {}

    class FakeSave:
        def __call__(
            self,
            agent_id: str,
            name: str,
            url: str,
            enabled: bool,
            cidrs: tuple[str, ...] | list[str],
            token: str | None,
        ) -> None:
            spy["args"] = (agent_id, name, url, enabled, cidrs)
            spy["token"] = token

    app = _fresh_app()
    app.dependency_overrides[provide_save_agent] = lambda: FakeSave()
    payload = {
        "id": "agent-1",
        "name": "VPS Netcup",
        "url": "http://vps.example.de:8766",
        "token": "s3cret",
        "cidrs": ["10.0.0.0/24"],
    }
    resp = TestClient(app).post("/api/agents", json=payload)
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    # Der Rand reicht PRIMITIVE durch (kein domain-Objekt am Rand); der Use-Case
    # baut das RemoteAgent. Token GETRENNT durchgereicht.
    assert spy["args"] == (
        "agent-1",
        "VPS Netcup",
        "http://vps.example.de:8766",
        True,
        ["10.0.0.0/24"],
    )
    assert spy["token"] == "s3cret"


def test_post_agent_missing_required_field_returns_500() -> None:
    # AS-IS (kein BaseModel): body["id"] hart -> KeyError -> 500. Saubere 422 = Phase 4.
    class FakeSave:
        def __call__(self, *args: Any, **kwargs: Any) -> None: ...

    app = _fresh_app()
    app.dependency_overrides[provide_save_agent] = lambda: FakeSave()
    resp = TestClient(app, raise_server_exceptions=False).post(
        "/api/agents", json={"name": "no-id"}
    )
    assert resp.status_code == 500


# ── DELETE /api/agents/{agent_id} ────────────────────────────────────────────────


def test_delete_agent_returns_ok_and_calls_delete() -> None:
    spy: dict[str, Any] = {}

    class FakeDelete:
        def __call__(self, agent_id: str) -> None:
            spy["id"] = agent_id

    app = _fresh_app()
    app.dependency_overrides[provide_delete_agent] = lambda: FakeDelete()
    resp = TestClient(app).delete("/api/agents/agent-1")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    assert spy["id"] == "agent-1"


def test_delete_unknown_agent_is_idempotent_200() -> None:
    class FakeDelete:
        def __call__(self, agent_id: str) -> None: ...

    app = _fresh_app()
    app.dependency_overrides[provide_delete_agent] = lambda: FakeDelete()
    resp = TestClient(app).delete("/api/agents/does-not-exist")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}


# ── GET /api/agents/{agent_id}/ping ──────────────────────────────────────────────


def test_ping_unknown_agent_returns_404() -> None:
    class FakePing:
        async def __call__(self, agent_id: str) -> AgentPingResult:
            raise AgentNotFoundError(agent_id)

    app = _fresh_app()
    app.dependency_overrides[provide_ping_agent] = lambda: FakePing()
    resp = TestClient(app).get("/api/agents/unknown/ping")
    assert resp.status_code == 404
    assert resp.json() == {"error": "Agent not found"}


def test_ping_reachable_true_omits_error_key() -> None:
    spy: dict[str, Any] = {}

    class FakePing:
        async def __call__(self, agent_id: str) -> AgentPingResult:
            spy["id"] = agent_id
            return AgentPingResult(
                reachable=True, version="1.0.0", platform="Linux", hostname="vps"
            )

    app = _fresh_app()
    app.dependency_overrides[provide_ping_agent] = lambda: FakePing()
    resp = TestClient(app).get("/api/agents/agent-1/ping")
    assert resp.status_code == 200
    # KONDITIONAL: reachable=True -> KEIN error-Key.
    assert resp.json() == {
        "reachable": True,
        "version": "1.0.0",
        "platform": "Linux",
        "hostname": "vps",
    }
    assert spy["id"] == "agent-1"


def test_ping_unreachable_returns_200_with_error_flag() -> None:
    class FakePing:
        async def __call__(self, agent_id: str) -> AgentPingResult:
            return AgentPingResult(reachable=False, error="Connection refused")

    app = _fresh_app()
    app.dependency_overrides[provide_ping_agent] = lambda: FakePing()
    resp = TestClient(app).get("/api/agents/agent-1/ping")
    assert resp.status_code == 200
    # KONDITIONAL: reachable=False -> {error, reachable: False}, KEINE Info-Felder.
    assert resp.json() == {"error": "Connection refused", "reachable": False}


# ── POST /api/agents/{agent_id}/scan ─────────────────────────────────────────────


def test_scan_unknown_agent_returns_404() -> None:
    class FakeScan:
        async def __call__(self, agent_id: str, config: dict[str, Any]) -> list[dict[str, Any]]:
            raise AgentNotFoundError(agent_id)

    app = _fresh_app()
    app.dependency_overrides[provide_scan_via_agent] = lambda: FakeScan()
    resp = TestClient(app).post("/api/agents/unknown/scan", json={"cidr": "10.0.0.0/24"})
    assert resp.status_code == 404
    assert resp.json() == {"error": "Agent not found"}


def test_scan_exception_returns_503() -> None:
    class FakeScan:
        async def __call__(self, agent_id: str, config: dict[str, Any]) -> list[dict[str, Any]]:
            raise RuntimeError("ws handshake failed")

    app = _fresh_app()
    app.dependency_overrides[provide_scan_via_agent] = lambda: FakeScan()
    resp = TestClient(app).post("/api/agents/agent-1/scan", json={"cidr": "10.0.0.0/24"})
    assert resp.status_code == 503
    assert resp.json() == {"error": "ws handshake failed"}


def test_scan_uses_wait_for_with_300s_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    # Nagelt timeout=300.0 + except Exception -> 503: wait_for laeuft in Timeout.
    import asyncio

    spy: dict[str, Any] = {}

    class FakeScan:
        async def __call__(self, agent_id: str, config: dict[str, Any]) -> list[dict[str, Any]]:
            return []

    async def boom_wait_for(awaitable: Any, timeout: float) -> Any:
        spy["timeout"] = timeout
        if asyncio.iscoroutine(awaitable):
            awaitable.close()
        raise TimeoutError

    app = _fresh_app()
    app.dependency_overrides[provide_scan_via_agent] = lambda: FakeScan()
    monkeypatch.setattr("api.agent.asyncio.wait_for", boom_wait_for)

    resp = TestClient(app).post("/api/agents/agent-1/scan", json={"cidr": "10.0.0.0/24"})
    assert resp.status_code == 503
    assert "error" in resp.json()
    assert spy["timeout"] == 300.0


def test_scan_success_passes_results_through() -> None:
    hosts = [{"type": "host_detail", "ip": "10.0.0.5", "mac": "AA:BB:CC:DD:EE:01"}]

    class FakeScan:
        async def __call__(self, agent_id: str, config: dict[str, Any]) -> list[dict[str, Any]]:
            return hosts

    app = _fresh_app()
    app.dependency_overrides[provide_scan_via_agent] = lambda: FakeScan()
    resp = TestClient(app).post("/api/agents/agent-1/scan", json={"cidr": "10.0.0.0/24"})
    assert resp.status_code == 200
    assert resp.json() == hosts
