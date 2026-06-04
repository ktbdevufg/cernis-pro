"""Characterization-Contract der lebenden agent-REST-Endpunkte (Altcode main.py).

Netzwerk-/DB-/crypto-frei: die Endpunkt-Funktionen werden auf eine FRISCHE App
gehaengt (``add_api_route``, keine main-Lifespan), ihre Modulfunktionen sind am
main-Namespace gemockt (``get_agents``, ``save_agent``, ``delete_agent``,
``ping_agent``, ``proxy_scan`` -- alle in main.py:62 als Aliase importiert).
``get_agent_token`` wird in den Handlern LOKAL importiert
(``from modules.agent import get_agent_token``) und daher an der Quelle gepatcht:
``monkeypatch.setattr("modules.agent.get_agent_token", ...)``.

Festgehalten wird das HEUTIGE Verhalten der vier frontend-verdrahteten Routen
(``GET/POST /api/agents``, ``DELETE /api/agents/{id}``,
``GET /api/agents/{id}/ping``) plus der beobachtbare Ist-Zustand der
nicht-frontend-verdrahteten ``POST /api/agents/{id}/scan`` (404/503/Wire-Durchreichung).

KAPUTTER TOKEN-KANAL (AS-IS dokumentiert, NICHT repariert, NICHT gruen-gemockt):
Der Scan-Client sendet den Token im WebSocket-HEADER
(``extra_headers={"X-Agent-Token": token}``, modules/agent.py:161), die
zurueckgestellte Server-Seite prueft den Token aber im ersten Body-Message
(``config.get("token")``, modules/agent.py:212). Der Header-Token erreicht den
Body-Check nie -> der Auth-Pfad ist gebrochen. Dieser Test charakterisiert NUR
die clientseitig beobachtbare HueLLe der Scan-Route (Route existiert, ``wait_for``
mit ``timeout=300.0``, Exception -> 503, Erfolgs-Liste wird 1:1 durchgereicht) und
behauptet NICHT, dass der Token-Kanal funktioniert.

Die Server-Seite (``create_agent_app``, ``/agent/info``, ``/agent/scan``) ist ein
zurueckgestelltes Standalone-Deployable und wird hier NICHT charakterisiert.
"""

from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import main

# ── Beispiel-Registry-Eintrag, wie ``get_agents`` ihn liefert ────────────────────
# Token bereits maskiert ("••••••••"), cidrs bereits zur Liste geparst -- exakt die
# Form, die die DB-Funktion zurueckgibt. Die Route darf daran nichts mehr aendern.
_AGENT_ROW = {
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


def _fresh_app() -> FastAPI:
    """Frische App mit den fuenf agent-Routen, ohne main-Lifespan."""
    app = FastAPI()
    app.add_api_route("/api/agents", main.api_get_agents, methods=["GET"])
    app.add_api_route("/api/agents", main.api_add_agent, methods=["POST"])
    app.add_api_route("/api/agents/{agent_id}", main.api_delete_agent, methods=["DELETE"])
    app.add_api_route("/api/agents/{agent_id}/ping", main.api_ping_agent, methods=["GET"])
    app.add_api_route("/api/agents/{agent_id}/scan", main.api_agent_scan, methods=["POST"])
    return app


# ── GET /api/agents ──────────────────────────────────────────────────────────────


def test_get_agents_passes_masked_row_through(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main, "get_agents", lambda: [_AGENT_ROW])
    resp = TestClient(_fresh_app()).get("/api/agents")
    assert resp.status_code == 200
    body = resp.json()
    assert body == [_AGENT_ROW]
    # Vertrag: Maskierung NICHT aufgehoben, cidrs als Liste (nicht JSON-String) durchgereicht.
    assert body[0]["token"] == "••••••••"
    assert body[0]["cidrs"] == ["10.0.0.0/24"]


def test_get_agents_empty_returns_empty_list(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main, "get_agents", lambda: [])
    resp = TestClient(_fresh_app()).get("/api/agents")
    assert resp.status_code == 200
    assert resp.json() == []


# ── POST /api/agents ─────────────────────────────────────────────────────────────


def test_post_agent_passes_raw_payload_and_returns_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    spy: dict[str, Any] = {}

    def fake_save(agent: dict[str, Any]) -> None:
        spy["agent"] = agent

    monkeypatch.setattr(main, "save_agent", fake_save)
    payload = {
        "id": "agent-1",
        "name": "VPS Netcup",
        "url": "http://vps.example.de:8766",
        "token": "s3cret",
        "cidrs": ["10.0.0.0/24"],
    }
    resp = TestClient(_fresh_app()).post("/api/agents", json=payload)
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    # Spy: das vom Client gesendete dict landet unveraendert bei save_agent.
    assert spy["agent"] == payload


def test_post_agent_missing_required_field_returns_500(monkeypatch: pytest.MonkeyPatch) -> None:
    # AS-IS: kein Body-Schema, fehlendes Pflichtfeld -> KeyError -> 500;
    # saubere 422-Heilung = api-Haertung Phase 4 mit S1.
    def fake_save(agent: dict[str, Any]) -> None:
        # Repliziert den harten Zugriff aus modules/agent.py:104 (agent["id"]).
        _ = agent["id"]

    monkeypatch.setattr(main, "save_agent", fake_save)
    # Payload ohne "id".
    resp = TestClient(_fresh_app(), raise_server_exceptions=False).post(
        "/api/agents", json={"name": "no-id"}
    )
    assert resp.status_code == 500


# ── DELETE /api/agents/{agent_id} ────────────────────────────────────────────────


def test_delete_agent_returns_ok_and_calls_delete(monkeypatch: pytest.MonkeyPatch) -> None:
    spy: dict[str, Any] = {}
    monkeypatch.setattr(main, "delete_agent", lambda agent_id: spy.__setitem__("id", agent_id))
    resp = TestClient(_fresh_app()).delete("/api/agents/agent-1")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    assert spy["id"] == "agent-1"


def test_delete_unknown_agent_is_idempotent_200(monkeypatch: pytest.MonkeyPatch) -> None:
    # delete_agent prueft keine Existenz (DELETE ... WHERE id=?). Vertrag: kein 404,
    # immer 200 {"ok": True}, auch bei unbekannter id.
    monkeypatch.setattr(main, "delete_agent", lambda agent_id: None)
    resp = TestClient(_fresh_app()).delete("/api/agents/does-not-exist")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}


# ── GET /api/agents/{agent_id}/ping ──────────────────────────────────────────────


def test_ping_unknown_agent_returns_404(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main, "get_agents", lambda: [_AGENT_ROW])
    resp = TestClient(_fresh_app()).get("/api/agents/unknown/ping")
    assert resp.status_code == 404
    assert resp.json() == {"error": "Agent not found"}


def test_ping_reachable_true_passes_info_through(monkeypatch: pytest.MonkeyPatch) -> None:
    spy: dict[str, Any] = {}

    async def fake_ping(url: str, token: str) -> dict[str, Any]:
        spy["url"] = url
        spy["token"] = token
        return {"reachable": True, "version": "1.0.0", "platform": "Linux", "hostname": "vps"}

    monkeypatch.setattr(main, "get_agents", lambda: [_AGENT_ROW])
    monkeypatch.setattr(main, "ping_agent", fake_ping)
    monkeypatch.setattr("modules.agent.get_agent_token", lambda agent_id: "plain-token")

    resp = TestClient(_fresh_app()).get("/api/agents/agent-1/ping")
    assert resp.status_code == 200
    assert resp.json() == {
        "reachable": True,
        "version": "1.0.0",
        "platform": "Linux",
        "hostname": "vps",
    }
    # Spy: ping_agent(agent["url"], token) -- url aus der Liste, Token aus get_agent_token.
    assert spy["url"] == _AGENT_ROW["url"]
    assert spy["token"] == "plain-token"


def test_ping_unreachable_returns_200_with_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    # Unerreichbarkeit ist KEIN HTTP-Fehler: 200 mit {reachable: False} im Body
    # (so liefert ping_agent bei urllib-Exception).
    async def fake_ping(url: str, token: str) -> dict[str, Any]:
        return {"error": "Connection refused", "reachable": False}

    monkeypatch.setattr(main, "get_agents", lambda: [_AGENT_ROW])
    monkeypatch.setattr(main, "ping_agent", fake_ping)
    monkeypatch.setattr("modules.agent.get_agent_token", lambda agent_id: "plain-token")

    resp = TestClient(_fresh_app()).get("/api/agents/agent-1/ping")
    assert resp.status_code == 200
    assert resp.json() == {"error": "Connection refused", "reachable": False}


# ── POST /api/agents/{agent_id}/scan ─────────────────────────────────────────────
# NUR Huelle: 404/503/Wire-Durchreichung. KEIN funktionierender Token-Kanal (s. Docstring).


def test_scan_unknown_agent_returns_404(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main, "get_agents", lambda: [_AGENT_ROW])
    monkeypatch.setattr("modules.agent.get_agent_token", lambda agent_id: "plain-token")
    resp = TestClient(_fresh_app()).post("/api/agents/unknown/scan", json={"cidr": "10.0.0.0/24"})
    assert resp.status_code == 404
    assert resp.json() == {"error": "Agent not found"}


def test_scan_proxy_exception_returns_503(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_proxy(url: str, token: str, config: dict[str, Any]) -> list[dict[str, Any]]:
        raise RuntimeError("ws handshake failed")

    monkeypatch.setattr(main, "get_agents", lambda: [_AGENT_ROW])
    monkeypatch.setattr(main, "proxy_scan", fake_proxy)
    monkeypatch.setattr("modules.agent.get_agent_token", lambda agent_id: "plain-token")

    resp = TestClient(_fresh_app()).post("/api/agents/agent-1/scan", json={"cidr": "10.0.0.0/24"})
    assert resp.status_code == 503
    assert resp.json() == {"error": "ws handshake failed"}


def test_scan_timeout_returns_503(monkeypatch: pytest.MonkeyPatch) -> None:
    # Nagelt timeout=300.0 + except Exception -> 503: wait_for laeuft in Timeout.
    import asyncio

    async def fake_proxy(url: str, token: str, config: dict[str, Any]) -> list[dict[str, Any]]:
        return []

    async def boom_wait_for(awaitable: Any, timeout: float) -> Any:
        # awaitable schliessen (vermeidet "never awaited"-Warnung), dann Timeout werfen.
        if asyncio.iscoroutine(awaitable):
            awaitable.close()
        raise TimeoutError

    monkeypatch.setattr(main, "get_agents", lambda: [_AGENT_ROW])
    monkeypatch.setattr(main, "proxy_scan", fake_proxy)
    monkeypatch.setattr("modules.agent.get_agent_token", lambda agent_id: "plain-token")
    monkeypatch.setattr("main.asyncio.wait_for", boom_wait_for)

    resp = TestClient(_fresh_app()).post("/api/agents/agent-1/scan", json={"cidr": "10.0.0.0/24"})
    assert resp.status_code == 503
    assert "error" in resp.json()


def test_scan_success_passes_results_through(monkeypatch: pytest.MonkeyPatch) -> None:
    # NUR Wire-Durchreichung der proxy_scan-Rueckgabe -- KEIN Beweis eines funktionierenden
    # Token-Kanals (s. Modul-Docstring: Header-Token erreicht den Body-Check nie).
    hosts = [{"type": "host_detail", "ip": "10.0.0.5", "mac": "AA:BB:CC:DD:EE:01"}]

    async def fake_proxy(url: str, token: str, config: dict[str, Any]) -> list[dict[str, Any]]:
        return hosts

    monkeypatch.setattr(main, "get_agents", lambda: [_AGENT_ROW])
    monkeypatch.setattr(main, "proxy_scan", fake_proxy)
    monkeypatch.setattr("modules.agent.get_agent_token", lambda agent_id: "plain-token")

    resp = TestClient(_fresh_app()).post("/api/agents/agent-1/scan", json={"cidr": "10.0.0.0/24"})
    assert resp.status_code == 200
    assert resp.json() == hosts
