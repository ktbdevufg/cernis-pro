"""Tests fuer ``UrllibAgentPinger`` -- gemocktes ``urllib`` (kein echtes Netz).

Getestet: (1) Port-Konformitaet, (2) HTTP-200 -> ``reachable=True`` (vom Pinger
selbst gesetzt) + version/platform/hostname aus dem Body, (3) der Token wandert
in den ``X-Agent-Token``-Header des GET ``/agent/info``, (4) Exception ->
``reachable=False`` + ``error`` + ``logger.warning("agent_ping_failed", ...)``,
(5) der blockierende urllib-Call laeuft via ``asyncio.to_thread`` in einem
ANDEREN Thread als der Event-Loop.

Async-Smokes laufen ueber ``asyncio.run`` (kein ``pytest-asyncio`` -- nicht
installiert, wie in S.3/M.3). Gemockt wird am IMPORT-ORT IM ADAPTER-MODUL.
"""

import asyncio
import json
import threading
import urllib.error
from typing import Any

import pytest

from infrastructure.agent.pinger import UrllibAgentPinger
from ports.agent import AgentPinger

URL = "http://vps.example.de:8766"
TOKEN = "plain-token"


class _FakeResponse:
    """Minimaler Stand-in fuer das urlopen-Context-Manager-Objekt."""

    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def read(self) -> bytes:
        return self._payload


def test_conforms_to_agent_pinger_protocol() -> None:
    _: AgentPinger = UrllibAgentPinger()


def test_http_200_sets_reachable_true_and_maps_body(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def fake_urlopen(request: Any, timeout: int = 0) -> _FakeResponse:
        seen["full_url"] = request.full_url
        seen["headers"] = dict(request.headers)
        seen["timeout"] = timeout
        body = {"reachable": True, "version": "1.0.0", "platform": "Linux", "hostname": "vps"}
        return _FakeResponse(json.dumps(body).encode())

    monkeypatch.setattr("infrastructure.agent.pinger.urllib.request.urlopen", fake_urlopen)

    result = asyncio.run(UrllibAgentPinger().ping(URL, TOKEN))

    assert result.reachable is True
    assert result.version == "1.0.0"
    assert result.platform == "Linux"
    assert result.hostname == "vps"
    assert result.error == ""
    # GET geht gegen /agent/info, Token im X-Agent-Token-Header, timeout=5.
    assert seen["full_url"] == f"{URL}/agent/info"
    # urllib normalisiert Header-Namen zu Titlecase ("X-agent-token").
    assert seen["headers"]["X-agent-token"] == TOKEN
    assert seen["timeout"] == 5


def test_exception_returns_unreachable_and_warns(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom_urlopen(request: Any, timeout: int = 0) -> _FakeResponse:
        raise urllib.error.URLError("Connection refused")

    warnings: list[tuple[str, dict[str, Any]]] = []

    def fake_warning(event: str, **kw: Any) -> None:
        warnings.append((event, kw))

    monkeypatch.setattr("infrastructure.agent.pinger.urllib.request.urlopen", boom_urlopen)
    monkeypatch.setattr("infrastructure.agent.pinger._logger.warning", fake_warning)

    result = asyncio.run(UrllibAgentPinger().ping(URL, TOKEN))

    # AS-IS: Unerreichbarkeit ist ein legitimes Ergebnis, kein Fehler.
    assert result.reachable is False
    assert "Connection refused" in result.error
    # Muster-i: nicht mehr STUMM -- Warn-Log mit url + error.
    assert warnings and warnings[0][0] == "agent_ping_failed"
    assert warnings[0][1]["url"] == URL
    assert "Connection refused" in warnings[0][1]["error"]


def test_non_object_body_is_treated_as_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(request: Any, timeout: int = 0) -> _FakeResponse:
        # Gueltiges JSON, aber kein Objekt -> keine brauchbare /agent/info-Antwort.
        return _FakeResponse(b"[1, 2, 3]")

    monkeypatch.setattr("infrastructure.agent.pinger.urllib.request.urlopen", fake_urlopen)
    monkeypatch.setattr("infrastructure.agent.pinger._logger.warning", lambda *a, **k: None)

    result = asyncio.run(UrllibAgentPinger().ping(URL, TOKEN))
    assert result.reachable is False


def test_blocking_call_runs_in_worker_thread(monkeypatch: pytest.MonkeyPatch) -> None:
    """Beweis fuer den to_thread-Pfad: urlopen laeuft NICHT im Loop-Thread."""
    loop_thread = threading.get_ident()
    seen: dict[str, int] = {}

    def fake_urlopen(request: Any, timeout: int = 0) -> _FakeResponse:
        seen["call_thread"] = threading.get_ident()
        return _FakeResponse(b'{"reachable": true}')

    monkeypatch.setattr("infrastructure.agent.pinger.urllib.request.urlopen", fake_urlopen)

    asyncio.run(UrllibAgentPinger().ping(URL, TOKEN))

    # to_thread fuehrt den blockierenden Call in einem Executor-Thread aus.
    assert seen["call_thread"] != loop_thread
