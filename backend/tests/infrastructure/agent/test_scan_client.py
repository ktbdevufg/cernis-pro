"""Tests fuer ``WebsocketsAgentScanClient`` -- gemocktes ``websockets`` (kein Netz).

Getestet: (1) Port-Konformitaet, (2) der Token wandert in den BODY der ERSTEN
Nachricht (``{**config, "token": token}``), NICHT in einen Verbindungs-Header
(Spy auf ``connect``-kwargs UND auf die gesendete Message) -- die Token-Kanal-
Reparatur aus ADR 0008, (3) ``host_detail`` wird gesammelt, (4) ``scan_complete``
bricht die Schleife ab, (5) ein Verbindungsfehler -> ``AgentScanError`` (KEIN
Pseudo-Host in der Liste) + ``logger.warning``, (6) ws_url-Schema (http->ws).

Async-Smokes laufen ueber ``asyncio.run`` (kein ``pytest-asyncio``). Gemockt wird
am IMPORT-ORT IM ADAPTER-MODUL.
"""

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any

import pytest

from infrastructure.agent.errors import AgentScanError
from infrastructure.agent.scan_client import WebsocketsAgentScanClient
from ports.agent import AgentScanClient

URL = "http://vps.example.de:8766"
TOKEN = "plain-token"
CONFIG = {"cidr": "10.0.0.0/24"}


class _FakeWebSocket:
    """Stand-in fuer die WS-Verbindung: send-Spy + async-Iterator ueber Messages."""

    def __init__(self, incoming: list[dict[str, Any]], sent: list[str]) -> None:
        self._incoming = incoming
        self._sent = sent

    async def send(self, message: str) -> None:
        self._sent.append(message)

    def __aiter__(self) -> AsyncIterator[str]:
        async def _gen() -> AsyncIterator[str]:
            for item in self._incoming:
                yield json.dumps(item)

        return _gen()


class _FakeConnect:
    """Stand-in fuer ``websockets.connect(...)`` als async-Context-Manager."""

    def __init__(self, ws: _FakeWebSocket, spy: dict[str, Any]) -> None:
        self._ws = ws
        self._spy = spy

    async def __aenter__(self) -> _FakeWebSocket:
        return self._ws

    async def __aexit__(self, *_exc: object) -> None:
        return None


def _install_connect(
    monkeypatch: pytest.MonkeyPatch,
    incoming: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[str]]:
    """Patcht ``websockets.connect`` und gibt (connect-spy, sent-messages) zurueck."""
    spy: dict[str, Any] = {}
    sent: list[str] = []

    def fake_connect(ws_url: str, **kwargs: Any) -> _FakeConnect:
        spy["ws_url"] = ws_url
        spy["kwargs"] = kwargs
        return _FakeConnect(_FakeWebSocket(incoming, sent), spy)

    monkeypatch.setattr("infrastructure.agent.scan_client.websockets.connect", fake_connect)
    return spy, sent


def test_conforms_to_agent_scan_client_protocol() -> None:
    _: AgentScanClient = WebsocketsAgentScanClient()


def test_token_goes_into_first_message_body_not_header(monkeypatch: pytest.MonkeyPatch) -> None:
    """KRITISCHER VERTRAG (ADR 0008): Token im Body der ersten Nachricht."""
    spy, sent = _install_connect(monkeypatch, incoming=[{"type": "scan_complete"}])

    asyncio.run(WebsocketsAgentScanClient().scan(URL, TOKEN, CONFIG))

    # Erste (einzige) gesendete Nachricht = config + token im Body.
    assert len(sent) == 1
    first = json.loads(sent[0])
    assert first["token"] == TOKEN
    assert first["cidr"] == CONFIG["cidr"]
    # Token NICHT im Verbindungs-Header: keine header-tragenden connect-kwargs.
    assert "extra_headers" not in spy["kwargs"]
    assert "additional_headers" not in spy["kwargs"]


def test_ws_url_scheme_http_to_ws(monkeypatch: pytest.MonkeyPatch) -> None:
    spy, _sent = _install_connect(monkeypatch, incoming=[{"type": "scan_complete"}])
    asyncio.run(WebsocketsAgentScanClient().scan(URL, TOKEN, CONFIG))
    assert spy["ws_url"] == "ws://vps.example.de:8766/agent/scan"


def test_https_url_scheme_to_wss(monkeypatch: pytest.MonkeyPatch) -> None:
    spy, _sent = _install_connect(monkeypatch, incoming=[{"type": "scan_complete"}])
    asyncio.run(WebsocketsAgentScanClient().scan("https://secure.example.de", TOKEN, CONFIG))
    assert spy["ws_url"] == "wss://secure.example.de/agent/scan"


def test_collects_host_detail_until_scan_complete(monkeypatch: pytest.MonkeyPatch) -> None:
    incoming: list[dict[str, Any]] = [
        {"type": "host_detail", "ip": "10.0.0.5", "mac": "AA:BB:CC:DD:EE:01"},
        {"type": "host_detail", "ip": "10.0.0.6", "mac": "AA:BB:CC:DD:EE:02"},
        {"type": "scan_complete", "total_found": 2},
        {"type": "host_detail", "ip": "10.0.0.7"},  # nach complete -> ignoriert
    ]
    _install_connect(monkeypatch, incoming=incoming)

    results = asyncio.run(WebsocketsAgentScanClient().scan(URL, TOKEN, CONFIG))

    assert len(results) == 2
    assert [r["ip"] for r in results] == ["10.0.0.5", "10.0.0.6"]


def test_error_message_breaks_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    incoming = [
        {"type": "host_detail", "ip": "10.0.0.5"},
        {"type": "error", "message": "scan aborted"},
        {"type": "host_detail", "ip": "10.0.0.6"},  # nach error -> ignoriert
    ]
    _install_connect(monkeypatch, incoming=incoming)

    results = asyncio.run(WebsocketsAgentScanClient().scan(URL, TOKEN, CONFIG))

    # Nur der erste host_detail vor dem error-Frame.
    assert [r["ip"] for r in results] == ["10.0.0.5"]


def test_connection_failure_raises_agent_scan_error_no_pseudo_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """S3-Heilung: ein WS-Fehler ist KEIN Pseudo-Host, sondern AgentScanError."""
    warnings: list[tuple[str, dict[str, Any]]] = []

    def boom_connect(ws_url: str, **kwargs: Any) -> _FakeConnect:
        raise OSError("ws handshake failed")

    monkeypatch.setattr("infrastructure.agent.scan_client.websockets.connect", boom_connect)
    monkeypatch.setattr(
        "infrastructure.agent.scan_client._logger.warning",
        lambda event, **kw: warnings.append((event, kw)),
    )

    with pytest.raises(AgentScanError) as exc_info:
        asyncio.run(WebsocketsAgentScanClient().scan(URL, TOKEN, CONFIG))

    # Der Fehler traegt die url + den Grund; kein Pseudo-Host wird zurueckgegeben.
    assert exc_info.value.url == URL
    assert "ws handshake failed" in exc_info.value.reason
    assert warnings and warnings[0][0] == "agent_scan_failed"
