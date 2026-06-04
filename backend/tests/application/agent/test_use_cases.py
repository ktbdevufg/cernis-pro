"""Tests der agent-Use-Cases gegen In-Memory-Fakes der Ports.

Kein echtes SQLite/keyring/Netz noetig -- wir testen gegen die Protocols, also
reichen in-memory dicts und Spies. Kern der Behauptungen: die Variante-B-Trennung
(Stammdaten ins Repository, Token getrennt in den SecretStore unter
``token_key(id)``), der enabled-Filter fuer ping/scan (deaktiviert ->
``AgentNotFoundError``), und dass der Token aus dem SecretStore an die Clients
gereicht wird.

Async-Smokes laufen ueber ``asyncio.run`` (kein ``pytest-asyncio``).
"""

import asyncio
from typing import Any

import pytest

from application.agent import (
    AgentNotFoundError,
    DeleteAgent,
    ListAgents,
    PingAgent,
    SaveAgent,
    ScanViaAgent,
)
from domain.agent import AgentPingResult, RemoteAgent, token_key
from ports.agent import AgentPinger, AgentRepository, AgentScanClient
from ports.settings import SecretStore

AGENT_ID = "agent-1"


def _agent(agent_id: str = AGENT_ID, **over: Any) -> RemoteAgent:
    base: dict[str, Any] = {
        "id": agent_id,
        "name": "VPS Netcup",
        "url": "http://vps.example.de:8766",
        "enabled": True,
        "cidrs": ("10.0.0.0/24",),
    }
    base.update(over)
    return RemoteAgent(**base)


class FakeAgentRepository:
    """In-Memory-Implementierung des AgentRepository-Protocols."""

    def __init__(self) -> None:
        self._data: dict[str, RemoteAgent] = {}

    def get(self, agent_id: str) -> RemoteAgent | None:
        return self._data.get(agent_id)

    def get_all(self, enabled_only: bool) -> list[RemoteAgent]:
        agents = list(self._data.values())
        if enabled_only:
            agents = [a for a in agents if a.enabled]
        return agents

    def save(self, agent: RemoteAgent) -> None:
        self._data[agent.id] = agent

    def delete(self, agent_id: str) -> None:
        self._data.pop(agent_id, None)


class FakeSecretStore:
    """In-Memory-Implementierung des SecretStore-Protocols."""

    def __init__(self) -> None:
        self._data: dict[str, str] = {}

    def get(self, key: str) -> str | None:
        return self._data.get(key)

    def set(self, key: str, value: str) -> None:
        self._data[key] = value

    def delete(self, key: str) -> None:
        self._data.pop(key, None)

    def exists(self, key: str) -> bool:
        return key in self._data


class FakeAgentPinger:
    """Spy-Implementierung des AgentPinger-Protocols."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.result = AgentPingResult(reachable=True, version="1.0.0")

    async def ping(self, url: str, token: str) -> AgentPingResult:
        self.calls.append((url, token))
        return self.result


class FakeAgentScanClient:
    """Spy-Implementierung des AgentScanClient-Protocols."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self.result: list[dict[str, Any]] = [{"type": "host_detail", "ip": "10.0.0.5"}]

    async def scan(self, url: str, token: str, config: dict[str, Any]) -> list[dict[str, Any]]:
        self.calls.append((url, token, config))
        return self.result


@pytest.fixture
def repo() -> FakeAgentRepository:
    return FakeAgentRepository()


@pytest.fixture
def secrets() -> FakeSecretStore:
    return FakeSecretStore()


# ── Struktureller Vertrag: Fakes erfuellen die Ports ──────────────────────


def test_fakes_conform_to_ports() -> None:
    _r: AgentRepository = FakeAgentRepository()
    _s: SecretStore = FakeSecretStore()
    _p: AgentPinger = FakeAgentPinger()
    _c: AgentScanClient = FakeAgentScanClient()


# ── ListAgents ────────────────────────────────────────────────────────────


def test_list_agents_returns_enabled_only(
    repo: FakeAgentRepository, secrets: FakeSecretStore
) -> None:
    repo.save(_agent("on", enabled=True))
    repo.save(_agent("off", enabled=False))
    result = ListAgents(repo)()
    assert {a.id for a in result} == {"on"}


# ── SaveAgent (Variante-B-Trennung) ───────────────────────────────────────


def test_save_agent_writes_repo_and_token_separately(
    repo: FakeAgentRepository, secrets: FakeSecretStore
) -> None:
    SaveAgent(repo, secrets)(_agent(), token="s3cret")
    # Stammdaten im Repository ...
    assert repo.get(AGENT_ID) == _agent()
    # ... Token getrennt im SecretStore unter token_key(id).
    assert secrets.get(token_key(AGENT_ID)) == "s3cret"


def test_save_agent_empty_token_deletes_from_secret_store(
    repo: FakeAgentRepository, secrets: FakeSecretStore
) -> None:
    secrets.set(token_key(AGENT_ID), "alt")
    SaveAgent(repo, secrets)(_agent(), token="")
    # Leeres Token -> Secret geloescht (idempotentes Muster UpdateSecret).
    assert secrets.exists(token_key(AGENT_ID)) is False
    # Stammdaten trotzdem gespeichert.
    assert repo.get(AGENT_ID) == _agent()


def test_save_agent_none_token_deletes_from_secret_store(
    repo: FakeAgentRepository, secrets: FakeSecretStore
) -> None:
    secrets.set(token_key(AGENT_ID), "alt")
    SaveAgent(repo, secrets)(_agent(), token=None)
    assert secrets.exists(token_key(AGENT_ID)) is False


# ── DeleteAgent (loescht beides) ──────────────────────────────────────────


def test_delete_agent_removes_repo_and_token(
    repo: FakeAgentRepository, secrets: FakeSecretStore
) -> None:
    repo.save(_agent())
    secrets.set(token_key(AGENT_ID), "s3cret")
    DeleteAgent(repo, secrets)(AGENT_ID)
    assert repo.get(AGENT_ID) is None
    # Kein verwaister Token im Keystore.
    assert secrets.exists(token_key(AGENT_ID)) is False


def test_delete_unknown_agent_is_idempotent(
    repo: FakeAgentRepository, secrets: FakeSecretStore
) -> None:
    # Weder Repo noch Secret vorhanden -> kein Fehler.
    DeleteAgent(repo, secrets)("never-existed")


# ── PingAgent ─────────────────────────────────────────────────────────────


def test_ping_unknown_agent_raises_not_found(
    repo: FakeAgentRepository, secrets: FakeSecretStore
) -> None:
    pinger = FakeAgentPinger()
    with pytest.raises(AgentNotFoundError) as exc_info:
        asyncio.run(PingAgent(repo, pinger, secrets)("unknown"))
    assert exc_info.value.agent_id == "unknown"
    # Kein Ping-Versuch auf einen unbekannten Agenten.
    assert pinger.calls == []


def test_ping_disabled_agent_raises_not_found(
    repo: FakeAgentRepository, secrets: FakeSecretStore
) -> None:
    # Altcode-treu: ein deaktivierter Agent ist fuer ping unsichtbar.
    repo.save(_agent(enabled=False))
    pinger = FakeAgentPinger()
    with pytest.raises(AgentNotFoundError):
        asyncio.run(PingAgent(repo, pinger, secrets)(AGENT_ID))
    assert pinger.calls == []


def test_ping_reads_token_from_secret_store_and_passes_it(
    repo: FakeAgentRepository, secrets: FakeSecretStore
) -> None:
    repo.save(_agent())
    secrets.set(token_key(AGENT_ID), "s3cret")
    pinger = FakeAgentPinger()
    result = asyncio.run(PingAgent(repo, pinger, secrets)(AGENT_ID))
    assert result.reachable is True
    # url + Token-aus-SecretStore an den Pinger gereicht.
    assert pinger.calls == [(_agent().url, "s3cret")]


def test_ping_missing_token_passes_empty_string(
    repo: FakeAgentRepository, secrets: FakeSecretStore
) -> None:
    # Kein Token gesetzt -> "" (kein None an den Pinger).
    repo.save(_agent())
    pinger = FakeAgentPinger()
    asyncio.run(PingAgent(repo, pinger, secrets)(AGENT_ID))
    assert pinger.calls == [(_agent().url, "")]


# ── ScanViaAgent ──────────────────────────────────────────────────────────


def test_scan_unknown_agent_raises_not_found(
    repo: FakeAgentRepository, secrets: FakeSecretStore
) -> None:
    client = FakeAgentScanClient()
    with pytest.raises(AgentNotFoundError):
        asyncio.run(ScanViaAgent(repo, client, secrets)("unknown", {"cidr": "10.0.0.0/24"}))
    assert client.calls == []


def test_scan_disabled_agent_raises_not_found(
    repo: FakeAgentRepository, secrets: FakeSecretStore
) -> None:
    repo.save(_agent(enabled=False))
    client = FakeAgentScanClient()
    with pytest.raises(AgentNotFoundError):
        asyncio.run(ScanViaAgent(repo, client, secrets)(AGENT_ID, {"cidr": "10.0.0.0/24"}))
    assert client.calls == []


def test_scan_reads_token_and_passes_config(
    repo: FakeAgentRepository, secrets: FakeSecretStore
) -> None:
    repo.save(_agent())
    secrets.set(token_key(AGENT_ID), "s3cret")
    client = FakeAgentScanClient()
    config = {"cidr": "10.0.0.0/24"}
    results = asyncio.run(ScanViaAgent(repo, client, secrets)(AGENT_ID, config))
    assert results == client.result
    assert client.calls == [(_agent().url, "s3cret", config)]
