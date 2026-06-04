"""Use-Cases der agent-Domaene (NUR Client-Seite).

Orchestrieren Domaene + Ports. Kennen ``domain/`` und ``ports/``, NIEMALS
``infrastructure/`` (maschinell per import-linter erzwungen). Alle Ports kommen
per Constructor-Injection als Protocol-Typ herein -- nie ein konkreter Adapter.
Kein State ueber Aufrufe hinaus, keine Framework-Imports.

Hier wird die Variante-B-Trennung sichtbar verdrahtet (Muster settings): die
Stammdaten gehen ins ``AgentRepository`` (tokenlos), der Token getrennt in den
``SecretStore`` unter ``token_key(id)``. Repository und SecretStore laufen so nie
auseinander; der Token verlaesst den SecretStore nur, um an Pinger/ScanClient
weitergereicht zu werden -- in die DB gelangt er nie.
"""

from typing import Any

from application.agent.errors import AgentNotFoundError
from domain.agent import AgentPingResult, RemoteAgent, token_key
from ports.agent import AgentPinger, AgentRepository, AgentScanClient
from ports.settings import SecretStore


class ListAgents:
    """Listet die aktiven Agenten (enabled-gefiltert, altcode-treu)."""

    def __init__(self, repository: AgentRepository) -> None:
        self._repository = repository

    def __call__(self) -> list[RemoteAgent]:
        # Altcode-treu: ``get_agents`` las ausschliesslich ``WHERE enabled=1``.
        return self._repository.get_all(enabled_only=True)


class SaveAgent:
    """Legt einen Agenten an/aktualisiert ihn; verwahrt den Token getrennt."""

    def __init__(self, repository: AgentRepository, secret_store: SecretStore) -> None:
        self._repository = repository
        self._secret_store = secret_store

    def __call__(self, agent: RemoteAgent, token: str | None) -> None:
        # Stammdaten ins Repository (tokenlos) ...
        self._repository.save(agent)
        # ... das Geheimnis getrennt in den SecretStore (Muster UpdateSecret):
        # gesetzter Token -> speichern, leer/None -> loeschen (idempotent).
        if token:
            self._secret_store.set(token_key(agent.id), token)
        else:
            self._secret_store.delete(token_key(agent.id))


class DeleteAgent:
    """Loescht einen Agenten samt seinem Token -- keine verwaisten Geheimnisse."""

    def __init__(self, repository: AgentRepository, secret_store: SecretStore) -> None:
        self._repository = repository
        self._secret_store = secret_store

    def __call__(self, agent_id: str) -> None:
        self._repository.delete(agent_id)
        # Sonst bliebe der Token im Keystore verwaist zurueck.
        self._secret_store.delete(token_key(agent_id))


class PingAgent:
    """Prueft die Erreichbarkeit eines aktiven Agenten gegen ``/agent/info``."""

    def __init__(
        self,
        repository: AgentRepository,
        pinger: AgentPinger,
        secret_store: SecretStore,
    ) -> None:
        self._repository = repository
        self._pinger = pinger
        self._secret_store = secret_store

    async def __call__(self, agent_id: str) -> AgentPingResult:
        agent = self._active_agent_or_raise(agent_id)
        token = self._secret_store.get(token_key(agent_id)) or ""
        return await self._pinger.ping(agent.url, token)

    def _active_agent_or_raise(self, agent_id: str) -> RemoteAgent:
        # Enabled-gefilterte Sicht: ein deaktivierter Agent ist unsichtbar
        # (altcode-treu) -> AgentNotFoundError, kein Heilen.
        agent = self._repository.get(agent_id)
        if agent is None or not agent.enabled:
            raise AgentNotFoundError(agent_id)
        return agent


class ScanViaAgent:
    """Treibt einen Proxy-Scan ueber einen aktiven Agenten (WebSocket)."""

    def __init__(
        self,
        repository: AgentRepository,
        scan_client: AgentScanClient,
        secret_store: SecretStore,
    ) -> None:
        self._repository = repository
        self._scan_client = scan_client
        self._secret_store = secret_store

    async def __call__(self, agent_id: str, config: dict[str, Any]) -> list[dict[str, Any]]:
        agent = self._active_agent_or_raise(agent_id)
        token = self._secret_store.get(token_key(agent_id)) or ""
        return await self._scan_client.scan(agent.url, token, config)

    def _active_agent_or_raise(self, agent_id: str) -> RemoteAgent:
        agent = self._repository.get(agent_id)
        if agent is None or not agent.enabled:
            raise AgentNotFoundError(agent_id)
        return agent
