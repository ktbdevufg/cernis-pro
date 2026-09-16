"""Ports der agent-Domaene (NUR Client-Seite): Vertraege fuer Persistenz und
ausgehende I/O gegen Remote-Agenten.

Drei getrennte Vertraege:

* ``AgentRepository`` -- REINE Persistenz der Agent-Stammdaten. TOKEN-FREI: der
  Token ist KEIN Bestandteil von ``RemoteAgent`` und laeuft hier nie durch. Das
  Geheimnis lebt im ``SecretStore`` (``ports/settings.py``), den der Use-Case
  separat bedient -- exakt das Variante-B-Muster der settings-Domaene
  (Repository fuer Nicht-Geheimes, SecretStore fuer Secrets). Es gibt darum
  bewusst KEINEN neuen Krypto-Port.
* ``AgentPinger`` -- ausgehender Erreichbarkeits-Check gegen ``/agent/info``.
* ``AgentScanClient`` -- ausgehender Proxy-Scan-Client (WebSocket).

Ping/Scan nehmen den Token als PARAMETER: der Use-Case liest ihn aus dem
``SecretStore`` (via ``domain.agent.token_key``) und reicht ihn herein. Die
Clients kennen weder Keystore noch Key-Schema.

Bewusste Entscheidung: KEIN ``@runtime_checkable``. Die Vertragspruefung laeuft
statisch ueber mypy und ueber die Verdrahtung im Composition Root (``app.py``),
nicht zur Laufzeit per ``isinstance``.

Import von ``domain`` ist erlaubt -- der import-linter-Contract verbietet nur die
Gegenrichtung (domain -> ports) sowie Importe aus ``infrastructure``/``api``.
"""

from typing import Any, Protocol

from domain.agent import AgentPingResult, RemoteAgent


class AgentRepository(Protocol):
    """Reine Persistenz der Remote-Agent-Stammdaten (token-frei, keine I/O)."""

    def get(self, agent_id: str) -> RemoteAgent | None:
        """Ein Agent anhand der id, oder ``None`` wenn nicht vorhanden.

        ``None`` ist ein legitimer Zustand ("nicht registriert"), kein Fehler.
        """
        ...

    def get_all(self, enabled_only: bool) -> list[RemoteAgent]:
        """Alle Agenten. ``enabled_only=True`` filtert auf ``enabled`` (der
        Altcode las ausschliesslich ``WHERE enabled=1``).

        Leerer Bestand -> ``[]``, niemals ``None``.
        """
        ...

    def save(self, agent: RemoteAgent) -> None:
        """Upsert auf ``agent.id`` -- legt an oder aktualisiert.

        Nimmt das Domaenen-Objekt OHNE Token; das Geheimnis schreibt der
        Use-Case getrennt in den ``SecretStore``, nicht das Repository.
        """
        ...

    def delete(self, agent_id: str) -> None:
        """Loescht einen Agenten. Idempotent -- kein Fehler bei unbekannter id
        (altcode-treu: ``DELETE ... WHERE id=?`` ohne Existenzpruefung).

        Das Loeschen des zugehoerigen Tokens aus dem ``SecretStore`` ist Sache
        des Use-Case, nicht des Repositorys.
        """
        ...

    def clear_all(self) -> None:
        """Leert alle Agent-Stammdaten (nur die eigene Tabelle).

        Token-frei wie der uebrige Vertrag: die Tokens im ``SecretStore`` raeumt
        der Use-Case getrennt, nicht das Repository.
        """
        ...


class AgentPinger(Protocol):
    """Ausgehender Erreichbarkeits-Check gegen einen Remote-Agenten."""

    async def ping(self, url: str, token: str) -> AgentPingResult:
        """Prueft ``/agent/info`` des Remote und liefert dessen Info.

        Unerreichbarkeit ist KEIN Fehler, sondern
        ``AgentPingResult(reachable=False, error=...)`` -- analog zum Altcode,
        der bei einer Exception ``{"error": ..., "reachable": False}`` lieferte.
        """
        ...


class AgentScanClient(Protocol):
    """Ausgehender Proxy-Scan gegen einen Remote-Agenten (WebSocket)."""

    async def scan(self, url: str, token: str, config: dict[str, Any]) -> list[dict[str, Any]]:
        """Sendet die Scan-Config an den Remote und sammelt die Host-Ergebnisse.

        ``config`` und die Rueckgabe bleiben ``dict[str, Any]`` -- das
        Host-Format ist im Bestand noch nicht typisiert (eine Typisierung waere
        Scope-Creep). Leeres Ergebnis -> ``[]``.
        """
        ...
