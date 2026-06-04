"""Domaenenmodelle der agent-Domaene (NUR Client-Seite): Remote-Agent-Stammdaten
und Ping-Ergebnis.

Reine Domaenenlogik (stdlib + dataclasses, ADR 0002) -- kein Wissen ueber
Persistenz (SQLite ist Infrastruktur), kein HTTP, keine Krypto, keine Uhr.

v2-S4-Schnitt: ``RemoteAgent`` ist TOKENLOS. Das Geheimnis (Agent-Token) lebt im
OS-Keystore (``SecretStore``), nicht im Stammdaten-Aggregat und nie in der DB.
Der Altcode trug den Fernet-verschluesselten Token in der ``remote_agents``-
Spalte ``token`` und maskierte ihn beim Lesen zu ``"••••••••"`` -- beide Mechaniken
(Token-Feld, ``to_dict``-Maske) entfallen hier bewusst: man kann nicht
maskieren, was nicht da ist. Den Token verbindet der Use-Case ueber
``domain.agent.token_key`` mit dem Keystore; das Repository sieht ihn nie.

Tote Altcode-DB-Spalten ``last_seen``/``version``/``platform`` (im Schema
vorhanden, aber von ``save_agent`` NIE geschrieben) sind KEINE Modellfelder. Was
ein Live-Ping ueber den Remote liefert (``version``/``platform``/``hostname``),
ist ein Ergebnis-Wertobjekt (``AgentPingResult``), kein Stammdatum.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class RemoteAgent:
    """Stammdaten eines Remote-Agenten (Client-Sicht) -- TOKENLOS.

    Das geteilte Geheimnis liegt im ``SecretStore`` unter ``token_key(id)``,
    nicht hier. ``cidrs`` sind die Subnetze, die dieser Agent scannen darf;
    als ``tuple`` statt ``list``, weil das Aggregat frozen ist (analog zu
    ``Device.tags``/``open_ports``).
    """

    id: str
    name: str
    url: str
    enabled: bool = True
    cidrs: tuple[str, ...] = ()


@dataclass(frozen=True)
class AgentPingResult:
    """Ergebnis eines Live-Pings gegen ``/agent/info`` des Remote (Wertobjekt).

    Reines Resultat, kein Stammdatum: ``version``/``platform``/``hostname``
    kommen erst vom erreichbaren Remote, nicht aus der Persistenz.
    ``reachable=False`` plus gefuelltes ``error`` bildet den Altcode-Fall ab, in
    dem ``ping_agent`` bei einer urllib-Exception ``{"error": ..., "reachable":
    False}`` lieferte -- Unerreichbarkeit ist KEIN Fehlerzustand, sondern ein
    legitimes Ergebnis.
    """

    reachable: bool
    version: str = ""
    platform: str = ""
    hostname: str = ""
    error: str = ""
