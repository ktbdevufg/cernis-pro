"""Adapter fuer den Port ``AgentPinger`` (urllib GET ``/agent/info``).

Ausgehender Erreichbarkeits-Check gegen einen Remote-Agenten, nativ ueber
``urllib`` (keine neue Dependency, altcode-treuer Transport). ``urllib`` ist
blockierend; der Aufruf laeuft daher in ``asyncio.to_thread``, damit der
``async``-Port-Vertrag den Event-Loop nicht blockiert.

S3-Linie (ADR 0001/0008): Unerreichbarkeit ist KEIN Fehler, sondern ein
legitimes Ergebnis (``AgentPingResult(reachable=False, error=...)``) -- das
bleibt AS-IS gegenueber dem Altcode. Damit der Fehlschlag aber nicht STUMM ist,
wird er als ``logger.warning("agent_ping_failed", ...)`` sichtbar gemacht.

Der Token ist ein Parameter (der Use-Case liest ihn aus dem ``SecretStore``); der
Pinger kennt weder Keystore noch Key-Schema. Er wandert in den
``X-Agent-Token``-Header -- das ist plain HTTP-GET, wo der Header korrekt und
unstrittig ist (der gebrochene Token-Kanal betraf nur den WebSocket-Scan-Pfad,
siehe ``scan_client.py`` / ADR 0008).
"""

import asyncio
import json
import urllib.request

import structlog

from domain.agent import AgentPingResult

_logger = structlog.get_logger(__name__)

_TIMEOUT_SECONDS = 5


def _fetch_info(url: str, token: str) -> dict[str, object]:
    """Blockierender GET ``/agent/info`` -- laeuft im Thread-Executor."""
    request = urllib.request.Request(
        f"{url}/agent/info",
        headers={"X-Agent-Token": token},
    )
    with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as response:
        decoded = json.loads(response.read())
    if not isinstance(decoded, dict):
        # Eine wohlgeformte /agent/info-Antwort ist ein Objekt; alles andere ist
        # ein unbrauchbares Ergebnis -> als unerreichbar behandeln (s. unten).
        raise ValueError("agent/info lieferte kein JSON-Objekt")
    return decoded


class UrllibAgentPinger:
    """Erfuellt das ``AgentPinger``-Protocol strukturell (urllib in to_thread)."""

    async def ping(self, url: str, token: str) -> AgentPingResult:
        try:
            info = await asyncio.to_thread(_fetch_info, url, token)
        except Exception as exc:  # jede I/O-/Parse-Stoerung = unerreichbar
            # AS-IS: Unerreichbarkeit ist ein legitimes Ergebnis, kein Fehler.
            # Muster-i: nicht mehr STUMM -- der Fehlschlag wird geloggt.
            _logger.warning("agent_ping_failed", url=url, error=str(exc))
            return AgentPingResult(reachable=False, error=str(exc))
        # HTTP-200 ist der Erreichbarkeitsbeweis: reachable=True setzt der Pinger
        # selbst; version/platform/hostname kommen aus dem Body.
        return AgentPingResult(
            reachable=True,
            version=str(info.get("version", "")),
            platform=str(info.get("platform", "")),
            hostname=str(info.get("hostname", "")),
        )
