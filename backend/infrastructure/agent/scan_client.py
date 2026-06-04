"""Adapter fuer den Port ``AgentScanClient`` (WebSocket-Proxy-Scan).

Sendet die Scan-Config an einen Remote-Agenten und sammelt die Host-Ergebnisse.
``websockets`` ist eine deklarierte Dependency (``pyproject.toml``) und wird
darum TOP-LEVEL importiert -- kein optionaler ``try/except ImportError`` mit
stillem Fallback (Finding S3): fehlt die Lib, ist das ein Setup-Fehler, kein
Pseudo-Ergebnis.

TOKEN-KANAL-REPARATUR (ADR 0008): Der Token wandert in den BODY der ersten
WebSocket-Nachricht (``{**config, "token": token}``), NICHT in einen
Verbindungs-Header. Begruendung: die zurueckgestellte Server-Seite prueft den
Token genau dort (``config.get("token")``), ein In-Band-Auth-Frame ist
transport-/proxy-/versions-robuster als ``extra_headers`` beim WS-Handshake (das
Kwarg wurde ueber websockets-Versionen hinweg umbenannt). Der Altcode legte den
Token in den Header und die Server-Seite las den Body -> der Kanal war gebrochen.

S3-Linie: ein Verbindungs-/Uebertragungsfehler wird NICHT als Pseudo-Host in die
Ergebnisliste geschmuggelt (so der Altcode), sondern als typisierter
``AgentScanError`` propagiert -- plus ``logger.warning``, damit der Fehlschlag
sichtbar ist. Die api-Schicht mappt den Fehler spaeter auf einen Statuscode.
"""

import json
from typing import Any

import structlog
import websockets

from infrastructure.agent.errors import AgentScanError

_logger = structlog.get_logger(__name__)

_PING_TIMEOUT_SECONDS = 10


def _to_ws_url(url: str) -> str:
    """http -> ws, https -> wss, plus ``/agent/scan`` (altcode-treu)."""
    return url.replace("http://", "ws://").replace("https://", "wss://") + "/agent/scan"


class WebsocketsAgentScanClient:
    """Erfuellt das ``AgentScanClient``-Protocol strukturell (WebSocket)."""

    async def scan(self, url: str, token: str, config: dict[str, Any]) -> list[dict[str, Any]]:
        ws_url = _to_ws_url(url)
        results: list[dict[str, Any]] = []
        try:
            async with websockets.connect(ws_url, ping_timeout=_PING_TIMEOUT_SECONDS) as ws:
                # Token im BODY der ersten Nachricht -- NICHT im Header (ADR 0008).
                await ws.send(json.dumps({**config, "token": token}))
                async for raw in ws:
                    data = json.loads(raw)
                    message_type = data.get("type")
                    if message_type == "host_detail":
                        results.append(data)
                    elif message_type in ("scan_complete", "error"):
                        break
        except Exception as exc:  # jede WS-/Transport-Stoerung
            # Muster-i (S3): NICHT als Pseudo-Host in results schmuggeln, sondern
            # sichtbar machen und als typisierten Fehler propagieren.
            _logger.warning("agent_scan_failed", url=url, error=str(exc))
            raise AgentScanError(url, str(exc)) from exc
        return results
