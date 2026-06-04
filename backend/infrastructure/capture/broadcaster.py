"""Adapter fuer ``CaptureBroadcasterPort`` -- der WS-Fan-out des Live-Captures (C.3).

1:1 nach ``WebSocketMonitorBroadcaster`` (M.9): der C.5-Use-Case iteriert
``async for ps in sniffer.stream(...)`` und ruft pro Paket ``broadcast(ps)`` --
ohne die WS-Connections zu kennen; dieser Adapter haelt die Connections und macht
das Fan-out. Damit ersetzt er den kaputten Altcode-``_subscribers``/``prn``-Pfad
(stilles ``except: pass`` aus dem Sniffer-Thread) durch einen sauberen Push, der
KOMPLETT im Eventloop laeuft (der Adapter sieht den Sniffer-Thread nie -- die
Thread->Loop-Naht liegt im ``packet_sniffer`` ueber die Queue).

NAHT (Port-Vertrag): ``broadcast`` nimmt ein DOMAENEN-``PacketSummary``, KEIN
fertiges WS-dict. Das ``capture_packet``-Frame baut DIESER Adapter am Rand (die
JSON-Projektion bleibt am Rand, nicht im Use-Case). Feldsatz = ``PacketSummary``-
Felder (Altcode-``to_dict`` lieferte ``asdict`` -- gleiche Felder, hier explizit
projiziert, plus der ``type``-Discriminator des Frames).

SUBSCRIBER-LIFECYCLE: ``subscribe``/``unsubscribe`` sind Adapter-Erweiterungen
ueber den Port hinaus -- nur der ``/ws/capture``-Handler (Composition Root) ruft
sie beim Connect/Disconnect. Der Use-Case sieht NUR ``broadcast``. Eine einzige
langlebige Instanz wird in ``app.py`` gebaut und Use-Case + Handler teilen sie.

DEAD-CLEANUP (M.9-treu): Fan-out ueber einen ``list()``-Snapshot; eine Connection,
deren ``send_json`` wirft (Client weg, Broken Pipe), wird gesammelt und nach der
Runde entfernt (best-effort + Warn-Log pro toter Connection -- mit Log kein stiller
S3-Fang). Keine Subscriber -> No-op.
"""

from typing import Any

import structlog
from fastapi import WebSocket

from domain.capture import PacketSummary

_logger = structlog.get_logger(__name__)


class WebSocketCaptureBroadcaster:
    """Erfuellt ``CaptureBroadcasterPort`` strukturell; haelt die WS-Subscriber."""

    def __init__(self) -> None:
        # Liste statt Set (M.9-Begruendung): WebSocket nicht garantiert hashbar/
        # identitaetsstabil; Verbindungsreihenfolge bleibt erhalten.
        self._subscribers: list[WebSocket] = []

    async def subscribe(self, websocket: WebSocket) -> None:
        """Registriert eine WS-Connection fuer kuenftige ``capture_packet``-Frames."""
        self._subscribers.append(websocket)

    async def unsubscribe(self, websocket: WebSocket) -> None:
        """Entfernt eine WS-Connection. Idempotent (Disconnect kann mehrfach auslaufen)."""
        if websocket in self._subscribers:
            self._subscribers.remove(websocket)

    async def broadcast(self, packet: PacketSummary) -> None:
        """Baut das ``capture_packet``-Frame und pusht es an alle Subscriber.

        Fan-out ueber einen ``list()``-Snapshot; tote Connections werden gesammelt
        und nach der Runde entfernt (best-effort + Warn-Log). Ein fehlgeschlagener
        Push an einen Subscriber killt die ANDEREN nicht (und nicht den Capture-Strom).
        """
        frame: dict[str, Any] = {
            "type": "capture_packet",
            "timestamp": packet.timestamp,
            "src_ip": packet.src_ip,
            "dst_ip": packet.dst_ip,
            "src_mac": packet.src_mac,
            "dst_mac": packet.dst_mac,
            "protocol": packet.protocol,
            "src_port": packet.src_port,
            "dst_port": packet.dst_port,
            "length": packet.length,
            "info": packet.info,
            "is_ipv6": packet.is_ipv6,
        }
        dead: list[WebSocket] = []
        for websocket in list(self._subscribers):
            try:
                await websocket.send_json(frame)
            except Exception as exc:
                _logger.warning("capture_broadcast_subscriber_dropped", error=str(exc))
                dead.append(websocket)
        for websocket in dead:
            await self.unsubscribe(websocket)
