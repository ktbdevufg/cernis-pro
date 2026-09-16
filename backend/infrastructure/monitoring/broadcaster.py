"""Adapter fuer ``MonitorBroadcasterPort`` -- der WS-Fan-out des Live-Monitors (M.9).

Der monitor-Loop (``RunMonitor``, M.5) ist ein ENDLOSER zentraler Loop, der pro
Mess-Runde ein Update an N WS-Subscriber PUSHT (Fan-out) -- anders als der
scanning-Use-Case (ein endlicher Generator <-> ein WS-Handler, kein Broadcaster).
Darum ein ECHTER Broadcaster mit Subscriber-Verwaltung: ``RunMonitor`` ruft nur
``broadcast(target, sample, event)`` und weiss nicht, dass dahinter WS-Connections
haengen; dieser Adapter haelt die Connections und macht das eigentliche Fan-out.

NAHT (Port-Vertrag): ``broadcast`` nimmt DOMAENEN-Objekte (MonitorTarget /
PingSample / MonitorEventType|None), KEIN fertiges WS-dict. Das ``monitor_update``-
Frame baut DIESER Adapter am Rand -- altcode-treu zu ``modules/monitor._broadcast``
(``modules/monitor.py`` Z.276-285): ``ts`` ist der ROHE UNIX-``timestamp`` (float,
KEINE ``%H:%M:%S``-Formatierung -- die Format-Naht aus M.2 betrifft nur DB/REST,
NICHT den WS-Frame). ``event`` serialisiert als sein StrEnum-Wert oder ``None``.

SUBSCRIBER-LIFECYCLE: ``subscribe``/``unsubscribe`` sind Adapter-Erweiterungen
ueber den Port hinaus -- nur der ``/ws/monitor``-Handler (Composition Root,
``ws_monitor.py``) ruft sie beim Connect/Disconnect. ``RunMonitor`` sieht NUR
``broadcast``. Eine EINZIGE langlebige Instanz wird in ``app.py`` gebaut und an
``RunMonitor`` UND ``make_ws_monitor`` uebergeben -- Loop und Handler teilen
dieselben Subscriber.

DEAD-CLEANUP (altcode-treu, ``modules/monitor.py`` Z.207-215): Das Fan-out laeuft
ueber einen ``list()``-Snapshot der Subscriber; eine Connection, deren ``send_json``
wirft (Client weg, Broken Pipe), wird gesammelt und nach der Runde entfernt
(best-effort + Warn-Log pro toter Connection -- mit Log kein stiller S3-Fallback).
Keine Subscriber -> ``broadcast`` ist ein No-op (kein Fehler, Port-Vertrag).

FastAPI-Import: zulaessig -- dieser Adapter liegt in ``infrastructure/`` (kennt den
Transport), nicht im api-Ring. ``WebSocket`` ist hier nur der Connection-Handle des
Subscribers; die Frame-Form bleibt der einzige Vertrag nach aussen.
"""

from typing import Any

import structlog
from fastapi import WebSocket

from domain.monitoring import MonitorEventType, MonitorTarget, PingSample

_logger = structlog.get_logger(__name__)


class WebSocketMonitorBroadcaster:
    """Erfuellt ``MonitorBroadcasterPort`` strukturell; haelt die WS-Subscriber.

    Langlebige Singleton-Instanz (in ``app.py`` einmal gebaut): der monitor-Loop
    broadcastet hinein, die WS-Handler subscriben/unsubscriben. Keine Doppelpruefung
    beim ``subscribe`` -- der Handler registriert genau einmal pro Connection.
    """

    def __init__(self) -> None:
        # Liste statt Set: WebSocket ist nicht garantiert hashbar/identitaetsstabil
        # ueber alle Starlette-Versionen, und die Reihenfolge (Verbindungsreihenfolge)
        # ist altcode-treu (``_subscribers: list``). Doppel-Eintraege entstehen nicht
        # (ein subscribe je Connection).
        self._subscribers: list[WebSocket] = []

    async def subscribe(self, websocket: WebSocket) -> None:
        """Registriert eine WS-Connection fuer kuenftige ``monitor_update``-Frames."""
        self._subscribers.append(websocket)

    async def unsubscribe(self, websocket: WebSocket) -> None:
        """Entfernt eine WS-Connection. Idempotent -- ein nie/schon entferntes Handle
        ist kein Fehler (Disconnect kann mehrfach auslaufen)."""
        if websocket in self._subscribers:
            self._subscribers.remove(websocket)

    async def broadcast(
        self,
        target: MonitorTarget,
        sample: PingSample,
        event: MonitorEventType | None,
    ) -> None:
        """Baut das ``monitor_update``-Frame und pusht es an alle Subscriber.

        Frame-Form exakt wie Altcode ``_broadcast`` (``modules/monitor.py``
        Z.276-285): ``ts`` roher UNIX-Timestamp (float), ``event`` als StrEnum-Wert
        oder ``None``. Fan-out ueber einen ``list()``-Snapshot; tote Connections
        werden gesammelt und nach der Runde entfernt (best-effort + Warn-Log).
        """
        frame: dict[str, Any] = {
            "type": "monitor_update",
            "target_id": target.id,
            "label": target.label,
            "alive": sample.alive,
            "rtt_ms": sample.rtt_ms,
            "loss_pct": sample.loss_pct,
            "event": event.value if event else None,
            "ts": sample.timestamp,
        }
        dead: list[WebSocket] = []
        for websocket in list(self._subscribers):
            try:
                await websocket.send_json(frame)
            except Exception as exc:
                # Client weg / Broken Pipe: NICHT den Loop killen -- sammeln,
                # geloggt entfernen. Mit Log kein stiller S3-Fang.
                _logger.warning("monitor_broadcast_subscriber_dropped", error=str(exc))
                dead.append(websocket)
        for websocket in dead:
            await self.unsubscribe(websocket)
