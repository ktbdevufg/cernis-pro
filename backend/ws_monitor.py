"""WebSocket-Handler ``/ws/monitor`` -- lebt im Composition Root, NICHT im api-Ring.

Warum hier und nicht in ``api/`` (gleiche Begruendung wie ``ws_scan.py``): Der
Handler verdrahtet den Broadcaster-Adapter (``infrastructure``) mit dem
``RunMonitor``-Status (``application``) und baut den Connect-Frame aus beiden --
Importe, die der api-Ring laut import-linter nicht halten darf (api -> nur
application). ``backend/ws_monitor.py`` liegt flach in ``backend/`` -- kein Submodul
eines ``root_package`` --, ist also wie ``app.py``/``ws_scan.py`` von den Contracts
ausgenommen (Composition-Root-Ausnahme).

ROLLENTEILUNG WS vs. Broadcaster (M.9-Naht):
* Der **Broadcaster** (``infrastructure.monitoring.broadcaster``) haelt die
  Subscriber und baut die laufenden ``monitor_update``-Frames (Fan-out aus dem
  Loop). Er kennt die Targets NICHT.
* Dieser **Handler** baut den CONNECT-Frame (``{"type":"monitor_status",...}``),
  denn der braucht den ``current_status`` MIT ``label``-Anreicherung -- und die
  Anreicherung (RunMonitor-Status + TargetSource) kennt nur der Composition Root.
  Beides ueber den injizierten ``status_provider`` gekapselt.

LIFECYCLE (altcode-treu, ``main.ws_monitor`` Z.410-423): accept -> Connect-Frame
senden -> ``broadcaster.subscribe`` -> offen halten (``while True: sleep(30)``, nur
Keep-Alive, der Push kommt aus dem Loop ueber den Broadcaster) -> ``finally:
broadcaster.unsubscribe``. Der Connect-Frame geht BEWUSST VOR dem ``subscribe``
(wie der Altcode): so kann zwischen Frame und Registrierung kein Loop-Update den
Connect-Frame ueberholen.

Der Handler bekommt Broadcaster + ``status_provider`` injiziert (gebaut in
``app.py``) -- er konstruiert nichts selbst.
"""

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import WebSocket

# Keep-Alive-Takt des offenen Handlers (altcode-treu, ``main.ws_monitor``): der
# Handler empfaengt passiv, die ``monitor_update``-Frames pusht der Loop ueber den
# Broadcaster. Der Sleep haelt die Coroutine nur am Leben.
_KEEPALIVE_SECONDS = 30

# Der Broadcaster-Handle (subscribe/unsubscribe). Als ``Any`` gehalten, damit dieser
# Composition-Root-Modul keinen harten Typ-Vertrag ueber den Port hinaus aufmacht --
# app.py uebergibt die konkrete WebSocketMonitorBroadcaster-Instanz.
Broadcaster = Any

# Liefert die angereicherte Status-Map ``{tid: {"alive": bool, "label": str}}``
# (RunMonitor.current_status() + TargetSource-Anreicherung). Verdrahtet in app.py.
StatusProvider = Callable[[], dict[str, dict[str, Any]]]


def make_ws_monitor(
    broadcaster: Broadcaster,
    status_provider: StatusProvider,
) -> Callable[[WebSocket], Awaitable[None]]:
    """Baut den ``/ws/monitor``-Handler mit injiziertem Broadcaster + Status-Provider.

    ``broadcaster`` ist die EINE langlebige Broadcaster-Instanz, die auch der
    ``RunMonitor``-Loop bespielt -- so sieht eine frisch verbundene Connection die
    naechste Loop-Runde. ``status_provider()`` liefert die label-angereicherte
    Status-Map fuer den Connect-Frame (frisch je Connect aufgeloest).
    """

    async def ws_monitor(websocket: WebSocket) -> None:
        await websocket.accept()

        # Connect-Frame VOR dem subscribe (Altcode-Reihenfolge): aktueller Stand mit
        # label-Anreicherung. Form exakt wie Altcode-Connect-Frame.
        await websocket.send_json({"type": "monitor_status", "status": status_provider()})

        await broadcaster.subscribe(websocket)
        try:
            # Offen halten: die monitor_update-Frames pusht der Loop ueber den
            # Broadcaster, dieser Handler empfaengt passiv. Hier nur Keep-Alive.
            # Ein Client-Disconnect cancelt diese Coroutine (CancelledError, eine
            # BaseException) bzw. wirft beim Schreiben -- beides laeuft ueber das
            # ``finally`` ins unsubscribe. Altcode-treu (``main.ws_monitor`` haelt
            # ebenso nur ``while True: sleep(30)`` + ``finally: unsubscribe``).
            while True:
                await _sleep(_KEEPALIVE_SECONDS)
        finally:
            await broadcaster.unsubscribe(websocket)

    return ws_monitor


async def _sleep(seconds: float) -> None:
    """Indirektion um ``asyncio.sleep`` -- haelt den Keep-Alive-Takt an EINER Stelle
    und macht den Loop in Tests ohne echten Zeitverbrauch ersetzbar."""
    await asyncio.sleep(seconds)
