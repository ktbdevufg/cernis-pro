"""WebSocket-Handler ``/ws/pcap`` -- lebt im Composition Root, NICHT im api-Ring.

NEUBAU des kaputten Altcode-WS (``main.ws_pcap`` Z.1513-1531): dort haengte der
Handler einen ``send_packet``-Callback ueber ``pcap_subscribe`` in den Sniffer-
Thread, mit stillem ``except: pass`` um jeden Sende-Fehler (S3) und ohne Dead-
Cleanup. Hier laeuft das Fan-out sauber ueber den ``WebSocketCaptureBroadcaster``
(C.3, M.9-Stil): der ``RunCapture``-Loop broadcastet ``capture_packet``-Frames in
DIESELBE Broadcaster-Singleton-Instanz, dieser Handler subscribet nur.

Warum hier und nicht in ``api/`` (gleiche Begruendung wie ``ws_monitor.py``): Der
Handler verdrahtet den Broadcaster-Adapter (``infrastructure``) mit dem WS-
Transport -- ein Import, den der api-Ring laut import-linter nicht halten darf
(api -> nur application). ``backend/ws_pcap.py`` liegt flach in ``backend/`` -- kein
Submodul eines ``root_package`` --, ist also wie ``app.py``/``ws_monitor.py`` von
den Contracts ausgenommen (Composition-Root-Ausnahme).

LIFECYCLE (ws_monitor-treu, KEIN Connect-Frame): accept -> ``subscribe`` -> offen
halten (``while True: sleep(30)``, nur Keep-Alive, der Push kommt aus dem
RunCapture-Loop ueber den Broadcaster) -> ``finally: unsubscribe``. Anders als
``/ws/monitor`` gibt es KEINEN Connect-Frame: der Capture hat keinen "aktuellen
Stand"-Frame (die Pakete kommen rein, sobald ein Capture laeuft). WICHTIG: Der WS-
Connect startet KEINEN Capture -- ein WS ohne laufenden ``RunCapture``-Loop bekommt
einfach keine Frames (altcode-treu; der Start laeuft ueber ``POST /api/pcap/start``).

Der Handler bekommt den Broadcaster injiziert (gebaut in ``app.py``) -- er
konstruiert nichts selbst.
"""

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import WebSocket

# Keep-Alive-Takt des offenen Handlers (ws_monitor-treu): der Handler empfaengt
# passiv, die capture_packet-Frames pusht der RunCapture-Loop ueber den Broadcaster.
_KEEPALIVE_SECONDS = 30

# Der Broadcaster-Handle (subscribe/unsubscribe). Als ``Any`` gehalten, damit dieser
# Composition-Root-Modul keinen harten Typ-Vertrag ueber den Port hinaus aufmacht --
# app.py uebergibt die konkrete WebSocketCaptureBroadcaster-Instanz.
Broadcaster = Any


def make_ws_pcap(broadcaster: Broadcaster) -> Callable[[WebSocket], Awaitable[None]]:
    """Baut den ``/ws/pcap``-Handler mit injiziertem Broadcaster-Singleton.

    ``broadcaster`` ist die EINE langlebige Instanz, die auch der ``RunCapture``-Loop
    bespielt -- so sieht eine frisch verbundene Connection die naechsten Pakete des
    laufenden Captures (oder nichts, wenn keiner laeuft).
    """

    async def ws_pcap(websocket: WebSocket) -> None:
        await websocket.accept()
        # KEIN Connect-Frame (anders als /ws/monitor): Capture hat keinen Stand-Frame.
        await broadcaster.subscribe(websocket)
        try:
            # Offen halten: die capture_packet-Frames pusht der RunCapture-Loop ueber
            # den Broadcaster, dieser Handler empfaengt passiv. Hier nur Keep-Alive.
            # Ein Client-Disconnect cancelt diese Coroutine (CancelledError) bzw. wirft
            # beim Schreiben -- beides laeuft ueber das ``finally`` ins unsubscribe.
            while True:
                await _sleep(_KEEPALIVE_SECONDS)
        finally:
            await broadcaster.unsubscribe(websocket)

    return ws_pcap


async def _sleep(seconds: float) -> None:
    """Indirektion um ``asyncio.sleep`` -- haelt den Keep-Alive-Takt an EINER Stelle
    und macht den Loop in Tests ohne echten Zeitverbrauch ersetzbar."""
    await asyncio.sleep(seconds)
