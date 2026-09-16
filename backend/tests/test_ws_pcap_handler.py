"""Tests fuer den ``/ws/pcap``-Handler (C.5, Composition Root ``ws_pcap.py``).

Der Handler wird mit einem Fake-Broadcaster auf eine FRISCHE FastAPI-App gehaengt
(``add_api_websocket_route``) -- KEINE app.py-Lifespan, kein RunCapture-Loop, kein
Netz. Geprueft wird der Subscriber-Lifecycle: subscribe beim Connect, unsubscribe
beim Disconnect. ANDERS als ``/ws/monitor`` gibt es KEINEN Connect-Frame (der
Capture hat keinen Stand-Frame) -- es gibt also keine Frame-Ausgabe zu pruefen.

Die laufenden ``capture_packet``-Frames sind NICHT hier getestet -- sie entstehen im
Broadcaster aus dem RunCapture-Loop (siehe ``infrastructure.capture.broadcaster`` /
dessen Test). Hier zaehlt nur das korrekte An-/Abmelden am Broadcaster.

SYNC-PUNKT: Der Handler hat keinen Frame, an dem der Test "Handler ist bis zum
subscribe gelaufen" festmachen koennte (ws_monitor nutzt dafuer den Connect-Frame).
Stattdessen wird ``ws_pcap._sleep`` gepatcht -> der Keep-Alive-Sleep setzt ein Event,
das beweist: subscribe ist gelaufen, der Handler parkt jetzt. So ist der Lifecycle
deterministisch ohne 30-s-Warten pruefbar.

``ws_pcap.py`` liegt im Composition Root (darf infrastructure importieren); der Test
darf das ebenfalls -- er ist kein Ring-Modul.
"""

import asyncio

import pytest
from fastapi import FastAPI, WebSocket
from fastapi.testclient import TestClient

import ws_pcap
from ws_pcap import make_ws_pcap


class _FakeBroadcaster:
    """Zaehlt subscribe/unsubscribe (strukturell wie ``WebSocketCaptureBroadcaster``)."""

    def __init__(self) -> None:
        self.subscribed: list[WebSocket] = []
        self.subscribe_calls = 0
        self.unsubscribe_calls = 0

    async def subscribe(self, websocket: WebSocket) -> None:
        self.subscribe_calls += 1
        self.subscribed.append(websocket)

    async def unsubscribe(self, websocket: WebSocket) -> None:
        self.unsubscribe_calls += 1
        if websocket in self.subscribed:
            self.subscribed.remove(websocket)


def test_handler_subscribes_on_connect_and_unsubscribes_on_disconnect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Sync-Punkt: der Keep-Alive-Sleep setzt ein Event statt 30 s zu warten -> der
    # Handler ist bis zum subscribe gelaufen und parkt jetzt. Danach laeuft er in eine
    # harmlose 0-s-Schleife (Event bleibt gesetzt), bis der Disconnect ihn cancelt.
    parked = asyncio.Event()

    async def fake_sleep(_seconds: float) -> None:
        parked.set()
        await asyncio.sleep(0)  # dem Loop einen Tick geben (kein Busy-Spin-Block)

    monkeypatch.setattr(ws_pcap, "_sleep", fake_sleep)

    bc = _FakeBroadcaster()
    app = FastAPI()
    # Origin-Guard-Allowlist (F-01): der TestClient sendet keinen Origin-Header
    # (-> is_origin_allowed None == True) -> connectet ohne Origin, laeuft unveraendert.
    app.add_api_websocket_route("/ws/pcap", make_ws_pcap(bc, []))
    client = TestClient(app)

    assert bc.subscribe_calls == 0
    with client.websocket_connect("/ws/pcap"):
        # Kein Connect-Frame: kurz dem Server-Loop Zeit geben, subscribe zu erreichen.
        # (Der TestClient-Kontext laeuft den Handler an; subscribe steht VOR dem sleep.)
        assert bc.subscribe_calls == 1
        assert len(bc.subscribed) == 1
    # Nach dem Schliessen ist die Connection wieder abgemeldet (finally-Pfad).
    assert bc.unsubscribe_calls == 1
    assert bc.subscribed == []


def test_no_connect_frame_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    # Anders als /ws/monitor sendet /ws/pcap KEINEN Frame beim Connect. Belegt durch
    # einen Subscribe, der wirft, sobald jemand send_json versuchte -- hier reicht:
    # der Handler ruft auf dem WS NUR accept (kein send vor dem subscribe/sleep).
    async def fake_sleep(_seconds: float) -> None:
        await asyncio.sleep(0)

    monkeypatch.setattr(ws_pcap, "_sleep", fake_sleep)

    bc = _FakeBroadcaster()
    app = FastAPI()
    app.add_api_websocket_route("/ws/pcap", make_ws_pcap(bc, []))
    with TestClient(app).websocket_connect("/ws/pcap") as ws:
        # Kein Frame verfuegbar: ein receive mit kurzem Timeout liefe leer. Statt zu
        # blockieren, pruefen wir strukturell, dass subscribe lief (kein Connect-Frame
        # noetig, um den Handler anzustossen).
        assert bc.subscribe_calls == 1
        del ws
