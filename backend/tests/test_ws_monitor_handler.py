"""Tests fuer den ``/ws/monitor``-Handler (M.9, Composition Root ``ws_monitor.py``).

Der Handler wird mit einem Fake-Broadcaster + Fake-``status_provider`` auf eine
FRISCHE FastAPI-App gehaengt (``add_api_websocket_route``) -- KEINE app.py-Lifespan,
kein echter Loop, kein Netz. Geprueft wird:

* der CONNECT-Frame (``{"type":"monitor_status","status": <angereichert>}``) -- die
  einzige ohne Loop-Takt deterministisch beobachtbare Ausgabe (wie der
  M.1-Charakterisierer, nur gegen den v2-Handler statt ``main.ws_monitor``);
* der Subscriber-Lifecycle: subscribe beim Connect, unsubscribe beim Disconnect.

Die laufenden ``monitor_update``-Frames sind NICHT hier getestet -- sie entstehen im
Broadcaster aus dem Loop-Takt (siehe ``infrastructure.monitoring.broadcaster`` /
dessen Test). Hier zaehlt nur, dass der Handler korrekt an den Broadcaster
an-/abmeldet und den Connect-Frame aus dem ``status_provider`` baut.

``ws_monitor.py`` liegt im Composition Root (darf infrastructure/application
importieren); der Test darf das ebenfalls -- er ist kein Ring-Modul.
"""

from typing import Any

from fastapi import FastAPI, WebSocket
from fastapi.testclient import TestClient

from ws_monitor import make_ws_monitor


class _FakeBroadcaster:
    """Zaehlt subscribe/unsubscribe und haelt die aktuell registrierten Connections.

    Strukturell wie ``WebSocketMonitorBroadcaster`` (subscribe/unsubscribe), aber
    ohne Fan-out -- der Handler ruft nur diese beiden Methoden.
    """

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


def _client(
    status: dict[str, dict[str, Any]],
    broadcaster: _FakeBroadcaster | None = None,
) -> tuple[TestClient, _FakeBroadcaster]:
    bc = broadcaster or _FakeBroadcaster()
    app = FastAPI()
    app.add_api_websocket_route("/ws/monitor", make_ws_monitor(bc, lambda: status))
    return TestClient(app), bc


# ── Connect-Frame (angereicherte Status-Map) ───────────────────────────────


def test_connect_frame_carries_enriched_status() -> None:
    # Der status_provider liefert bereits die {tid:{alive,label}}-Form (die
    # Anreicherung passiert im Composition Root); der Handler reicht sie 1:1 als
    # Connect-Frame durch -- Shape wie der Altcode-Connect-Frame.
    status = {"wlan": {"alive": True, "label": "WLAN"}}
    client, _ = _client(status)
    with client.websocket_connect("/ws/monitor") as ws:
        frame = ws.receive_json()
    assert frame == {
        "type": "monitor_status",
        "status": {"wlan": {"alive": True, "label": "WLAN"}},
    }


def test_connect_frame_empty_status_is_empty_map() -> None:
    # Leerer Status (noch nichts gemessen / keine Targets) -> leere status-Map,
    # niemals null. Altcode-treu (``status: {}``).
    client, _ = _client({})
    with client.websocket_connect("/ws/monitor") as ws:
        frame = ws.receive_json()
    assert frame == {"type": "monitor_status", "status": {}}


# ── Subscriber-Lifecycle ────────────────────────────────────────────────────


def test_handler_subscribes_on_connect_and_unsubscribes_on_disconnect() -> None:
    status = {"gw_eth0": {"alive": False, "label": "Gateway (eth0)"}}
    client, bc = _client(status)
    assert bc.subscribe_calls == 0
    with client.websocket_connect("/ws/monitor") as ws:
        # Connect-Frame konsumieren, damit der Handler bis zum subscribe gelaufen ist.
        ws.receive_json()
        assert bc.subscribe_calls == 1
        assert len(bc.subscribed) == 1
    # Nach dem Schliessen ist die Connection wieder abgemeldet (finally-Pfad).
    assert bc.unsubscribe_calls == 1
    assert bc.subscribed == []


def test_connect_frame_built_before_subscribe() -> None:
    # SCHARFER Reihenfolge-Vertrag (altcode-treu): der Connect-Frame wird GEBAUT
    # (status_provider aufgerufen) BEVOR subscribe laeuft -- so kann kein Loop-Update
    # den Connect-Frame ueberholen. Schwacher Test ("beide passieren") wuerde auch bei
    # vertauschter Reihenfolge gruen; darum eine GEMEINSAME Event-Sequenz: sowohl
    # status_provider als auch subscribe haengen ihren Marker an dieselbe Liste an.
    # Die Reihenfolge in der Liste ist die echte Aufrufreihenfolge im Handler.
    events: list[str] = []

    class _OrderingBroadcaster:
        async def subscribe(self, _ws: WebSocket) -> None:
            events.append("subscribe")

        async def unsubscribe(self, _ws: WebSocket) -> None:
            events.append("unsubscribe")

    def _ordering_status() -> dict[str, dict[str, Any]]:
        events.append("status_provider")
        return {"wlan": {"alive": True, "label": "WLAN"}}

    app = FastAPI()
    app.add_api_websocket_route(
        "/ws/monitor", make_ws_monitor(_OrderingBroadcaster(), _ordering_status)
    )
    with TestClient(app).websocket_connect("/ws/monitor") as ws:
        ws.receive_json()  # Connect-Frame konsumieren, Handler ist bis zum sleep gelaufen.

    # status_provider (Connect-Frame-Bau) MUSS vor subscribe stehen.
    assert events[0] == "status_provider"
    assert events[1] == "subscribe"
    assert events.index("status_provider") < events.index("subscribe")
