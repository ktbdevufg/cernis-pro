"""Characterization-Contract des WebSocket ``/ws/monitor`` (Altcode ``main.ws_monitor``).

Schreibt den Connect-Frame fest -- Sicherheitsnetz fuer die monitoring-Migration.
Netzwerk-/DB-frei: der Handler laeuft auf einer FRISCHEN App
(``add_api_websocket_route``), damit KEINE main-Lifespan (init_db/Monitor/Scheduler
gegen die echte cernis.db) feuert.

Was ``ws_monitor`` beim Connect TUT (Altcode main.py):
    accept -> monitor_subscribe(ws)
    -> send_json({"type": "monitor_status", "status": get_current_status()})
    -> while True: await asyncio.sleep(30)   # haelt offen, bis der Client geht

GENAU der erste Frame ist ohne Loop-Takt beobachtbar und wird hier eingefroren.

BEWUSST NICHT Teil dieses Contracts -- und WARUM:
    ``monitor_update``-Frames entstehen AUSSCHLIESSLICH im Endlos-asyncio-Loop
    ``modules.monitor.run_monitor`` (via ``_broadcast``), getaktet durch
    ``await asyncio.sleep(_interval)`` und echte Ping-Subprozesse. Diese Frame-
    Erzeugung haengt am Loop-Takt + Netz-I/O und ist ohne Loop-Eingriff nicht
    deterministisch testbar. M.1 friert sie NICHT ein. Die Uebergangs-Logik
    (up/down/degraded) wird in M.2/M.5 als reine Funktion extrahiert und DORT
    sauber getestet -- erst dann ist die ``monitor_update``-Form vertraglich.

``get_current_status`` ist In-Memory (``modules.monitor._status``-dict, keine DB).
Die Fixture isoliert den Modul-State VOR und NACH jedem Test, damit kein globaler
State zwischen Tests leakt (die typische In-Memory-Falle).
"""

from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import main
from modules import monitor


@pytest.fixture
def ws_client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    # In-Memory-State VOR dem Test sichern und leeren -- kein Leak aus
    # vorherigen Tests/Imports.
    saved_status = dict(monitor._status)
    saved_subs = list(monitor._subscribers)
    monitor._status.clear()
    monitor._subscribers.clear()

    # get_current_status liest monitor._status; wir setzen einen bekannten Stand.
    monitor._status["wlan"] = True
    monkeypatch.setattr(
        monitor,
        "_targets",
        [monitor.MonitorTarget(id="wlan", label="WLAN", host="192.168.1.1", interface="")],
    )

    fresh = FastAPI()
    fresh.add_api_websocket_route("/ws/monitor", main.ws_monitor)
    client = TestClient(fresh)
    try:
        yield client
    finally:
        # State NACH dem Test sauber zuruecksetzen.
        monitor._status.clear()
        monitor._status.update(saved_status)
        monitor._subscribers.clear()
        monitor._subscribers.extend(saved_subs)


def test_ws_monitor_sends_status_frame_on_connect(ws_client: TestClient) -> None:
    with ws_client.websocket_connect("/ws/monitor") as ws:
        frame = ws.receive_json()

    assert frame == {
        "type": "monitor_status",
        "status": {"wlan": {"alive": True, "label": "WLAN"}},
    }


def test_ws_monitor_status_frame_empty_when_no_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Leerer In-Memory-State -> leere status-Map (AS-IS). Eigene Isolation, da
    # diese Probe den Stand bewusst vor dem Connect leert.
    saved_status = dict(monitor._status)
    saved_subs = list(monitor._subscribers)
    monitor._status.clear()
    monitor._subscribers.clear()
    try:
        fresh = FastAPI()
        fresh.add_api_websocket_route("/ws/monitor", main.ws_monitor)
        with TestClient(fresh).websocket_connect("/ws/monitor") as ws:
            frame = ws.receive_json()
        assert frame == {"type": "monitor_status", "status": {}}
    finally:
        monitor._status.clear()
        monitor._status.update(saved_status)
        monitor._subscribers.clear()
        monitor._subscribers.extend(saved_subs)


def test_ws_monitor_registers_and_unregisters_subscriber(ws_client: TestClient) -> None:
    # subscribe beim Connect, unsubscribe im finally beim Disconnect (AS-IS).
    assert monitor._subscribers == []
    with ws_client.websocket_connect("/ws/monitor") as ws:
        ws.receive_json()
        assert len(monitor._subscribers) == 1
    # Nach dem Schliessen ist der Subscriber wieder entfernt.
    assert monitor._subscribers == []
