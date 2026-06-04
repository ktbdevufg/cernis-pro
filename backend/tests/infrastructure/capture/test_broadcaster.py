"""Tests fuer ``WebSocketCaptureBroadcaster`` (M.9-Stil).

Getestet: (1) Port-Konformitaet, (2) subscribe/broadcast + Frame-Form
(``capture_packet`` mit den ``PacketSummary``-Feldern), (3) Dead-Cleanup: ein toter
WS (``send_json`` wirft) killt die ANDEREN Subscriber nicht und wird entfernt;
Warn-Log statt stiller S3-Fang.

Async ueber ``asyncio.run`` (kein ``pytest-asyncio``). Der ``WebSocket`` ist ein
Fake mit ``send_json`` -- der Adapter braucht nur diese Methode.
"""

import asyncio
from typing import Any

import pytest

from domain.capture import PacketSummary
from infrastructure.capture.broadcaster import WebSocketCaptureBroadcaster
from ports.capture import CaptureBroadcasterPort

_PACKET = PacketSummary(
    timestamp=123.0,
    src_ip="10.0.0.1",
    dst_ip="10.0.0.2",
    src_mac="aa:bb",
    dst_mac="cc:dd",
    protocol="HTTPS",
    src_port=51000,
    dst_port=443,
    length=74,
    info="SYN",
    is_ipv6=False,
)


class _FakeWS:
    def __init__(self) -> None:
        self.frames: list[dict[str, Any]] = []

    async def send_json(self, frame: dict[str, Any]) -> None:
        self.frames.append(frame)


class _DeadWS:
    async def send_json(self, frame: dict[str, Any]) -> None:
        raise RuntimeError("broken pipe")


def test_conforms_to_broadcaster_protocol() -> None:
    _: CaptureBroadcasterPort = WebSocketCaptureBroadcaster()


def test_broadcast_builds_capture_packet_frame() -> None:
    bc = WebSocketCaptureBroadcaster()
    ws = _FakeWS()

    async def _run() -> None:
        await bc.subscribe(ws)  # type: ignore[arg-type]
        await bc.broadcast(_PACKET)

    asyncio.run(_run())
    assert len(ws.frames) == 1
    frame = ws.frames[0]
    assert frame["type"] == "capture_packet"
    assert frame["src_ip"] == "10.0.0.1"
    assert frame["dst_ip"] == "10.0.0.2"
    assert frame["protocol"] == "HTTPS"
    assert frame["dst_port"] == 443
    assert frame["length"] == 74
    assert frame["info"] == "SYN"
    assert frame["is_ipv6"] is False
    assert frame["timestamp"] == 123.0


def test_broadcast_no_subscribers_is_noop() -> None:
    bc = WebSocketCaptureBroadcaster()
    # Kein Subscriber -> kein Fehler.
    asyncio.run(bc.broadcast(_PACKET))


def test_dead_subscriber_does_not_kill_others_and_is_removed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    warnings: list[str] = []

    class _Logger:
        def warning(self, event: str, **kw: Any) -> None:
            warnings.append(event)

    monkeypatch.setattr("infrastructure.capture.broadcaster._logger", _Logger())

    bc = WebSocketCaptureBroadcaster()
    dead = _DeadWS()
    alive = _FakeWS()

    async def _run() -> None:
        await bc.subscribe(dead)  # type: ignore[arg-type]
        await bc.subscribe(alive)  # type: ignore[arg-type]
        await bc.broadcast(_PACKET)

    asyncio.run(_run())

    # Der lebende Subscriber bekam sein Frame, trotz totem Nachbarn.
    assert len(alive.frames) == 1
    # Der tote Subscriber wurde entfernt (Dead-Cleanup) ...
    assert dead not in bc._subscribers
    assert alive in bc._subscribers
    # ... und der Drop wurde geloggt (kein stiller S3-Fang).
    assert "capture_broadcast_subscriber_dropped" in warnings
