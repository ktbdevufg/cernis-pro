"""Tests fuer ``MonitorPingerAdapter`` -- gemocktes ``modules.monitor._ping_burst``.

Getestet: (1) Port-Konformitaet, (2) ``ping`` awaitet das bereits-async
``_ping_burst`` und reicht ``host``/``interface`` durch, (3) das Mapping
``PingResult`` -> ``PingSample`` ist charakterisierungstreu (target_id aus dem
Target gesetzt, RTT-Sentinel ``-1.0`` + loss_pct unveraendert uebernommen),
(4) ``_ping_burst`` wird DIREKT geawaitet (kein ``run_in_executor`` -- es ist schon
async; Beweis: der Fake laeuft im Loop-Thread, nicht in einem Executor-Thread).

Async-Smokes laufen ueber ``asyncio.run`` (kein ``pytest-asyncio`` -- nicht
installiert, wie in S.3/M.3). Gemockt wird am IMPORT-ORT IM ADAPTER-MODUL.
"""

import asyncio
import threading
from dataclasses import dataclass

import pytest

from domain.monitoring import MonitorTarget, PingSample
from infrastructure.monitoring import pinger
from infrastructure.monitoring.pinger import MonitorPingerAdapter
from ports.monitoring import MonitorPingerPort

_TARGET = MonitorTarget(id="wlan", label="WLAN", host="192.168.1.1", interface="en0")


@dataclass
class _FakePingResult:
    """Minimaler Stand-in fuer ``modules.monitor.PingResult`` (nur die genutzten Felder)."""

    alive: bool
    rtt_ms: float
    loss_pct: float
    timestamp: float


def test_conforms_to_pinger_protocol() -> None:
    _: MonitorPingerPort = MonitorPingerAdapter()


def test_ping_awaits_burst_and_passes_host_interface(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, object] = {}

    async def fake_burst(host: str, interface: str = "") -> _FakePingResult:
        seen["host"] = host
        seen["interface"] = interface
        return _FakePingResult(alive=True, rtt_ms=3.5, loss_pct=0.0, timestamp=100.0)

    monkeypatch.setattr(pinger, "_ping_burst", fake_burst)
    sample = asyncio.run(MonitorPingerAdapter().ping(_TARGET))

    assert isinstance(sample, PingSample)
    assert seen == {"host": "192.168.1.1", "interface": "en0"}
    # target_id aus dem Target gesetzt (Altcode liess es leer).
    assert sample.target_id == "wlan"
    assert sample.host == "192.168.1.1"
    assert sample.alive is True
    assert sample.rtt_ms == 3.5
    assert sample.loss_pct == 0.0
    assert sample.timestamp == 100.0


def test_ping_preserves_rtt_sentinel_on_unreachable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Nicht erreichbar: alive=False, RTT-Sentinel -1.0 UNVERAENDERT (nicht None).
    async def fake_burst(host: str, interface: str = "") -> _FakePingResult:
        return _FakePingResult(alive=False, rtt_ms=-1.0, loss_pct=100.0, timestamp=50.0)

    monkeypatch.setattr(pinger, "_ping_burst", fake_burst)
    sample = asyncio.run(MonitorPingerAdapter().ping(_TARGET))
    assert sample.alive is False
    assert sample.rtt_ms == -1.0  # Sentinel bleibt, KEINE None-Normalisierung
    assert sample.loss_pct == 100.0


def test_ping_burst_awaited_directly_not_in_executor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # _ping_burst ist schon async -> direkt awaiten. Beweis: der Fake laeuft im
    # SELBEN Thread wie der Loop (kein run_in_executor, das in einen Worker-Thread
    # auslagern wuerde).
    call_thread: dict[str, int] = {}

    async def fake_burst(host: str, interface: str = "") -> _FakePingResult:
        call_thread["tid"] = threading.get_ident()
        return _FakePingResult(alive=True, rtt_ms=1.0, loss_pct=0.0, timestamp=1.0)

    monkeypatch.setattr(pinger, "_ping_burst", fake_burst)

    async def _run() -> None:
        loop_tid = threading.get_ident()
        await MonitorPingerAdapter().ping(_TARGET)
        assert call_thread["tid"] == loop_tid  # im Loop-Thread, NICHT im Executor

    asyncio.run(_run())
