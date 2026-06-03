"""Tests fuer ``MonitorNotifierAdapter`` -- gemocktes ``modules.monitor._notify_macos``.

Getestet: (1) Port-Konformitaet, (2) ``_notify_macos`` laeuft im Executor (blockierend
-> nicht im Loop-Thread), (3) Mapping Event -> Altcode-Wortlaut (Titel/Nachricht),
(4) degraded loest KEINEN Versand aus (nur up/down), (5) best-effort: ein Fehler im
``_notify_macos`` wird gefangen + geloggt, NICHT in den Loop geworfen.

Der Linux-no-op-Pfad (osascript fehlt) ist im Adapter durch den Executor-Aufruf +
den internen Altcode-``except: pass`` abgedeckt; hier wird das Verhalten ueber den
Mock charakterisiert (kein echtes osascript noetig).
"""

import asyncio
import threading

import pytest

from domain.monitoring import MonitorEvent, MonitorEventType
from infrastructure.monitoring import notifier
from infrastructure.monitoring.notifier import MonitorNotifierAdapter
from ports.monitoring import MonitorNotifierPort


def _event(event_type: MonitorEventType, label: str = "WLAN") -> MonitorEvent:
    return MonitorEvent(target_id="wlan", label=label, event=event_type, rtt_ms=-1.0)


def test_conforms_to_notifier_protocol() -> None:
    _: MonitorNotifierPort = MonitorNotifierAdapter()


def test_notify_down_maps_to_altcode_wording(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, str] = {}

    def fake_notify(title: str, message: str) -> None:
        seen["title"] = title
        seen["message"] = message

    monkeypatch.setattr(notifier, "_notify_macos", fake_notify)
    asyncio.run(MonitorNotifierAdapter().notify(_event(MonitorEventType.DOWN)))
    assert seen["title"] == "CERNIS PRO — Network Alert"
    assert seen["message"] == "WLAN is DOWN"


def test_notify_up_maps_to_back_up(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, str] = {}
    monkeypatch.setattr(notifier, "_notify_macos", lambda t, m: seen.update(title=t, message=m))
    asyncio.run(MonitorNotifierAdapter().notify(_event(MonitorEventType.UP)))
    assert seen["message"] == "WLAN is back UP"


def test_notify_degraded_does_not_send(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(notifier, "_notify_macos", lambda t, m: calls.append((t, m)))
    asyncio.run(MonitorNotifierAdapter().notify(_event(MonitorEventType.DEGRADED)))
    # degraded loest im Altcode keine Notification aus -> kein Versand.
    assert calls == []


def test_notify_runs_in_executor_not_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    call_thread: dict[str, int] = {}

    def fake_notify(title: str, message: str) -> None:
        call_thread["tid"] = threading.get_ident()

    monkeypatch.setattr(notifier, "_notify_macos", fake_notify)

    async def _run() -> None:
        loop_tid = threading.get_ident()
        await MonitorNotifierAdapter().notify(_event(MonitorEventType.DOWN))
        assert call_thread["tid"] != loop_tid  # im Executor, nicht im Loop

    asyncio.run(_run())


def test_notify_is_best_effort_on_error(monkeypatch: pytest.MonkeyPatch) -> None:
    # Ein unerwarteter Fehler darf NICHT in den Loop propagieren (best-effort).
    def boom(title: str, message: str) -> None:
        raise RuntimeError("osascript exploded")

    monkeypatch.setattr(notifier, "_notify_macos", boom)
    # Kein raise -> der Adapter faengt + loggt.
    asyncio.run(MonitorNotifierAdapter().notify(_event(MonitorEventType.DOWN)))
