"""Tests fuer ``RunMonitor`` (M.5) -- gegen Fake-Implementierungen aller Ports.

Reine application-Schicht: KEIN echtes Netz/osascript/sqlite/WS, KEINE Adapter.
Konfigurierbare, aufzeichnende Fakes steuern die Szenarien. Async-Smokes via
``asyncio.run`` (kein ``pytest-asyncio``, wie in der ganzen Migration).

Der Endlos-Loop ``run()`` wird NICHT live getestet (nur der triviale while/sleep-
Rahmen). Getestet wird ``tick()`` -- eine Iteration -- deterministisch:

* Pro-Target-Sequenz: ping -> rtt.save; broadcast IMMER (auch event=None); notify
  NUR bei should_notify; save_event NUR bei Event; status korrekt aktualisiert.
* monitor_update (in M.1 als "-> M.5" ausgeklammert): der Fake-Broadcaster zeichnet
  ``broadcast(target, sample, event)`` auf -- jetzt deterministisch pruefbar.
* Mehr-Iterations-Sequenz: zwei ``tick``-Aufrufe -> prev->now-Uebergaenge
  (Erstmessung up; dann down -> DOWN-Event + Notify beim zweiten tick).
* disabled Target wird uebersprungen; ``current_status()`` ist eine defensive Kopie.
"""

import asyncio

from application.monitoring import RunMonitor
from domain.monitoring import (
    MonitorEvent,
    MonitorEventType,
    MonitorTarget,
    PingSample,
)

# ── Konfigurierbare, aufzeichnende Fakes ────────────────────────────────────


class _FakePinger:
    """Liefert pro target_id ein vorgegebenes ``PingSample`` (oder einen Default).

    Mit ``script`` koennen je Aufruf unterschiedliche Samples geliefert werden
    (fuer Mehr-Iterations-Sequenzen): script[target_id] ist eine Liste, die pro
    ping(target) vorne abgearbeitet wird.
    """

    def __init__(
        self,
        default: PingSample | None = None,
        script: dict[str, list[PingSample]] | None = None,
    ) -> None:
        self._default = default
        self._script = script or {}

    async def ping(self, target: MonitorTarget) -> PingSample:
        queue = self._script.get(target.id)
        if queue:
            return queue.pop(0)
        if self._default is not None:
            return self._default
        return PingSample(target_id=target.id, host=target.host, alive=True, rtt_ms=1.0)


class _RecordingRtt:
    def __init__(self) -> None:
        self.saved: list[PingSample] = []

    def save(self, sample: PingSample) -> None:
        self.saved.append(sample)

    def recent(self, target_id: str, limit: int) -> list[PingSample]:
        return []


class _RecordingEvents:
    def __init__(self) -> None:
        self.saved: list[MonitorEvent] = []

    def save(self, event: MonitorEvent) -> None:
        self.saved.append(event)

    def recent(self, limit: int) -> list[MonitorEvent]:
        return []


class _RecordingNotifier:
    def __init__(self) -> None:
        self.notified: list[MonitorEvent] = []

    async def notify(self, event: MonitorEvent) -> None:
        self.notified.append(event)


class _RecordingBroadcaster:
    def __init__(self) -> None:
        self.updates: list[tuple[str, bool, MonitorEventType | None]] = []

    async def broadcast(
        self,
        target: MonitorTarget,
        sample: PingSample,
        event: MonitorEventType | None,
    ) -> None:
        self.updates.append((target.id, sample.alive, event))


class _StaticTargetSource:
    def __init__(self, targets: list[MonitorTarget]) -> None:
        self._targets = targets

    def load(self) -> list[MonitorTarget]:
        return list(self._targets)


def _target(tid: str = "wlan", *, enabled: bool = True) -> MonitorTarget:
    return MonitorTarget(
        id=tid, label=tid.upper(), host="192.168.1.1", interface="", enabled=enabled
    )


def _build(
    pinger: _FakePinger,
    targets: list[MonitorTarget],
) -> tuple[RunMonitor, _RecordingRtt, _RecordingEvents, _RecordingNotifier, _RecordingBroadcaster]:
    rtt = _RecordingRtt()
    events = _RecordingEvents()
    notifier = _RecordingNotifier()
    broadcaster = _RecordingBroadcaster()
    uc = RunMonitor(
        pinger=pinger,
        rtt_history=rtt,
        event_repo=events,
        notifier=notifier,
        broadcaster=broadcaster,
        target_source=_StaticTargetSource(targets),
    )
    return uc, rtt, events, notifier, broadcaster


# ── Eine Iteration ──────────────────────────────────────────────────────────


def test_tick_first_measurement_up_saves_event_no_notify() -> None:
    # Erstmessung (prev=None): alive -> UP-Event. should_notify(None, UP) ist False
    # (keine Notification bei Erstmessung). save_event JA, notify NEIN.
    sample = PingSample(
        target_id="wlan", host="h", alive=True, rtt_ms=2.0, loss_pct=0.0, timestamp=99.0
    )
    uc, rtt, events, notifier, broadcaster = _build(_FakePinger(default=sample), [_target()])

    asyncio.run(uc.tick())

    assert len(rtt.saved) == 1  # rtt IMMER gespeichert
    assert len(events.saved) == 1  # Erstmessung erzeugt UP-Event
    assert events.saved[0].event is MonitorEventType.UP
    assert events.saved[0].rtt_ms == 2.0
    assert events.saved[0].timestamp == 99.0  # aus PingSample.timestamp
    assert notifier.notified == []  # KEINE Notification bei Erstmessung
    assert broadcaster.updates == [("wlan", True, MonitorEventType.UP)]  # broadcast IMMER
    assert uc.current_status() == {"wlan": True}


def test_tick_stable_up_no_event_but_broadcasts() -> None:
    # prev=True, now=True, loss<=30 -> kein Event. broadcast TROTZDEM (event=None).
    sample = PingSample(target_id="wlan", host="h", alive=True, rtt_ms=1.0, loss_pct=0.0)
    uc, _rtt, events, notifier, broadcaster = _build(_FakePinger(default=sample), [_target()])
    uc._status["wlan"] = True  # prev = True

    asyncio.run(uc.tick())

    assert events.saved == []  # kein Uebergang
    assert notifier.notified == []
    assert broadcaster.updates == [("wlan", True, None)]  # broadcast mit event=None
    assert uc.current_status() == {"wlan": True}


def test_tick_degraded_event_but_no_notify() -> None:
    # prev=True, now=True, loss>30 -> DEGRADED. save_event JA, notify NEIN
    # (should_notify gibt fuer degraded False).
    sample = PingSample(target_id="wlan", host="h", alive=True, rtt_ms=5.0, loss_pct=50.0)
    uc, _rtt, events, notifier, broadcaster = _build(_FakePinger(default=sample), [_target()])
    uc._status["wlan"] = True

    asyncio.run(uc.tick())

    assert len(events.saved) == 1
    assert events.saved[0].event is MonitorEventType.DEGRADED
    assert notifier.notified == []  # degraded -> keine Notification
    assert broadcaster.updates == [("wlan", True, MonitorEventType.DEGRADED)]


def test_tick_disabled_target_skipped() -> None:
    uc, rtt, _events, _notifier, broadcaster = _build(_FakePinger(), [_target(enabled=False)])

    asyncio.run(uc.tick())

    # Kein Ping, kein rtt, kein broadcast, kein Status fuer disabled Target.
    assert rtt.saved == []
    assert broadcaster.updates == []
    assert uc.current_status() == {}


def test_tick_multiple_targets_each_processed() -> None:
    pinger = _FakePinger(
        script={
            "a": [PingSample(target_id="a", host="h", alive=True, rtt_ms=1.0)],
            "b": [PingSample(target_id="b", host="h", alive=False, rtt_ms=-1.0)],
        }
    )
    uc, rtt, events, _notifier, broadcaster = _build(pinger, [_target("a"), _target("b")])

    asyncio.run(uc.tick())

    assert len(rtt.saved) == 2
    assert {u[0] for u in broadcaster.updates} == {"a", "b"}
    # a: Erstmessung up -> UP; b: Erstmessung down -> DOWN. Beides save_event.
    assert {e.event for e in events.saved} == {MonitorEventType.UP, MonitorEventType.DOWN}
    assert uc.current_status() == {"a": True, "b": False}


# ── Mehr-Iterations-Sequenz (prev->now-Uebergaenge) ─────────────────────────


def test_two_ticks_up_then_down_fires_down_with_notify() -> None:
    # tick 1: Erstmessung up (UP-Event, KEIN notify). tick 2: jetzt down -> DOWN-Flanke
    # (DOWN-Event + should_notify(True, DOWN)=True -> notify).
    pinger = _FakePinger(
        script={
            "wlan": [
                PingSample(target_id="wlan", host="h", alive=True, rtt_ms=2.0),
                PingSample(target_id="wlan", host="h", alive=False, rtt_ms=-1.0),
            ]
        }
    )
    uc, _rtt, events, notifier, broadcaster = _build(pinger, [_target()])

    asyncio.run(uc.tick())  # 1: up
    assert uc.current_status() == {"wlan": True}
    assert notifier.notified == []  # Erstmessung -> kein notify

    asyncio.run(uc.tick())  # 2: down-Flanke
    assert uc.current_status() == {"wlan": False}
    assert [e.event for e in events.saved] == [MonitorEventType.UP, MonitorEventType.DOWN]
    # Notify NUR beim DOWN (Flanke mit prev=True), nicht beim ersten UP.
    assert len(notifier.notified) == 1
    assert notifier.notified[0].event is MonitorEventType.DOWN
    # broadcast in BEIDEN Ticks.
    assert [u[2] for u in broadcaster.updates] == [MonitorEventType.UP, MonitorEventType.DOWN]


def test_two_ticks_down_then_up_recovery_notifies() -> None:
    # tick 1: Erstmessung down (DOWN, kein notify). tick 2: up -> UP-Flanke + notify.
    pinger = _FakePinger(
        script={
            "wlan": [
                PingSample(target_id="wlan", host="h", alive=False, rtt_ms=-1.0),
                PingSample(target_id="wlan", host="h", alive=True, rtt_ms=3.0),
            ]
        }
    )
    uc, _rtt, events, notifier, _broadcaster = _build(pinger, [_target()])

    asyncio.run(uc.tick())
    asyncio.run(uc.tick())

    assert [e.event for e in events.saved] == [MonitorEventType.DOWN, MonitorEventType.UP]
    assert len(notifier.notified) == 1
    assert notifier.notified[0].event is MonitorEventType.UP


def test_two_ticks_stable_down_second_yields_no_event() -> None:
    # tick 1: Erstmessung down (DOWN-Event). tick 2: weiterhin down (prev=False,
    # now=False) -> KEIN Event (dauerhaft-ab erzeugt nichts), aber broadcast.
    pinger = _FakePinger(default=PingSample(target_id="wlan", host="h", alive=False, rtt_ms=-1.0))
    uc, _rtt, events, _notifier, broadcaster = _build(pinger, [_target()])

    asyncio.run(uc.tick())
    asyncio.run(uc.tick())

    assert [e.event for e in events.saved] == [MonitorEventType.DOWN]  # nur tick 1
    assert len(broadcaster.updates) == 2  # broadcast in beiden
    assert broadcaster.updates[1] == ("wlan", False, None)  # tick 2: kein Event


# ── current_status() defensive Kopie ────────────────────────────────────────


def test_current_status_is_defensive_copy() -> None:
    uc, *_ = _build(_FakePinger(), [_target()])
    asyncio.run(uc.tick())
    snapshot = uc.current_status()
    snapshot["wlan"] = False  # Mutation der Kopie
    snapshot["injected"] = True
    # Der interne State bleibt unberuehrt.
    assert uc.current_status() == {"wlan": True}


def test_stop_clears_running_flag() -> None:
    uc, *_ = _build(_FakePinger(), [_target()])
    uc._running = True
    uc.stop()
    assert uc._running is False
