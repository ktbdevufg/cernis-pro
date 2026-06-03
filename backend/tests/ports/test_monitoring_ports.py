"""Strukturtest der monitoring-Ports (M.3): Fakes erfuellen die Protocols.

Reine ``typing.Protocol``-Vertraege haben kein Verhalten -- der Verhaltenstest
kommt mit den Adaptern (M.4). Hier wird NUR die strukturelle Konformitaet geprueft:

* **statisch (mypy):** Jede ``_assert_*``-Funktion nimmt den Port-TYP als Parameter
  und bekommt die Fake-Instanz uebergeben. Erfuellt ein Fake das Protocol nicht
  (falsche Signatur, fehlende Methode), schlaegt ``uv run mypy`` fehl -- das ist die
  eigentliche Pruefung.
* **dynamisch (pytest):** Ein minimaler Smoke ruft jede Methode einmal auf und
  prueft, dass die Domaenen-Rueckgabetypen herauskommen.

Die async-Smokes werden ueber ``asyncio.run`` (stdlib) getrieben -- BEWUSST kein
``pytest-asyncio``/``anyio``-Marker (gleiche Begruendung wie scanning S.3: keine
solche Test-Dependency im Projekt, in einem reinen Ports-Schritt keine einfuehren).

KEIN ``@runtime_checkable`` an den Ports -> bewusst KEIN ``isinstance``-Check.
"""

import asyncio

from domain.monitoring import (
    MonitorEvent,
    MonitorEventType,
    MonitorTarget,
    PingSample,
)
from ports.monitoring import (
    MonitorBroadcasterPort,
    MonitorEventRepository,
    MonitorNotifierPort,
    MonitorPingerPort,
    MonitorTargetSource,
    RttHistoryRepository,
)

# ── Fakes: minimale, vertragstreue Implementierungen ────────────────────────


class _FakePinger:
    async def ping(self, target: MonitorTarget) -> PingSample:
        return PingSample(
            target_id=target.id, host=target.host, alive=True, rtt_ms=3.0, loss_pct=0.0
        )


class _FakeNotifier:
    def __init__(self) -> None:
        self.calls: list[MonitorEvent] = []

    async def notify(self, event: MonitorEvent) -> None:
        self.calls.append(event)


class _FakeBroadcaster:
    def __init__(self) -> None:
        self.updates: list[tuple[str, bool, MonitorEventType | None]] = []

    async def broadcast(
        self,
        target: MonitorTarget,
        sample: PingSample,
        event: MonitorEventType | None,
    ) -> None:
        self.updates.append((target.id, sample.alive, event))


class _FakeRttHistory:
    def __init__(self) -> None:
        self.saved: list[PingSample] = []

    def save(self, sample: PingSample) -> None:
        self.saved.append(sample)

    def recent(self, target_id: str, limit: int) -> list[PingSample]:
        return [s for s in self.saved if s.target_id == target_id][:limit]


class _FakeEventRepo:
    def __init__(self) -> None:
        self.saved: list[MonitorEvent] = []

    def save(self, event: MonitorEvent) -> None:
        self.saved.append(event)

    def recent(self, limit: int) -> list[MonitorEvent]:
        return list(reversed(self.saved))[:limit]


class _FakeTargetSource:
    def load(self) -> list[MonitorTarget]:
        return [MonitorTarget(id="wlan", label="WLAN", host="192.168.1.1", interface="")]


# ── Statische Konformitaet: mypy prueft die Zuweisung an den Port-Typ ───────


def _assert_pinger(_: MonitorPingerPort) -> None: ...
def _assert_notifier(_: MonitorNotifierPort) -> None: ...
def _assert_broadcaster(_: MonitorBroadcasterPort) -> None: ...
def _assert_rtt(_: RttHistoryRepository) -> None: ...
def _assert_events(_: MonitorEventRepository) -> None: ...
def _assert_target_source(_: MonitorTargetSource) -> None: ...


def test_fakes_satisfy_ports_statically() -> None:
    """mypy-Beweis: jeder Fake genuegt seinem Port (Konformitaet rein statisch)."""
    _assert_pinger(_FakePinger())
    _assert_notifier(_FakeNotifier())
    _assert_broadcaster(_FakeBroadcaster())
    _assert_rtt(_FakeRttHistory())
    _assert_events(_FakeEventRepo())
    _assert_target_source(_FakeTargetSource())


# ── Dynamischer Smoke: Methoden aufrufbar, Domaenentypen kommen heraus ──────


def test_pinger_returns_ping_sample() -> None:
    pinger: MonitorPingerPort = _FakePinger()
    target = MonitorTarget(id="wlan", label="WLAN", host="192.168.1.1", interface="")
    sample = asyncio.run(pinger.ping(target))
    assert isinstance(sample, PingSample)
    assert sample.target_id == "wlan"
    assert sample.alive is True


def test_notifier_consumes_event() -> None:
    notifier = _FakeNotifier()
    port: MonitorNotifierPort = notifier
    evt = MonitorEvent(target_id="wlan", label="WLAN", event=MonitorEventType.DOWN, rtt_ms=-1.0)
    asyncio.run(port.notify(evt))
    assert notifier.calls == [evt]


def test_broadcaster_accepts_domain_objects() -> None:
    broadcaster = _FakeBroadcaster()
    port: MonitorBroadcasterPort = broadcaster
    target = MonitorTarget(id="wlan", label="WLAN", host="192.168.1.1", interface="")
    sample = PingSample(target_id="wlan", host="192.168.1.1", alive=True, rtt_ms=3.0)
    asyncio.run(port.broadcast(target, sample, MonitorEventType.UP))
    # event=None ist vertraglich erlaubt (kein Uebergang).
    asyncio.run(port.broadcast(target, sample, None))
    assert broadcaster.updates == [("wlan", True, MonitorEventType.UP), ("wlan", True, None)]


def test_rtt_history_save_then_recent() -> None:
    repo: RttHistoryRepository = _FakeRttHistory()
    repo.save(PingSample(target_id="wlan", host="h", alive=True, rtt_ms=1.0))
    repo.save(PingSample(target_id="lan", host="h", alive=True, rtt_ms=2.0))
    recent = repo.recent("wlan", 10)
    assert len(recent) == 1
    assert recent[0].target_id == "wlan"
    assert repo.recent("unknown", 10) == []  # Leer-Zustand, nicht None


def test_event_repo_save_then_recent_newest_first() -> None:
    repo: MonitorEventRepository = _FakeEventRepo()
    older = MonitorEvent(target_id="wlan", label="WLAN", event=MonitorEventType.UP, rtt_ms=1.0)
    newer = MonitorEvent(target_id="wlan", label="WLAN", event=MonitorEventType.DOWN, rtt_ms=-1.0)
    repo.save(older)
    repo.save(newer)
    recent = repo.recent(10)
    assert recent[0] is newer  # neueste zuerst
    assert repo.recent(0) == []  # limit 0


def test_target_source_loads_targets() -> None:
    source: MonitorTargetSource = _FakeTargetSource()
    targets = source.load()
    assert len(targets) == 1
    assert isinstance(targets[0], MonitorTarget)
    assert targets[0].id == "wlan"
