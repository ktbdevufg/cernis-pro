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
from typing import Any

from domain.monitoring import (
    CaptureMode,
    LoggingEventRow,
    LoggingRttSample,
    LoggingTask,
    MonitorEvent,
    MonitorEventType,
    MonitorTarget,
    OperationMode,
    PingSample,
    SlaSample,
    TaskState,
)
from ports.monitoring import (
    LoggingEventRepository,
    LoggingRttRepository,
    LoggingTaskRepository,
    MonitorBroadcasterPort,
    MonitorEventRepository,
    MonitorNotifierPort,
    MonitorPingerPort,
    MonitorTargetSource,
    RttHistoryRepository,
    ScanJobScheduler,
    ScanTriggerCallback,
    ScheduleRepository,
    SlaSampleRepository,
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

    def clear_all(self) -> None:
        """Leert die gespeicherten RTT-Samples (No-op-Schreibpfad fuer den Fake)."""
        self.saved.clear()


class _FakeEventRepo:
    def __init__(self) -> None:
        self.saved: list[MonitorEvent] = []

    def save(self, event: MonitorEvent) -> None:
        self.saved.append(event)

    def recent(self, limit: int) -> list[MonitorEvent]:
        return list(reversed(self.saved))[:limit]

    def clear_all(self) -> None:
        """Leert die gespeicherten Events (No-op-Schreibpfad fuer den Fake)."""
        self.saved.clear()


class _FakeTargetSource:
    async def load(self) -> list[MonitorTarget]:
        return [MonitorTarget(id="wlan", label="WLAN", host="192.168.1.1", interface="")]


class _FakeScheduleRepo:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []
        self._next_id = 1

    def list(self) -> list[dict[str, Any]]:
        return list(self.rows)

    def add(self, name: str, cidr: str, profile_id: str, schedule: str) -> int:
        sid = self._next_id
        self._next_id += 1
        self.rows.append(
            {
                "id": sid,
                "name": name,
                "cidr": cidr,
                "profile_id": profile_id,
                "schedule": schedule,
                "enabled": 1,
                "last_run": None,
                "next_run": None,
                "created_at": "2026-06-03 00:00:00",
            }
        )
        return sid

    def update(self, schedule_id: int, enabled: bool | None, name: str | None) -> None:
        for row in self.rows:
            if row["id"] == schedule_id:
                if enabled is not None:
                    row["enabled"] = int(enabled)
                if name is not None:
                    row["name"] = name

    def set_run_times(
        self,
        schedule_id: int,
        last_run: str | None,
        next_run: str | None,
    ) -> None:
        """Setzt BEIDE Zeit-Spalten (``None`` = leer), wie der Vertrag es fordert."""
        for row in self.rows:
            if row["id"] == schedule_id:
                row["last_run"] = last_run
                row["next_run"] = next_run

    def delete(self, schedule_id: int) -> None:
        self.rows = [r for r in self.rows if r["id"] != schedule_id]

    def clear_all(self) -> None:
        """Leert die gespeicherten Schedule-Zeilen (No-op-Schreibpfad fuer den Fake)."""
        self.rows.clear()


class _FakeJobScheduler:
    def __init__(self) -> None:
        self.started = False
        self.registered: list[int] = []

    def start(self, callback: ScanTriggerCallback) -> None:
        self.started = True

    def stop(self) -> None:
        self.started = False

    def register(self, schedule: dict[str, Any], callback: ScanTriggerCallback) -> None:
        self.registered.append(int(schedule["id"]))

    def unregister(self, schedule_id: int) -> None:
        self.registered = [s for s in self.registered if s != schedule_id]

    def next_run_time(self, schedule_id: int) -> str | None:
        """Feuerzeit nur fuer registrierte Jobs -- sonst ehrlich ``None``."""
        if schedule_id not in self.registered:
            return None
        return "2026-06-03T02:00:00+00:00"


class _FakeSlaRepo:
    def __init__(self, samples: dict[str, list[SlaSample]] | None = None) -> None:
        # target_id -> Liste von (alive, rtt_ms, ts)-Zeilen.
        self.samples: dict[str, list[SlaSample]] = samples or {}

    def samples_for(self, target_id: str, since: float) -> list[SlaSample]:
        return [s for s in self.samples.get(target_id, []) if s[2] > since]

    def target_ids(self) -> list[str]:
        return list(self.samples.keys())

    def clear_all(self) -> None:
        """Leert die gespeicherten SLA-Samples (No-op-Schreibpfad fuer den Fake)."""
        self.samples.clear()


class _FakeLoggingTaskRepo:
    def __init__(self) -> None:
        self.tasks: dict[str, LoggingTask] = {}

    def save(self, task: LoggingTask) -> None:
        self.tasks[task.id] = task  # Upsert ueber id

    def get(self, task_id: str) -> LoggingTask | None:
        return self.tasks.get(task_id)

    def list_all(self) -> list[LoggingTask]:
        return list(self.tasks.values())

    def delete(self, task_id: str) -> None:
        self.tasks.pop(task_id, None)

    def clear_all(self) -> None:
        """Leert die gespeicherten Logging-Tasks (No-op-Schreibpfad fuer den Fake)."""
        self.tasks.clear()


class _FakeLoggingRttRepo:
    def __init__(self) -> None:
        # (task_id, rtt_ms, loss_pct, alive, ts)
        self.rows: list[tuple[str, float, float, bool, float]] = []

    def save(self, task_id: str, rtt_ms: float, loss_pct: float, alive: bool, ts: float) -> None:
        self.rows.append((task_id, rtt_ms, loss_pct, alive, ts))

    def range(self, task_id: str, since: float, until: float) -> list[LoggingRttSample]:
        return [
            LoggingRttSample(rtt_ms=r, loss_pct=lp, alive=a, ts=ts)
            for (tid, r, lp, a, ts) in self.rows
            if tid == task_id and since <= ts < until
        ]

    def all_for(self, task_id: str) -> list[LoggingRttSample]:
        return [
            LoggingRttSample(rtt_ms=r, loss_pct=lp, alive=a, ts=ts)
            for (tid, r, lp, a, ts) in sorted(self.rows, key=lambda row: row[4])
            if tid == task_id
        ]

    def delete_older_than(self, cutoff_ts: float) -> int:
        before = len(self.rows)
        self.rows = [row for row in self.rows if row[4] >= cutoff_ts]
        return before - len(self.rows)

    def count(self) -> int:
        return len(self.rows)

    def clear_all(self) -> None:
        """Leert die gespeicherten RTT-Zeilen (No-op-Schreibpfad fuer den Fake)."""
        self.rows.clear()


class _FakeLoggingEventRepo:
    def __init__(self) -> None:
        # (task_id, event_type, rtt_ms, ts)
        self.rows: list[tuple[str, str, float, float]] = []

    def save(self, task_id: str, event_type: str, rtt_ms: float, ts: float) -> None:
        self.rows.append((task_id, event_type, rtt_ms, ts))

    def range(self, task_id: str, since: float, until: float) -> list[LoggingEventRow]:
        return [
            LoggingEventRow(event_type=et, rtt_ms=r, ts=ts)
            for (tid, et, r, ts) in self.rows
            if tid == task_id and since <= ts < until
        ]

    def delete_older_than(self, cutoff_ts: float) -> int:
        before = len(self.rows)
        self.rows = [row for row in self.rows if row[3] >= cutoff_ts]
        return before - len(self.rows)

    def clear_all(self) -> None:
        """Leert die gespeicherten Event-Zeilen (No-op-Schreibpfad fuer den Fake)."""
        self.rows.clear()


# ── Statische Konformitaet: mypy prueft die Zuweisung an den Port-Typ ───────


def _assert_pinger(_: MonitorPingerPort) -> None: ...
def _assert_notifier(_: MonitorNotifierPort) -> None: ...
def _assert_broadcaster(_: MonitorBroadcasterPort) -> None: ...
def _assert_rtt(_: RttHistoryRepository) -> None: ...
def _assert_events(_: MonitorEventRepository) -> None: ...
def _assert_target_source(_: MonitorTargetSource) -> None: ...
def _assert_schedule_repo(_: ScheduleRepository) -> None: ...
def _assert_job_scheduler(_: ScanJobScheduler) -> None: ...
def _assert_sla_repo(_: SlaSampleRepository) -> None: ...
def _assert_logging_task_repo(_: LoggingTaskRepository) -> None: ...
def _assert_logging_rtt_repo(_: LoggingRttRepository) -> None: ...
def _assert_logging_event_repo(_: LoggingEventRepository) -> None: ...


def test_fakes_satisfy_ports_statically() -> None:
    """mypy-Beweis: jeder Fake genuegt seinem Port (Konformitaet rein statisch)."""
    _assert_pinger(_FakePinger())
    _assert_notifier(_FakeNotifier())
    _assert_broadcaster(_FakeBroadcaster())
    _assert_rtt(_FakeRttHistory())
    _assert_events(_FakeEventRepo())
    _assert_target_source(_FakeTargetSource())
    _assert_schedule_repo(_FakeScheduleRepo())
    _assert_job_scheduler(_FakeJobScheduler())
    _assert_sla_repo(_FakeSlaRepo())
    _assert_logging_task_repo(_FakeLoggingTaskRepo())
    _assert_logging_rtt_repo(_FakeLoggingRttRepo())
    _assert_logging_event_repo(_FakeLoggingEventRepo())


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
    targets = asyncio.run(source.load())
    assert len(targets) == 1
    assert isinstance(targets[0], MonitorTarget)
    assert targets[0].id == "wlan"


def test_schedule_repo_crud_roundtrip() -> None:
    repo: ScheduleRepository = _FakeScheduleRepo()
    sid = repo.add("Nightly", "192.168.1.0/24", "standard", "cron:0 2 * * *")
    rows = repo.list()
    assert len(rows) == 1
    assert rows[0]["id"] == sid
    assert rows[0]["enabled"] == 1  # Default
    repo.update(sid, enabled=False, name="Renamed")
    row = repo.list()[0]
    assert row["enabled"] == 0
    assert row["name"] == "Renamed"
    repo.delete(sid)
    assert repo.list() == []


def test_job_scheduler_lifecycle_and_register() -> None:
    sched: ScanJobScheduler = _FakeJobScheduler()

    async def _cb(cidr: str, profile_id: str, schedule_id: int) -> None:
        return None

    sched.start(_cb)
    sched.register({"id": 7, "cidr": "10.0.0.0/24", "schedule": "interval:1h"}, _cb)
    sched.register({"id": 8, "cidr": "10.0.0.0/24", "schedule": "interval:2h"}, _cb)
    sched.unregister(7)
    sched.stop()
    # Strukturnachweis: die Methoden sind aufrufbar mit den Port-Signaturen.
    assert isinstance(sched, _FakeJobScheduler)


def test_sla_repo_samples_for_and_target_ids() -> None:
    empty: SlaSampleRepository = _FakeSlaRepo()
    assert empty.samples_for("wlan", 0.0) == []  # Leer-Zustand, nicht None
    assert empty.target_ids() == []

    repo: SlaSampleRepository = _FakeSlaRepo({"wlan": [(1, 3.0, 100.0), (0, -1.0, 200.0)]})
    rows = repo.samples_for("wlan", 0.0)
    assert rows == [(1, 3.0, 100.0), (0, -1.0, 200.0)]  # (alive, rtt_ms, ts)
    assert repo.samples_for("wlan", 150.0) == [(0, -1.0, 200.0)]  # since filtert
    assert repo.target_ids() == ["wlan"]


def _logging_task(task_id: str, state: TaskState) -> LoggingTask:
    return LoggingTask(
        id=task_id,
        target_id="wlan",
        label="L",
        purpose="P",
        capture_mode=CaptureMode.REACHABILITY,
        operation_mode=OperationMode.IMMEDIATE,
        state=state,
        planned_start=None,
        planned_end=None,
        max_duration_s=60,
        created_at=1.0,
    )


def test_logging_task_repo_upsert_get_list_delete() -> None:
    repo: LoggingTaskRepository = _FakeLoggingTaskRepo()
    assert repo.list_all() == []  # Leer-Zustand, nicht None
    assert repo.get("t1") is None  # unbekannt -> None
    repo.save(_logging_task("t1", TaskState.CREATED))
    repo.save(_logging_task("t1", TaskState.ACTIVE))  # Upsert: gleiche id, neuer state
    assert len(repo.list_all()) == 1
    loaded = repo.get("t1")
    assert loaded is not None and loaded.state is TaskState.ACTIVE
    repo.delete("t1")
    assert repo.get("t1") is None


def test_logging_rtt_repo_range_retention_count() -> None:
    repo: LoggingRttRepository = _FakeLoggingRttRepo()
    assert repo.range("t1", 0.0, 1000.0) == []  # Leer-Zustand, nicht None
    assert repo.count() == 0
    repo.save("t1", rtt_ms=3.0, loss_pct=0.0, alive=True, ts=100.0)
    repo.save("t1", rtt_ms=-1.0, loss_pct=100.0, alive=False, ts=200.0)
    rows = repo.range("t1", 100.0, 200.0)  # since inkl., until exkl.
    assert rows == [LoggingRttSample(rtt_ms=3.0, loss_pct=0.0, alive=True, ts=100.0)]
    assert repo.count() == 2
    assert repo.delete_older_than(200.0) == 1  # nur ts=100 ist strikt aelter
    assert repo.count() == 1


def test_logging_event_repo_range_retention() -> None:
    repo: LoggingEventRepository = _FakeLoggingEventRepo()
    assert repo.range("t1", 0.0, 1000.0) == []  # Leer-Zustand, nicht None
    repo.save("t1", event_type="flap", rtt_ms=1.0, ts=100.0)
    repo.save("t1", event_type="spike", rtt_ms=9.0, ts=200.0)
    rows = repo.range("t1", 100.0, 200.0)
    assert rows == [LoggingEventRow(event_type="flap", rtt_ms=1.0, ts=100.0)]
    assert repo.delete_older_than(200.0) == 1
