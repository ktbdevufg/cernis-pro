"""Tests fuer ``MonitorLoggingSink`` (B-II, Schreibpfad des Langzeit-Loggings).

Gegen aufzeichnende Fake-Repos (in-memory): belegt die Filter- und capture_mode-Logik
des Adapters deterministisch, ohne echtes sqlite und ohne den Loop.

Gedeckt:
* Filter: nur ACTIVE + Zeitfenster offen + gleiches target_id wird bedient.
* REACHABILITY_LATENCY -> JEDE Messung ein rtt-save.
* REACHABILITY / INTERFACE_STATUS -> nur die Flanke (event != None) ein event-save,
  KEIN rtt-save (vorerst gleicher Schreibpfad, s. Modul-Docstring des Adapters).
* event_type ist der rohe str-Wert des Domaenen-Events.
* Best-effort: ein werfendes Repo killt record NICHT (Fehler geschluckt+geloggt).
"""

import asyncio

from domain.monitoring import (
    CaptureMode,
    LoggingEventRow,
    LoggingRttSample,
    LoggingTask,
    MonitorEventType,
    MonitorTarget,
    OperationMode,
    PingSample,
    TaskState,
)
from infrastructure.monitoring.logging_sink import MonitorLoggingSink


class _FakeTaskRepo:
    """``LoggingTaskRepository``-Fake -- der Sink nutzt nur ``list_all``.

    Die uebrigen Protocol-Methoden sind Stubs mit AssertionError (Muster
    ``test_logging_retention``): der Sink darf sie nicht rufen.
    """

    def __init__(self, tasks: list[LoggingTask]) -> None:
        self._tasks = tasks

    def list_all(self) -> list[LoggingTask]:
        return list(self._tasks)

    def save(self, task: LoggingTask) -> None:
        raise AssertionError("save darf vom Sink nicht gerufen werden")

    def get(self, task_id: str) -> LoggingTask | None:
        raise AssertionError("get darf vom Sink nicht gerufen werden")

    def delete(self, task_id: str) -> None:
        raise AssertionError("delete darf vom Sink nicht gerufen werden")


class _RecordingRtt:
    def __init__(self) -> None:
        self.saved: list[tuple[str, float, float, bool, float]] = []

    def save(self, task_id: str, rtt_ms: float, loss_pct: float, alive: bool, ts: float) -> None:
        self.saved.append((task_id, rtt_ms, loss_pct, alive, ts))

    def range(self, task_id: str, since: float, until: float) -> list[LoggingRttSample]:
        raise AssertionError("range darf vom Sink nicht gerufen werden")

    def all_for(self, task_id: str) -> list[LoggingRttSample]:
        raise AssertionError("all_for darf vom Sink nicht gerufen werden")

    def delete_older_than(self, cutoff_ts: float) -> int:
        raise AssertionError("delete_older_than darf vom Sink nicht gerufen werden")

    def count(self) -> int:
        raise AssertionError("count darf vom Sink nicht gerufen werden")


class _RecordingEvents:
    def __init__(self) -> None:
        self.saved: list[tuple[str, str, float, float]] = []

    def save(self, task_id: str, event_type: str, rtt_ms: float, ts: float) -> None:
        self.saved.append((task_id, event_type, rtt_ms, ts))

    def range(self, task_id: str, since: float, until: float) -> list[LoggingEventRow]:
        raise AssertionError("range darf vom Sink nicht gerufen werden")

    def delete_older_than(self, cutoff_ts: float) -> int:
        raise AssertionError("delete_older_than darf vom Sink nicht gerufen werden")


def _task(
    *,
    task_id: str = "task-1",
    target_id: str = "wlan",
    capture_mode: CaptureMode = CaptureMode.REACHABILITY_LATENCY,
    state: TaskState = TaskState.ACTIVE,
    effective_start: float | None = 500.0,
    max_duration_s: int | None = 60,
    interval_s: int = 5,
) -> LoggingTask:
    return LoggingTask(
        id=task_id,
        target_id=target_id,
        label="L",
        purpose="P",
        capture_mode=capture_mode,
        operation_mode=OperationMode.IMMEDIATE,
        state=state,
        planned_start=None,
        planned_end=None,
        max_duration_s=max_duration_s,
        created_at=1.0,
        effective_start=effective_start,
        interval_s=interval_s,
    )


def _target(tid: str = "wlan") -> MonitorTarget:
    return MonitorTarget(id=tid, label=tid.upper(), host="h", interface="", enabled=True)


def _sample(
    *, target_id: str = "wlan", alive: bool = True, rtt_ms: float = 2.0, loss_pct: float = 0.0
) -> PingSample:
    return PingSample(
        target_id=target_id,
        host="h",
        alive=alive,
        rtt_ms=rtt_ms,
        loss_pct=loss_pct,
        timestamp=520.0,
    )


def _build(tasks: list[LoggingTask]) -> tuple[MonitorLoggingSink, _RecordingRtt, _RecordingEvents]:
    rtt = _RecordingRtt()
    events = _RecordingEvents()
    sink = MonitorLoggingSink(_FakeTaskRepo(tasks), rtt, events)
    return sink, rtt, events


# ── REACHABILITY_LATENCY: jede Messung ein RTT-Punkt ────────────────────────


def test_reachability_latency_saves_rtt_every_measurement() -> None:
    sink, rtt, events = _build([_task(capture_mode=CaptureMode.REACHABILITY_LATENCY)])

    # event=None (keine Flanke) -> trotzdem ein RTT-Punkt.
    asyncio.run(sink.record(_target(), _sample(rtt_ms=3.0, loss_pct=0.0), None, now=520.0))

    assert rtt.saved == [("task-1", 3.0, 0.0, True, 520.0)]
    assert events.saved == []  # REACHABILITY_LATENCY schreibt keine eigenen Flanken-Events


# ── REACHABILITY_LATENCY: Intervall-Ausduennung (C-2) ───────────────────────
# Fake-Uhr ueber den now-Parameter von record(). Fenster grosszuegig (max_duration_s
# 100000), damit is_window_active bei allen now-Werten offen ist -- getestet wird die
# Ausduennung, nicht das Fenster (das deckt der Filter-Block oben ab).


def test_interval_thins_dense_rtt_points() -> None:
    # interval_s=30: erster Tick schreibt; ein Tick nach 10 s NICHT; ein Tick nach 35 s
    # (seit dem letzten GESCHRIEBENEN) WIEDER.
    sink, rtt, _events = _build([_task(interval_s=30, effective_start=0.0, max_duration_s=100000)])

    asyncio.run(sink.record(_target(), _sample(rtt_ms=1.0), None, now=1000.0))
    assert [r[4] for r in rtt.saved] == [1000.0]  # erster Tick: geschrieben

    # +10 s -> < interval_s seit 1000 -> NICHT geschrieben.
    asyncio.run(sink.record(_target(), _sample(rtt_ms=2.0), None, now=1010.0))
    assert [r[4] for r in rtt.saved] == [1000.0]  # unveraendert

    # +35 s (seit dem letzten GESCHRIEBENEN bei 1000) -> >= 30 -> WIEDER geschrieben.
    asyncio.run(sink.record(_target(), _sample(rtt_ms=3.0), None, now=1035.0))
    assert [r[4] for r in rtt.saved] == [1000.0, 1035.0]


def test_interval_measures_from_last_written_not_last_tick() -> None:
    # Das Intervall laeuft ab dem letzten GESCHRIEBENEN Punkt, nicht ab dem letzten Tick:
    # ein verworfener Zwischen-Tick verschiebt das Fenster nicht.
    sink, rtt, _events = _build([_task(interval_s=30, effective_start=0.0, max_duration_s=100000)])
    asyncio.run(sink.record(_target(), _sample(), None, now=1000.0))  # schreibt
    asyncio.run(sink.record(_target(), _sample(), None, now=1020.0))  # +20 -> skip
    asyncio.run(sink.record(_target(), _sample(), None, now=1031.0))  # +31 seit 1000 -> schreibt
    assert [r[4] for r in rtt.saved] == [1000.0, 1031.0]


def test_interval_boundary_is_inclusive() -> None:
    # Genau interval_s seit dem letzten Punkt (>=) -> geschrieben (nicht >).
    sink, rtt, _events = _build([_task(interval_s=30, effective_start=0.0, max_duration_s=100000)])
    asyncio.run(sink.record(_target(), _sample(), None, now=1000.0))
    asyncio.run(sink.record(_target(), _sample(), None, now=1030.0))  # exakt +30 -> schreibt
    assert [r[4] for r in rtt.saved] == [1000.0, 1030.0]


def test_flank_is_never_thinned_in_latency_mode() -> None:
    # Eine Flanke (event != None) wird IMMER sofort geschrieben -- auch wenn das
    # Intervall noch nicht abgelaufen ist (sonst verpasst man den beobachteten Ausfall).
    sink, rtt, events = _build([_task(interval_s=300, effective_start=0.0, max_duration_s=100000)])
    asyncio.run(sink.record(_target(), _sample(), None, now=1000.0))  # erster Tick: schreibt
    # +5 s, aber MIT Flanke -> trotz interval_s=300 sofort geschrieben.
    asyncio.run(
        sink.record(_target(), _sample(alive=False, rtt_ms=-1.0), MonitorEventType.DOWN, now=1005.0)
    )
    assert [r[4] for r in rtt.saved] == [1000.0, 1005.0]
    # Die Flanke wird im REACHABILITY_LATENCY-Modus als RTT-Punkt geschrieben, nicht als
    # eigenes Event (der Modus fuehrt keine separaten Flanken-Events, s. Adapter-Docstring).
    assert events.saved == []
    # Ein gewoehnlicher Tick kurz danach (ohne Flanke) wird wieder ausgeduennt: der
    # Flanken-Punkt bei 1005 hat _letzter_rtt_ts aktualisiert.
    asyncio.run(sink.record(_target(), _sample(), None, now=1010.0))
    assert [r[4] for r in rtt.saved] == [1000.0, 1005.0]


def test_two_tasks_have_independent_interval_ts() -> None:
    # Zwei Tasks am selben Ziel fuehren unabhaengige letzte-ts: das Schreiben/Skippen
    # des einen beeinflusst den anderen nicht.
    sink, rtt, _events = _build(
        [
            _task(task_id="a", interval_s=30, effective_start=0.0, max_duration_s=100000),
            _task(task_id="b", interval_s=30, effective_start=0.0, max_duration_s=100000),
        ]
    )
    asyncio.run(sink.record(_target(), _sample(), None, now=1000.0))  # beide schreiben
    assert sorted(r[0] for r in rtt.saved) == ["a", "b"]
    # +35 s -> beide wieder (jeder ab seinem eigenen letzten Punkt bei 1000).
    asyncio.run(sink.record(_target(), _sample(), None, now=1035.0))
    assert sorted(r[0] for r in rtt.saved) == ["a", "a", "b", "b"]


def test_default_interval_5_thins_at_5s() -> None:
    # Default interval_s=5 = heutiges dichtes Verhalten an der 5-s-Grenze: ein Tick nach
    # 3 s wird verworfen, nach 5 s wieder geschrieben.
    sink, rtt, _events = _build(
        [_task(effective_start=0.0, max_duration_s=100000)]  # interval_s Default 5
    )
    asyncio.run(sink.record(_target(), _sample(), None, now=1000.0))
    asyncio.run(sink.record(_target(), _sample(), None, now=1003.0))  # +3 -> skip
    asyncio.run(sink.record(_target(), _sample(), None, now=1005.0))  # +5 -> schreibt
    assert [r[4] for r in rtt.saved] == [1000.0, 1005.0]


# ── REACHABILITY: nur die Flanke ────────────────────────────────────────────


def test_reachability_saves_event_only_on_flank() -> None:
    sink, rtt, events = _build([_task(capture_mode=CaptureMode.REACHABILITY)])

    # event=None -> nichts.
    asyncio.run(sink.record(_target(), _sample(), None, now=520.0))
    assert rtt.saved == []
    assert events.saved == []

    # event=DOWN -> genau eine Event-Flanke (roher str-Wert), KEIN rtt-save.
    asyncio.run(
        sink.record(_target(), _sample(alive=False, rtt_ms=-1.0), MonitorEventType.DOWN, now=520.0)
    )
    assert rtt.saved == []
    assert events.saved == [("task-1", "down", -1.0, 520.0)]


def test_interface_status_saves_event_only_on_flank() -> None:
    # INTERFACE_STATUS schreibt in B-II denselben Flanken-Pfad wie REACHABILITY.
    sink, rtt, events = _build([_task(capture_mode=CaptureMode.INTERFACE_STATUS)])

    asyncio.run(sink.record(_target(), _sample(), None, now=520.0))
    assert events.saved == []

    asyncio.run(sink.record(_target(), _sample(), MonitorEventType.UP, now=520.0))
    assert rtt.saved == []
    assert events.saved == [("task-1", "up", 2.0, 520.0)]


# ── Filter: state / Fenster / target_id ─────────────────────────────────────


def test_skips_non_active_task() -> None:
    sink, rtt, events = _build([_task(state=TaskState.PAUSED)])
    asyncio.run(sink.record(_target(), _sample(), None, now=520.0))
    assert rtt.saved == []
    assert events.saved == []


def test_skips_task_with_closed_window() -> None:
    # effective_start 500 + max 60 -> Fenster [500, 560). now=600 ist abgelaufen.
    sink, rtt, _events = _build([_task(effective_start=500.0, max_duration_s=60)])
    asyncio.run(sink.record(_target(), _sample(), None, now=600.0))
    assert rtt.saved == []


def test_skips_task_on_other_target() -> None:
    sink, rtt, _events = _build([_task(target_id="lan")])
    asyncio.run(sink.record(_target("wlan"), _sample(target_id="wlan"), None, now=520.0))
    assert rtt.saved == []


def test_only_matching_task_among_many_is_served() -> None:
    tasks = [
        _task(task_id="ok", target_id="wlan", state=TaskState.ACTIVE),
        _task(task_id="paused", target_id="wlan", state=TaskState.PAUSED),
        _task(task_id="other-target", target_id="lan", state=TaskState.ACTIVE),
    ]
    sink, rtt, _events = _build(tasks)
    asyncio.run(sink.record(_target("wlan"), _sample(target_id="wlan"), None, now=520.0))
    # Nur die aktive Aufgabe am richtigen Ziel mit offenem Fenster.
    assert [r[0] for r in rtt.saved] == ["ok"]


# ── Best-effort: ein werfendes Repo killt record nicht ──────────────────────


def test_record_is_best_effort_on_repo_failure() -> None:
    class _ThrowingRtt:
        def save(self, *args: object, **kwargs: object) -> None:
            raise RuntimeError("db kaputt")

    sink = MonitorLoggingSink(
        _FakeTaskRepo([_task(capture_mode=CaptureMode.REACHABILITY_LATENCY)]),
        _ThrowingRtt(),  # type: ignore[arg-type]
        _RecordingEvents(),
    )

    # Wirft NICHT -- der Fehler wird geschluckt+geloggt (Loop darf nicht sterben).
    asyncio.run(sink.record(_target(), _sample(), None, now=520.0))
