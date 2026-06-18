"""Tests fuer die B-II-Lifespan-Use-Cases: Resume + periodischer Retention-Runner.

Reine application-Schicht: KEIN echtes sqlite, kein Loop-Takt. Fake-Repos + ein
Fake-``EnforceLoggingRetention``-Doppel belegen die Naht:

* ``ResumeActiveLoggingTasks``: aktive Aufgabe mit offenem Fenster bleibt ACTIVE
  (kein save), mit abgelaufenem Fenster -> FINISHED (save). Nicht-aktive ignoriert.
* ``RunLoggingRetention.tick``: rechnet now-basierte Cutoffs und ruft enforce.run;
  best-effort (ein werfender enforce killt den tick NICHT). ``run``/``stop`` trivial.
"""

import asyncio

from application.monitoring import (
    ResumeActiveLoggingTasks,
    ResumeResult,
    RunLoggingRetention,
)
from application.monitoring.use_cases import (
    _EVENT_RETENTION_S,
    _RTT_RETENTION_S,
    LoggingRetentionResult,
)
from domain.monitoring import (
    CaptureMode,
    LoggingTask,
    OperationMode,
    TaskState,
)


class _FakeTaskRepo:
    """``LoggingTaskRepository``-Fake -- Resume nutzt nur ``list_all`` + ``save``.

    ``get``/``delete`` sind AssertionError-Stubs (Muster ``test_logging_retention``):
    der Resume-Use-Case darf sie nicht rufen.
    """

    def __init__(self, tasks: list[LoggingTask]) -> None:
        self._store = {t.id: t for t in tasks}
        self.saved: list[LoggingTask] = []

    def list_all(self) -> list[LoggingTask]:
        return list(self._store.values())

    def save(self, task: LoggingTask) -> None:
        self._store[task.id] = task
        self.saved.append(task)

    def get(self, task_id: str) -> LoggingTask | None:
        raise AssertionError("get darf von ResumeActiveLoggingTasks nicht gerufen werden")

    def delete(self, task_id: str) -> None:
        raise AssertionError("delete darf von ResumeActiveLoggingTasks nicht gerufen werden")


def _immediate(
    *,
    task_id: str,
    state: TaskState = TaskState.ACTIVE,
    effective_start: float | None = 500.0,
    max_duration_s: int | None = 60,
) -> LoggingTask:
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
        max_duration_s=max_duration_s,
        created_at=1.0,
        effective_start=effective_start,
    )


# ── ResumeActiveLoggingTasks ────────────────────────────────────────────────


def test_resume_keeps_active_task_with_open_window() -> None:
    # Fenster [500, 560), now=520 -> offen -> bleibt ACTIVE, KEIN save.
    repo = _FakeTaskRepo([_immediate(task_id="ok", effective_start=500.0, max_duration_s=60)])
    result = ResumeActiveLoggingTasks(repo)(now=520.0)
    assert result == ResumeResult(kept_active=1, finished=0)
    assert repo.saved == []  # nichts geschrieben -- der Sink nimmt sie automatisch auf


def test_resume_finishes_active_task_with_expired_window() -> None:
    # Fenster [500, 560), now=600 -> abgelaufen -> FINISHED + save.
    repo = _FakeTaskRepo([_immediate(task_id="old", effective_start=500.0, max_duration_s=60)])
    result = ResumeActiveLoggingTasks(repo)(now=600.0)
    assert result == ResumeResult(kept_active=0, finished=1)
    assert len(repo.saved) == 1
    assert repo.saved[0].state is TaskState.FINISHED
    assert repo.saved[0].effective_start is None  # stop leert ihn (ADR 0033)


def test_resume_ignores_non_active_tasks() -> None:
    # PAUSED/CREATED/FINISHED werden nicht angefasst (nur ACTIVE wird geprueft).
    repo = _FakeTaskRepo(
        [
            _immediate(task_id="paused", state=TaskState.PAUSED),
            _immediate(task_id="created", state=TaskState.CREATED),
            _immediate(task_id="finished", state=TaskState.FINISHED, effective_start=None),
        ]
    )
    result = ResumeActiveLoggingTasks(repo)(now=600.0)
    assert result == ResumeResult(kept_active=0, finished=0)
    assert repo.saved == []


def test_resume_mixes_kept_and_finished() -> None:
    repo = _FakeTaskRepo(
        [
            _immediate(task_id="ok", effective_start=500.0, max_duration_s=60),  # offen bei 520
            _immediate(task_id="old", effective_start=100.0, max_duration_s=60),  # zu bei 520
        ]
    )
    result = ResumeActiveLoggingTasks(repo)(now=520.0)
    assert result == ResumeResult(kept_active=1, finished=1)
    assert [t.id for t in repo.saved] == ["old"]


# ── RunLoggingRetention ─────────────────────────────────────────────────────


class _FakeEnforce:
    """Doppel fuer ``EnforceLoggingRetention``: zeichnet die Cutoffs auf."""

    def __init__(self) -> None:
        self.calls: list[tuple[float, float]] = []

    def run(self, rtt_cutoff_ts: float, event_cutoff_ts: float) -> LoggingRetentionResult:
        self.calls.append((rtt_cutoff_ts, event_cutoff_ts))
        return LoggingRetentionResult(rtt_deleted=0, event_deleted=0)


def test_retention_tick_computes_now_based_cutoffs() -> None:
    enforce = _FakeEnforce()
    runner = RunLoggingRetention(enforce)  # type: ignore[arg-type]

    asyncio.run(runner.tick())

    assert len(enforce.calls) == 1
    rtt_cutoff, event_cutoff = enforce.calls[0]
    # Cutoffs sind now - Retention-Spanne; der RTT-Cutoff liegt nach dem Event-Cutoff
    # (30 Tage vs. 1 Jahr) -- ihre Differenz ist exakt die Spannen-Differenz.
    assert rtt_cutoff - event_cutoff == _EVENT_RETENTION_S - _RTT_RETENTION_S


def test_retention_tick_is_best_effort_on_enforce_failure() -> None:
    class _ThrowingEnforce:
        def run(self, rtt_cutoff_ts: float, event_cutoff_ts: float) -> LoggingRetentionResult:
            raise RuntimeError("retention kaputt")

    runner = RunLoggingRetention(_ThrowingEnforce())  # type: ignore[arg-type]
    # Wirft NICHT -- der periodische Task darf nicht sterben.
    asyncio.run(runner.tick())


def test_retention_stop_clears_running_flag() -> None:
    runner = RunLoggingRetention(_FakeEnforce())  # type: ignore[arg-type]
    runner._running = True
    runner.stop()
    assert runner._running is False
