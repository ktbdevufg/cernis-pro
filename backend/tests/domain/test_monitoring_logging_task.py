"""Unit-Tests der Logging-Aufgaben-Domaene (B-I Schritt 1, domain, zeitfrei).

Deckt die reinen Regeln ab: jeder Zustandsuebergang erlaubt + verboten, das
Konflikt-Praedikat mit/ohne aktivem Peer, und das Zeitfenster-Praedikat an seinen
Grenzen (genau am Start, genau am Ende, ausserhalb) -- fuer ``SCHEDULED`` wie
``IMMEDIATE``. Keine Uhr, keine Persistenz: ``now`` und der Bezugs-ts kommen als
Parameter rein.
"""

import dataclasses
from datetime import datetime

import pytest

from domain.monitoring import (
    CaptureMode,
    InvalidTaskTransition,
    LoggingTask,
    OperationMode,
    TaskState,
    conflicts_with,
    is_window_active,
    pause,
    resume,
    start,
    stop,
)


def _task(
    *,
    state: TaskState = TaskState.CREATED,
    operation_mode: OperationMode = OperationMode.SCHEDULED,
    task_id: str = "task-1",
    target_id: str = "target-1",
    planned_start: float | None = None,
    planned_end: float | None = None,
    max_duration_s: int | None = None,
    effective_start: float | None = None,
    recur_start_minute: int | None = None,
    recur_end_minute: int | None = None,
    recur_weekdays: frozenset[int] = frozenset(),
    recur_from: float | None = None,
    recur_until: float | None = None,
) -> LoggingTask:
    """Baut einen LoggingTask mit sprechenden Defaults fuer die einzelnen Faelle."""
    return LoggingTask(
        id=task_id,
        target_id=target_id,
        label="Test-Aufgabe",
        purpose="Charakterisierung",
        capture_mode=CaptureMode.REACHABILITY,
        operation_mode=operation_mode,
        state=state,
        planned_start=planned_start,
        planned_end=planned_end,
        max_duration_s=max_duration_s,
        created_at=1000.0,
        effective_start=effective_start,
        recur_start_minute=recur_start_minute,
        recur_end_minute=recur_end_minute,
        recur_weekdays=recur_weekdays,
        recur_from=recur_from,
        recur_until=recur_until,
    )


# --- Zustandsuebergaenge: erlaubt ---------------------------------------------


def test_start_created_to_active() -> None:
    result = start(_task(state=TaskState.CREATED), 500.0)
    assert result.state is TaskState.ACTIVE


def test_pause_active_to_paused() -> None:
    result = pause(_task(state=TaskState.ACTIVE))
    assert result.state is TaskState.PAUSED


def test_resume_paused_to_active() -> None:
    result = resume(_task(state=TaskState.PAUSED))
    assert result.state is TaskState.ACTIVE


def test_stop_active_to_finished() -> None:
    result = stop(_task(state=TaskState.ACTIVE))
    assert result.state is TaskState.FINISHED


def test_stop_paused_to_finished() -> None:
    result = stop(_task(state=TaskState.PAUSED))
    assert result.state is TaskState.FINISHED


def test_transition_returns_new_instance_and_leaves_original_untouched() -> None:
    # frozen -> dataclasses.replace: das Original bleibt unveraendert (kein In-Place).
    original = _task(state=TaskState.CREATED)
    result = start(original, 500.0)
    assert original.state is TaskState.CREATED
    assert result is not original
    # Zustand UND effective_start aendern sich (erster Start setzt ihn), sonst gleich.
    assert result == dataclasses.replace(original, state=TaskState.ACTIVE, effective_start=500.0)


# --- Zustandsuebergaenge: verboten --------------------------------------------


@pytest.mark.parametrize(
    "state",
    [TaskState.ACTIVE, TaskState.PAUSED, TaskState.FINISHED],
)
def test_start_from_non_created_raises(state: TaskState) -> None:
    with pytest.raises(InvalidTaskTransition):
        start(_task(state=state), 500.0)


@pytest.mark.parametrize(
    "state",
    [TaskState.CREATED, TaskState.PAUSED, TaskState.FINISHED],
)
def test_pause_from_non_active_raises(state: TaskState) -> None:
    with pytest.raises(InvalidTaskTransition):
        pause(_task(state=state))


@pytest.mark.parametrize(
    "state",
    [TaskState.CREATED, TaskState.ACTIVE, TaskState.FINISHED],
)
def test_resume_from_non_paused_raises(state: TaskState) -> None:
    with pytest.raises(InvalidTaskTransition):
        resume(_task(state=state))


@pytest.mark.parametrize(
    "state",
    [TaskState.CREATED, TaskState.FINISHED],
)
def test_stop_from_non_active_or_paused_raises(state: TaskState) -> None:
    with pytest.raises(InvalidTaskTransition):
        stop(_task(state=state))


def test_invalid_transition_carries_transition_and_state() -> None:
    with pytest.raises(InvalidTaskTransition) as exc_info:
        pause(_task(state=TaskState.CREATED))
    assert exc_info.value.transition == "pause"
    assert exc_info.value.state is TaskState.CREATED
    assert "pause" in str(exc_info.value)
    assert "created" in str(exc_info.value)


def test_invalid_transition_is_standalone_not_value_error() -> None:
    # Analog ScheduleParseError: EIGENSTAENDIG, erbt NICHT von ValueError -- ein
    # versehentliches ``except ValueError`` faengt es nicht mit.
    assert not issubclass(InvalidTaskTransition, ValueError)
    assert issubclass(InvalidTaskTransition, Exception)


# --- effective_start (ADR 0033) -----------------------------------------------


def test_first_start_sets_effective_start() -> None:
    # Erster Start (effective_start None) setzt ihn auf den uebergebenen ts.
    result = start(_task(state=TaskState.CREATED, effective_start=None), 500.0)
    assert result.effective_start == 500.0


def test_start_does_not_overwrite_existing_effective_start() -> None:
    # Ein bereits gesetzter effective_start bleibt unveraendert (nur erster Start setzt).
    task = _task(state=TaskState.CREATED, effective_start=300.0)
    result = start(task, 500.0)
    assert result.effective_start == 300.0


def test_pause_keeps_effective_start() -> None:
    # Pause laesst effective_start stehen (Maximaldauer ist reine Wanduhr, Pause zaehlt mit).
    task = _task(state=TaskState.ACTIVE, effective_start=500.0)
    assert pause(task).effective_start == 500.0


def test_resume_keeps_effective_start() -> None:
    # Fortsetzen aus Pause setzt effective_start NICHT neu (bleibt der erste Start).
    task = _task(state=TaskState.PAUSED, effective_start=500.0)
    assert resume(task).effective_start == 500.0


def test_stop_clears_effective_start() -> None:
    # Stop leert effective_start (Aufgabe beendet).
    active = _task(state=TaskState.ACTIVE, effective_start=500.0)
    assert stop(active).effective_start is None
    paused = _task(state=TaskState.PAUSED, effective_start=500.0)
    assert stop(paused).effective_start is None


# --- conflicts_with -----------------------------------------------------------


def test_conflicts_with_active_peer_same_target() -> None:
    candidate = _task(task_id="cand", target_id="t1", state=TaskState.CREATED)
    peer = _task(task_id="peer", target_id="t1", state=TaskState.ACTIVE)
    assert conflicts_with(candidate, [peer]) is True


def test_no_conflict_without_active_peer() -> None:
    candidate = _task(task_id="cand", target_id="t1", state=TaskState.CREATED)
    # Peer am selben Ziel, aber nicht ACTIVE -> kein Konflikt.
    paused_peer = _task(task_id="peer", target_id="t1", state=TaskState.PAUSED)
    finished_peer = _task(task_id="peer2", target_id="t1", state=TaskState.FINISHED)
    assert conflicts_with(candidate, [paused_peer, finished_peer]) is False


def test_no_conflict_with_active_peer_on_different_target() -> None:
    candidate = _task(task_id="cand", target_id="t1", state=TaskState.CREATED)
    other_target_peer = _task(task_id="peer", target_id="t2", state=TaskState.ACTIVE)
    assert conflicts_with(candidate, [other_target_peer]) is False


def test_no_conflict_with_empty_others() -> None:
    candidate = _task(task_id="cand", target_id="t1")
    assert conflicts_with(candidate, []) is False


def test_active_candidate_does_not_conflict_with_itself() -> None:
    # Ein bereits aktiver Kandidat darf in others enthalten sein, ohne mit sich selbst
    # zu kollidieren (Ausklammerung ueber die id).
    candidate = _task(task_id="same", target_id="t1", state=TaskState.ACTIVE)
    assert conflicts_with(candidate, [candidate]) is False


# --- is_window_active: SCHEDULED ----------------------------------------------


@pytest.mark.parametrize(
    ("now", "expected"),
    [
        (99.0, False),  # vor dem Fenster
        (100.0, True),  # genau am Start (inklusiv)
        (150.0, True),  # mitten im Fenster
        (199.0, True),  # kurz vor Ende
        (200.0, False),  # genau am Ende (exklusiv)
        (201.0, False),  # nach dem Fenster
    ],
)
def test_window_active_scheduled_boundaries(now: float, expected: bool) -> None:
    task = _task(
        operation_mode=OperationMode.SCHEDULED,
        planned_start=100.0,
        planned_end=200.0,
    )
    assert is_window_active(task, now) is expected


def test_window_inactive_scheduled_without_bounds() -> None:
    # Fehlt eine Grenze, gibt es kein definiertes Fenster -> False (kein stiller
    # Fallback auf "immer aktiv").
    no_start = _task(operation_mode=OperationMode.SCHEDULED, planned_start=None, planned_end=200.0)
    no_end = _task(operation_mode=OperationMode.SCHEDULED, planned_start=100.0, planned_end=None)
    assert is_window_active(no_start, 150.0) is False
    assert is_window_active(no_end, 150.0) is False


# --- is_window_active: IMMEDIATE ----------------------------------------------


@pytest.mark.parametrize(
    ("now", "expected"),
    [
        (499.0, False),  # vor dem effektiven Start
        (500.0, True),  # genau am Start (inklusiv)
        (520.0, True),  # innerhalb der Dauer
        (559.0, True),  # kurz vor Ablauf
        (560.0, False),  # genau am Ablauf (Start + 60s, exklusiv)
        (561.0, False),  # nach Ablauf
    ],
)
def test_window_active_immediate_boundaries(now: float, expected: bool) -> None:
    task = _task(operation_mode=OperationMode.IMMEDIATE, max_duration_s=60)
    # Bezugs-ts (effektiver Start) kommt explizit vom Use-Case rein.
    assert is_window_active(task, now, reference_ts=500.0) is expected


def test_window_inactive_immediate_without_reference_or_duration() -> None:
    # Ohne Bezugs-ts oder ohne max_duration_s ist kein Fenster bestimmbar -> False.
    task = _task(operation_mode=OperationMode.IMMEDIATE, max_duration_s=60)
    assert is_window_active(task, 520.0, reference_ts=None) is False
    no_duration = _task(operation_mode=OperationMode.IMMEDIATE, max_duration_s=None)
    assert is_window_active(no_duration, 520.0, reference_ts=500.0) is False


# --- is_window_active: IMMEDIATE gegen effective_start (ADR 0033) --------------
# Der Bezugs-ts kommt jetzt aus task.effective_start, OHNE dass der Aufrufer ihn
# extern uebergibt. reference_ts bleibt nur als optionaler Override.


@pytest.mark.parametrize(
    ("now", "expected"),
    [
        (499.0, False),  # vor dem effektiven Start
        (500.0, True),  # genau am effective_start (inklusiv)
        (559.0, True),  # kurz vor Ablauf
        (560.0, False),  # genau am Ablauf (effective_start + 60s, exklusiv)
    ],
)
def test_window_active_immediate_uses_effective_start(now: float, expected: bool) -> None:
    # KEIN reference_ts uebergeben -> die Domaene zieht task.effective_start.
    task = _task(operation_mode=OperationMode.IMMEDIATE, max_duration_s=60, effective_start=500.0)
    assert is_window_active(task, now) is expected


def test_window_inactive_immediate_without_effective_start() -> None:
    # Fehlt effective_start (noch nie gestartet / schon beendet) und kein reference_ts
    # -> kein Fenster -> False.
    task = _task(operation_mode=OperationMode.IMMEDIATE, max_duration_s=60, effective_start=None)
    assert is_window_active(task, 520.0) is False


def test_window_immediate_reference_ts_overrides_effective_start() -> None:
    # Wird reference_ts explizit uebergeben, hat er Vorrang vor effective_start.
    task = _task(operation_mode=OperationMode.IMMEDIATE, max_duration_s=60, effective_start=500.0)
    # Override auf 1000 -> bei now=520 (im effective_start-Fenster, aber vor Override) False.
    assert is_window_active(task, 520.0, reference_ts=1000.0) is False
    assert is_window_active(task, 1010.0, reference_ts=1000.0) is True


# --- interval_s (C-2, Mess-Intervall) -----------------------------------------


def test_logging_task_interval_s_defaults_to_5() -> None:
    # Reiner Datentraeger: ohne Angabe traegt der Task das heutige dichte Verhalten (5 s).
    # Das _task-Helper reicht interval_s NICHT durch -> der Domaenen-Default greift.
    assert _task().interval_s == 5


def test_logging_task_carries_explicit_interval_s() -> None:
    # Ein explizit gesetztes Intervall wird unveraendert getragen.
    task = LoggingTask(
        id="t",
        target_id="tgt",
        label="L",
        purpose="P",
        capture_mode=CaptureMode.REACHABILITY_LATENCY,
        operation_mode=OperationMode.IMMEDIATE,
        state=TaskState.CREATED,
        planned_start=None,
        planned_end=None,
        max_duration_s=60,
        created_at=1.0,
        interval_s=30,
    )
    assert task.interval_s == 30


# --- is_window_active: RECURRING ----------------------------------------------
# Minute + Wochentag werden zeitzonenunabhaengig aus der LOKALEN Sicht derselben
# Test-now abgeleitet (kein hardcodiertes Minuten-/Wochentags-Literal) -- Muster wie
# ``_active_window`` in test_scheduler_use_cases.py.

NOW = 1_700_000_000.0  # fixer Bezugs-ts; alle Erwartungen lokal daraus abgeleitet


def _local_minute_and_weekday(now: float) -> tuple[int, int]:
    """Lokale Wanduhr-Minute + Wochentag derselben epoch -- wie in der Domaene."""
    local = datetime.fromtimestamp(now)
    return local.hour * 60 + local.minute, local.weekday()


def test_window_active_recurring_in_window_weekday_and_range() -> None:
    # now im Tagesfenster + Wochentag passt + im Gesamtzeitraum -> True.
    now_minute, weekday = _local_minute_and_weekday(NOW)
    task = _task(
        operation_mode=OperationMode.RECURRING,
        recur_start_minute=now_minute,
        recur_end_minute=now_minute + 1,
        recur_weekdays=frozenset({weekday}),
        recur_from=NOW - 1000.0,
        recur_until=NOW + 1000.0,
    )
    assert is_window_active(task, NOW) is True


def test_window_inactive_recurring_before_recur_from() -> None:
    # now vor recur_from -> False (auch wenn Tagesfenster + Wochentag passen).
    now_minute, weekday = _local_minute_and_weekday(NOW)
    task = _task(
        operation_mode=OperationMode.RECURRING,
        recur_start_minute=now_minute,
        recur_end_minute=now_minute + 1,
        recur_weekdays=frozenset({weekday}),
        recur_from=NOW + 1.0,  # Gesamtzeitraum beginnt erst nach now
        recur_until=None,
    )
    assert is_window_active(task, NOW) is False


def test_window_inactive_recurring_at_or_after_recur_until() -> None:
    # now >= recur_until -> False (Ende exklusiv).
    now_minute, weekday = _local_minute_and_weekday(NOW)
    task = _task(
        operation_mode=OperationMode.RECURRING,
        recur_start_minute=now_minute,
        recur_end_minute=now_minute + 1,
        recur_weekdays=frozenset({weekday}),
        recur_from=NOW - 1000.0,
        recur_until=NOW,  # genau am Ende -> exklusiv blockiert
    )
    assert is_window_active(task, NOW) is False


def test_window_recurring_recur_until_none_never_blocks_by_range_end() -> None:
    # recur_until None heisst "kein Ende" -> Zeitraum-Ende blockiert nie.
    now_minute, weekday = _local_minute_and_weekday(NOW)
    task = _task(
        operation_mode=OperationMode.RECURRING,
        recur_start_minute=now_minute,
        recur_end_minute=now_minute + 1,
        recur_weekdays=frozenset({weekday}),
        recur_from=NOW - 1000.0,
        recur_until=None,
    )
    assert is_window_active(task, NOW) is True


def test_window_inactive_recurring_weekday_not_in_set() -> None:
    # Wochentag nicht in recur_weekdays -> False.
    now_minute, weekday = _local_minute_and_weekday(NOW)
    other_weekday = (weekday + 1) % 7
    task = _task(
        operation_mode=OperationMode.RECURRING,
        recur_start_minute=now_minute,
        recur_end_minute=now_minute + 1,
        recur_weekdays=frozenset({other_weekday}),
        recur_from=None,
        recur_until=None,
    )
    assert is_window_active(task, NOW) is False


def test_window_active_recurring_empty_weekdays_counts_every_day() -> None:
    # recur_weekdays leer = jeder Tag zaehlt -> Wochentag-Pruefung greift nicht.
    now_minute, _ = _local_minute_and_weekday(NOW)
    task = _task(
        operation_mode=OperationMode.RECURRING,
        recur_start_minute=now_minute,
        recur_end_minute=now_minute + 1,
        recur_weekdays=frozenset(),  # leer = alle Tage
        recur_from=None,
        recur_until=None,
    )
    assert is_window_active(task, NOW) is True


def test_window_active_recurring_now_minute_equals_start_is_inclusive() -> None:
    # now_minute == recur_start_minute -> True (Start inklusiv).
    now_minute, _ = _local_minute_and_weekday(NOW)
    task = _task(
        operation_mode=OperationMode.RECURRING,
        recur_start_minute=now_minute,
        recur_end_minute=now_minute + 5,
        recur_weekdays=frozenset(),
        recur_from=None,
        recur_until=None,
    )
    assert is_window_active(task, NOW) is True


def test_window_inactive_recurring_now_minute_equals_end_is_exclusive() -> None:
    # now_minute == recur_end_minute -> False (Ende exklusiv).
    now_minute, _ = _local_minute_and_weekday(NOW)
    task = _task(
        operation_mode=OperationMode.RECURRING,
        recur_start_minute=now_minute - 5,
        recur_end_minute=now_minute,  # Fenster endet genau jetzt -> exklusiv
        recur_weekdays=frozenset(),
        recur_from=None,
        recur_until=None,
    )
    assert is_window_active(task, NOW) is False


def test_window_inactive_recurring_without_daily_window() -> None:
    # recur_start_minute None -> kein Tagesfenster definiert -> False (kein Fallback).
    now_minute, _ = _local_minute_and_weekday(NOW)
    no_start = _task(
        operation_mode=OperationMode.RECURRING,
        recur_start_minute=None,
        recur_end_minute=now_minute + 1,
    )
    no_end = _task(
        operation_mode=OperationMode.RECURRING,
        recur_start_minute=now_minute,
        recur_end_minute=None,
    )
    assert is_window_active(no_start, NOW) is False
    assert is_window_active(no_end, NOW) is False


# --- is_window_active: Gegenprobe SCHEDULED/IMMEDIATE unveraendert -------------


def test_window_scheduled_still_behaves_unchanged() -> None:
    # Bestandstest-aequivalenter SCHEDULED-Fall bleibt gruen (Logik unveraendert).
    task = _task(
        operation_mode=OperationMode.SCHEDULED,
        planned_start=100.0,
        planned_end=200.0,
    )
    assert is_window_active(task, 100.0) is True  # Start inklusiv
    assert is_window_active(task, 200.0) is False  # Ende exklusiv


def test_window_immediate_still_behaves_unchanged() -> None:
    # Bestandstest-aequivalenter IMMEDIATE-Fall bleibt gruen (Logik unveraendert).
    task = _task(operation_mode=OperationMode.IMMEDIATE, max_duration_s=60)
    assert is_window_active(task, 500.0, reference_ts=500.0) is True
    assert is_window_active(task, 560.0, reference_ts=500.0) is False
