"""Tests fuer ``GetLoggingTaskEvents`` (Schnitt 1b-events) -- Event-Liste gegen Fakes.

Reine application-Schicht: KEIN echtes sqlite -- der Fake-Event-Port liefert die rohen
``LoggingEventRow``-Objekte, die der Use-Case unveraendert (in Eingabe-Reihenfolge)
durchreicht. Gespiegelt aus ``test_logging_sla_use_case.py`` (Muster ``GetLoggingTaskSla``),
mit dem EINEN Unterschied: der Event-Port hat KEIN ``all_for`` -- der Use-Case nutzt
darum IMMER ``range``, auch im voll-offenen Fall (beide ``None`` -> ``range(0.0, CUTOFF)``).

* OHNE since/until -> ``range(task_id, 0.0, _OPEN_UNTIL_CUTOFF)`` (voll-offen, uhrfrei).
* MIT since UND until -> ``range`` mit genau diesen Grenzen.
* Nur since -> ``range`` mit eff_until = fester Cutoff (offene Obergrenze).
* Nur until -> ``range`` mit eff_since = 0.0 (offene Untergrenze).
* Unbekannter Task -> ``LoggingTaskNotFound`` (Event-Repo wird gar nicht erst gefragt).
* Rueckgabe in Eingabe-Reihenfolge (Pass-Through, keine Umsortierung).
"""

import pytest

from application.monitoring import GetLoggingTaskEvents, LoggingTaskNotFound
from domain.monitoring import (
    CaptureMode,
    LoggingEventRow,
    LoggingTask,
    OperationMode,
    TaskState,
)


def _task(task_id: str = "t1") -> LoggingTask:
    """Baut einen REACHABILITY_LATENCY-Task (Test-Helfer, Muster SLA-Test)."""
    return LoggingTask(
        id=task_id,
        target_id="wlan",
        label="L",
        purpose="P",
        capture_mode=CaptureMode.REACHABILITY_LATENCY,
        operation_mode=OperationMode.IMMEDIATE,
        state=TaskState.ACTIVE,
        planned_start=None,
        planned_end=None,
        max_duration_s=3600,
        created_at=1000.0,
    )


class _FakeTaskRepo:
    """``LoggingTaskRepository``-Fake -- nur ``get`` wird vom Use-Case gerufen.

    Die uebrigen Protocol-Methoden sind ``raise AssertionError``-Stubs (Muster der
    Nachbar-Fakes): strukturelle Konformitaet zu ``LoggingTaskRepository`` (mypy) + der
    Beleg, dass der Events-Use-Case nur ``get`` nutzt.
    """

    def __init__(self, tasks: list[LoggingTask] | None = None) -> None:
        self._store = {t.id: t for t in (tasks or [])}

    def get(self, task_id: str) -> LoggingTask | None:
        return self._store.get(task_id)

    def save(self, task: LoggingTask) -> None:
        raise AssertionError("save darf vom Events-Use-Case nicht gerufen werden")

    def list_all(self) -> list[LoggingTask]:
        raise AssertionError("list_all darf vom Events-Use-Case nicht gerufen werden")

    def delete(self, task_id: str) -> None:
        raise AssertionError("delete darf vom Events-Use-Case nicht gerufen werden")

    def clear_all(self) -> None:
        """Leert den internen Task-Speicher (No-op-Naht fuer den Fake)."""
        self._store.clear()


class _FakeEventRepo:
    """``LoggingEventRepository``-Fake -- nur ``range`` wird gerufen; zeichnet das auf.

    Die uebrigen Protocol-Methoden sind ``raise AssertionError``-Stubs: strukturelle
    Konformitaet zu ``LoggingEventRepository`` (mypy), und der Beleg, dass der
    Events-Use-Case NUR ``range`` nutzt (es gibt kein ``all_for`` im Event-Port).
    """

    def __init__(self, rows: dict[str, list[LoggingEventRow]] | None = None) -> None:
        self._rows = rows or {}
        # (task_id, since, until) jedes range-Aufrufs -- belegt die since/until-Naht.
        self.range_calls: list[tuple[str, float, float]] = []

    def range(self, task_id: str, since: float, until: float) -> list[LoggingEventRow]:
        # Der Fake filtert NICHT (die Naht ist "welche Grenzen", nicht das Repo-Filter);
        # er gibt die hinterlegten Zeilen in Eingabe-Reihenfolge zurueck.
        self.range_calls.append((task_id, since, until))
        return self._rows.get(task_id, [])

    def save(self, task_id: str, event_type: str, rtt_ms: float, ts: float) -> None:
        raise AssertionError("save darf vom Events-Use-Case nicht gerufen werden")

    def delete_older_than(self, cutoff_ts: float) -> int:
        raise AssertionError("delete_older_than darf vom Events-Use-Case nicht gerufen werden")

    def clear_all(self) -> None:
        """Leert die hinterlegten Event-Zeilen (No-op-Naht fuer den Fake)."""
        self._rows.clear()


def test_without_since_until_uses_full_open_range() -> None:
    # Kein all_for im Event-Port: beide None -> range(0.0, _OPEN_UNTIL_CUTOFF), uhrfrei.
    rows = [
        LoggingEventRow(event_type="down", rtt_ms=-1.0, ts=1_700_000_000.0),
        LoggingEventRow(event_type="up", rtt_ms=5.0, ts=1_700_000_010.0),
    ]
    task_repo = _FakeTaskRepo([_task("t1")])
    event_repo = _FakeEventRepo({"t1": rows})

    result = GetLoggingTaskEvents(task_repo, event_repo)("t1")

    assert event_repo.range_calls == [("t1", 0.0, 9_999_999_999.0)]
    # Rueckgabe in Eingabe-Reihenfolge (Pass-Through, rohe Domaenenobjekte).
    assert result == rows


def test_with_since_and_until_uses_range_with_those_bounds() -> None:
    rows = [LoggingEventRow(event_type="down", rtt_ms=-1.0, ts=1_700_000_050.0)]
    task_repo = _FakeTaskRepo([_task("t1")])
    event_repo = _FakeEventRepo({"t1": rows})

    result = GetLoggingTaskEvents(task_repo, event_repo)(
        "t1", since=1_700_000_000.0, until=1_700_000_100.0
    )

    assert event_repo.range_calls == [("t1", 1_700_000_000.0, 1_700_000_100.0)]
    assert result == rows


def test_only_since_uses_range_with_open_upper_bound() -> None:
    # Nur since -> eff_until = fester Cutoff (offene Obergrenze, uhrfrei).
    task_repo = _FakeTaskRepo([_task("t1")])
    event_repo = _FakeEventRepo({"t1": []})

    GetLoggingTaskEvents(task_repo, event_repo)("t1", since=1_700_000_000.0)

    assert event_repo.range_calls == [("t1", 1_700_000_000.0, 9_999_999_999.0)]


def test_only_until_uses_range_with_zero_lower_bound() -> None:
    # Nur until -> eff_since = 0.0 (offene Untergrenze).
    task_repo = _FakeTaskRepo([_task("t1")])
    event_repo = _FakeEventRepo({"t1": []})

    GetLoggingTaskEvents(task_repo, event_repo)("t1", until=1_700_000_100.0)

    assert event_repo.range_calls == [("t1", 0.0, 1_700_000_100.0)]


def test_unknown_task_raises_not_found_without_touching_event_repo() -> None:
    task_repo = _FakeTaskRepo([])  # kein Task "nope"
    event_repo = _FakeEventRepo({})

    with pytest.raises(LoggingTaskNotFound):
        GetLoggingTaskEvents(task_repo, event_repo)("nope")
    assert event_repo.range_calls == []  # Event-Repo gar nicht erst gefragt


def test_empty_events_yield_empty_list() -> None:
    task_repo = _FakeTaskRepo([_task("t1")])
    event_repo = _FakeEventRepo({"t1": []})

    result = GetLoggingTaskEvents(task_repo, event_repo)("t1")

    assert result == []
    assert event_repo.range_calls == [("t1", 0.0, 9_999_999_999.0)]
