"""Tests fuer ``GetLoggingTaskRtt`` (Block 3c) -- rohe RTT-Samples gegen Fakes.

Reine application-Schicht: KEIN echtes sqlite -- der Fake-RTT-Port liefert die rohen
``LoggingRttSample``-Objekte, die der Use-Case unveraendert durchreicht (KEINE Rechnung,
Pass-Through). Gespiegelt aus ``test_logging_events_use_case.py``, mit dem EINEN
Unterschied: das ``LoggingRttRepository`` HAT ein ``all_for`` (anders als der Event-Port)
-- bei beiden Grenzen ``None`` nutzt der Use-Case ``all_for``, sonst ``range`` (Muster
``GetLoggingTaskSla``).

* OHNE since/until -> ``all_for(task_id)`` (gesamter Task-Zeitraum), KEIN range.
* MIT since UND until -> ``range`` mit genau diesen Grenzen.
* Nur since -> ``range`` mit eff_until = fester Cutoff (offene Obergrenze).
* Nur until -> ``range`` mit eff_since = 0.0 (offene Untergrenze).
* Unbekannter Task -> ``LoggingTaskNotFound`` (RTT-Repo wird gar nicht erst gefragt).
* Rueckgabe in Eingabe-Reihenfolge (Pass-Through, keine Umsortierung).
"""

import pytest

from application.monitoring import GetLoggingTaskRtt, LoggingTaskNotFound
from domain.monitoring import (
    CaptureMode,
    LoggingRttSample,
    LoggingTask,
    OperationMode,
    TaskState,
)


def _task(task_id: str = "t1") -> LoggingTask:
    """Baut einen REACHABILITY_LATENCY-Task (Test-Helfer, Muster Events-Test)."""
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
    Beleg, dass der RTT-Use-Case nur ``get`` nutzt.
    """

    def __init__(self, tasks: list[LoggingTask] | None = None) -> None:
        self._store = {t.id: t for t in (tasks or [])}

    def get(self, task_id: str) -> LoggingTask | None:
        return self._store.get(task_id)

    def save(self, task: LoggingTask) -> None:
        raise AssertionError("save darf vom RTT-Use-Case nicht gerufen werden")

    def list_all(self) -> list[LoggingTask]:
        raise AssertionError("list_all darf vom RTT-Use-Case nicht gerufen werden")

    def delete(self, task_id: str) -> None:
        raise AssertionError("delete darf vom RTT-Use-Case nicht gerufen werden")

    def clear_all(self) -> None:
        """Leert den internen Task-Speicher (No-op-Naht fuer den Fake)."""
        self._store.clear()


class _FakeRttRepo:
    """``LoggingRttRepository``-Fake -- ``all_for``/``range`` werden gerufen; zeichnet das auf.

    Die uebrigen Protocol-Methoden sind ``raise AssertionError``-Stubs: strukturelle
    Konformitaet zu ``LoggingRttRepository`` (mypy), und der Beleg, dass der RTT-Use-Case
    NUR ``all_for``/``range`` nutzt.
    """

    def __init__(self, samples: dict[str, list[LoggingRttSample]] | None = None) -> None:
        self._samples = samples or {}
        self.all_for_calls: list[str] = []
        # (task_id, since, until) jedes range-Aufrufs -- belegt die since/until-Naht.
        self.range_calls: list[tuple[str, float, float]] = []

    def all_for(self, task_id: str) -> list[LoggingRttSample]:
        self.all_for_calls.append(task_id)
        return self._samples.get(task_id, [])

    def range(self, task_id: str, since: float, until: float) -> list[LoggingRttSample]:
        # Der Fake filtert NICHT (die Naht ist "welche Grenzen", nicht das Repo-Filter);
        # er gibt die hinterlegten Samples in Eingabe-Reihenfolge zurueck.
        self.range_calls.append((task_id, since, until))
        return self._samples.get(task_id, [])

    def save(self, task_id: str, rtt_ms: float, loss_pct: float, alive: bool, ts: float) -> None:
        raise AssertionError("save darf vom RTT-Use-Case nicht gerufen werden")

    def delete_older_than(self, cutoff_ts: float) -> int:
        raise AssertionError("delete_older_than darf vom RTT-Use-Case nicht gerufen werden")

    def count(self) -> int:
        raise AssertionError("count darf vom RTT-Use-Case nicht gerufen werden")

    def clear_all(self) -> None:
        """Leert die hinterlegten Samples (No-op-Naht fuer den Fake)."""
        self._samples.clear()


def test_without_since_until_uses_all_for() -> None:
    # Beide None -> all_for (gesamter Task-Zeitraum), KEIN range (Muster GetLoggingTaskSla).
    samples = [
        LoggingRttSample(rtt_ms=4.0, loss_pct=0.0, alive=True, ts=1_700_000_000.0),
        LoggingRttSample(rtt_ms=-1.0, loss_pct=100.0, alive=False, ts=1_700_000_010.0),
    ]
    task_repo = _FakeTaskRepo([_task("t1")])
    rtt_repo = _FakeRttRepo({"t1": samples})

    result = GetLoggingTaskRtt(task_repo, rtt_repo)("t1")

    assert rtt_repo.all_for_calls == ["t1"]
    assert rtt_repo.range_calls == []
    # Rueckgabe in Eingabe-Reihenfolge (Pass-Through, rohe Domaenenobjekte).
    assert result == samples


def test_with_since_and_until_uses_range_with_those_bounds() -> None:
    samples = [LoggingRttSample(rtt_ms=3.0, loss_pct=0.0, alive=True, ts=1_700_000_050.0)]
    task_repo = _FakeTaskRepo([_task("t1")])
    rtt_repo = _FakeRttRepo({"t1": samples})

    result = GetLoggingTaskRtt(task_repo, rtt_repo)(
        "t1", since=1_700_000_000.0, until=1_700_000_100.0
    )

    assert rtt_repo.range_calls == [("t1", 1_700_000_000.0, 1_700_000_100.0)]
    assert rtt_repo.all_for_calls == []
    assert result == samples


def test_only_since_uses_range_with_open_upper_bound() -> None:
    # Nur since -> eff_until = fester Cutoff (offene Obergrenze, uhrfrei).
    task_repo = _FakeTaskRepo([_task("t1")])
    rtt_repo = _FakeRttRepo({"t1": []})

    GetLoggingTaskRtt(task_repo, rtt_repo)("t1", since=1_700_000_000.0)

    assert rtt_repo.range_calls == [("t1", 1_700_000_000.0, 9_999_999_999.0)]
    assert rtt_repo.all_for_calls == []


def test_only_until_uses_range_with_zero_lower_bound() -> None:
    # Nur until -> eff_since = 0.0 (offene Untergrenze).
    task_repo = _FakeTaskRepo([_task("t1")])
    rtt_repo = _FakeRttRepo({"t1": []})

    GetLoggingTaskRtt(task_repo, rtt_repo)("t1", until=1_700_000_100.0)

    assert rtt_repo.range_calls == [("t1", 0.0, 1_700_000_100.0)]
    assert rtt_repo.all_for_calls == []


def test_unknown_task_raises_not_found_without_touching_rtt_repo() -> None:
    task_repo = _FakeTaskRepo([])  # kein Task "nope"
    rtt_repo = _FakeRttRepo({})

    with pytest.raises(LoggingTaskNotFound):
        GetLoggingTaskRtt(task_repo, rtt_repo)("nope")
    assert rtt_repo.all_for_calls == []  # RTT-Repo gar nicht erst gefragt
    assert rtt_repo.range_calls == []


def test_empty_samples_yield_empty_list() -> None:
    task_repo = _FakeTaskRepo([_task("t1")])
    rtt_repo = _FakeRttRepo({"t1": []})

    result = GetLoggingTaskRtt(task_repo, rtt_repo)("t1")

    assert result == []
    assert rtt_repo.all_for_calls == ["t1"]
