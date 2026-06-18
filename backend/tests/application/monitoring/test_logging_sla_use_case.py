"""Tests fuer ``GetLoggingTaskSla`` (C-3) -- EIGENER Logging-SLA-Pfad gegen Fakes.

Reine application-Schicht: KEIN echtes sqlite, KEIN Mock der Domaene -- die echte
``compute_sla_stats`` (M.2) rechnet auf den vom Fake gelieferten ``LoggingRttSample``-
Objekten. Getestet wird die Naht des Use-Cases:

* Bekannte Samples -> erwartete uptime%/avg/downtime; ``task_id`` injiziert.
* Das Task-``interval_s`` wird an ``compute_sla_stats`` durchgereicht (Downtime-
  Schaetzung intervall-korrekt).
* Unbekannter Task -> ``LoggingTaskNotFound`` (RTT-Repo wird gar nicht erst gefragt).
* Leere Samples -> Domaenen-Null-Stats (``uptime_pct=None``), mit ``task_id``.
* OHNE since/until -> ``all_for`` (Bestandsverhalten, gesamter Task-Zeitraum).
* MIT since/until -> ``range`` statt ``all_for`` (Schnitt 1b, der Ausschnitt).
"""

import pytest

from application.monitoring import GetLoggingTaskSla, LoggingTaskNotFound
from domain.monitoring import (
    CaptureMode,
    LoggingRttSample,
    LoggingTask,
    OperationMode,
    TaskState,
)


def _task(task_id: str = "t1", *, interval_s: int = 5) -> LoggingTask:
    """Baut einen REACHABILITY_LATENCY-Task mit waehlbarem ``interval_s`` (Test-Helfer)."""
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
        interval_s=interval_s,
    )


class _FakeTaskRepo:
    """``LoggingTaskRepository``-Fake -- nur ``get`` wird vom Use-Case gerufen.

    Die uebrigen Protocol-Methoden sind ``raise AssertionError``-Stubs (Muster der
    Nachbar-Fakes): sie duerfen vom SLA-Use-Case nicht gerufen werden und erfuellen
    zugleich die strukturelle Konformitaet zu ``LoggingTaskRepository`` (mypy).
    """

    def __init__(self, tasks: list[LoggingTask] | None = None) -> None:
        self._store = {t.id: t for t in (tasks or [])}

    def get(self, task_id: str) -> LoggingTask | None:
        return self._store.get(task_id)

    def save(self, task: LoggingTask) -> None:
        raise AssertionError("save darf vom SLA-Use-Case nicht gerufen werden")

    def list_all(self) -> list[LoggingTask]:
        raise AssertionError("list_all darf vom SLA-Use-Case nicht gerufen werden")

    def delete(self, task_id: str) -> None:
        raise AssertionError("delete darf vom SLA-Use-Case nicht gerufen werden")


class _FakeRttRepo:
    """``LoggingRttRepository``-Fake -- nur ``all_for`` wird gerufen; zeichnet das auf.

    Die uebrigen Protocol-Methoden sind ``raise AssertionError``-Stubs (Muster der
    Nachbar-Fakes): strukturelle Konformitaet zu ``LoggingRttRepository`` (mypy), und
    der Beleg, dass der SLA-Use-Case NUR ``all_for`` nutzt.
    """

    def __init__(self, samples: dict[str, list[LoggingRttSample]] | None = None) -> None:
        self._samples = samples or {}
        self.all_for_calls: list[str] = []
        # (task_id, since, until) jedes range-Aufrufs -- belegt die since/until-Naht.
        self.range_calls: list[tuple[str, float, float]] = []

    def all_for(self, task_id: str) -> list[LoggingRttSample]:
        self.all_for_calls.append(task_id)
        return self._samples.get(task_id, [])

    def save(self, task_id: str, rtt_ms: float, loss_pct: float, alive: bool, ts: float) -> None:
        raise AssertionError("save darf vom SLA-Use-Case nicht gerufen werden")

    def range(self, task_id: str, since: float, until: float) -> list[LoggingRttSample]:
        # Schnitt 1b: bei gesetztem since/until nutzt der Use-Case range statt all_for.
        # Liefert dieselben Test-Samples wie all_for (der Fake filtert nicht -- die Naht
        # ist "welche Methode + welche Grenzen", nicht das Filter-Verhalten des Repos).
        self.range_calls.append((task_id, since, until))
        return self._samples.get(task_id, [])

    def delete_older_than(self, cutoff_ts: float) -> int:
        raise AssertionError("delete_older_than darf vom SLA-Use-Case nicht gerufen werden")

    def count(self) -> int:
        raise AssertionError("count darf vom SLA-Use-Case nicht gerufen werden")


def test_known_samples_yield_expected_stats_with_task_id() -> None:
    # Drei alive (rtt 4/6/0 -> avg ueber rtt>0: (4+6)/2=5), ein down -> uptime 3/4=75.
    samples = [
        LoggingRttSample(rtt_ms=4.0, loss_pct=0.0, alive=True, ts=1_700_000_000.0),
        LoggingRttSample(rtt_ms=6.0, loss_pct=0.0, alive=True, ts=1_700_000_005.0),
        LoggingRttSample(rtt_ms=0.0, loss_pct=0.0, alive=True, ts=1_700_000_010.0),
        LoggingRttSample(rtt_ms=-1.0, loss_pct=100.0, alive=False, ts=1_700_000_015.0),
    ]
    task_repo = _FakeTaskRepo([_task("t1", interval_s=5)])
    rtt_repo = _FakeRttRepo({"t1": samples})

    result = GetLoggingTaskSla(task_repo, rtt_repo)("t1")

    assert result["task_id"] == "t1"  # injiziert (Domaene setzt es nicht)
    assert result["samples"] == 4
    assert result["uptime_pct"] == 75.0  # 3/4 alive
    assert result["avg_rtt_ms"] == 5.0  # mean([4,6]) -- 0/Sentinel fallen raus
    assert result["downtime_mins"] == 0.1  # 1 down * 5s / 60 -> 0.0833 -> 0.1
    assert rtt_repo.all_for_calls == ["t1"]


def test_interval_s_is_passed_through_to_downtime() -> None:
    # Derselbe down-Sample, aber interval_s=60 -> Downtime 12x groesser (60/5).
    samples = [
        LoggingRttSample(rtt_ms=5.0, loss_pct=0.0, alive=True, ts=1_700_000_000.0),
        LoggingRttSample(rtt_ms=-1.0, loss_pct=100.0, alive=False, ts=1_700_000_060.0),
    ]
    task_repo = _FakeTaskRepo([_task("t1", interval_s=60)])
    rtt_repo = _FakeRttRepo({"t1": samples})

    result = GetLoggingTaskSla(task_repo, rtt_repo)("t1")

    assert result["downtime_mins"] == 1.0  # 1 down * 60s / 60 -> 1.0
    assert result["uptime_pct"] == 50.0  # intervall-unabhaengig


def test_unknown_task_raises_not_found_without_touching_rtt_repo() -> None:
    task_repo = _FakeTaskRepo([])  # kein Task "nope"
    rtt_repo = _FakeRttRepo({})

    with pytest.raises(LoggingTaskNotFound):
        GetLoggingTaskSla(task_repo, rtt_repo)("nope")
    assert rtt_repo.all_for_calls == []  # RTT-Repo gar nicht erst gefragt


def test_empty_samples_yield_null_stats_with_task_id() -> None:
    task_repo = _FakeTaskRepo([_task("t1")])
    rtt_repo = _FakeRttRepo({"t1": []})

    result = GetLoggingTaskSla(task_repo, rtt_repo)("t1")

    assert result["task_id"] == "t1"  # auch im Leerfall injiziert
    assert result["samples"] == 0
    assert result["uptime_pct"] is None  # Domaenen-Null-Stat: None, NICHT 0
    assert result["avg_rtt_ms"] == 0
    assert result["chart"] == []


# ── since/until-Naht (Schnitt 1b): all_for vs. range ────────────────────────


def test_without_since_until_uses_all_for_not_range() -> None:
    # Bestandsverhalten: ohne Zeitraum-Grenzen liest der Use-Case ALLE Punkte (all_for),
    # range wird gar nicht erst gerufen.
    samples = [
        LoggingRttSample(rtt_ms=4.0, loss_pct=0.0, alive=True, ts=1_700_000_000.0),
        LoggingRttSample(rtt_ms=6.0, loss_pct=0.0, alive=True, ts=1_700_000_005.0),
    ]
    task_repo = _FakeTaskRepo([_task("t1")])
    rtt_repo = _FakeRttRepo({"t1": samples})

    result = GetLoggingTaskSla(task_repo, rtt_repo)("t1")

    assert rtt_repo.all_for_calls == ["t1"]  # all_for genutzt
    assert rtt_repo.range_calls == []  # range NICHT gerufen
    assert result["samples"] == 2  # die all_for-Punkte gerechnet


def test_with_since_and_until_uses_range_with_those_bounds() -> None:
    # Schnitt 1b: gesetzte since UND until -> range mit genau diesen Grenzen; all_for
    # wird NICHT gerufen.
    samples = [
        LoggingRttSample(rtt_ms=5.0, loss_pct=0.0, alive=True, ts=1_700_000_000.0),
    ]
    task_repo = _FakeTaskRepo([_task("t1")])
    rtt_repo = _FakeRttRepo({"t1": samples})

    result = GetLoggingTaskSla(task_repo, rtt_repo)(
        "t1", since=1_700_000_000.0, until=1_700_000_100.0
    )

    assert rtt_repo.range_calls == [("t1", 1_700_000_000.0, 1_700_000_100.0)]
    assert rtt_repo.all_for_calls == []  # all_for NICHT gerufen
    assert result["task_id"] == "t1"
    assert result["samples"] == 1


def test_only_since_uses_range_with_zero_lower_bound() -> None:
    # Nur since gesetzt -> range mit eff_until = fester Cutoff (offene Obergrenze,
    # uhrfrei). eff_since = das gesetzte since.
    task_repo = _FakeTaskRepo([_task("t1")])
    rtt_repo = _FakeRttRepo({"t1": []})

    GetLoggingTaskSla(task_repo, rtt_repo)("t1", since=1_700_000_000.0)

    assert len(rtt_repo.range_calls) == 1
    task_id, since, until = rtt_repo.range_calls[0]
    assert task_id == "t1"
    assert since == 1_700_000_000.0  # gesetztes since
    assert until == 9_999_999_999.0  # _OPEN_UNTIL_CUTOFF (Jahr 2286, fester Wert)
    assert rtt_repo.all_for_calls == []


def test_only_until_uses_range_with_zero_lower_bound() -> None:
    # Nur until gesetzt -> range mit eff_since = 0.0 (offene Untergrenze).
    task_repo = _FakeTaskRepo([_task("t1")])
    rtt_repo = _FakeRttRepo({"t1": []})

    GetLoggingTaskSla(task_repo, rtt_repo)("t1", until=1_700_000_100.0)

    assert rtt_repo.range_calls == [("t1", 0.0, 1_700_000_100.0)]
    assert rtt_repo.all_for_calls == []
