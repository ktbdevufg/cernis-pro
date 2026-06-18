"""Tests der Logging-Aufgaben-Lifecycle-Use-Cases (B-I Schritt 3) gegen Fake-Repos.

Reine application-Schicht: KEIN echtes sqlite. Ein aufzeichnender Fake-
``LoggingTaskRepository`` (in-memory dict ueber ``id``) belegt die Naht jedes
Use-Cases:

* ``CreateLoggingTask`` -> Zustand CREATED + ``save`` gerufen (reine Anlage, kein Konflikt).
* ``StartLoggingTask`` -> CREATED->ACTIVE + ``save``; Konflikt am Ziel ->
  ``LoggingTaskConflict`` (mit der ID des laufenden Konkurrenten); unbekannt ->
  ``LoggingTaskNotFound``; falscher Ausgangszustand -> ``InvalidTaskTransition`` durchgereicht.
* ``Pause``/``Resume``/``Stop`` -> Uebergang + ``save``; ``Resume`` prueft VOR dem
  resume die Konfliktregel; falscher Ausgangszustand -> ``InvalidTaskTransition``.
* ``List``/``Detail`` -> Pass-Through (Detail: unbekannt -> ``LoggingTaskNotFound``).
* ``CheckLogVolume`` -> count + Ueber-Schwelle-bool (unter/ueber Schwelle).
"""

import pytest

from application.monitoring import (
    CheckLogVolume,
    CreateLoggingTask,
    DeleteLoggingTask,
    GetLoggingTaskDetail,
    InvalidTaskTransition,
    ListLoggingTasks,
    LoggingTaskConflict,
    LoggingTaskNotFound,
    LogVolumeResult,
    PauseLoggingTask,
    ResumeLoggingTask,
    StartLoggingTask,
    StopLoggingTask,
)
from application.monitoring.use_cases import _LOG_VOLUME_THRESHOLD
from domain.monitoring import CaptureMode, LoggingTask, OperationMode, TaskState


class _FakeTaskRepo:
    """Aufzeichnender ``LoggingTaskRepository``-Fake (in-memory ueber ``id``)."""

    def __init__(self, tasks: list[LoggingTask] | None = None) -> None:
        self._store: dict[str, LoggingTask] = {t.id: t for t in (tasks or [])}
        self.saved: list[LoggingTask] = []
        self.deleted: list[str] = []

    def save(self, task: LoggingTask) -> None:
        self._store[task.id] = task
        self.saved.append(task)

    def get(self, task_id: str) -> LoggingTask | None:
        return self._store.get(task_id)

    def list_all(self) -> list[LoggingTask]:
        return list(self._store.values())

    def delete(self, task_id: str) -> None:
        self.deleted.append(task_id)
        self._store.pop(task_id, None)


class _FakeRttRepo:
    """``LoggingRttRepository``-Fake -- nur ``count`` wird vom CheckLogVolume gerufen."""

    def __init__(self, count: int) -> None:
        self._count = count

    def save(self, task_id: str, rtt_ms: float, loss_pct: float, alive: bool, ts: float) -> None:
        raise AssertionError("save darf von CheckLogVolume nicht gerufen werden")

    def range(self, task_id: str, since: float, until: float) -> list:  # type: ignore[type-arg]
        raise AssertionError("range darf von CheckLogVolume nicht gerufen werden")

    def delete_older_than(self, cutoff_ts: float) -> int:
        raise AssertionError("delete_older_than darf von CheckLogVolume nicht gerufen werden")

    def count(self) -> int:
        return self._count


def _task(
    task_id: str = "t1",
    *,
    target_id: str = "wlan",
    state: TaskState = TaskState.CREATED,
) -> LoggingTask:
    """Baut einen ``LoggingTask`` in beliebigem Zustand (Test-Helfer)."""
    return LoggingTask(
        id=task_id,
        target_id=target_id,
        label="L",
        purpose="P",
        capture_mode=CaptureMode.REACHABILITY,
        operation_mode=OperationMode.IMMEDIATE,
        state=state,
        planned_start=None,
        planned_end=None,
        max_duration_s=3600,
        created_at=1000.0,
    )


# ── CreateLoggingTask ───────────────────────────────────────────────────────


def test_create_legt_im_zustand_created_an_und_speichert() -> None:
    repo = _FakeTaskRepo()
    create = CreateLoggingTask(repo)

    task = create(
        task_id="abc",
        target_id="wlan",
        label="Server-Logging",
        purpose="Stoerungssuche",
        capture_mode="reachability_latency",
        operation_mode="immediate",
        created_at=1234.0,
        max_duration_s=7200,
    )

    assert task.state is TaskState.CREATED
    assert task.id == "abc"
    assert task.capture_mode is CaptureMode.REACHABILITY_LATENCY
    assert task.operation_mode is OperationMode.IMMEDIATE
    assert task.max_duration_s == 7200
    assert task.created_at == 1234.0
    # save wurde mit genau diesem Task gerufen.
    assert repo.saved == [task]


def test_create_scheduled_uebernimmt_fenster() -> None:
    repo = _FakeTaskRepo()
    task = CreateLoggingTask(repo)(
        task_id="s1",
        target_id="wlan",
        label="L",
        purpose="P",
        capture_mode="interface_status",
        operation_mode="scheduled",
        created_at=1.0,
        planned_start=10.0,
        planned_end=20.0,
    )
    assert task.operation_mode is OperationMode.SCHEDULED
    assert (task.planned_start, task.planned_end) == (10.0, 20.0)


# ── StartLoggingTask ────────────────────────────────────────────────────────


def test_start_created_wird_active_und_gespeichert() -> None:
    repo = _FakeTaskRepo([_task("t1", state=TaskState.CREATED)])
    started = StartLoggingTask(repo)("t1", now=999.0)
    assert started.state is TaskState.ACTIVE
    # now wird als effektiver Start durchgereicht (ADR 0033, B-II).
    assert started.effective_start == 999.0
    assert repo.saved == [started]


def test_start_unbekannt_wirft_not_found() -> None:
    repo = _FakeTaskRepo()
    with pytest.raises(LoggingTaskNotFound) as exc:
        StartLoggingTask(repo)("nope", now=1.0)
    assert exc.value.task_id == "nope"
    assert repo.saved == []


def test_start_konflikt_am_selben_ziel_wirft_conflict() -> None:
    # running laeuft bereits ACTIVE am Ziel wlan; candidate will am selben Ziel starten.
    running = _task("running", target_id="wlan", state=TaskState.ACTIVE)
    candidate = _task("candidate", target_id="wlan", state=TaskState.CREATED)
    repo = _FakeTaskRepo([running, candidate])

    with pytest.raises(LoggingTaskConflict) as exc:
        StartLoggingTask(repo)("candidate", now=1.0)

    assert exc.value.running_task_id == "running"
    assert exc.value.target_id == "wlan"
    # Kein save trotz Konflikt (der candidate bleibt CREATED).
    assert repo.saved == []


def test_start_anderes_ziel_kein_konflikt() -> None:
    running = _task("running", target_id="lan", state=TaskState.ACTIVE)
    candidate = _task("candidate", target_id="wlan", state=TaskState.CREATED)
    repo = _FakeTaskRepo([running, candidate])

    started = StartLoggingTask(repo)("candidate", now=1.0)
    assert started.state is TaskState.ACTIVE


def test_start_falscher_ausgangszustand_reicht_transition_durch() -> None:
    # Schon FINISHED -> domain.start wirft InvalidTaskTransition (durchgereicht).
    repo = _FakeTaskRepo([_task("t1", state=TaskState.FINISHED)])
    with pytest.raises(InvalidTaskTransition):
        StartLoggingTask(repo)("t1", now=1.0)


# ── Pause / Resume / Stop ───────────────────────────────────────────────────


def test_pause_active_wird_paused() -> None:
    repo = _FakeTaskRepo([_task("t1", state=TaskState.ACTIVE)])
    paused = PauseLoggingTask(repo)("t1")
    assert paused.state is TaskState.PAUSED
    assert repo.saved == [paused]


def test_pause_falscher_zustand_wirft_transition() -> None:
    repo = _FakeTaskRepo([_task("t1", state=TaskState.CREATED)])
    with pytest.raises(InvalidTaskTransition):
        PauseLoggingTask(repo)("t1")
    assert repo.saved == []


def test_pause_unbekannt_wirft_not_found() -> None:
    with pytest.raises(LoggingTaskNotFound):
        PauseLoggingTask(_FakeTaskRepo())("nope")


def test_resume_paused_wird_active() -> None:
    repo = _FakeTaskRepo([_task("t1", state=TaskState.PAUSED)])
    resumed = ResumeLoggingTask(repo)("t1")
    assert resumed.state is TaskState.ACTIVE
    assert repo.saved == [resumed]


def test_resume_konflikt_am_ziel_wirft_conflict() -> None:
    # Ein anderer Task laeuft bereits ACTIVE am Ziel -> Fortsetzen kollidiert.
    running = _task("running", target_id="wlan", state=TaskState.ACTIVE)
    paused = _task("paused", target_id="wlan", state=TaskState.PAUSED)
    repo = _FakeTaskRepo([running, paused])

    with pytest.raises(LoggingTaskConflict) as exc:
        ResumeLoggingTask(repo)("paused")
    assert exc.value.running_task_id == "running"
    assert repo.saved == []


def test_resume_falscher_zustand_wirft_transition() -> None:
    repo = _FakeTaskRepo([_task("t1", state=TaskState.CREATED)])
    with pytest.raises(InvalidTaskTransition):
        ResumeLoggingTask(repo)("t1")


def test_stop_active_wird_finished() -> None:
    repo = _FakeTaskRepo([_task("t1", state=TaskState.ACTIVE)])
    finished = StopLoggingTask(repo)("t1")
    assert finished.state is TaskState.FINISHED
    assert repo.saved == [finished]


def test_stop_paused_wird_finished() -> None:
    repo = _FakeTaskRepo([_task("t1", state=TaskState.PAUSED)])
    finished = StopLoggingTask(repo)("t1")
    assert finished.state is TaskState.FINISHED


def test_stop_falscher_zustand_wirft_transition() -> None:
    repo = _FakeTaskRepo([_task("t1", state=TaskState.CREATED)])
    with pytest.raises(InvalidTaskTransition):
        StopLoggingTask(repo)("t1")


def test_stop_unbekannt_wirft_not_found() -> None:
    with pytest.raises(LoggingTaskNotFound):
        StopLoggingTask(_FakeTaskRepo())("nope")


# ── Delete / List / Detail ──────────────────────────────────────────────────


def test_delete_reicht_an_repo_durch() -> None:
    repo = _FakeTaskRepo([_task("t1")])
    DeleteLoggingTask(repo)("t1")
    assert repo.deleted == ["t1"]


def test_delete_unbekannt_ist_idempotent() -> None:
    repo = _FakeTaskRepo()
    DeleteLoggingTask(repo)("nope")  # kein Fehler
    assert repo.deleted == ["nope"]


def test_list_gibt_alle_zurueck() -> None:
    tasks = [_task("a"), _task("b")]
    repo = _FakeTaskRepo(tasks)
    assert {t.id for t in ListLoggingTasks(repo)()} == {"a", "b"}


def test_list_leer_ist_leere_liste() -> None:
    assert ListLoggingTasks(_FakeTaskRepo())() == []


def test_detail_gibt_task_zurueck() -> None:
    repo = _FakeTaskRepo([_task("t1")])
    assert GetLoggingTaskDetail(repo)("t1").id == "t1"


def test_detail_unbekannt_wirft_not_found() -> None:
    with pytest.raises(LoggingTaskNotFound) as exc:
        GetLoggingTaskDetail(_FakeTaskRepo())("nope")
    assert exc.value.task_id == "nope"


# ── CheckLogVolume ──────────────────────────────────────────────────────────


def test_check_volume_unter_schwelle() -> None:
    result = CheckLogVolume(_FakeRttRepo(count=5))()
    assert result == LogVolumeResult(count=5, over_threshold=False)


def test_check_volume_ueber_schwelle() -> None:
    result = CheckLogVolume(_FakeRttRepo(count=_LOG_VOLUME_THRESHOLD + 1))()
    assert result.count == _LOG_VOLUME_THRESHOLD + 1
    assert result.over_threshold is True


def test_check_volume_genau_auf_schwelle_ist_nicht_drueber() -> None:
    # over_threshold ist strikt > Schwelle -- GENAU auf der Schwelle gilt als nicht drueber.
    result = CheckLogVolume(_FakeRttRepo(count=_LOG_VOLUME_THRESHOLD))()
    assert result.over_threshold is False
