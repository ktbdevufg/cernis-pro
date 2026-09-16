"""Tests der RECURRING-Logging <-> Scheduler-Job-Naht (Block 3b, Etappe 3b-3).

Belegt die beiden Composition-Root-Erben-Wrapper aus ``app.py`` direkt (Unit, kein
TestClient -- der Wrapper ist auf Modulebene importierbar, sein Verhalten haengt nicht
am HTTP-Rand): beim Anlegen eines RECURRING-Tasks entsteht automatisch ein ScheduledJob
(``job_type`` "monitoring_window", ``task_id`` in den params); bei IMMEDIATE/SCHEDULED
NICHT; und das Loeschen raeumt den zugehoerigen Job wieder ab.

Gegen schlanke in-memory Fakes (Muster ``test_scheduler_api._FakeScheduledJobRepository``):
ein Fake-LoggingTaskRepository (nur ``save``/``delete``) und ein Fake-ScheduledJobRepository
(``add``/``list_all``/``delete``). Die echten Use-Cases (``CreateScheduledJob``/
``ListScheduledJobs``/``DeleteScheduledJob``) laufen darueber -- so wird die Wrapper-Naht
inklusive params-Projektion mitgeprueft, ohne echtes SQLite.
"""

from app import _CreateLoggingTaskWithSchedule, _DeleteLoggingTaskWithUnschedule
from application.scheduler import (
    CreateScheduledJob,
    DeleteScheduledJob,
    ListScheduledJobs,
)
from domain.monitoring import LoggingTask
from domain.scheduler.models import DailyWindow, JobState, ScheduledJob


class _FakeLoggingTaskRepository:
    """In-memory ``LoggingTaskRepository``-Fake (nur die hier genutzten Methoden)."""

    def __init__(self) -> None:
        self.saved: list[LoggingTask] = []
        self.deleted: list[str] = []

    def save(self, task: LoggingTask) -> None:
        self.saved.append(task)

    def delete(self, task_id: str) -> None:
        self.deleted.append(task_id)


class _FakeScheduledJobRepository:
    """In-memory ``ScheduledJobRepository``-Fake (AUTOINCREMENT-aehnliche id)."""

    def __init__(self) -> None:
        self._jobs: list[ScheduledJob] = []
        self._next_id = 1

    def add(
        self,
        job_type: str,
        params: tuple[tuple[str, str], ...],
        window: DailyWindow,
    ) -> int:
        job = ScheduledJob(
            id=self._next_id,
            job_type=job_type,
            params=params,
            window=window,
            state=JobState.ACTIVE,
        )
        self._jobs.append(job)
        self._next_id += 1
        return job.id

    def list_all(self) -> list[ScheduledJob]:
        return list(self._jobs)

    def delete(self, job_id: int) -> None:
        self._jobs = [job for job in self._jobs if job.id != job_id]


def _build_create(
    task_repo: _FakeLoggingTaskRepository, job_repo: _FakeScheduledJobRepository
) -> _CreateLoggingTaskWithSchedule:
    """Baut den Create-Wrapper ueber den Fakes (das ``type: ignore`` fuer die partiellen
    Fakes an EINER Stelle gekapselt -- Muster ``test_scheduler_api._wire_create``)."""
    return _CreateLoggingTaskWithSchedule(
        task_repo,  # type: ignore[arg-type]
        CreateScheduledJob(job_repo),  # type: ignore[arg-type]
    )


def _build_delete(
    task_repo: _FakeLoggingTaskRepository, job_repo: _FakeScheduledJobRepository
) -> _DeleteLoggingTaskWithUnschedule:
    """Baut den Delete-Wrapper ueber den Fakes (das ``type: ignore`` an EINER Stelle)."""
    return _DeleteLoggingTaskWithUnschedule(
        task_repo,  # type: ignore[arg-type]
        ListScheduledJobs(job_repo),  # type: ignore[arg-type]
        DeleteScheduledJob(job_repo),  # type: ignore[arg-type]
    )


def _recurring_kwargs(**overrides: object) -> dict[str, object]:
    """Valide RECURRING-Create-kwargs (Tagesfenster 10:00-11:00, Mo-Fr) -- ueberschreibbar."""
    kwargs: dict[str, object] = {
        "task_id": "task-recur",
        "target_id": "wlan",
        "label": "Wiederkehrend",
        "purpose": "Abend-Logging",
        "capture_mode": "reachability_latency",
        "operation_mode": "recurring",
        "created_at": 100.0,
        "recur_start_minute": 600,
        "recur_end_minute": 660,
        "recur_weekdays": frozenset({0, 1, 2, 3, 4}),
    }
    kwargs.update(overrides)
    return kwargs


def test_recurring_create_legt_scheduler_job_an() -> None:
    task_repo = _FakeLoggingTaskRepository()
    job_repo = _FakeScheduledJobRepository()
    create = _build_create(task_repo, job_repo)

    task = create(**_recurring_kwargs(recur_until=5000.0))

    jobs = job_repo.list_all()
    assert len(jobs) == 1
    job = jobs[0]
    assert job.job_type == "monitoring_window"
    params = dict(job.params)
    assert params["task_id"] == task.id == "task-recur"
    # recur_until wird als String in den params getragen (leer = unbegrenzt).
    assert params["recur_until"] == "5000.0"
    # Das Tagesfenster spiegelt die recur_*-Felder des Tasks.
    assert (job.window.start_minute, job.window.end_minute) == (600, 660)
    assert job.window.weekdays == frozenset({0, 1, 2, 3, 4})


def test_recurring_create_ohne_recur_until_traegt_leeren_string() -> None:
    task_repo = _FakeLoggingTaskRepository()
    job_repo = _FakeScheduledJobRepository()
    create = _build_create(task_repo, job_repo)

    create(**_recurring_kwargs())  # kein recur_until

    job = job_repo.list_all()[0]
    assert dict(job.params)["recur_until"] == ""
    assert job.window.until_epoch == 0.0


def test_immediate_create_legt_keinen_job_an() -> None:
    task_repo = _FakeLoggingTaskRepository()
    job_repo = _FakeScheduledJobRepository()
    create = _build_create(task_repo, job_repo)

    create(
        task_id="task-immediate",
        target_id="wlan",
        label="Sofort",
        purpose="P",
        capture_mode="reachability",
        operation_mode="immediate",
        created_at=100.0,
        max_duration_s=3600,
    )

    # Kein RECURRING -> kein Auto-Job; die Task-Anlage selbst lief regulaer.
    assert job_repo.list_all() == []
    assert len(task_repo.saved) == 1


def test_delete_raeumt_zugehoerigen_job_ab() -> None:
    task_repo = _FakeLoggingTaskRepository()
    job_repo = _FakeScheduledJobRepository()
    create = _build_create(task_repo, job_repo)
    delete = _build_delete(task_repo, job_repo)

    task = create(**_recurring_kwargs())
    assert len(job_repo.list_all()) == 1

    delete(task.id)

    # Task-Definition geloescht UND der monitoring_window-Job abgeraeumt.
    assert task_repo.deleted == [task.id]
    assert job_repo.list_all() == []


def test_delete_ohne_passenden_job_ist_kein_fehler() -> None:
    # Loeschen eines Tasks, fuer den es keinen Job gibt (war nicht RECURRING) -> No-Op.
    task_repo = _FakeLoggingTaskRepository()
    job_repo = _FakeScheduledJobRepository()
    delete = _build_delete(task_repo, job_repo)

    delete("unbekannt")

    assert task_repo.deleted == ["unbekannt"]
    assert job_repo.list_all() == []
