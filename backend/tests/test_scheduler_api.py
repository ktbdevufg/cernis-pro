"""End-to-end-Test der scheduler-API (Block 3a, Etappe 3b) gegen app.py via TestClient.

Deckt die fuenf Verwaltungs-Routen ab (Muster ``test_dns_watch_api.py``/``test_cve_api.py``):
``POST /api/scheduler/jobs`` (liefert id), ``GET /api/scheduler/jobs`` (flache Wire-Form,
weekdays/params korrekt projiziert), ``POST .../pause`` / ``.../resume`` und
``DELETE .../{job_id}`` (rufen den jeweiligen Runner).

Die Runner werden -- wie im Composition Root -- per ``dependency_overrides`` verdrahtet:
Create/List laufen gegen die ECHTEN Verwaltungs-Use-Cases (``CreateScheduledJob``/
``ListScheduledJobs``) ueber ein in-memory Fake-Repo (so wird die Projektion auf die flache
Wire-Form mitgeprueft), pause/resume/delete gegen schmale Spy-Callables (geprueft wird, dass
die Route den Runner mit der ``job_id`` aufruft). Der alte ``ApschedulerJobScheduler`` ist
nicht betroffen -- hier laeuft nur der v2-Scheduler.
"""

from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.scheduler import (
    CreateJobBody,
    ScheduledJobOut,
    provide_scheduler_create,
    provide_scheduler_delete,
    provide_scheduler_list,
    provide_scheduler_pause,
    provide_scheduler_resume,
)
from app import create_app
from application.scheduler import CreateScheduledJob, ListScheduledJobs
from domain.scheduler.models import DailyWindow, JobState, ScheduledJob
from infrastructure.config import AppConfig


class _FakeScheduledJobRepository:
    """In-memory ``ScheduledJobRepository``-Fake (nur die hier genutzten Methoden).

    Vergibt eine AUTOINCREMENT-aehnliche id und haelt die Jobs in Anlage-Reihenfolge --
    genug fuer ``CreateScheduledJob``/``ListScheduledJobs`` im API-Test (kein echtes SQLite
    noetig, der Adapter hat eigene Tests in ``test_scheduler_jobs_db.py``).
    """

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


@pytest.fixture
def app() -> Iterator[FastAPI]:
    """Frisch gebaute App (Lifespan via TestClient pro Test -- kein Loop noetig)."""
    yield create_app(AppConfig())


# ── Create/List: echte Use-Cases + Fake-Repo, Projektion auf die flache Wire-Form ──


def _wire_create(repo: _FakeScheduledJobRepository) -> object:
    """Anlege-Runner wie im Composition Root: CreateJobBody -> DailyWindow + params -> id."""

    def _create(body: CreateJobBody) -> int:
        window = DailyWindow(
            start_minute=body.window.start_minute,
            end_minute=body.window.end_minute,
            weekdays=frozenset(body.window.weekdays),
            from_epoch=body.window.from_epoch,
            until_epoch=body.window.until_epoch,
        )
        params = tuple((k, v) for k, v in body.params)
        return CreateScheduledJob(repo)(body.job_type, params, window)  # type: ignore[arg-type]

    return _create


def _wire_list(repo: _FakeScheduledJobRepository) -> object:
    """Lese-Runner wie im Composition Root: ScheduledJob -> flache ScheduledJobOut."""

    def _list() -> list[ScheduledJobOut]:
        return [
            ScheduledJobOut(
                id=job.id,
                job_type=job.job_type,
                params=[(k, v) for k, v in job.params],
                start_minute=job.window.start_minute,
                end_minute=job.window.end_minute,
                weekdays=sorted(job.window.weekdays),
                from_epoch=job.window.from_epoch,
                until_epoch=job.window.until_epoch,
                state=job.state.value,
            )
            for job in ListScheduledJobs(repo)()  # type: ignore[arg-type]
        ]

    return _list


def test_post_jobs_liefert_id(app: FastAPI) -> None:
    """``POST /api/scheduler/jobs`` -> 200 + ``{"id": <int>}``; der Job liegt im Repo."""
    repo = _FakeScheduledJobRepository()
    app.dependency_overrides[provide_scheduler_create] = lambda: _wire_create(repo)

    with TestClient(app) as client:
        resp = client.post(
            "/api/scheduler/jobs",
            json={
                "job_type": "monitoring_window",
                "params": [["target", "1.2.3.4"], ["mode", "ping"]],
                "window": {
                    "start_minute": 540,
                    "end_minute": 600,
                    "weekdays": [0, 2, 4],
                    "from_epoch": 1000.0,
                    "until_epoch": 0.0,
                },
            },
        )

    assert resp.status_code == 200
    assert resp.json() == {"id": 1}
    assert len(repo.list_all()) == 1


def test_get_jobs_liefert_flache_wire_form(app: FastAPI) -> None:
    """``GET /api/scheduler/jobs`` -> der angelegte Job in flacher Wire-Form (weekdays/params)."""
    repo = _FakeScheduledJobRepository()
    app.dependency_overrides[provide_scheduler_create] = lambda: _wire_create(repo)
    app.dependency_overrides[provide_scheduler_list] = lambda: _wire_list(repo)

    with TestClient(app) as client:
        client.post(
            "/api/scheduler/jobs",
            json={
                "job_type": "monitoring_window",
                "params": [["target", "1.2.3.4"]],
                "window": {
                    "start_minute": 540,
                    "end_minute": 600,
                    # bewusst unsortiert -> die Projektion muss sortieren
                    "weekdays": [4, 0, 2],
                    "from_epoch": 1000.0,
                    "until_epoch": 2000.0,
                },
            },
        )
        resp = client.get("/api/scheduler/jobs")

    assert resp.status_code == 200
    assert resp.json() == [
        {
            "id": 1,
            "job_type": "monitoring_window",
            "params": [["target", "1.2.3.4"]],
            "start_minute": 540,
            "end_minute": 600,
            "weekdays": [0, 2, 4],
            "from_epoch": 1000.0,
            "until_epoch": 2000.0,
            "state": "active",
        }
    ]


def test_get_jobs_leer_liefert_leere_liste(app: FastAPI) -> None:
    """Ohne angelegte Jobs -> 200 + leere Liste (legitimer Leerzustand)."""
    repo = _FakeScheduledJobRepository()
    app.dependency_overrides[provide_scheduler_list] = lambda: _wire_list(repo)

    with TestClient(app) as client:
        resp = client.get("/api/scheduler/jobs")

    assert resp.status_code == 200
    assert resp.json() == []


# ── pause/resume/delete: Spy-Callable, geprueft wird der Aufruf mit der job_id ──


def test_pause_ruft_runner_mit_job_id(app: FastAPI) -> None:
    """``POST .../pause`` -> 200 ``{"ok": true}`` + Runner mit der job_id aufgerufen."""
    calls: list[int] = []
    app.dependency_overrides[provide_scheduler_pause] = lambda: calls.append

    with TestClient(app) as client:
        resp = client.post("/api/scheduler/jobs/7/pause")

    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    assert calls == [7]


def test_resume_ruft_runner_mit_job_id(app: FastAPI) -> None:
    """``POST .../resume`` -> 200 ``{"ok": true}`` + Runner mit der job_id aufgerufen."""
    calls: list[int] = []
    app.dependency_overrides[provide_scheduler_resume] = lambda: calls.append

    with TestClient(app) as client:
        resp = client.post("/api/scheduler/jobs/9/resume")

    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    assert calls == [9]


def test_delete_ruft_runner_mit_job_id(app: FastAPI) -> None:
    """``DELETE .../{job_id}`` -> 200 ``{"ok": true}`` + Runner mit der job_id aufgerufen."""
    calls: list[int] = []
    app.dependency_overrides[provide_scheduler_delete] = lambda: calls.append

    with TestClient(app) as client:
        resp = client.delete("/api/scheduler/jobs/13")

    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    assert calls == [13]
