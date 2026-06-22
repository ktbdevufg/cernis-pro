"""Tests fuer die scheduler-Use-Cases: Lifespan-Worker + Verwaltungs-Use-Cases.

Worker (``RunScheduler.tick``): faelliger Job im Fenster wird ausgefuehrt (Handler mit den
params des Jobs aufgerufen), PAUSED laeuft nicht, abgelaufener Job wird auf FINISHED gesetzt
und NICHT ausgefuehrt, fehlender Handler crasht nicht, eine Handler-Exception killt den
Loop nicht. Verwaltungs-Use-Cases: Create legt an + gibt id, Pause/Resume/Delete wirken
ueber das Repo.

In-Memory ``_FakeRepository`` + ``_FakeHandler`` (zaehlt run-Aufrufe, kann werfen). Die Zeit
wird ueber ``now_provider`` deterministisch injiziert. WICHTIG: ``_wall_minute_and_weekday``
nutzt LOKALE Zeit -- die Test-Fenster werden aus der lokalen Minute/Wochentag DERSELBEN
Test-epoch abgeleitet (kein hardcodiertes Minuten-/Wochentags-Literal), damit die Tests
zeitzonenunabhaengig gruen sind. Async-Worker-Tests laufen ueber ``asyncio.run`` (Muster
der cve-Use-Case-Tests).
"""

import asyncio
from collections.abc import Callable
from datetime import datetime

from application.scheduler.use_cases import (
    CreateScheduledJob,
    DeleteScheduledJob,
    ListScheduledJobs,
    PauseScheduledJob,
    ResumeScheduledJob,
    RunScheduler,
)
from domain.scheduler.models import DailyWindow, JobState, ScheduledJob

NOW = 1_700_000_000.0
PARAMS: tuple[tuple[str, str], ...] = (("target", "host-a"),)


class _FakeRepository:
    """In-Memory-Repo nach ``ScheduledJobRepository``-Vertrag (Liste + id-Vergabe)."""

    def __init__(self) -> None:
        self._jobs: list[ScheduledJob] = []
        self._next_id = 1

    def add(self, job_type: str, params: tuple[tuple[str, str], ...], window: DailyWindow) -> int:
        job_id = self._next_id
        self._next_id += 1
        self._jobs.append(
            ScheduledJob(
                id=job_id,
                job_type=job_type,
                params=params,
                window=window,
                state=JobState.ACTIVE,
            )
        )
        return job_id

    def get(self, job_id: int) -> ScheduledJob | None:
        return next((j for j in self._jobs if j.id == job_id), None)

    def list_active(self) -> list[ScheduledJob]:
        return [j for j in self._jobs if j.state == JobState.ACTIVE]

    def list_all(self) -> list[ScheduledJob]:
        return list(self._jobs)

    def update_state(self, job_id: int, state: JobState) -> None:
        for i, job in enumerate(self._jobs):
            if job.id == job_id:
                self._jobs[i] = ScheduledJob(
                    id=job.id,
                    job_type=job.job_type,
                    params=job.params,
                    window=job.window,
                    state=state,
                )
                return

    def delete(self, job_id: int) -> None:
        self._jobs = [j for j in self._jobs if j.id != job_id]

    def clear_all(self) -> None:
        self._jobs = []


class _FakeHandler:
    """Zaehlt ``run``-Aufrufe + merkt sich die params; kann auf Wunsch werfen."""

    def __init__(self, job_type: str, fail: bool = False) -> None:
        self.job_type = job_type
        self._fail = fail
        self.calls: list[tuple[tuple[str, str], ...]] = []

    async def run(self, params: tuple[tuple[str, str], ...]) -> None:
        self.calls.append(params)
        if self._fail:
            raise RuntimeError("handler boom")


def _active_window(now_epoch: float = NOW) -> DailyWindow:
    """Ein Fenster, das fuer ``now_epoch`` JETZT aktiv ist -- aus der LOKALEN Zeit derselben
    epoch abgeleitet (kein Hardcoden), damit der Test zeitzonenunabhaengig gruen ist.
    """
    local = datetime.fromtimestamp(now_epoch)
    now_minute = local.hour * 60 + local.minute
    return DailyWindow(
        start_minute=now_minute,
        end_minute=now_minute + 1,
        weekdays=frozenset(),  # leer = alle Tage
        from_epoch=0.0,
        until_epoch=0.0,  # kein Ende -> nie abgelaufen
    )


def _at(ts: float) -> Callable[[], float]:
    return lambda: ts


# ── Worker: faelliger Job im Fenster ──────────────────────────────────────────


def test_tick_fuehrt_aktiven_job_im_fenster_aus() -> None:
    repo = _FakeRepository()
    job_id = repo.add("scan", PARAMS, _active_window())
    handler = _FakeHandler("scan")
    worker = RunScheduler(repo, {"scan": handler}, now_provider=_at(NOW))

    asyncio.run(worker.tick())

    assert handler.calls == [PARAMS]
    # Job bleibt aktiv (kein Stilllegen).
    assert repo.get(job_id).state == JobState.ACTIVE  # type: ignore[union-attr]


def test_tick_fuehrt_pausierten_job_nicht_aus() -> None:
    repo = _FakeRepository()
    job_id = repo.add("scan", PARAMS, _active_window())
    repo.update_state(job_id, JobState.PAUSED)
    handler = _FakeHandler("scan")
    worker = RunScheduler(repo, {"scan": handler}, now_provider=_at(NOW))

    asyncio.run(worker.tick())

    assert handler.calls == []


def test_tick_setzt_abgelaufenen_job_auf_finished_und_fuehrt_ihn_nicht_aus() -> None:
    repo = _FakeRepository()
    base = _active_window()
    expired = DailyWindow(
        start_minute=base.start_minute,
        end_minute=base.end_minute,
        weekdays=base.weekdays,
        from_epoch=0.0,
        until_epoch=NOW - 1.0,  # Ende liegt vor now -> abgelaufen
    )
    job_id = repo.add("scan", PARAMS, expired)
    handler = _FakeHandler("scan")
    worker = RunScheduler(repo, {"scan": handler}, now_provider=_at(NOW))

    asyncio.run(worker.tick())

    assert handler.calls == []
    assert repo.get(job_id).state == JobState.FINISHED  # type: ignore[union-attr]


def test_tick_ueberspringt_job_ausserhalb_des_fensters() -> None:
    repo = _FakeRepository()
    local = datetime.fromtimestamp(NOW)
    now_minute = local.hour * 60 + local.minute
    # Fenster liegt komplett spaeter am Tag (mind. 2 Minuten Abstand, am Tagesrand geclamped).
    start = min(now_minute + 2, 1438)
    outside = DailyWindow(
        start_minute=start,
        end_minute=start + 1,
        weekdays=frozenset(),
        from_epoch=0.0,
        until_epoch=0.0,
    )
    repo.add("scan", PARAMS, outside)
    handler = _FakeHandler("scan")
    worker = RunScheduler(repo, {"scan": handler}, now_provider=_at(NOW))

    asyncio.run(worker.tick())

    assert handler.calls == []


def test_tick_ohne_handler_crasht_nicht() -> None:
    repo = _FakeRepository()
    repo.add("unbekannt", PARAMS, _active_window())
    # Registry kennt den job_type nicht.
    worker = RunScheduler(repo, {}, now_provider=_at(NOW))

    # Kein Crash, tick kehrt ruhig zurueck.
    asyncio.run(worker.tick())


def test_tick_faengt_handler_exception_und_laeuft_weiter() -> None:
    repo = _FakeRepository()
    repo.add("scan", PARAMS, _active_window())
    handler = _FakeHandler("scan", fail=True)
    worker = RunScheduler(repo, {"scan": handler}, now_provider=_at(NOW))

    # Kein Re-raise: tick ueberlebt die Handler-Exception.
    asyncio.run(worker.tick())

    assert handler.calls == [PARAMS]


# ── Verwaltungs-Use-Cases ─────────────────────────────────────────────────────


def test_create_gibt_id_und_legt_an() -> None:
    repo = _FakeRepository()
    create = CreateScheduledJob(repo)

    job_id = create("scan", PARAMS, _active_window())

    assert job_id == 1
    listed = ListScheduledJobs(repo)()
    assert len(listed) == 1
    assert listed[0].id == job_id
    assert listed[0].job_type == "scan"
    assert listed[0].params == PARAMS
    assert listed[0].state == JobState.ACTIVE


def test_pause_und_resume_wirken_ueber_das_repo() -> None:
    repo = _FakeRepository()
    create = CreateScheduledJob(repo)
    job_id = create("scan", PARAMS, _active_window())

    PauseScheduledJob(repo)(job_id)
    assert ListScheduledJobs(repo)()[0].state == JobState.PAUSED

    ResumeScheduledJob(repo)(job_id)
    assert ListScheduledJobs(repo)()[0].state == JobState.ACTIVE


def test_delete_entfernt_den_job() -> None:
    repo = _FakeRepository()
    create = CreateScheduledJob(repo)
    job_id = create("scan", PARAMS, _active_window())

    DeleteScheduledJob(repo)(job_id)

    assert ListScheduledJobs(repo)() == []
