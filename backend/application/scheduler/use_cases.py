"""Use-Cases der scheduler-Domaene: Lifespan-Worker (``RunScheduler``) + Verwaltungs-Use-Cases.

Kennt ``domain/scheduler`` und ``ports/scheduler``, NIE ``infrastructure``/``modules``
(import-linter). Die Ports kommen per Constructor-Injection herein; die Zeit ist stdlib
(``time.time()``, Muster ``RunCveMonitor``/``RunMonitor`` -- ``import time`` ist erlaubt,
es ist keine Domaenenlogik).

LIFESPAN-WORKER (Weg 2): pro ``tick`` werden die faelligen AKTIVEN Jobs ausgefuehrt und
abgelaufene Jobs auf ``FINISHED`` gesetzt. Der Worker kennt den Job-INHALT NICHT -- er
waehlt per ``job_type`` den registrierten ``JobHandler`` (Registry, im Composition Root
befuellt) und ruft ``handler.run(params)``. Was der Job tut, lebt im Handler, nicht hier.

LOOP-FORM (testbar, Muster RunCveMonitor): ``tick()`` ist EINE Iteration (voll mit Fakes
deterministisch testbar). ``run()`` ist nur der Rahmen ``while self._running: tick();
sleep(interval)``. ``stop()`` setzt das Flag.

FEHLERTOLERANZ (S3/streng): ein fehlschlagender Handler-Aufruf wird GELOGGT und killt den
Loop NICHT -- der naechste Job (und der naechste Tick) laeuft weiter. Ein fehlender
Handler ist ehrlich: es wird geloggt und nichts getan (kein Crash, kein vorgetaeuschter
Erfolg).
"""

import asyncio
import time
from collections.abc import Callable, Mapping
from datetime import datetime

import structlog

from domain.scheduler.logic import is_active_job, is_expired
from domain.scheduler.models import DailyWindow, JobState, ScheduledJob
from ports.scheduler import JobHandler, ScheduledJobRepository

__all__ = [
    "DEFAULT_TICK_INTERVAL_SECONDS",
    "CreateScheduledJob",
    "DeleteScheduledJob",
    "ListScheduledJobs",
    "PauseScheduledJob",
    "ResumeScheduledJob",
    "RunScheduler",
]

_logger = structlog.get_logger(__name__)

# Gemaechlicher Wecker-Takt: ein Job mit 60-min-Fenster braucht keine Sekundengenauigkeit.
# Bewusst.
DEFAULT_TICK_INTERVAL_SECONDS: int = 30


def _wall_minute_and_weekday(now_epoch: float) -> tuple[int, int]:
    """Leitet (lokale Minute seit Mitternacht, Wochentag 0=Mo..6=So) aus ``now_epoch`` ab.

    ``datetime.fromtimestamp`` ohne tz = lokale Zeit; das ist hier GEWOLLT, weil das
    Tagesfenster gegen die lokale Wanduhr des Nutzers gemeint ist (Konvention aus
    ``models.py``).
    """
    local = datetime.fromtimestamp(now_epoch)
    return local.hour * 60 + local.minute, local.weekday()


# ── Worker ───────────────────────────────────────────────────────────────────


class RunScheduler:
    """Lifespan-Worker: fuehrt pro ``tick`` die faelligen aktiven Jobs aus.

    Entkoppelt vom Aufgaben-INHALT (Weg 2): ``_handlers`` ist die Registry
    ``job_type -> JobHandler`` (im Composition Root befuellt). Der Worker waehlt anhand
    des ``job_type`` den Handler und ruft ``run(params)`` -- ohne zu wissen, WAS der Job
    tut. ``now_provider`` (Default ``time.time``) macht die Zeit injizierbar/testbar.
    """

    def __init__(
        self,
        repository: ScheduledJobRepository,
        handlers: Mapping[str, JobHandler],
        interval: int = DEFAULT_TICK_INTERVAL_SECONDS,
        now_provider: Callable[[], float] = time.time,
    ) -> None:
        self._repository = repository
        self._handlers = handlers
        self._interval = interval
        self._now = now_provider
        self._running = False

    async def tick(self) -> None:
        """Eine Iteration: abgelaufene Jobs stilllegen, faellige aktive Jobs ausfuehren."""
        now = self._now()
        now_minute, weekday = _wall_minute_and_weekday(now)
        for job in self._repository.list_active():
            if is_expired(job.window, now_epoch=now):
                # Gesamtzeitraum abgelaufen -> stilllegen, NICHT ausfuehren.
                self._repository.update_state(job.id, JobState.FINISHED)
                continue
            if is_active_job(job, now_epoch=now, now_minute=now_minute, weekday=weekday):
                await self._dispatch(job)
            # Jobs, die weder abgelaufen noch gerade im Fenster sind, werden uebersprungen.

    async def _dispatch(self, job: ScheduledJob) -> None:
        """Waehlt den Handler per ``job_type`` und ruft ``run(params)`` fehlertolerant auf."""
        handler = self._handlers.get(job.job_type)
        if handler is None:
            # Ehrlich: kein Handler registriert -> nichts tun (kein Crash, kein
            # vorgetaeuschter Erfolg).
            _logger.warning("scheduler_no_handler", job_id=job.id, job_type=job.job_type)
            return
        try:
            await handler.run(job.params)
        except Exception as exc:
            # Ein einzelner Handler-Fehler killt den Loop NIE (S3): loggen, weiter.
            _logger.warning(
                "scheduler_handler_failed",
                job_id=job.id,
                job_type=job.job_type,
                error=str(exc),
            )

    async def run(self) -> None:
        """Endlos-Rahmen: tickt bis ``stop()``. Die Logik sitzt in ``tick``."""
        self._running = True
        while self._running:
            await self.tick()
            await asyncio.sleep(self._interval)

    def stop(self) -> None:
        """Setzt das Loop-Flag (Abbruch nach der laufenden Iteration)."""
        self._running = False


# ── Verwaltungs-Use-Cases ─────────────────────────────────────────────────────


class CreateScheduledJob:
    """Legt einen neuen geplanten Job an (``state`` startet ``ACTIVE``) und liefert die id."""

    def __init__(self, repository: ScheduledJobRepository) -> None:
        self._repository = repository

    def __call__(
        self,
        job_type: str,
        params: tuple[tuple[str, str], ...],
        window: DailyWindow,
    ) -> int:
        return self._repository.add(job_type, params, window)


class ListScheduledJobs:
    """Liefert alle geplanten Jobs ueber alle Zustaende (Verwaltungs-Sicht)."""

    def __init__(self, repository: ScheduledJobRepository) -> None:
        self._repository = repository

    def __call__(self) -> list[ScheduledJob]:
        return self._repository.list_all()


class PauseScheduledJob:
    """Haelt einen Job an (``ACTIVE`` -> ``PAUSED``)."""

    def __init__(self, repository: ScheduledJobRepository) -> None:
        self._repository = repository

    def __call__(self, job_id: int) -> None:
        self._repository.update_state(job_id, JobState.PAUSED)


class ResumeScheduledJob:
    """Setzt einen pausierten Job fort (``PAUSED`` -> ``ACTIVE``)."""

    def __init__(self, repository: ScheduledJobRepository) -> None:
        self._repository = repository

    def __call__(self, job_id: int) -> None:
        self._repository.update_state(job_id, JobState.ACTIVE)


class DeleteScheduledJob:
    """Loescht einen Job (unbekannte id ist ein No-Op, kein Fehler)."""

    def __init__(self, repository: ScheduledJobRepository) -> None:
        self._repository = repository

    def __call__(self, job_id: int) -> None:
        self._repository.delete(job_id)
