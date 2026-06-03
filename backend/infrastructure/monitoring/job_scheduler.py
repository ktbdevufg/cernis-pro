"""Adapter fuer ``ScanJobScheduler`` -- APScheduler-Job-Engine (kein DB-Zugriff).

Kapselt ``AsyncIOScheduler`` hinter dem Port. Importiert ``apscheduler`` DIREKT
(wie der Altcode ``modules/scheduler``), NICHT ueber ``modules`` -- der
scheduler-Adapter ist bewusst ``modules``-frei (haelt den ADR-0007-Footprint klein;
die ignore-Zeile deckt nur Pinger/Notifier).

Trigger-Bau: ``register`` parst den Schedule-String ueber die reine
``domain.parse_schedule`` -> ``ScheduleSpec`` und baut daraus via ``match`` +
``assert_never`` das APScheduler-Trigger-Objekt (``IntervalSpec`` -> ``IntervalTrigger``,
``CronSpec`` -> ``CronTrigger``). Die Exhaustiveness der ``ScheduleSpec``-Union
greift hier: ein neuer Spec-Typ ohne ``case`` bricht mypy.

ParseError-Propagation: ``parse_schedule`` wirft ``ScheduleParseError`` bei einem
kaputten String -- der Adapter faengt das NICHT (KEIN stiller 24h-Fallback wie der
Altcode). Es propagiert an den Aufrufer (``ManageSchedules``), der best-effort
entscheidet (Schedule-Zeile bleibt, kein Job, Warn-Log).

S3-FIXES (bewusste v2-Abweichungen, kein Charakterisierer deckt den Job-Pfad):
* ``HAS_SCHEDULER``-try/except-ImportError + die Gates ENTFERNT -- ``apscheduler``
  ist feste dep; der ``False``-Pfad (still-no-op-Scheduler, Jobs laufen nie) ist
  genau der verdeckte Fehlschlag, den v2 nicht will.
* ``_register_job``-``except: print`` -> ``structlog``-Log; der eigentliche
  ``ScheduleParseError`` propagiert (best-effort im Use-Case), andere unerwartete
  Fehler werden geloggt, nicht stumm verschluckt.
* ``unregister`` auf einen nie/schon entfernten Job -> idempotenter Fang MIT
  ``structlog``-Log (Altcode: stilles ``except: pass``). "Job gibt es nicht" ist ein
  legitimer Leer-Zustand, aber sichtbar gemacht.
"""

from typing import Any, assert_never

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from domain.monitoring import (
    CronSpec,
    IntervalSpec,
    ScheduleSpec,
    parse_schedule,
)
from ports.monitoring import ScanTriggerCallback

_logger = structlog.get_logger(__name__)


def _build_trigger(spec: ScheduleSpec) -> IntervalTrigger | CronTrigger:
    """Baut das APScheduler-Trigger-Objekt aus der reinen ``ScheduleSpec``.

    ``match`` + ``assert_never``: mypy prueft, dass beide Spec-Varianten behandelt
    sind -- ein neuer Spec-Typ ohne ``case`` bricht hier.
    """
    match spec:
        case IntervalSpec(unit=unit, value=value):
            # unit ist "minutes" | "hours" | "days" -- als Keyword an IntervalTrigger.
            return IntervalTrigger(**{unit: value})
        case CronSpec(minute=m, hour=h, day=d, month=mo, day_of_week=dow):
            return CronTrigger(minute=m, hour=h, day=d, month=mo, day_of_week=dow)
        case _:
            assert_never(spec)


class ApschedulerJobScheduler:
    """Erfuellt das ``ScanJobScheduler``-Protocol strukturell (AsyncIOScheduler)."""

    def __init__(self) -> None:
        self._scheduler: AsyncIOScheduler | None = None

    def start(self, callback: ScanTriggerCallback) -> None:
        """Startet die Engine. Die bereits gespeicherten aktiven Schedules
        registriert der Use-Case (``ManageSchedules``/Verdrahtung), nicht der
        Adapter -- der Adapter kennt das Repo NICHT.
        """
        if self._scheduler is not None:
            return  # Doppelstart-Schutz
        self._scheduler = AsyncIOScheduler()
        self._scheduler.start()

    def stop(self) -> None:
        if self._scheduler is not None:
            self._scheduler.shutdown(wait=False)
            self._scheduler = None

    def register(self, schedule: dict[str, Any], callback: ScanTriggerCallback) -> None:
        """Registriert (oder ersetzt) den Job fuer eine Schedule-Zeile.

        Parst ``schedule["schedule"]`` via ``domain.parse_schedule`` -- ein
        ``ScheduleParseError`` propagiert (kein stiller Fallback). Wenn die Engine
        nicht laeuft, ist das ein No-op (kein Job ohne Scheduler).
        """
        if self._scheduler is None:
            return
        trigger = _build_trigger(parse_schedule(str(schedule["schedule"])))
        schedule_id = int(schedule["id"])
        self._scheduler.add_job(
            callback,
            trigger=trigger,
            id=f"scan_{schedule_id}",
            kwargs={
                "cidr": str(schedule["cidr"]),
                "profile_id": str(schedule["profile_id"]),
                "schedule_id": schedule_id,
            },
            replace_existing=True,
            misfire_grace_time=300,
        )

    def unregister(self, schedule_id: int) -> None:
        """Entfernt den Job. Idempotent -- ein nie/schon entfernter Job ist kein
        Fehler, wird aber geloggt (Altcode: stilles except:pass).
        """
        if self._scheduler is None:
            return
        try:
            self._scheduler.remove_job(f"scan_{schedule_id}")
        except Exception:
            # "Job gibt es nicht" ist ein legitimer Leer-Zustand (z. B. nie
            # registriert) -- idempotent, aber sichtbar geloggt statt stumm.
            _logger.warning("scan_job_unregister_noop", schedule_id=schedule_id)
