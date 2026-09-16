"""JobHandler fuer den job_type ``monitoring_window`` -- der erste Abnehmer des Schedulers (3b).

Beendet einen RECURRING-Logging-Task sauber am ENDE seines Gesamtzeitraums. Das
taegliche Aufzeichnen im Tagesfenster macht der vorhandene Sink von selbst (der
RECURRING-Zweig von ``is_window_active``, 3b-1) -- dieser Handler raeumt nur den
Gesamtzeitraum ab: laeuft er noch, ist nichts zu tun; ist er abgelaufen, wird der Task
ueber ``StopLoggingTask`` auf FINISHED gesetzt, damit er nicht ewig-aktiv haengenbleibt.

Liegt in ``application``, weil er einen monitoring-Use-Case (``StopLoggingTask``)
ORCHESTRIERT -- der ``infrastructure``-Ring darf ``application`` nicht importieren
(import-linter "infrastructure kennt nicht application/api"). Er erfuellt den
``ports.scheduler``-``JobHandler``-Vertrag STRUKTURELL (Klassenattribut ``job_type`` +
``async run``); der Scheduler kennt ihn nur ueber die Registry, die im Composition Root
befuellt wird. ``application`` darf ``domain``/``ports`` kennen -- der ``time``-Import
ist stdlib (keine Domaenenlogik, Muster ``RunMonitor``/``RunScheduler``).

FEHLERTOLERANZ (S3/streng): der Handler wirft NIE -- der Scheduler-Loop darf nicht an
einem einzelnen Handler sterben. Fehlende/kaputte ``params`` werden ehrlich geloggt und
ignoriert (kein Crash, kein vorgetaeuschter Erfolg); ein bereits beendeter/geloeschter
Task (``LoggingTaskNotFound``/``InvalidTaskTransition``) ist KEIN Fehler, nur eine
Info-Notiz.
"""

import time
from collections.abc import Callable

import structlog

from application.monitoring.errors import LoggingTaskNotFound
from application.monitoring.use_cases import StopLoggingTask
from domain.monitoring import InvalidTaskTransition

__all__ = ["MonitoringWindowHandler"]

_logger = structlog.get_logger(__name__)


class MonitoringWindowHandler:
    """Beendet einen RECURRING-Logging-Task am Ende seines Gesamtzeitraums (job_type-Naht).

    Erfuellt den ``JobHandler``-Vertrag: Klassenattribut ``job_type`` +
    ``async run(params)``. Die ``params`` sind die opaquen Schluessel-Wert-Tupel des
    ScheduledJob -- dieser Handler liest daraus ``task_id`` und ``recur_until``.

    Ablauf in ``run`` (alles fehlertolerant, wirft NIE):
    * keine ``task_id`` -> nichts zu beenden, geloggt + return.
    * ``recur_until`` leer -> unbegrenzter Gesamtzeitraum, nichts zu beenden, return
      (der Sink laeuft weiter).
    * ``recur_until`` unparsbar -> geloggt + return (kein Crash).
    * ``now < recur_until`` -> Gesamtzeitraum laeuft noch, nichts tun (der Sink zeichnet
      im Tagesfenster auf).
    * sonst (abgelaufen) -> ``StopLoggingTask(task_id)``; ein bereits beendeter Task ist
      KEIN Fehler (Info), jede andere Exception wird geloggt, aber nicht geworfen.
    """

    job_type: str = "monitoring_window"

    def __init__(
        self,
        stop_task: StopLoggingTask,
        now_provider: Callable[[], float] = time.time,
    ) -> None:
        self._stop_task = stop_task
        self._now_provider = now_provider

    async def run(self, params: tuple[tuple[str, str], ...]) -> None:
        """Beendet den Task, wenn sein Gesamtzeitraum abgelaufen ist (sonst No-Op)."""
        data = dict(params)

        task_id = data.get("task_id")
        if not task_id:
            # Ehrlich: ohne task_id gibt es nichts zu beenden (kein Crash).
            _logger.warning("monitoring_window_handler_no_task_id")
            return

        recur_until_raw = data.get("recur_until", "")
        if not recur_until_raw:
            # Leeres recur_until = unbegrenzter Gesamtzeitraum -> nichts zu beenden.
            return
        try:
            recur_until = float(recur_until_raw)
        except ValueError:
            _logger.warning("monitoring_window_handler_bad_recur_until", value=recur_until_raw)
            return

        if self._now_provider() < recur_until:
            # Gesamtzeitraum laeuft noch -> nichts tun (der Sink zeichnet im Tagesfenster auf).
            return

        # Zeitraum abgelaufen -> Task beenden. Ein schon beendeter/geloeschter Task ist
        # KEIN Fehler (idempotent gedacht), nur eine Info; jede andere Exception wird
        # geloggt, aber NICHT geworfen (der Scheduler-Loop darf nicht sterben, S3).
        try:
            self._stop_task(task_id)
        except (LoggingTaskNotFound, InvalidTaskTransition):
            _logger.info("monitoring_window_already_stopped", task_id=task_id)
        except Exception as exc:
            _logger.warning("monitoring_window_stop_failed", task_id=task_id, error=str(exc))
