"""JobHandler fuer den job_type ``blocklist_refresh`` -- woechentlicher Auto-Refresh.

Erfuellt den ``ports.scheduler``-``JobHandler``-Vertrag STRUKTURELL (Klassenattribut
``job_type`` + ``async run``), Muster ``application/monitoring/scheduler_handler.py``.
Liegt in ``application``, weil er den blocklist-Use-Case ``RefreshDueSources``
ORCHESTRIERT; der ``infrastructure``-Ring darf ``application`` nicht importieren
(import-linter). Der Scheduler kennt ihn nur ueber die Registry, die der Composition
Root befuellt.

ZEITMODELL (bewusst, Muster cve ``due_reason``): ``DailyWindow`` ist ein TAGESFENSTER,
kein "alle N Tage". Der Job tickt TAEGLICH in einem breiten Fenster (03:00-04:00 lokal,
weekdays leer = alle Tage); die ECHTE Faelligkeit (alle ``interval_days``) liegt in
``RefreshDueSources`` (``last_fetched_ts``-Vergleich). So entkoppeln wir den groben
Wecker-Takt von der feinen Pro-Quelle-Faelligkeit.

FEHLERTOLERANZ (S3/streng): der Handler wirft NIE -- der Scheduler-Loop faengt ohnehin,
aber wir loggen die Ergebnis-Zusammenfassung sauber und verschlucken keinen Fehler still.
``params`` werden nicht gebraucht (leeres Tupel); das Intervall liest ein injizierter
Callable LIVE (eine geaenderte Setting wirkt beim naechsten Lauf).
"""

from collections.abc import Callable

import structlog

from application.blocklist.use_cases import RefreshDueSources

__all__ = ["BlocklistRefreshHandler"]

_logger = structlog.get_logger(__name__)


class BlocklistRefreshHandler:
    """Refresht die faelligen Quellen, wenn der Scheduler im Tagesfenster tickt.

    Erfuellt den ``JobHandler``-Vertrag: Klassenattribut ``job_type`` +
    ``async run(params)``. Liest ``interval_days`` ueber den injizierten Callable (LIVE
    aus den Settings) und ruft ``refresh_due(interval_days)`` -- die Faelligkeit je Quelle
    entscheidet der Use-Case ueber ``last_fetched_ts``. ``params`` sind ungenutzt.
    """

    job_type: str = "blocklist_refresh"

    def __init__(
        self,
        refresh_due: RefreshDueSources,
        read_interval_days: Callable[[], int],
    ) -> None:
        self._refresh_due = refresh_due
        self._read_interval_days = read_interval_days

    async def run(self, params: tuple[tuple[str, str], ...]) -> None:
        """Refresht die faelligen Quellen und loggt die Bilanz (wirft NIE)."""
        interval_days = self._read_interval_days()
        results = self._refresh_due(interval_days)
        refreshed = len(results)
        broken = sum(1 for result in results if not result.ok)
        _logger.info(
            "blocklist_refresh_due_done",
            interval_days=interval_days,
            refreshed=refreshed,
            broken=broken,
        )
