"""Application-Exceptions der monitoring-Use-Cases.

Eigene Fehlerklassen OHNE HTTP-/Transport-Details -- das Mapping auf WS-Frames bzw.
Statuscodes passiert in ``api/`` (M.9).

Der ``RunMonitor``-Loop ist best-effort und propagiert im Normalbetrieb keine
Fehler an den Aufrufer (Notifier-Fehler faengt der Adapter mit Log; Ping liefert
einen ``alive=False``-``PingSample`` statt zu werfen). Diese Basisklasse ist der
gemeinsame Aufhaenger fuer kuenftige monitoring-Use-Case-Fehler (z. B. Lese-Pfade
in M.7/M.9), analog ``ScanningApplicationError``.
"""


class MonitoringApplicationError(Exception):
    """Basis fuer Fehler der monitoring-Use-Cases (gemeinsamer Aufhaenger fuer api/)."""


class LoggingTaskNotFound(MonitoringApplicationError):
    """Eine Logging-Aufgaben-Definition mit dieser ``id`` existiert nicht.

    Geworfen von den Lifecycle-Use-Cases (Start/Pause/Resume/Stop/Detail), wenn
    ``LoggingTaskRepository.get`` ``None`` liefert. Der api-Rand (Schritt 3b) mappt
    ihn auf 404. Traegt die gesuchte ``task_id`` im Bezug, damit der Fehler ohne
    Kontext-Rekonstruktion sprechend ist (Muster ``InvalidTaskTransition``).
    """

    def __init__(self, task_id: str) -> None:
        super().__init__(f"Logging-Aufgabe {task_id!r} nicht gefunden")
        self.task_id = task_id


class LoggingTaskConflict(MonitoringApplicationError):
    """Am selben Ziel laeuft bereits eine aktive Logging-Aufgabe (Konzept-Regel).

    Pro Ziel darf nur EINE Aufgabe gleichzeitig ``ACTIVE`` sein. Geworfen beim Start
    (``StartLoggingTask``) und beim Fortsetzen aus Pause (``ResumeLoggingTask``), wenn
    die Domaenen-``conflicts_with`` einen laufenden Konkurrenten am ``target_id``
    findet. Der api-Rand (Schritt 3b) mappt ihn auf 409 und baut aus ``running_task_id``
    + ``target_id`` die Konzept-Meldung ("Fuer <Ziel> laeuft bereits ein Monitoring
    ..."). Beide Bezugs-Felder werden darum getragen.
    """

    def __init__(self, running_task_id: str, target_id: str) -> None:
        super().__init__(
            f"Fuer Ziel {target_id!r} laeuft bereits die Logging-Aufgabe "
            f"{running_task_id!r} (pro Ziel nur eine aktiv)"
        )
        self.running_task_id = running_task_id
        self.target_id = target_id
