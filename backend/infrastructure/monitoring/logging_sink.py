"""Adapter fuer ``MonitorLoggingSinkPort`` -- der Schreibpfad des Langzeit-Loggings (B-II).

Haengt am Live-Connectivity-Loop (``RunMonitor`` ruft ``record`` pro Tick je Target)
und schreibt die Messdaten in die opt-in Logging-Tabellen (``monitoring_log_rtt`` /
``monitoring_log_events``) -- ABER nur fuer Aufgaben, die genau JETZT aktiv sind
(state ``ACTIVE`` UND Zeitfenster offen) und an genau DIESEM Target haengen. Der
fluechtige Live-Monitor (rtt_history/monitor_events) bleibt voellig unberuehrt: dies
ist ein ZUSAETZLICHER best-effort-Aufruf, kein Eingriff in den bestehenden Pfad.

CAPTURE-MODE-Logik (was geschrieben wird):
* ``REACHABILITY_LATENCY`` -> dichte RTT-Punkte (rtt_repo.save), AUSGEDUENNT nach dem
  Mess-Intervall ``task.interval_s`` (C-2): ein RTT-Punkt nur, wenn seit dem letzten
  geschriebenen Punkt DIESES Tasks ``>= interval_s`` Sekunden vergangen sind (oder noch
  keiner da). Eine Flanke (``event != None``) wird dabei IMMER sofort geschrieben --
  NIE ausgeduennt (sonst verpasst man den Ausfall, den man beobachtet).
* ``REACHABILITY`` und ``INTERFACE_STATUS`` -> NUR die Erreichbarkeits-/Status-FLANKE
  (event != None) ein event_repo.save, KEINE dichten RTT-Punkte.

AUSDUENN-MECHANIK (C-2, rein im Sink, KEIN DB-Roundtrip pro Tick): ``_letzter_rtt_ts``
haelt in-memory den letzten geschriebenen RTT-ts je ``task.id`` (``dict[str, float]``).
Neustart-Verlust ist akzeptiert (erster Tick nach Neustart schreibt, das Intervall
laeuft ab da -- harmlos, kein Verfaelschen). KEIN aktives Cleanup beendeter Tasks: ein
liegengebliebener Eintrag ist ein einzelner float (minimal) und wird beim naechsten
Neustart entfernt; ein aktives Aufraeumen wuerde die schlanke ``record``-Schleife um
eine zweite Buchhaltung (welche Tasks NICHT bedient wurden) erweitern, ohne fachlichen
Gewinn -- bewusst weggelassen.

INTERFACE_STATUS vs. REACHABILITY (vorerst gleicher Schreibpfad -- begruendet): Fachlich
unterscheiden sie sich (Interface-Up/Down vs. Ziel-Erreichbarkeit), aber der Live-Loop
misst HEUTE nur das Erreichbarkeits-Signal (``classify_transition`` ueber ``alive``);
ein Interface-Status-Signal existiert als messbarer Wert noch nicht. Darum schreiben
beide Modi in B-II die GLEICHE Flanke (``event != None`` -> ``str(event)``). Das ist
KEIN Vorbau ueber das jetzt Messbare hinaus -- sobald der Loop ein eigenes
Interface-Signal liefert, bekommt ``INTERFACE_STATUS`` hier seinen eigenen Zweig. Der
gespeicherte ``event_type`` ist der rohe ``str``-Wert des Domaenen-Events (``str(event)``
== der ``MonitorEventType``-Wert, z. B. ``"up"``/``"down"``) -- der Logging-Event-Store
fuehrt ihn als rohen ``str`` (Port-Vertrag), nicht als Live-Monitor-Enum.

BEST-EFFORT (Vertrag des Ports): Der GANZE Schreibblock pro Tick steht in einem
try/except. Ein Persistenz-Fehler wird mit ``structlog`` geloggt und NIE nach oben
geworfen -- der Loop darf nie wegen Logging sterben (Muster ``MonitorNotifierAdapter`` /
``_MonitorAlertRaiser``: der Adapter traegt den Fang, der Use-Case verlaesst sich darauf).
"""

import structlog

from domain.monitoring import (
    CaptureMode,
    MonitorEventType,
    MonitorTarget,
    PingSample,
    TaskState,
    is_window_active,
)
from ports.monitoring import (
    LoggingEventRepository,
    LoggingRttRepository,
    LoggingTaskRepository,
)

_logger = structlog.get_logger(__name__)


class MonitorLoggingSink:
    """Erfuellt das ``MonitorLoggingSinkPort``-Protocol strukturell.

    Haelt die drei Logging-Repos und entscheidet pro ``record`` selbst, welche Aufgaben
    aktiv sind und was sie schreiben. Der Loop bleibt logging-blind (s. Modul-Docstring).
    """

    def __init__(
        self,
        task_repo: LoggingTaskRepository,
        rtt_repo: LoggingRttRepository,
        event_repo: LoggingEventRepository,
    ) -> None:
        self._task_repo = task_repo
        self._rtt_repo = rtt_repo
        self._event_repo = event_repo
        # C-2: letzter geschriebener RTT-ts je task.id (in-memory, Neustart-Verlust ok).
        # Traegt die Ausduennung der dichten RTT-Punkte nach task.interval_s -- s.
        # Modul-Docstring (kein DB-Roundtrip, kein aktives Cleanup).
        self._letzter_rtt_ts: dict[str, float] = {}

    async def record(
        self,
        target: MonitorTarget,
        sample: PingSample,
        event: MonitorEventType | None,
        now: float,
    ) -> None:
        """Schreibt die Messung in alle JETZT aktiven Aufgaben am Ziel (best-effort)."""
        try:
            for task in self._task_repo.list_all():
                # Nur Aufgaben an genau diesem Target, ACTIVE und mit offenem Fenster.
                # is_window_active zieht den Bezugs-ts aus task.effective_start (ADR 0033).
                if (
                    task.target_id != target.id
                    or task.state is not TaskState.ACTIVE
                    or not is_window_active(task, now)
                ):
                    continue
                if task.capture_mode is CaptureMode.REACHABILITY_LATENCY:
                    # Dichte RTT-Punkte, ausgeduennt nach task.interval_s (C-2). Eine
                    # Flanke (event != None) wird IMMER sofort geschrieben -- nie
                    # ausgeduennt (sonst verpasst man den beobachteten Ausfall). Sonst
                    # nur schreiben, wenn seit dem letzten geschriebenen Punkt dieses
                    # Tasks >= interval_s vergangen sind (oder noch keiner da). Der
                    # Sentinel -1.0 (nicht erreichbar) bleibt erhalten.
                    letzter = self._letzter_rtt_ts.get(task.id)
                    if event is not None or letzter is None or (now - letzter) >= task.interval_s:
                        self._rtt_repo.save(
                            task.id, sample.rtt_ms, sample.loss_pct, sample.alive, now
                        )
                        self._letzter_rtt_ts[task.id] = now
                elif event is not None:
                    # REACHABILITY + INTERFACE_STATUS: nur die Flanke (s. Modul-Docstring,
                    # vorerst gleicher Schreibpfad). event_type als roher str-Wert.
                    self._event_repo.save(task.id, str(event), sample.rtt_ms, now)
        except Exception as exc:
            # Best-effort: Logging-Fehler werden geloggt, NIE nach oben geworfen --
            # der Live-Loop darf nie wegen Logging sterben (Port-Vertrag).
            _logger.warning("logging_sink_record_failed", target_id=target.id, error=str(exc))
