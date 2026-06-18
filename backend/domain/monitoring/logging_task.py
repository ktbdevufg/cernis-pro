"""Langzeit-Logging-Aufgaben der monitoring-Domaene -- reine, zeitfreie Logik.

Der opt-in Logging-Kern (Auftrag B-I) ist GETRENNT vom fluechtigen Live-Monitor:
``monitor_events``/``rtt_history`` bleiben unangetastet. Diese Datei definiert nur,
WAS eine Logging-Aufgabe ist (``LoggingTask`` + die drei Klassifikations-Enums) und
die reinen Zustands-/Zeitfenster-Regeln darueber. Sie kennt KEINE Persistenz, KEINEN
Loop, KEINE Uhr: jede zeitabhaengige Frage bekommt ``now`` bzw. den Bezugs-ts als
Parameter -- kein ``time.time()`` in der Domaene (ADR 0002, stdlib only, framework-frei).

Muster konsequent aus der Nachbarschaft uebernommen: frozen dataclasses + StrEnum
(``models.py``), eigenstaendiger Domaenen-Fehler analog ``ScheduleParseError``
(``schedule.py``, erbt von ``Exception``, NICHT von ``ValueError``), Zustands-
uebergaenge als reine Funktionen, die via ``dataclasses.replace`` einen NEUEN
``LoggingTask`` zurueckgeben (kein In-Place-Mutieren auf einer frozen dataclass).

Die ``float``-Zeitstempel sind Unix-ts -- dasselbe Muster wie ``PingSample.timestamp``.
"""

import dataclasses
from dataclasses import dataclass
from enum import StrEnum


class CaptureMode(StrEnum):
    """WAS eine Logging-Aufgabe aufzeichnet -- das fachliche Mess-Vokabular.

    Bewusst klein gehalten (drei Modi): ``INTERFACE_STATUS`` (nur der Up/Down-Zustand
    des Interfaces), ``REACHABILITY`` (Erreichbarkeit des Ziels) und
    ``REACHABILITY_LATENCY`` (Erreichbarkeit inkl. RTT). Erweiterbar fuer ein spaeteres
    "alles" -- aber JETZT NICHT ausgebaut (B-I-Grenze).
    """

    INTERFACE_STATUS = "interface_status"
    REACHABILITY = "reachability"
    REACHABILITY_LATENCY = "reachability_latency"


class OperationMode(StrEnum):
    """WIE der Zeitrahmen einer Logging-Aufgabe bestimmt wird.

    ``SCHEDULED``: festes Fenster zwischen ``planned_start`` und ``planned_end``.
    ``IMMEDIATE``: laeuft ab einem effektiven Start (vom Use-Case gefuehrt) fuer
    hoechstens ``max_duration_s`` Sekunden. Die Unterscheidung steuert, welche Felder
    ``is_window_active`` heranzieht.
    """

    SCHEDULED = "scheduled"
    IMMEDIATE = "immediate"


class TaskState(StrEnum):
    """Lebenszyklus-Zustand einer Logging-Aufgabe.

    ``CREATED`` (angelegt, laeuft noch nicht) -> ``ACTIVE`` (zeichnet auf) <->
    ``PAUSED`` (ausgesetzt) -> ``FINISHED`` (endgueltig beendet). Die erlaubten
    Uebergaenge sind in den Uebergangs-Funktionen unten kodiert.
    """

    CREATED = "created"
    ACTIVE = "active"
    PAUSED = "paused"
    FINISHED = "finished"


class InvalidTaskTransition(Exception):
    """Ein angeforderter Zustandsuebergang ist vom aktuellen ``state`` aus unzulaessig.

    EIGENSTAENDIG (erbt von ``Exception``, NICHT von ``ValueError`` -- analog
    ``ScheduleParseError``): der Aufrufer (B-II-Use-Case) kann genau diesen Fehler
    fangen, ohne einen unrelated ``ValueError`` mitzunehmen, und die Hierarchie macht
    den Zu-breit-Fang strukturell unmoeglich statt nur per Disziplin. Traegt den
    versuchten Uebergang (``state`` -> ``transition``) im Bezug, damit der Fehler ohne
    Kontext-Rekonstruktion sprechend ist.
    """

    def __init__(self, transition: str, state: "TaskState") -> None:
        super().__init__(f"Unzulaessiger Uebergang {transition!r} aus Zustand {state.value!r}")
        self.transition = transition
        self.state = state


@dataclass(frozen=True)
class LoggingTask:
    """Eine opt-in Langzeit-Logging-Aufgabe (reiner Datentraeger + Identitaet).

    ``id``/``target_id`` sind die Aufgaben- bzw. Ziel-Identitaet, ``label``/``purpose``
    die benutzerseitige Beschreibung. ``capture_mode``/``operation_mode`` klassifizieren
    WAS aufgezeichnet wird und WIE der Zeitrahmen bestimmt ist, ``state`` haelt den
    Lebenszyklus.

    Die Zeitfelder sind Unix-ts (``float``, Muster ``PingSample``) bzw. ``None``, wenn
    fuer den Modus nicht relevant: ``planned_start``/``planned_end`` tragen das Fenster
    der ``SCHEDULED``-Aufgaben, ``max_duration_s`` die Maximaldauer der
    ``IMMEDIATE``-Aufgaben. ``created_at`` ist der Anlege-ts. Die Domaene rechnet nur
    mit diesen Werten -- sie fuellt sie NICHT (kein ``time.time()`` hier).
    """

    id: str
    target_id: str
    label: str
    purpose: str
    capture_mode: CaptureMode
    operation_mode: OperationMode
    state: TaskState
    planned_start: float | None
    planned_end: float | None
    max_duration_s: int | None
    created_at: float
    # Effektiver Start (absoluter Unix-ts), gesetzt beim ERSTEN Uebergang nach ACTIVE
    # (Start-Knopf). Bleibt ueber Pausen UNVERAENDERT (Fortsetzen setzt ihn NICHT neu)
    # und wird erst bei FINISHED wieder geleert (``None``). Bezugs-ts des
    # ``IMMEDIATE``-Fensters (Maximaldauer = reine Wanduhr ab hier, Pausenzeit zaehlt
    # MIT -- ADR 0033). Default ``None``, ans Ende einsortiert: so bleiben die
    # bestehenden positionsbasierten ``LoggingTask(...)``-Konstruktionen gueltig.
    effective_start: float | None = None


@dataclass(frozen=True)
class LoggingRttSample:
    """Ein dichter RTT-Messpunkt EINER Logging-Aufgabe (reiner Datentraeger).

    BEWUSST ein benannter frozen Datentraeger -- NICHT ein nacktes ``tuple`` wie
    ``SlaSample``: dieser Messpunkt traegt VIER fachlich verschiedene Werte
    (``rtt_ms``/``loss_pct``/``alive``/``ts``), bei denen die Positions-Bedeutung
    eines Tuples leicht verwechselbar waere; das Hausmuster fuer mehrfeldige
    Repo-Rueckgaben sind benannte frozen dataclasses (``PingSample``,
    ``MonitorEvent``). ``SlaSample`` blieb ein Tuple, weil es das EingabeFORMAT der
    reinen ``compute_sla_stats`` 1:1 spiegelt -- hier gibt es keine solche Fremd-
    Signatur, an die wir uns binden muessten. ``ts`` ist Unix-ts (Muster
    ``PingSample.timestamp``); der RTT-Sentinel ``-1.0`` (nicht erreichbar) bleibt
    wie in ``PingSample`` erhalten.
    """

    rtt_ms: float
    loss_pct: float
    alive: bool
    ts: float


@dataclass(frozen=True)
class LoggingEventRow:
    """Eine Ereignis-/Anomalie-Flanke EINER Logging-Aufgabe (reiner Datentraeger).

    Symmetrisch zu ``LoggingRttSample`` -- benannter frozen Datentraeger statt Tuple:
    ``event_type``/``rtt_ms``/``ts`` sind drei fachlich verschiedene Werte, deren
    Positions-Bedeutung als Tuple verwechselbar waere (Hausmuster ``MonitorEvent``).
    ``event_type`` ist ein ROHER ``str`` (KEIN ``MonitorEventType``): der Logging-Kern
    ist vom Live-Monitor getrennt (s. Modul-Docstring) -- das Logging-Event-Vokabular
    wird von B-II bestimmt, nicht an die Live-Monitor-Enum gebunden. ``ts`` ist
    Unix-ts; der RTT-Sentinel ``-1.0`` bleibt erhalten.
    """

    event_type: str
    rtt_ms: float
    ts: float


def is_window_active(task: LoggingTask, now: float, reference_ts: float | None = None) -> bool:
    """Praedikat: liegt ``now`` innerhalb des aktiven Zeitfensters der Aufgabe?

    Reine Zeitrechnung -- die Domaene haelt KEINE Uhr, ``now`` kommt vom Use-Case.

    Der ``IMMEDIATE``-Bezugs-ts ist seit B-II der persistierte ``task.effective_start``
    (ADR 0033): er wird HIER herangezogen, der Aufrufer muss ihn NICHT mehr extern
    fuehren. ``reference_ts`` bleibt aus Kompatibilitaet als OPTIONALER Override
    erhalten (bestehende Aufrufe/Tests reichen ihn explizit) -- wird er uebergeben,
    hat er Vorrang vor ``effective_start``; sonst gilt ``effective_start``. So bleibt
    die zeitfreie Naht der Domaene erhalten und der Parameter wird zugleich
    entbehrlich, ohne bestehende Aufrufe zu brechen.

    * ``SCHEDULED``: aktiv, wenn ``planned_start <= now < planned_end`` (Start
      inklusiv, Ende exklusiv). Fehlt eine der beiden Grenzen, gibt es kein
      definiertes Fenster -> ``False`` (kein stiller Fallback auf "immer aktiv").
    * ``IMMEDIATE``: aktiv, wenn ``start_ts <= now < start_ts + max_duration_s`` mit
      ``start_ts`` = ``reference_ts`` (falls uebergeben) ODER ``task.effective_start``
      (Start inklusiv, Ablauf exklusiv). Fehlt der Bezugs-ts (noch nie gestartet bzw.
      schon beendet) oder ``max_duration_s``, ist kein Fenster bestimmbar -> ``False``.
    """
    if task.operation_mode is OperationMode.SCHEDULED:
        if task.planned_start is None or task.planned_end is None:
            return False
        return task.planned_start <= now < task.planned_end
    # IMMEDIATE: Fenster ab effektivem Start fuer max_duration_s Sekunden. Der explizite
    # reference_ts hat Vorrang (Kompatibilitaet), sonst gilt der persistierte
    # effective_start (ADR 0033) -- fehlt beides, ist kein Fenster bestimmbar.
    start_ts = reference_ts if reference_ts is not None else task.effective_start
    if start_ts is None or task.max_duration_s is None:
        return False
    return start_ts <= now < start_ts + task.max_duration_s


def conflicts_with(candidate: LoggingTask, others: list[LoggingTask]) -> bool:
    """Praedikat: kollidiert ``candidate`` mit einer bereits aktiven Aufgabe am selben Ziel?

    Reines Praedikat ueber die UEBERGEBENEN Aufgaben (die Domaene fragt nichts ab):
    ``True``, sobald in ``others`` eine Aufgabe mit demselben ``target_id`` im Zustand
    ``ACTIVE`` ist. ``candidate`` selbst wird ueber ``id`` ausgeklammert, damit ein
    bereits aktiver Kandidat nicht mit sich selbst kollidiert.
    """
    return any(
        other.id != candidate.id
        and other.target_id == candidate.target_id
        and other.state is TaskState.ACTIVE
        for other in others
    )


def start(task: LoggingTask, effective_start: float) -> LoggingTask:
    """Uebergang ``CREATED`` -> ``ACTIVE``; setzt den effektiven Start.

    Signatur ``start(task, effective_start)`` (NICHT ``start(task, now)``): die Domaene
    SETZT hier den ``effective_start`` -- der Parameter benennt also den Wert, den er
    bekommt, nicht eine generische Uhr. Der Use-Case reicht ``now`` als
    ``effective_start`` herein (er fuehrt die Zeit, die Domaene bleibt zeitfrei).

    Der ``effective_start`` wird NUR gesetzt, wenn er noch ``None`` ist (erster Start --
    ADR 0033): ein bereits gesetzter Wert bliebe unveraendert. Aus ``CREATED`` heraus
    ist er immer ``None``, der Guard ist also vor allem Aussage ueber die Invariante
    (erster Uebergang nach ACTIVE setzt ihn, kein spaeterer ueberschreibt ihn). Jeder
    andere Ausgangszustand wirft.
    """
    if task.state is not TaskState.CREATED:
        raise InvalidTaskTransition("start", task.state)
    new_effective_start = (
        task.effective_start if task.effective_start is not None else effective_start
    )
    return dataclasses.replace(task, state=TaskState.ACTIVE, effective_start=new_effective_start)


def pause(task: LoggingTask) -> LoggingTask:
    """Uebergang ``ACTIVE`` -> ``PAUSED``. Jeder andere Ausgangszustand wirft."""
    if task.state is not TaskState.ACTIVE:
        raise InvalidTaskTransition("pause", task.state)
    return dataclasses.replace(task, state=TaskState.PAUSED)


def resume(task: LoggingTask) -> LoggingTask:
    """Uebergang ``PAUSED`` -> ``ACTIVE``. Jeder andere Ausgangszustand wirft.

    Setzt ``effective_start`` NICHT neu (ADR 0033): Fortsetzen aus einer Pause behaelt
    den urspruenglichen effektiven Start -- die ``IMMEDIATE``-Maximaldauer ist reine
    Wanduhr ab dem ersten Start, die Pausenzeit zaehlt MIT.
    """
    if task.state is not TaskState.PAUSED:
        raise InvalidTaskTransition("resume", task.state)
    return dataclasses.replace(task, state=TaskState.ACTIVE)


def stop(task: LoggingTask) -> LoggingTask:
    """Uebergang ``{ACTIVE, PAUSED}`` -> ``FINISHED``; leert den effektiven Start.

    Setzt ``effective_start`` zurueck auf ``None`` (ADR 0033): die Aufgabe ist beendet,
    ein kuenftiger erneuter Start (sofern fachlich erlaubt) wuerde einen FRISCHEN
    effektiven Start setzen. Jeder andere Ausgangszustand als ``ACTIVE``/``PAUSED`` wirft.
    """
    if task.state not in (TaskState.ACTIVE, TaskState.PAUSED):
        raise InvalidTaskTransition("stop", task.state)
    return dataclasses.replace(task, state=TaskState.FINISHED, effective_start=None)
