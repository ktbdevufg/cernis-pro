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


def is_window_active(task: LoggingTask, now: float, reference_ts: float | None = None) -> bool:
    """Praedikat: liegt ``now`` innerhalb des aktiven Zeitfensters der Aufgabe?

    Reine Zeitrechnung -- die Domaene haelt KEINE Uhr, ``now`` (und bei ``IMMEDIATE``
    der ``reference_ts`` = effektiver Start) kommt vom Use-Case. Bewusst KEINE verdeckte
    Annahme ueber den Bezugs-ts: der Use-Case fuehrt den effektiven Start und uebergibt
    ihn explizit.

    * ``SCHEDULED``: aktiv, wenn ``planned_start <= now < planned_end`` (Start
      inklusiv, Ende exklusiv). Fehlt eine der beiden Grenzen, gibt es kein
      definiertes Fenster -> ``False`` (kein stiller Fallback auf "immer aktiv").
    * ``IMMEDIATE``: aktiv, wenn ``reference_ts <= now < reference_ts + max_duration_s``
      (Start inklusiv, Ablauf exklusiv). Fehlt ``reference_ts`` oder ``max_duration_s``,
      ist kein Fenster bestimmbar -> ``False``.
    """
    if task.operation_mode is OperationMode.SCHEDULED:
        if task.planned_start is None or task.planned_end is None:
            return False
        return task.planned_start <= now < task.planned_end
    # IMMEDIATE: Fenster ab effektivem Start fuer max_duration_s Sekunden.
    if reference_ts is None or task.max_duration_s is None:
        return False
    return reference_ts <= now < reference_ts + task.max_duration_s


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


def start(task: LoggingTask) -> LoggingTask:
    """Uebergang ``CREATED`` -> ``ACTIVE``. Jeder andere Ausgangszustand wirft."""
    if task.state is not TaskState.CREATED:
        raise InvalidTaskTransition("start", task.state)
    return dataclasses.replace(task, state=TaskState.ACTIVE)


def pause(task: LoggingTask) -> LoggingTask:
    """Uebergang ``ACTIVE`` -> ``PAUSED``. Jeder andere Ausgangszustand wirft."""
    if task.state is not TaskState.ACTIVE:
        raise InvalidTaskTransition("pause", task.state)
    return dataclasses.replace(task, state=TaskState.PAUSED)


def resume(task: LoggingTask) -> LoggingTask:
    """Uebergang ``PAUSED`` -> ``ACTIVE``. Jeder andere Ausgangszustand wirft."""
    if task.state is not TaskState.PAUSED:
        raise InvalidTaskTransition("resume", task.state)
    return dataclasses.replace(task, state=TaskState.ACTIVE)


def stop(task: LoggingTask) -> LoggingTask:
    """Uebergang ``{ACTIVE, PAUSED}`` -> ``FINISHED``. Jeder andere Ausgangszustand wirft."""
    if task.state not in (TaskState.ACTIVE, TaskState.PAUSED):
        raise InvalidTaskTransition("stop", task.state)
    return dataclasses.replace(task, state=TaskState.FINISHED)
