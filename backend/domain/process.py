"""Domaenenmodell der process-Domaene: Prozess-Sicht aus ``/proc`` als reine Werte.

Reine Domaenenlogik (stdlib + dataclasses, ADR 0002) -- kein Wissen ueber ``/proc``,
``psutil`` oder das Dateisystem (das ist Infrastruktur, ein spaeterer Schnitt), kein
HTTP, KEINE Uhr. Alles, was diese Domaene tut, ist Klassifikation und deterministischer
Strukturaufbau ueber bereits eingelesene Rohwerte. Zeitstempel kommen als FELD herein
(``ProcessInfo.create_time``) -- die Domaene fragt nie selbst die Uhr (testbar,
deterministisch).

Ein Wertobjekt + eine Klassifikation + ein Baum-Aufbau:

* ``ProcessInfo`` -- ein Prozess als reines Wertobjekt. Felder, die rootless nicht
  lesbar sind, sind ehrlich ``None`` bzw. leer statt erfunden.
* ``classify_kind`` -- Kernel-Thread vs. Userland-Prozess anhand cmdline + PID-Lage.
* ``build_process_tree`` -- baut aus den ppid-Beziehungen einen deterministischen Wald
  (mehrere Wurzeln moeglich), zyklen- und selbstreferenz-sicher.

DARSTELLUNG bleibt draussen: kein Mensch-lesbares Formatieren von ``create_time`` oder
``cmdline``, keine Icons -- das fuehrt api/Frontend. Die Domaene fuehrt nur Werte.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

# Grobe Prozess-Herkunft. PEP-695-Alias wie im uebrigen domain-Ring (traffic/interfaces/
# scanning nutzen ``type X = ...``); als Literal-Union statt StrEnum, weil es ein reines
# Klassifikations-Ergebnis ohne Verhalten ist.
type ProcessKind = Literal["kernel", "userland"]


@dataclass(frozen=True)
class ProcessInfo:
    """Ein Prozess als reines Wertobjekt (frozen).

    ``pid`` ist immer vorhanden (die Quelle ist der ``/proc/<pid>``-Eintrag selbst).
    ``name`` ist nie ``None`` -- ein nicht lesbarer Name wird zum leeren String ``""``,
    nicht zu ``None``. Die uebrigen Felder sind rootless oft nicht lesbar und dann
    ehrlich ``None`` (bzw. leeres Tuple), KEIN erfundener Wert:

    * ``ppid=None`` -- Eltern-PID nicht lesbar.
    * ``owner=None`` -- Eigentuemer (Username) nicht ermittelbar.
    * ``status=None`` -- Lebenszustand nicht lesbar.
    * ``create_time=None`` -- Startzeit (als uebergebenes FELD, keine interne Uhr) nicht
      lesbar.
    * ``exe_path=None`` -- absoluter Pfad zum ausgefuehrten Programm nicht ermittelbar
      (rootless oft nicht lesbar, Kernel-Threads haben keinen) -- KEIN erfundener Wert,
      ehrlich ``None`` analog ``owner``/``status``.
    * ``cmdline=()`` -- leeres Tuple heisst "nicht lesbar" (z. B. Kernel-Thread, dessen
      ``/proc/<pid>/cmdline`` leer ist) -- NICHT "kein Argument".
    """

    pid: int
    ppid: int | None
    name: str
    owner: str | None
    status: str | None
    create_time: float | None
    exe_path: str | None
    cmdline: tuple[str, ...]


def classify_kind(info: ProcessInfo) -> ProcessKind:
    """Klassifiziert einen Prozess als ``kernel`` oder ``userland`` -- rein, heuristisch.

    Kernel-Thread, wenn ``cmdline`` leer ist UND (``pid == 2`` ODER ``ppid == 2``).
    Sonst ``userland``.

    Heuristik: Kernel-Threads haengen unter Linux am ``kthreadd``-Prozess (pid 2) bzw.
    sind ``kthreadd`` selbst (pid 2). Sie haben ein leeres ``cmdline``, weil sie kein
    Userspace-Programm ausfuehren (``/proc/<pid>/cmdline`` ist fuer sie leer). Beide
    Bedingungen muessen zutreffen: ein leeres ``cmdline`` allein reicht nicht (es kann
    auch nur "nicht lesbar" bedeuten), und die PID-2-Verwandtschaft allein reicht nicht.

    Rein: kein I/O, keine Uhr; gleiche Eingabe -> gleiches Ergebnis.
    """
    if not info.cmdline and (info.pid == 2 or info.ppid == 2):
        return "kernel"
    return "userland"


@dataclass(frozen=True)
class ProcessNode:
    """Ein Knoten im Prozessbaum: ein Prozess samt seiner direkten Kinder (frozen).

    ``children`` ist die nach ``pid`` aufsteigend sortierte Folge der direkten
    Kind-Knoten -- leer fuer ein Blatt. Der Wald wird ueber ``build_process_tree``
    erzeugt; die Sortierung macht die Struktur deterministisch.
    """

    info: ProcessInfo
    children: tuple["ProcessNode", ...]


def build_process_tree(processes: Sequence[ProcessInfo]) -> tuple[ProcessNode, ...]:
    """Baut aus den ppid-Beziehungen einen deterministischen Wald -- rein, zyklen-sicher.

    Ein Prozess ist Wurzel, wenn seine ``ppid`` ``None`` ist ODER seine ``ppid`` nicht
    in der Menge der vorhandenen ``pid`` vorkommt (ein verwaister Prozess wird so selbst
    zur Wurzel, statt verloren zu gehen). Alle uebrigen Prozesse haengen als Kind unter
    ihrem Elternteil.

    Deterministisch: Wurzeln wie auch die Kinder jedes Knotens sind aufsteigend nach
    ``pid`` sortiert -- gleiche Eingabe (in beliebiger Reihenfolge) -> gleicher Baum.

    Zyklen- und selbstreferenz-sicher: Beim rekursiven Absteigen wird ein bereits
    besuchter ``pid`` nicht erneut eingehaengt. Damit fuehrt weder eine Selbstreferenz
    (``pid == ppid``) noch ein laengerer Zyklus zu einer Endlosschleife oder einem
    ``RecursionError`` -- die im Zyklus haengenden Prozesse erscheinen jeweils einmal
    (an ihrer ersten erreichten Stelle).

    Rein: kein I/O, keine Uhr.
    """
    # Erst die Prozesse nach pid eindeutig erfassen. Bei doppeltem pid (defensiv -- der
    # Adapter liefert eindeutige) gewinnt das letzte Vorkommen (dict-Semantik).
    by_pid: dict[int, ProcessInfo] = {p.pid: p for p in processes}

    # Kinder-Listen pro Eltern-pid sammeln. Nur Prozesse, deren ppid ein vorhandener
    # pid ist, sind echte Kinder; alle anderen werden Wurzeln.
    children_of: dict[int, list[ProcessInfo]] = {}
    roots: list[ProcessInfo] = []
    for info in by_pid.values():
        parent = info.ppid
        if parent is not None and parent in by_pid and parent != info.pid:
            children_of.setdefault(parent, []).append(info)
        else:
            # ppid None, unbekannt (verwaist) oder Selbstreferenz -> Wurzel.
            roots.append(info)

    def _node(info: ProcessInfo, visited: frozenset[int]) -> ProcessNode:
        # ``visited`` enthaelt die pids des Pfades von der Wurzel bis hierher -- ein
        # Kind, dessen pid darin schon vorkommt, wird nicht erneut abgestiegen (Zyklus).
        seen = visited | {info.pid}
        kids = children_of.get(info.pid, [])
        child_nodes = tuple(
            _node(child, seen)
            for child in sorted(kids, key=lambda c: c.pid)
            if child.pid not in seen
        )
        return ProcessNode(info=info, children=child_nodes)

    return tuple(_node(root, frozenset()) for root in sorted(roots, key=lambda p: p.pid))
