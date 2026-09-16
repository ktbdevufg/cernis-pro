"""Reine Domaenenlogik der cve-Domaene: Faelligkeit + is_new (stdlib, zeitfrei).

Hier wohnt die Karl-geklaerte Faelligkeits-Regel (ADR 0037). Ein Host wird (erneut)
geprueft, wenn EINER dieser drei Faelle zutrifft:

  1. NEU         -- der Host wurde noch nie geprueft (kein ``HostCheckState``).
  2. PORTS_GEAENDERT -- das aktuelle offene Port-Set unterscheidet sich vom zuletzt
     geprueften (NVD-Treffer haengen an Ports -> anderes Port-Set = neu zu pruefen).
  3. UEBERFAELLIG -- die letzte Pruefung ist aelter als das Auffrisch-Intervall
     (``cve_refresh_interval_hours``, Default 24h). 0/negativ = Auffrischung AUS
     (dann nur Fall 1+2). Begruendung: Geraete aendern sich selten, aber NVD
     veroeffentlicht laufend NEUE CVEs fuer DIESELBEN Geraete -- ohne Fall 3 saehe
     ein Nutzer, der wochenlang nur Latenz misst, nie neue CVEs.

Die Regel arbeitet gegen den BEKANNTEN GERAETE-BESTAND mit per-Host-Zeitstempel, NICHT
gegen ein einmaliges Scan-Ereignis -- darum entscheidet sie pro Host aus dessen
``HostCheckState`` + aktuellem Port-Set, nicht aus einem globalen "neuer Scan"-Signal.

Alles zeitfrei: ``now`` und die Intervalle kommen als rohe ``float``-Sekunden herein.
"""

from enum import StrEnum

from domain.cve.models import HostCheckState

__all__ = [
    "DEFAULT_NEW_WINDOW_SECONDS",
    "DEFAULT_REFRESH_INTERVAL_HOURS",
    "DueReason",
    "due_reason",
    "is_new",
]

# Auffrisch-Intervall (Fall 3) -- Default 24h (ADR 0037). 0/leer = Auffrischung AUS.
DEFAULT_REFRESH_INTERVAL_HOURS: int = 24

# is_new-Fenster: ein Befund gilt als "neu", wenn ihn CERNIS in den letzten 24h ZUERST
# sah (ADR 0037). Bewusst dieselbe Groesse wie das Auffrisch-Intervall, aber unabhaengig
# gefuehrt (verschiedene Belange: "frisch entdeckt" vs. "Pruefung faellig").
DEFAULT_NEW_WINDOW_SECONDS: float = 24 * 3600.0


class DueReason(StrEnum):
    """Warum ein Host faellig ist -- oder dass er es NICHT ist (``NOT_DUE``).

    ``StrEnum``, damit der Wert direkt log-/wire-tauglich ist, ohne dass die Domaene
    eine Wire-Form baut. Die Reihenfolge der Pruefung in ``due_reason`` ist NEW ->
    PORTS_CHANGED -> OVERDUE (der erste zutreffende Grund gewinnt, deterministisch).
    """

    NEW = "new"
    PORTS_CHANGED = "ports_changed"
    OVERDUE = "overdue"
    NOT_DUE = "not_due"


def due_reason(
    state: HostCheckState | None,
    current_ports: frozenset[int],
    now: float,
    refresh_interval_seconds: float,
) -> DueReason:
    """Entscheidet, OB und WARUM ein Host (erneut) geprueft werden muss (Faelle 1-3).

    * ``state is None`` -> ``NEW`` (Fall 1: noch nie geprueft).
    * ``current_ports != state.checked_ports`` -> ``PORTS_CHANGED`` (Fall 2).
    * ``refresh_interval_seconds > 0`` UND letzte Pruefung aelter -> ``OVERDUE`` (Fall 3).
      ``refresh_interval_seconds <= 0`` schaltet Fall 3 AB (Auffrischung aus).
    * sonst -> ``NOT_DUE``.

    Reine Funktion: keine Uhr, keine I/O. Resume-/idempotenz-tragend -- ein frisch
    gepruefter Host (state aktuell, Ports gleich, innerhalb Intervall) ist ``NOT_DUE``,
    also rattert ein Neustart NICHT alles neu durch (die Faelligkeit haengt am
    ``last_checked_ts`` je Host, nicht am Prozess-Start).
    """
    if state is None:
        return DueReason.NEW
    if current_ports != state.checked_ports:
        return DueReason.PORTS_CHANGED
    if refresh_interval_seconds > 0 and (now - state.last_checked_ts) >= refresh_interval_seconds:
        return DueReason.OVERDUE
    return DueReason.NOT_DUE


def is_new(first_seen_ts: float, now: float, window_seconds: float) -> bool:
    """Ist ein Befund "neu"? -- wenn CERNIS ihn innerhalb ``window_seconds`` ZUERST sah.

    Semantik (ADR 0037): "neu in den letzten 24h" (Default-Fenster). ``window_seconds <= 0``
    schaltet das Flag global ab (nie neu). Negative Differenz (Uhr-Sprung) zaehlt als neu
    (konservativ: lieber als neu markieren als einen frischen Befund verstecken).
    """
    if window_seconds <= 0:
        return False
    return (now - first_seen_ts) < window_seconds
