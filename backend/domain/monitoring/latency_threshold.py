"""Schwellwert-Alarme der monitoring-Domaene -- reine, zeitfreie Auswert-Logik.

Schnitt 1 (Domaene) des Schwellwert-Features: dieses Modul definiert NUR, WAS eine
Schwellwert-Regel ist (``LatencyThreshold`` + ``ThresholdCondition``), welchen
laufenden Auswert-Zustand der Sink dazu haelt (``ThresholdState``) und wie eine
einzelne Messung diesen Zustand fortschreibt (``evaluate_sample``). Es ist BEWUSST
vom ``LoggingTask`` getrennt: der Schwellwert ist eine eigene, vom Lebenszyklus der
Aufgabe unabhaengige Konfiguration -- sie lebt neben dem Task, nicht in ihm.

Muster konsequent aus der Nachbarschaft (``logging_task.py``) uebernommen: frozen
dataclasses + StrEnum, reine Funktionen ohne Uhr/I/O, Zustandsfortschreibung via
``dataclasses.replace`` (kein In-Place-Mutieren auf einer frozen dataclass). Keine
Persistenz, kein Loop, keine ``time.time()`` (ADR 0002, stdlib only). Die RTT-Werte
sind Millisekunden (``float``); der RTT-Sentinel ``-1.0`` (nicht erreichbar, siehe
``LoggingRttSample``) wird hier ausdruecklich NICHT als Latenz behandelt.
"""

import dataclasses
from dataclasses import dataclass
from enum import StrEnum


class ThresholdCondition(StrEnum):
    """WELCHE Bedingung einen Schwellwert-Alarm ausloesen kann.

    ``LATENCY_ABOVE``: die RTT liegt ueber einem konfigurierten Grenzwert (eine reine
    Latenz-Sache -- nur sinnvoll, wenn das Ziel ueberhaupt erreichbar ist).
    ``UNREACHABLE``: das Ziel ist nicht erreichbar (eine Erreichbarkeits-Sache --
    der Latenz-Grenzwert spielt hier keine Rolle).
    """

    LATENCY_ABOVE = "latency_above"
    UNREACHABLE = "unreachable"


@dataclass(frozen=True)
class LatencyThreshold:
    """Die vom Nutzer konfigurierte Schwellwert-Regel EINER Logging-Aufgabe.

    ``condition`` waehlt die Alarm-Bedingung (s. ``ThresholdCondition``). ``limit_ms``
    ist der RTT-Grenzwert in Millisekunden -- fachlich nur fuer ``LATENCY_ABOVE``
    relevant; bei ``UNREACHABLE`` ignoriert die Auswertung ihn vollstaendig.

    ``consecutive_n`` ist die Hysterese (Entprellung): der Alarm feuert erst, nachdem
    N aufeinanderfolgende Messungen die Bedingung verletzt haben. ``N=1`` feuert sofort
    bei der ersten Verletzung; der Default ``3`` daempft einzelne Ausreisser weg.

    ``notify_desktop``/``notify_email`` legen fest, ueber welche Kanaele eine gefeuerte
    Flanke gemeldet wird (reine Datentraeger -- das Versenden selbst ist NICHT Sache der
    Domaene).

    Wie bei ``AlertRule`` erzwingt die Domaene hier KEINE Validierung (z. B. ``N >= 1``
    oder ``limit_ms >= 0``): das ist eine Rand-Sache der aufrufenden Schichten. Die
    Funktion ``evaluate_sample`` bleibt fuer alle Werte wohldefiniert.
    """

    condition: ThresholdCondition
    limit_ms: float
    consecutive_n: int = 3
    notify_desktop: bool = True
    notify_email: bool = False


@dataclass(frozen=True)
class ThresholdState:
    """Der laufende Auswert-Zustand, den der Sink PRO Aufgabe haelt.

    Die Domaene rechnet nur -- sie haelt den Zustand nicht selbst, sondern bekommt ihn
    herein und gibt einen neuen zurueck. ``streak`` zaehlt die aktuelle Serie
    aufeinanderfolgender verletzender Messungen (auf 0 zurueckgesetzt, sobald eine
    Messung NICHT verletzt). ``in_alarm`` haelt fest, ob wir gerade im Alarm-Zustand
    sind -- so feuert der Alarm nur einmal pro Episode (Flanke), nicht bei jeder
    weiteren verletzenden Messung.
    """

    streak: int
    in_alarm: bool


# Startzustand vor der ersten Messung: noch keine Verletzungsserie, kein Alarm.
INITIAL_STATE = ThresholdState(streak=0, in_alarm=False)


def _is_violation(threshold: LatencyThreshold, rtt_ms: float, alive: bool) -> bool:
    """Verletzt DIESE eine Messung die Bedingung der Regel? (reines Praedikat)

    * ``UNREACHABLE``: verletzt genau dann, wenn das Ziel nicht erreichbar ist
      (``alive == False``). Die RTT spielt keine Rolle.
    * ``LATENCY_ABOVE``: verletzt genau dann, wenn das Ziel erreichbar ist
      (``alive == True``) UND die RTT STRIKT ueber dem Grenzwert liegt
      (``rtt_ms > limit_ms``). Wichtig: ``> `` ist strikt -- ein Wert GENAU am Limit
      verletzt NICHT.

      Bei ``alive == False`` ist ``LATENCY_ABOVE`` NICHT verletzt: ein nicht
      erreichbares Ziel ist eine Erreichbarkeits-Sache, keine Latenz-Sache. Damit
      faellt auch der RTT-Sentinel ``-1.0`` (nicht erreichbar, ``LoggingRttSample``)
      heraus -- er kommt mit ``alive == False`` und zaehlt nie als
      Latenz-Ueberschreitung. Der ``alive``-Vorbehalt ist hier die eigentliche
      Schutzschicht; der Sentinel ist ohnehin negativ und liegt nie ueber dem Limit.
    """
    if threshold.condition is ThresholdCondition.UNREACHABLE:
        return not alive
    # LATENCY_ABOVE: nur bei erreichbarem Ziel und strikt ueber dem Limit.
    return alive and rtt_ms > threshold.limit_ms


def evaluate_sample(
    threshold: LatencyThreshold,
    state: ThresholdState,
    rtt_ms: float,
    alive: bool,
) -> tuple[ThresholdState, bool]:
    """Schreibt den Auswert-Zustand um EINE Messung fort und meldet eine Alarm-Flanke.

    Rein und zeitfrei: gibt ``(neuer_state, fired)`` zurueck und mutiert nichts (das
    ``dataclasses.replace``-Muster der Uebergangs-Funktionen in ``logging_task.py``).
    ``fired`` ist ``True`` GENAU in dem Aufruf, der die Alarm-Flanke ausloest -- nicht
    waehrend der Alarm anhaelt.

    Ablauf:

    * Verletzt die Messung NICHT (s. ``_is_violation``), endet die laufende Episode:
      ``streak`` zurueck auf 0, ``in_alarm`` zurueck auf ``False``, ``fired=False``.
      Diese Entspannung ist bewusst: sie setzt die Flanke scharf, damit eine spaetere
      erneute Verletzungsserie WIEDER feuern kann (Flanke, kein Dauerfeuer und kein
      Einmal-und-nie-wieder).
    * Verletzt die Messung, waechst die Serie (``streak += 1``):
        - Erreicht der neue ``streak`` die Hysterese-Schwelle (``>= consecutive_n``)
          UND sind wir noch NICHT im Alarm: das ist die Alarm-FLANKE -> ``in_alarm``
          wird ``True`` und ``fired=True``.
        - Sonst (Schwelle noch nicht erreicht ODER bereits im Alarm): ``fired=False``.
          Solange der Alarm anhaelt, feuert KEINE weitere Messung erneut -- erst eine
          Entspannung und eine neue Serie koennen die naechste Flanke setzen.

    Warum so: ``in_alarm`` verhindert das Dauerfeuer bei anhaltender Verletzung; das
    Zuruecksetzen bei Entspannung verhindert, dass eine einmal gefeuerte Episode den
    Kanal fuer immer blockiert. Zusammen ergibt das eine saubere Flanken-Semantik.
    """
    if not _is_violation(threshold, rtt_ms, alive):
        # Entspannung -> Episode beendet, Flanke fuer die naechste Serie scharf gestellt.
        return dataclasses.replace(state, streak=0, in_alarm=False), False

    new_streak = state.streak + 1
    if new_streak >= threshold.consecutive_n and not state.in_alarm:
        # Alarm-Flanke: Schwelle frisch erreicht und vorher kein Alarm -> feuern.
        return dataclasses.replace(state, streak=new_streak, in_alarm=True), True
    # Serie waechst weiter, aber keine Flanke (Schwelle noch offen ODER schon im Alarm).
    return dataclasses.replace(state, streak=new_streak), False
