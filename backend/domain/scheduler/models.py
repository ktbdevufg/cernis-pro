"""Domaenenmodelle der scheduler-Domaene -- reine, zeitfreie Datentraeger (stdlib).

Die scheduler-Domaene ist vom Aufgaben-INHALT entkoppelt (Weg 2): sie kennt nur einen
ZEITPLAN plus eine OPAQUE Job-Referenz und urteilt NIE darueber, WAS ein Job tut. Das
Zeitplan-Modell ist bewusst SCHLANK -- ein wiederkehrendes Tagesfenster (kein Cron):

* ``DailyWindow`` -- das wiederkehrende Tagesfenster: ein Minuten-Intervall des Tages,
  optional auf bestimmte Wochentage beschraenkt, gueltig innerhalb eines Gesamtzeitraums.
* ``ScheduledJob`` -- der geplante Job: id + Zeitplan (``window``) + Zustand (``state``)
  + die OPAQUE Job-Referenz (``job_type``/``params``), die die Domaene NICHT interpretiert.

Beide ``frozen`` (unveraenderliche Domaenenwerte). Zeit als roher epoch-``float`` (UTC) --
die Domaene erzeugt keine Uhr, der Adapter/Use-Case reicht ``now`` (und die Wanduhr-Minute)
herein.
"""

from dataclasses import dataclass
from enum import StrEnum

__all__ = ["DailyWindow", "JobState", "ScheduledJob"]


class JobState(StrEnum):
    """Lebenszyklus eines geplanten Jobs.

    ``StrEnum``, damit der Wert direkt log-/wire-tauglich ist, ohne dass die Domaene
    eine Wire-Form baut. ``ACTIVE`` laeuft, ``PAUSED`` ruht (vom Nutzer angehalten),
    ``FINISHED`` ist abgeschlossen (z. B. vom Worker gesetzt, wenn der Gesamtzeitraum
    abgelaufen ist -- siehe ``logic.is_expired``).
    """

    ACTIVE = "active"
    PAUSED = "paused"
    FINISHED = "finished"


@dataclass(frozen=True)
class DailyWindow:
    """Das wiederkehrende Tagesfenster eines Jobs -- zeitzonenfrei rechenbar.

    Die Tages-Grenzen sind als MINUTEN SEIT MITTERNACHT gefuehrt (``start_minute`` /
    ``end_minute``) -- bewusst, weil so der Vergleich gegen die lokale Wanduhr-Minute, die
    der Aufrufer hereinreicht, OHNE Zeitzonen-Rechnung in der Domaene auskommt. Das Fenster
    ist halb-offen ``[start_minute, end_minute)`` (``end_minute > start_minute``).

    * ``start_minute`` -- Fensterbeginn (0..1439).
    * ``end_minute``   -- Fensterende (1..1440; ``> start_minute``, exklusiv).
    * ``weekdays``     -- aktive Wochentage (0=Montag .. 6=Sonntag). Die LEERE Menge
      bedeutet "alle Tage" (keine Wochentags-Einschraenkung).
    * ``from_epoch``   -- Beginn des Gesamtzeitraums (epoch-float UTC); vorher inaktiv.
    * ``until_epoch``  -- Ende des Gesamtzeitraums (epoch-float UTC). ``0.0`` ist der
      ehrliche "kein Ende"-Leerzustand (S3): unbegrenzt gueltig, KEIN Sentinel-Magie-Wert,
      sondern ein benannter Leerzustand.
    """

    start_minute: int
    end_minute: int
    weekdays: frozenset[int]
    from_epoch: float
    until_epoch: float


@dataclass(frozen=True)
class ScheduledJob:
    """Ein geplanter Job: Zeitplan + Zustand + OPAQUE Job-Referenz.

    Die Entkopplung (Weg 2) lebt in ``job_type``/``params``: beide sind fuer die
    scheduler-Domaene OPAQUE -- sie liest die Werte NICHT und interpretiert sie NICHT.
    Die Bedeutung (welcher Handler bedient ``job_type``, was ``params`` heisst) lebt im
    Composition Root bzw. beim ``JobHandler`` (siehe ``ports.scheduler``).

    * ``id``       -- stabile Identitaet (vom Repository vergeben).
    * ``job_type`` -- opaque Typ-Kennung (z. B. ``"monitoring_window"``).
    * ``params``   -- opaque Schluessel-Wert-Paare als sortierbare Tupel-Sequenz; bewusst
      KEIN dict, damit der Job ``frozen``/hashable bleibt. Die Domaene liest sie NICHT.
    * ``window``   -- das wiederkehrende Tagesfenster (``DailyWindow``).
    * ``state``    -- der Lebenszyklus-Zustand (``JobState``).
    """

    id: int
    job_type: str
    params: tuple[tuple[str, str], ...]
    window: DailyWindow
    state: JobState
