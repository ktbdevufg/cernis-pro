"""Reine Aggregation des Verhaltensprofil-Berichts mit Bezugsrahmen-Wahl (Etappe 1).

Dieser NEUE Reporting-Bericht verdichtet die zeitfreien Verhaltensprofile aus
``behavior_profile.py`` zu einem anzeigefertigen Bericht -- mit zwei
BEZUGSRAHMEN: EINE Logging-Aufgabe im Detail ("single") ODER ein Ueberblick ueber
ALLE Aufgaben/Geraete ("all"). Die Architektur ist 1:1 analog zu den
Nachbar-Berichten: neutrale frozen Eingabe-Typen, reine ``build``-Funktionen, ein
frozen Out-Report mit Bezugsrahmen-Wahl (wie ``dns_bypass_report.py``), aufgebaut
ueber einer bestehenden application-internen Rechen-Schicht (wie
``security_report.py`` ueber ``security_score.py``).

DATENQUELLE: die ``ProfileSample``-Listen je Logging-Aufgabe. Der Composition Root
(spaetere Etappe) baut diese neutralen Sample-Listen aus dem persistenten Stand und
reicht sie ueber ``BehaviorTaskInput`` herein -- diese Datei rechnet nur:
aggregiert ueber ``analyze_behavior`` und verdichtet die Profile zu Kennzahlen.

REINE RECHNUNG analog ``behavior_profile.py``: KEINE Uhr, KEINE Zeitzonen-Rechnung,
KEINE I/O, KEINE Persistenz, KEINE Domaenen-Importe (CLAUDE.md, Importregel
application -> domain/ports). Hier wird nur aggregiert, verdichtet und sortiert.
Technische Schluessel (``scope``) bleiben ROH -- nur die Anzeige wird spaeter (am
Rand) lokalisiert.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from application.monitoring.behavior_profile import (
    BehaviorProfile,
    ProfileSample,
    analyze_behavior,
)

# ── Eingabe-Datentraeger (frozen, neutral) ──────────────────────────────────
#
# Der Aufrufer (Composition Root) fuellt diese aus dem persistenten Stand: er baut
# die zeitfreie ``samples``-Liste je Logging-Aufgabe (Unix-ts -> weekday/
# minute_of_day/day_key in LOKALER Zeit, dieselbe Naht wie in behavior_profile).
# Diese Datei rechnet nur.


@dataclass(frozen=True)
class BehaviorTaskInput:
    """Neutrale Eingabe EINER Logging-Aufgabe fuer den Verhaltensprofil-Bericht.

    ``task_id`` ist der rohe Schluessel der RECURRING-Serie (technisch, nicht
    lokalisiert), ``label`` der Anzeigename der Aufgabe/des Geraets, ``samples`` die
    zeitfreien Messpunkte der Serie. Der Composition Root baut ``samples`` aus dem
    persistenten Stand; diese Datei rechnet damit nur (ruft ``analyze_behavior``).
    """

    task_id: str
    label: str
    samples: list[ProfileSample]


# ── Ergebnis-Datentraeger (frozen) ──────────────────────────────────────────


@dataclass(frozen=True)
class BehaviorReportEntry:
    """Verdichtete Kennzahlen EINER Aufgabe/eines Geraets fuer den "alle"-Ueberblick.

    ``label`` der Anzeigename, ``recorded_days`` die gezaehlten Aufzeichnungstage,
    ``has_enough_data`` ob genug Daten vorliegen, ``deviation_count`` die Zahl der
    Abweichungen in der Wochen-Heatmap. ``busiest_slot_start`` ist der ``slot_start``
    des aktivsten Tagesband-Slots (``None`` wenn das Tagesband leer ist oder alle
    ``activity_count`` 0 sind), ``busiest_weekday`` der ``weekday`` der aktivsten
    Wochen-Heatmap-Zelle (``None`` wenn leer oder alle 0). Bei Gleichstand gewinnt
    der frueheste ``slot_start`` bzw. der kleinste ``weekday`` (deterministisch).
    """

    label: str
    recorded_days: int
    has_enough_data: bool
    deviation_count: int
    busiest_slot_start: int | None
    busiest_weekday: int | None


@dataclass(frozen=True)
class BehaviorReport:
    """Das Gesamtergebnis der Verhaltensprofil-Aggregation (alles fuer den api-Rand).

    BEZUGSRAHMEN ueber ``scope`` (roher technischer Schluessel, nicht lokalisiert):
      * ``scope="single"`` -- Detailsicht EINER Aufgabe: ``single_profile`` und
        ``single_label`` sind gesetzt, ``entries`` ist leer.
      * ``scope="all"`` -- Ueberblick ueber ALLE Aufgaben: ``entries`` ist gefuellt
        (ein Eintrag je Aufgabe mit Daten), ``single_profile``/``single_label`` sind
        ``None``.
    """

    scope: Literal["single", "all"]
    entries: list[BehaviorReportEntry]
    single_profile: BehaviorProfile | None
    single_label: str | None = None


# ── Reine Funktionen (keine I/O, keine Uhr) ─────────────────────────────────


def _busiest_day_band_slot(profile: BehaviorProfile) -> int | None:
    """Liefert den ``slot_start`` des aktivsten Tagesband-Slots.

    Waehlt aus ``profile.day_band`` den ``DayBandSlot`` mit hoechstem
    ``activity_count``; bei Gleichstand gewinnt der frueheste ``slot_start``.
    ``None`` wenn das Tagesband leer ist oder der hoechste ``activity_count`` 0 ist.
    """
    best_slot: int | None = None
    best_count = 0
    for slot in profile.day_band:
        if slot.activity_count > best_count:
            best_count = slot.activity_count
            best_slot = slot.slot_start
        elif slot.activity_count == best_count and best_slot is not None:
            best_slot = min(best_slot, slot.slot_start)
    return best_slot


def _busiest_weekday(profile: BehaviorProfile) -> int | None:
    """Liefert den ``weekday`` der aktivsten Wochen-Heatmap-Zelle.

    Waehlt aus ``profile.week_heatmap`` die ``DaySlot`` mit hoechstem
    ``activity_count``; bei Gleichstand gewinnt der kleinste ``weekday``. ``None``
    wenn die Heatmap leer ist oder der hoechste ``activity_count`` 0 ist.
    """
    best_weekday: int | None = None
    best_count = 0
    for cell in profile.week_heatmap:
        if cell.activity_count > best_count:
            best_count = cell.activity_count
            best_weekday = cell.weekday
        elif cell.activity_count == best_count and best_weekday is not None:
            best_weekday = min(best_weekday, cell.weekday)
    return best_weekday


def build_single_behavior_report(
    task_input: BehaviorTaskInput,
    min_days: int = 14,
    day_min_coverage: float = 0.5,
    slot_minutes: int = 60,
    deviation_factor: float = 3.0,
) -> BehaviorReport:
    """Baut die Detailsicht EINER Logging-Aufgabe (``scope="single"``).

    Ruft ``analyze_behavior`` ueber ``task_input.samples`` mit den durchgereichten
    Parametern und legt das Ergebnis als ``single_profile`` samt ``single_label``
    (= ``task_input.label``) ab; ``entries`` bleibt leer. Alle Schwellen/Faktoren
    kommen als Parameter mit Defaults herein (spaeter aus analysis-Settings).
    Deterministisch, keine Uhr, keine I/O.
    """
    profile = analyze_behavior(
        task_input.samples,
        min_days=min_days,
        day_min_coverage=day_min_coverage,
        slot_minutes=slot_minutes,
        deviation_factor=deviation_factor,
    )
    return BehaviorReport(
        scope="single",
        entries=[],
        single_profile=profile,
        single_label=task_input.label,
    )


def build_all_behavior_report(
    task_inputs: list[BehaviorTaskInput],
    min_days: int = 14,
    day_min_coverage: float = 0.5,
    slot_minutes: int = 60,
    deviation_factor: float = 3.0,
) -> BehaviorReport:
    """Baut den Ueberblick ueber ALLE Logging-Aufgaben (``scope="all"``).

    Fuer jede ``task_input`` laeuft ``analyze_behavior`` ueber ihre Samples; aus dem
    Profil wird ein ``BehaviorReportEntry`` verdichtet (``label``, ``recorded_days``,
    ``has_enough_data``, ``deviation_count`` sowie ``busiest_slot_start`` via
    ``_busiest_day_band_slot`` und ``busiest_weekday`` via ``_busiest_weekday``).
    Die ``entries`` werden deterministisch sortiert: ``recorded_days`` absteigend,
    bei Gleichstand ``label`` aufsteigend (stabil). ``single_profile``/
    ``single_label`` bleiben ``None``. Alle Schwellen/Faktoren kommen als Parameter
    mit Defaults herein. Deterministisch, keine Uhr, keine I/O.
    """
    entries: list[BehaviorReportEntry] = []
    for task_input in task_inputs:
        profile = analyze_behavior(
            task_input.samples,
            min_days=min_days,
            day_min_coverage=day_min_coverage,
            slot_minutes=slot_minutes,
            deviation_factor=deviation_factor,
        )
        entries.append(
            BehaviorReportEntry(
                label=task_input.label,
                recorded_days=profile.recorded_days,
                has_enough_data=profile.has_enough_data,
                deviation_count=profile.deviation_count,
                busiest_slot_start=_busiest_day_band_slot(profile),
                busiest_weekday=_busiest_weekday(profile),
            )
        )
    entries.sort(key=lambda entry: (-entry.recorded_days, entry.label))
    return BehaviorReport(
        scope="all",
        entries=entries,
        single_profile=None,
        single_label=None,
    )
