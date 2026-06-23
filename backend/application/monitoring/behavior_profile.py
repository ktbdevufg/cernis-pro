"""Geraete-Verhaltensprofil als reine, zeitfreie Lese-Aggregation (Block 4, Etappe 1).

Diese Datei verdichtet die Messpunkte EINER RECURRING-Serie zu einem
Verhaltensprofil: einem ueber alle Tage gemittelten Tagesband (DayBandSlot),
einer Wochen-Heatmap (DaySlot je Wochentag x Tageszeit-Slot), einer Zaehlung
der tatsaechlichen Aufzeichnungstage und einer Mindest-Daten-Schwelle. Sie ist
REINE LESESICHT analog series_analysis.py: KEINE neue Messlogik, KEIN Sink, KEINE
Persistenz, KEIN Scheduler.

ZEITFREI wie die Domaene (CLAUDE.md, ADR 0002): KEINE Uhr, KEINE Zeitzonen-/
Wanduhr-Rechnung in dieser Datei. Die lokale Umrechnung Unix-ts -> weekday,
minute_of_day und day_key (lokales Datum als Tagesschluessel) macht der spaetere
Router-Rand (Etappe 2) und reicht sie bereits umgerechnet als ProfileSample
herein. So bleibt die Aggregation voll testbar, ohne dass die Zeitzone des
Testlaufs das Ergebnis beeinflusst -- dieselbe Naht wie enrich/enriched_rtt bei
series_analysis.

Muster aus der Nachbarschaft uebernommen: frozen dataclasses als Ergebnis-
Datentraeger, reine Funktionen, die via Parameter alle Zeit-/Kontext-Werte
hereingereicht bekommen (kein time.time()), gemeinsame Slot-Bucketung
(minute_of_day // slot_minutes) * slot_minutes wie series_analysis.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from statistics import median

# ── Eingabe-Datentraeger (frozen, zeitfreie Sample-Form) ────────────────────


@dataclass(frozen=True)
class ProfileSample:
    """EIN zeitfreier Messpunkt der RECURRING-Serie fuer das Verhaltensprofil.

    ``weekday`` ist der Wochentag (0..6, Mo=0), ``minute_of_day`` die Tagesminute
    (0..1439), ``day_key`` das lokale ISO-Datum (yyyy-mm-dd) als Tagesschluessel,
    ``alive`` ob der Messpunkt das Geraet erreichbar fand. Alle Felder werden vom
    Router-Rand aus dem Unix-``ts`` in LOKALER Zeit vorberechnet (s. Modul-Docstring)
    -- diese Datei rechnet keine Wanduhr.
    """

    weekday: int
    minute_of_day: int
    day_key: str
    alive: bool


# ── Ergebnis-Datentraeger (frozen) ──────────────────────────────────────────


@dataclass(frozen=True)
class DaySlot:
    """Ein Zelle der Wochen-Heatmap: ein Tageszeit-Slot eines Wochentags.

    ``weekday`` (0..6, Mo=0), ``slot_start`` die untere Bucket-Grenze des
    Tageszeit-Slots ((minute_of_day // slot_minutes) * slot_minutes),
    ``activity_count`` die Zahl der ``alive``-Samples in (weekday, slot_start),
    ``is_deviation`` ob dieser aktive Slot fuer diesen Wochentag untypisch ist
    (s. ``build_week_heatmap`` fuer die Regel).
    """

    weekday: int
    slot_start: int
    activity_count: int
    is_deviation: bool


@dataclass(frozen=True)
class DayBandSlot:
    """Ein Slot des ueber ALLE Wochentage gemittelten Tagesbandes.

    Wie ``DaySlot``, nur ohne Wochentag-Achse: ``slot_start`` der Tageszeit-Slot,
    ``activity_count`` die Zahl der ``alive``-Samples in diesem Slot ueber alle
    Wochentage, ``is_deviation`` ob der Slot fuer das Tagesband untypisch aktiv ist.
    """

    slot_start: int
    activity_count: int
    is_deviation: bool


@dataclass(frozen=True)
class BehaviorProfile:
    """Das Gesamtergebnis des Verhaltensprofils (alles, was der Router herausreicht).

    ``recorded_days`` ist die Zahl der gezaehlten Aufzeichnungstage (Tage ueber der
    Belegungsschwelle), ``has_enough_data`` ob ``recorded_days >= min_days``,
    ``day_band`` das gemittelte Tagesband, ``week_heatmap`` die Wochen-Heatmap,
    ``deviation_count`` die Summe der ``is_deviation`` ueber die Wochen-Heatmap.
    ``day_band``/``week_heatmap`` werden IMMER berechnet (auch bei zu wenig Daten,
    fuer spaetere Anzeige); ueber die Anzeige entscheidet der Aufrufer.
    """

    recorded_days: int
    has_enough_data: bool
    day_band: list[DayBandSlot]
    week_heatmap: list[DaySlot]
    deviation_count: int


# ── Reine Funktionen (keine I/O, keine Uhr) ─────────────────────────────────


def _slot_of(minute_of_day: int, slot_minutes: int) -> int:
    """Untere Bucket-Grenze einer Tagesminute (``(m // slot) * slot``)."""
    return (minute_of_day // slot_minutes) * slot_minutes


def count_recorded_days(
    samples: list[ProfileSample],
    day_min_coverage: float = 0.5,
    slot_minutes: int = 60,
) -> int:
    """Zaehlt die Tage mit ausreichender Belegung.

    Gruppiert die Samples nach ``day_key``. Ein Tag zaehlt nur, wenn der Anteil
    BELEGTER Slots am Tag mindestens ``day_min_coverage`` ist. Ein Slot gilt als
    belegt, sobald mindestens ein ``alive``-Sample in ihn faellt -- nicht erreichbare
    Samples (``alive=False``) tragen NICHT zur Belegung bei. Die Zahl moeglicher
    Slots am Tag ist ``1440 // slot_minutes``. Leere Eingabe -> ``0``.
    """
    slots_per_day = 1440 // slot_minutes
    busy_slots_per_day: dict[str, set[int]] = defaultdict(set)
    for sample in samples:
        if not sample.alive:
            continue
        busy_slots_per_day[sample.day_key].add(_slot_of(sample.minute_of_day, slot_minutes))

    return sum(
        1 for busy in busy_slots_per_day.values() if len(busy) / slots_per_day >= day_min_coverage
    )


def build_week_heatmap(
    samples: list[ProfileSample],
    slot_minutes: int = 60,
    deviation_factor: float = 3.0,
) -> list[DaySlot]:
    """Baut die Wochen-Heatmap je (Wochentag, Tageszeit-Slot) mit Abweichungsmarkierung.

    Buckert jeden ``alive``-Messpunkt nach Wochentag und Tageszeit-Slot
    ((minute_of_day // slot_minutes) * slot_minutes, gleiche Bucketung wie
    series_analysis). ``activity_count`` ist die Zahl der ``alive``-Samples je
    (weekday, slot_start); nicht erreichbare Samples gehen NICHT ein.

    Abweichungs-Regel (konservativ und deterministisch): Bezugsgroesse ist der
    Median der activity_count ueber ALLE moeglichen Slots desselben Wochentags
    (1440 // slot_minutes Slots, fehlende Slots zaehlen als 0). Ein Slot ist eine
    Abweichung, wenn er aktiv ist (count groesser 0), der typische Wert dieses
    Wochentags aber nahe null liegt -- konkret, wenn count groesser ist als
    deviation_factor mal dem Median. Liegt der Median bei 0 (der Wochentag ist
    typischerweise leer), genuegt jede Aktivitaet (count groesser 0) als Abweichung.
    Das markiert naechtliche Ausreisser an sonst leeren Slots, laesst aber regulaer
    belegte Slots (deren Median ueber dem Schwellwert liegt) in Ruhe.

    Nur Slots mit Aktivitaet (count groesser 0) erscheinen in der Ausgabe; sie ist
    aufsteigend nach (weekday, slot_start) sortiert. Leere Eingabe -> leere Liste.
    """
    slots_per_day = 1440 // slot_minutes
    counts: dict[tuple[int, int], int] = defaultdict(int)
    for sample in samples:
        if not sample.alive:
            continue
        counts[(sample.weekday, _slot_of(sample.minute_of_day, slot_minutes))] += 1

    # Pro Wochentag den Median ueber ALLE moeglichen Slots (fehlende = 0) bilden,
    # damit ein einzelner Ausreisser den Bezugswert nicht hochzieht.
    weekdays = {weekday for weekday, _slot in counts}
    median_per_weekday: dict[int, float] = {}
    for weekday in weekdays:
        all_slot_counts = [
            counts.get((weekday, slot_index * slot_minutes), 0)
            for slot_index in range(slots_per_day)
        ]
        median_per_weekday[weekday] = median(all_slot_counts)

    heatmap = [
        DaySlot(
            weekday=weekday,
            slot_start=slot_start,
            activity_count=count,
            is_deviation=_is_deviation(count, median_per_weekday[weekday], deviation_factor),
        )
        for (weekday, slot_start), count in counts.items()
    ]
    heatmap.sort(key=lambda slot: (slot.weekday, slot.slot_start))
    return heatmap


def build_day_band(
    samples: list[ProfileSample],
    slot_minutes: int = 60,
    deviation_factor: float = 3.0,
) -> list[DayBandSlot]:
    """Baut das ueber alle Wochentage zusammengefasste Tagesband mit Abweichungsmarkierung.

    Wie ``build_week_heatmap``, aber der Wochentag wird ignoriert: gruppiert nur
    nach Tageszeit-Slot. ``activity_count`` ist die Zahl der ``alive``-Samples je
    Slot ueber alle Wochentage. Die Abweichungs-Regel ist identisch, nur ist die
    Bezugsgroesse der Median der activity_count ueber ALLE moeglichen Tagesslots
    (1440 // slot_minutes, fehlende = 0). Nur aktive Slots erscheinen, aufsteigend
    nach ``slot_start`` sortiert. Leere Eingabe -> leere Liste.
    """
    slots_per_day = 1440 // slot_minutes
    counts: dict[int, int] = defaultdict(int)
    for sample in samples:
        if not sample.alive:
            continue
        counts[_slot_of(sample.minute_of_day, slot_minutes)] += 1

    all_slot_counts = [
        counts.get(slot_index * slot_minutes, 0) for slot_index in range(slots_per_day)
    ]
    band_median = median(all_slot_counts)

    band = [
        DayBandSlot(
            slot_start=slot_start,
            activity_count=count,
            is_deviation=_is_deviation(count, band_median, deviation_factor),
        )
        for slot_start, count in counts.items()
    ]
    band.sort(key=lambda slot: slot.slot_start)
    return band


def _is_deviation(count: int, typical_median: float, deviation_factor: float) -> bool:
    """Ob ein aktiver Slot fuer seine Bezugsgruppe untypisch ist.

    Inaktive Slots (count 0) sind nie eine Abweichung. Ist der typische Wert
    (Median der Bezugsgruppe) 0, genuegt jede Aktivitaet. Sonst muss count den
    typischen Wert um den Faktor deviation_factor uebersteigen (konservativ:
    regulaer belegte Slots, deren Median nahe count liegt, bleiben unmarkiert).
    """
    if count <= 0:
        return False
    if typical_median <= 0.0:
        return True
    return count > deviation_factor * typical_median


def analyze_behavior(
    samples: list[ProfileSample],
    min_days: int = 14,
    day_min_coverage: float = 0.5,
    slot_minutes: int = 60,
    deviation_factor: float = 3.0,
) -> BehaviorProfile:
    """Orchestriert das Verhaltensprofil aus zeitfreien Samples.

    Ruft ``count_recorded_days``, ``build_day_band`` und ``build_week_heatmap``,
    setzt ``has_enough_data = recorded_days >= min_days`` und
    ``deviation_count`` = Summe der ``is_deviation`` ueber die Wochen-Heatmap.
    Tagesband und Wochen-Heatmap werden auch bei zu wenig Daten berechnet (fuer
    spaetere Anzeige); ueber die Anzeige entscheidet der Aufrufer.
    """
    recorded_days = count_recorded_days(samples, day_min_coverage, slot_minutes)
    day_band = build_day_band(samples, slot_minutes, deviation_factor)
    week_heatmap = build_week_heatmap(samples, slot_minutes, deviation_factor)
    deviation_count = sum(1 for slot in week_heatmap if slot.is_deviation)

    return BehaviorProfile(
        recorded_days=recorded_days,
        has_enough_data=recorded_days >= min_days,
        day_band=day_band,
        week_heatmap=week_heatmap,
        deviation_count=deviation_count,
    )
