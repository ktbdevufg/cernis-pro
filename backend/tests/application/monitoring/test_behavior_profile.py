"""Tests fuer das zeitfreie Verhaltensprofil (Block 4, Etappe 1).

Reine application-Schicht: KEINE Repos, KEINE Uhr, KEIN Router. Die Samples
kommen bereits zeitfrei (weekday/minute_of_day/day_key vom Router-Rand
vorberechnet) -- so bleibt die Aggregation zeitzonen-unabhaengig pruefbar.

Abgedeckt: leere Eingabe; Tageszaehlung genau an der coverage-Grenze und ein Tag
darunter; Heatmap-Bucketung; Median-basierte Abweichungserkennung (naechtlicher
Ausreisser markiert, regulaerer Abend-Slot nicht); Tagesband-Zusammenfassung ueber
Wochentage; has_enough_data-Grenzfall (min_days exakt, darunter, darueber);
deviation_count stimmt mit der Heatmap ueberein.
"""

from __future__ import annotations

from application.monitoring.behavior_profile import (
    ProfileSample,
    analyze_behavior,
    build_day_band,
    build_week_heatmap,
    count_recorded_days,
)


def _sample(weekday: int, minute_of_day: int, day_key: str, alive: bool = True) -> ProfileSample:
    """Zeitfreier Messpunkt (Test-Helfer)."""
    return ProfileSample(weekday=weekday, minute_of_day=minute_of_day, day_key=day_key, alive=alive)


def _full_day(weekday: int, day_key: str, slot_minutes: int = 60) -> list[ProfileSample]:
    """Ein voll belegter Tag: ein alive-Sample in JEDEM Tageszeit-Slot."""
    slots_per_day = 1440 // slot_minutes
    return [
        _sample(weekday, slot_index * slot_minutes, day_key) for slot_index in range(slots_per_day)
    ]


# ── Leere Eingabe ───────────────────────────────────────────────────────────


def test_empty_input() -> None:
    assert count_recorded_days([]) == 0
    assert build_week_heatmap([]) == []
    assert build_day_band([]) == []

    profile = analyze_behavior([])
    assert profile.recorded_days == 0
    assert profile.has_enough_data is False
    assert profile.day_band == []
    assert profile.week_heatmap == []
    assert profile.deviation_count == 0


# ── count_recorded_days: coverage-Grenze ────────────────────────────────────


def test_count_full_day_counts() -> None:
    # Voll belegter Tag (24/24 Slots) liegt klar ueber jeder Schwelle <= 1.0.
    samples = _full_day(0, "2026-06-01")
    assert count_recorded_days(samples, day_min_coverage=0.5, slot_minutes=60) == 1


def test_count_exactly_at_coverage_threshold_counts() -> None:
    # Genau 12 von 24 Slots belegt = 0.5 Anteil. Grenze ist inklusiv (>=).
    day = [_sample(0, slot * 60, "2026-06-01") for slot in range(12)]
    assert count_recorded_days(day, day_min_coverage=0.5, slot_minutes=60) == 1


def test_count_just_below_threshold_does_not_count() -> None:
    # 11 von 24 Slots = 0.4583 < 0.5 -> der Tag zaehlt nicht.
    day = [_sample(0, slot * 60, "2026-06-01") for slot in range(11)]
    assert count_recorded_days(day, day_min_coverage=0.5, slot_minutes=60) == 0


def test_count_dead_samples_do_not_fill_slots() -> None:
    # 12 belegte Slots, aber alle alive=False -> keine Belegung -> zaehlt nicht.
    day = [_sample(0, slot * 60, "2026-06-01", alive=False) for slot in range(12)]
    assert count_recorded_days(day, day_min_coverage=0.5, slot_minutes=60) == 0


def test_count_multiple_samples_in_one_slot_count_once() -> None:
    # Drei alive-Samples in DEMSELBEN Slot belegen nur einen Slot.
    day = [_sample(0, 5, "2026-06-01"), _sample(0, 30, "2026-06-01"), _sample(0, 59, "2026-06-01")]
    # 1 belegter Slot von 24 = 0.0417 -> unter 0.5.
    assert count_recorded_days(day, day_min_coverage=0.5, slot_minutes=60) == 0


def test_count_separates_days_by_day_key() -> None:
    samples = _full_day(0, "2026-06-01") + _full_day(1, "2026-06-02")
    assert count_recorded_days(samples) == 2


# ── build_week_heatmap: Bucketung ───────────────────────────────────────────


def test_week_heatmap_bucketing() -> None:
    # minute_of_day 5, 30, 59 fallen alle in Slot 0; 60, 90 in Slot 60.
    samples = [
        _sample(0, 5, "d1"),
        _sample(0, 30, "d1"),
        _sample(0, 59, "d1"),
        _sample(0, 60, "d1"),
        _sample(0, 90, "d1"),
    ]
    heatmap = build_week_heatmap(samples, slot_minutes=60)
    by_slot = {slot.slot_start: slot.activity_count for slot in heatmap}
    assert by_slot == {0: 3, 60: 2}
    assert all(slot.weekday == 0 for slot in heatmap)


def test_week_heatmap_dead_samples_excluded() -> None:
    samples = [_sample(0, 10, "d1"), _sample(0, 20, "d1", alive=False)]
    heatmap = build_week_heatmap(samples, slot_minutes=60)
    assert len(heatmap) == 1
    assert heatmap[0].activity_count == 1


# ── Median-basierte Abweichungserkennung ────────────────────────────────────


def test_week_heatmap_nightly_outlier_is_deviation() -> None:
    # Montag ist typischerweise leer (Median ueber 24 Slots = 0): ein einziger
    # naechtlicher Slot mit Aktivitaet ist eine Abweichung.
    samples = [_sample(0, 3 * 60, "d1")]  # 03:00 Uhr
    heatmap = build_week_heatmap(samples, slot_minutes=60, deviation_factor=3.0)
    assert len(heatmap) == 1
    assert heatmap[0].is_deviation is True


def test_week_heatmap_regular_evening_slot_not_deviation() -> None:
    # Dienstag ist gut belegt: 16 von 24 Slots tragen je 5 Samples -> Median > 0.
    # Ein regulaerer Abend-Slot mit gleicher Last ist KEINE Abweichung.
    samples: list[ProfileSample] = []
    for slot in range(16):
        for _ in range(5):
            samples.append(_sample(1, slot * 60, "dx"))
    heatmap = build_week_heatmap(samples, slot_minutes=60, deviation_factor=3.0)
    # Median ueber 24 Slots: 16 Slots mit 5, 8 Slots mit 0 -> Median = 5.
    # Abend-Slot 18*60 ist nicht belegt; pruefe einen belegten Slot (count 5).
    evening = next(slot for slot in heatmap if slot.slot_start == 14 * 60)
    assert evening.activity_count == 5
    # 5 > 3.0 * 5 ist falsch -> keine Abweichung.
    assert evening.is_deviation is False


def test_week_heatmap_spike_above_factor_is_deviation() -> None:
    # Gut belegter Wochentag (Median 5), aber EIN Slot mit massivem Ausschlag (20).
    samples: list[ProfileSample] = []
    for slot in range(16):
        for _ in range(5):
            samples.append(_sample(2, slot * 60, "dy"))
    for _ in range(20):  # zusaetzliche Last in Slot 0 -> count dort 25
        samples.append(_sample(2, 0, "dy"))
    heatmap = build_week_heatmap(samples, slot_minutes=60, deviation_factor=3.0)
    spike = next(slot for slot in heatmap if slot.slot_start == 0)
    assert spike.activity_count == 25
    # Median bleibt 5 (Ausreisser zieht ihn nicht hoch). 25 > 3.0 * 5 = 15 -> Abweichung.
    assert spike.is_deviation is True


# ── build_day_band: Zusammenfassung ueber Wochentage ────────────────────────


def test_day_band_merges_across_weekdays() -> None:
    # Gleicher Tageszeit-Slot an drei verschiedenen Wochentagen -> ein Band-Slot mit 3.
    samples = [_sample(0, 8 * 60, "d1"), _sample(2, 8 * 60, "d2"), _sample(5, 8 * 60, "d3")]
    band = build_day_band(samples, slot_minutes=60)
    assert len(band) == 1
    assert band[0].slot_start == 8 * 60
    assert band[0].activity_count == 3


def test_day_band_sorted_by_slot_start() -> None:
    samples = [_sample(0, 20 * 60, "d1"), _sample(1, 2 * 60, "d2"), _sample(2, 11 * 60, "d3")]
    band = build_day_band(samples, slot_minutes=60)
    assert [slot.slot_start for slot in band] == [2 * 60, 11 * 60, 20 * 60]


def test_day_band_nightly_outlier_is_deviation() -> None:
    samples = [_sample(0, 4 * 60, "d1")]
    band = build_day_band(samples, slot_minutes=60, deviation_factor=3.0)
    assert band[0].is_deviation is True


# ── analyze_behavior: has_enough_data-Grenzfall ─────────────────────────────


def _n_full_days(n: int) -> list[ProfileSample]:
    """n voll belegte Tage mit eindeutigem day_key (Wochentag rotiert)."""
    samples: list[ProfileSample] = []
    for index in range(n):
        samples.extend(_full_day(index % 7, f"day-{index:03d}"))
    return samples


def test_has_enough_data_exactly_min_days() -> None:
    profile = analyze_behavior(_n_full_days(14), min_days=14)
    assert profile.recorded_days == 14
    assert profile.has_enough_data is True


def test_has_enough_data_one_below_min_days() -> None:
    profile = analyze_behavior(_n_full_days(13), min_days=14)
    assert profile.recorded_days == 13
    assert profile.has_enough_data is False


def test_has_enough_data_one_above_min_days() -> None:
    profile = analyze_behavior(_n_full_days(15), min_days=14)
    assert profile.recorded_days == 15
    assert profile.has_enough_data is True


def test_analyze_builds_views_even_without_enough_data() -> None:
    # Zu wenig Tage, aber Tagesband/Heatmap werden trotzdem berechnet.
    profile = analyze_behavior(_n_full_days(2), min_days=14)
    assert profile.has_enough_data is False
    assert profile.day_band != []
    assert profile.week_heatmap != []


def test_deviation_count_matches_heatmap() -> None:
    # Zwei naechtliche Ausreisser an sonst leeren Wochentagen -> beide Abweichungen.
    samples = [_sample(0, 3 * 60, "d1"), _sample(4, 23 * 60, "d2")]
    profile = analyze_behavior(samples)
    heatmap_deviations = sum(1 for slot in profile.week_heatmap if slot.is_deviation)
    assert profile.deviation_count == heatmap_deviations
    assert profile.deviation_count == 2
