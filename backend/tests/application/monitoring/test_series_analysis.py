"""Tests fuer die zeitfreie Serien-Auswertung (Block 3c, Etappe 1).

Reine application-Schicht: KEINE Repos, KEINE Uhr, KEIN Router. Die lokale
Anreicherung (``minute_of_day``/``day_key``) wird hier durch einen Test-``enrich``
ODER durch direkt gesetzte Felder simuliert -- so bleibt die Aggregation
zeitzonen-unabhaengig pruefbar (genau die Naht, die der spaetere Router fuellt).

Abgedeckt: Down/Up-Paarung, offener Abbruch am Ende, availability bei leerer
Sample-Liste (100.0), Heatmap-Bucketing, Ranking-Sortierung (day_count vor longest),
``has_latency`` je ``capture_mode``, und dass Outages ohne ``minute_of_day``/``day_key``
aus Heatmap/Ranking ausgespart, aber in ``outages`` gelistet bleiben.
"""

from __future__ import annotations

from collections.abc import Callable

from application.monitoring.series_analysis import (
    OutageInterval,
    analyze_series,
    build_heatmap,
    build_outages,
    build_ranking,
    compute_metrics,
)
from domain.monitoring import CaptureMode, LoggingEventRow, LoggingRttSample


def _down(ts: float) -> LoggingEventRow:
    """``"down"``-Flanke (Sentinel-RTT) zum Zeitpunkt ``ts`` (Test-Helfer)."""
    return LoggingEventRow(event_type="down", rtt_ms=-1.0, ts=ts)


def _up(ts: float, rtt_ms: float = 5.0) -> LoggingEventRow:
    """``"up"``-Flanke zum Zeitpunkt ``ts`` (Test-Helfer)."""
    return LoggingEventRow(event_type="up", rtt_ms=rtt_ms, ts=ts)


def _alive(ts: float) -> LoggingRttSample:
    return LoggingRttSample(rtt_ms=5.0, loss_pct=0.0, alive=True, ts=ts)


def _dead(ts: float) -> LoggingRttSample:
    return LoggingRttSample(rtt_ms=-1.0, loss_pct=100.0, alive=False, ts=ts)


def _enrich_with(
    values: dict[float, tuple[int, str | None]],
) -> Callable[[list[OutageInterval]], list[OutageInterval]]:
    """Baut einen ``enrich``, der je ``start_ts`` ein (minute_of_day, day_key) setzt.

    Simuliert die lokale Anreicherung des Routers, ohne echte Zeitzonen-Rechnung:
    fehlt ein ``start_ts`` in ``values``, bleibt die Anreicherung ``None`` (un-angereichert).
    """

    def _enrich(outages: list[OutageInterval]) -> list[OutageInterval]:
        enriched: list[OutageInterval] = []
        for outage in outages:
            entry = values.get(outage.start_ts)
            if entry is None:
                enriched.append(outage)
                continue
            minute_of_day, day_key = entry
            enriched.append(
                OutageInterval(
                    start_ts=outage.start_ts,
                    end_ts=outage.end_ts,
                    duration_s=outage.duration_s,
                    minute_of_day=minute_of_day,
                    day_key=day_key,
                )
            )
        return enriched

    return _enrich


# ── build_outages: Down/Up-Paarung ──────────────────────────────────────────


def test_down_up_pair_yields_closed_outage() -> None:
    events = [_down(100.0), _up(160.0)]

    outages = build_outages(events)

    assert len(outages) == 1
    assert outages[0].start_ts == 100.0
    assert outages[0].end_ts == 160.0
    assert outages[0].duration_s == 60.0


def test_two_down_up_pairs_yield_two_outages() -> None:
    events = [_down(100.0), _up(130.0), _down(200.0), _up(260.0)]

    outages = build_outages(events)

    assert len(outages) == 2
    assert (outages[0].start_ts, outages[0].end_ts, outages[0].duration_s) == (100.0, 130.0, 30.0)
    assert (outages[1].start_ts, outages[1].end_ts, outages[1].duration_s) == (200.0, 260.0, 60.0)


def test_double_down_keeps_first_start() -> None:
    # Zweites "down" ohne zwischenliegendes "up" haelt den urspruenglichen Start.
    events = [_down(100.0), _down(110.0), _up(160.0)]

    outages = build_outages(events)

    assert len(outages) == 1
    assert outages[0].start_ts == 100.0  # nicht 110.0
    assert outages[0].duration_s == 60.0


def test_up_without_open_outage_is_ignored() -> None:
    events = [_up(100.0), _down(200.0), _up(260.0)]

    outages = build_outages(events)

    assert len(outages) == 1
    assert outages[0].start_ts == 200.0


def test_empty_events_yield_no_outages() -> None:
    assert build_outages([]) == []


# ── build_outages: offener Abbruch am Ende ──────────────────────────────────


def test_open_outage_at_end_has_none_end_ts_and_duration_to_last_event() -> None:
    # Serie endet im Ausfall: "down" ohne folgendes "up". Dauer bis zum letzten
    # bekannten Event-ts (hier das spaetere, irrelevante "down" bei 250 -> last_ts).
    events = [_down(100.0), _up(130.0), _down(200.0), _down(250.0)]

    outages = build_outages(events)

    assert len(outages) == 2
    # geschlossen
    assert outages[0].end_ts == 130.0
    # offen: end_ts None, duration bis zum LETZTEN Event-ts (250.0)
    assert outages[1].start_ts == 200.0
    assert outages[1].end_ts is None
    assert outages[1].duration_s == 50.0  # 250 - 200


def test_single_down_open_outage_duration_zero() -> None:
    # Nur ein "down": last_ts == start_ts -> Dauer 0.0, end_ts None.
    outages = build_outages([_down(100.0)])

    assert len(outages) == 1
    assert outages[0].end_ts is None
    assert outages[0].duration_s == 0.0


# ── compute_metrics: availability ───────────────────────────────────────────


def test_availability_empty_samples_is_100() -> None:
    metrics = compute_metrics([], [], slot_minutes=60)

    assert metrics.availability_pct == 100.0
    assert metrics.outage_count == 0
    assert metrics.avg_outage_s == 0.0
    assert metrics.worst_slot_minute is None


def test_availability_is_alive_ratio_times_100_unrounded() -> None:
    # 2 von 3 alive -> 66.666...; NICHT gerundet (das macht der Router/das Frontend).
    rtt = [_alive(1.0), _alive(2.0), _dead(3.0)]

    metrics = compute_metrics(rtt, [], slot_minutes=60)

    assert metrics.availability_pct == 2 / 3 * 100.0


def test_avg_outage_s_over_closed_and_open() -> None:
    # Geschlossen (60s) + offen (40s) -> Mittel 50.0.
    outages = [
        OutageInterval(start_ts=100.0, end_ts=160.0, duration_s=60.0),
        OutageInterval(start_ts=300.0, end_ts=None, duration_s=40.0),
    ]

    metrics = compute_metrics([_alive(1.0)], outages, slot_minutes=60)

    assert metrics.outage_count == 2
    assert metrics.avg_outage_s == 50.0


# ── build_heatmap: Bucketing ────────────────────────────────────────────────


def test_heatmap_buckets_by_slot_minutes() -> None:
    # slot_minutes=60: Minuten 0..59 -> Bucket 0, 60..119 -> Bucket 60, usw.
    outages = [
        OutageInterval(start_ts=1.0, end_ts=2.0, duration_s=1.0, minute_of_day=10),
        OutageInterval(start_ts=2.0, end_ts=3.0, duration_s=1.0, minute_of_day=50),
        OutageInterval(start_ts=3.0, end_ts=4.0, duration_s=1.0, minute_of_day=75),
        OutageInterval(start_ts=4.0, end_ts=5.0, duration_s=1.0, minute_of_day=130),
    ]

    heatmap = build_heatmap(outages, slot_minutes=60)

    # Bucket 0 -> 2 (Minuten 10, 50), Bucket 60 -> 1 (75), Bucket 120 -> 1 (130).
    assert [(s.minute_of_day, s.outage_count) for s in heatmap] == [(0, 2), (60, 1), (120, 1)]


def test_heatmap_skips_unenriched_outages() -> None:
    outages = [
        OutageInterval(start_ts=1.0, end_ts=2.0, duration_s=1.0, minute_of_day=10),
        OutageInterval(start_ts=2.0, end_ts=3.0, duration_s=1.0, minute_of_day=None),
    ]

    heatmap = build_heatmap(outages, slot_minutes=60)

    assert [(s.minute_of_day, s.outage_count) for s in heatmap] == [(0, 1)]


# ── build_ranking: Sortierung ───────────────────────────────────────────────


def test_ranking_sorts_by_day_count_then_longest() -> None:
    # Slot 60: 2 distinkte Tage, laengster 30s. Slot 0: 1 Tag, laengster 90s.
    # day_count dominiert -> Slot 60 zuerst, obwohl Slot 0 den laengeren Abbruch hat.
    outages = [
        OutageInterval(
            start_ts=1.0, end_ts=2.0, duration_s=90.0, minute_of_day=5, day_key="2026-06-01"
        ),
        OutageInterval(
            start_ts=2.0, end_ts=3.0, duration_s=20.0, minute_of_day=70, day_key="2026-06-01"
        ),
        OutageInterval(
            start_ts=3.0, end_ts=4.0, duration_s=30.0, minute_of_day=70, day_key="2026-06-02"
        ),
    ]

    ranking = build_ranking(outages, slot_minutes=60)

    assert [(r.minute_of_day, r.day_count, r.longest_outage_s) for r in ranking] == [
        (60, 2, 30.0),  # 2 distinkte Tage gewinnt
        (0, 1, 90.0),
    ]


def test_ranking_tiebreak_by_longest_then_minute() -> None:
    # Gleicher day_count (1) -> laengerer Abbruch zuerst; bei Gleichstand minute aufsteigend.
    outages = [
        OutageInterval(start_ts=1.0, end_ts=2.0, duration_s=10.0, minute_of_day=5, day_key="d1"),
        OutageInterval(start_ts=2.0, end_ts=3.0, duration_s=50.0, minute_of_day=70, day_key="d1"),
        OutageInterval(start_ts=3.0, end_ts=4.0, duration_s=10.0, minute_of_day=130, day_key="d1"),
    ]

    ranking = build_ranking(outages, slot_minutes=60)

    assert [r.minute_of_day for r in ranking] == [60, 0, 120]  # 50s-Slot zuerst, dann minute asc


def test_ranking_skips_outage_without_day_key_in_day_count_but_counts_longest() -> None:
    # Ohne day_key: NICHT in die Tageszaehlung, aber die Dauer zaehlt fuer longest_outage_s.
    outages = [
        OutageInterval(start_ts=1.0, end_ts=2.0, duration_s=80.0, minute_of_day=5, day_key=None),
        OutageInterval(start_ts=2.0, end_ts=3.0, duration_s=20.0, minute_of_day=10, day_key="d1"),
    ]

    ranking = build_ranking(outages, slot_minutes=60)

    assert len(ranking) == 1
    assert ranking[0].minute_of_day == 0
    assert ranking[0].day_count == 1  # nur der day_key="d1"-Outage zaehlt als Tag
    assert ranking[0].longest_outage_s == 80.0  # der day_key=None-Outage liefert das Maximum


def test_ranking_skips_unenriched_minute_of_day() -> None:
    outages = [
        OutageInterval(start_ts=1.0, end_ts=2.0, duration_s=10.0, minute_of_day=None, day_key="d1"),
    ]

    assert build_ranking(outages, slot_minutes=60) == []


# ── analyze_series: Orchestrierung + has_latency ────────────────────────────


def test_has_latency_true_only_for_reachability_latency() -> None:
    for mode, expected in [
        (CaptureMode.REACHABILITY_LATENCY, True),
        (CaptureMode.REACHABILITY, False),
        (CaptureMode.INTERFACE_STATUS, False),
    ]:
        analysis = analyze_series(mode, [], [], slot_minutes=60, enrich=None)
        assert analysis.has_latency is expected


def test_analyze_without_enrich_lists_outages_but_empty_heatmap_and_ranking() -> None:
    events = [_down(100.0), _up(160.0)]
    rtt = [_alive(1.0), _dead(2.0)]

    analysis = analyze_series(CaptureMode.REACHABILITY, rtt, events, slot_minutes=60, enrich=None)

    # outages vollstaendig...
    assert len(analysis.outages) == 1
    assert analysis.outages[0].minute_of_day is None
    # ...aber Heatmap/Ranking leer (keine Anreicherung), worst_slot None.
    assert analysis.heatmap == []
    assert analysis.ranking == []
    assert analysis.metrics.outage_count == 1
    assert analysis.metrics.worst_slot_minute is None
    assert analysis.metrics.availability_pct == 50.0  # 1 von 2 alive


def test_analyze_with_enrich_fills_heatmap_and_ranking_and_worst_slot() -> None:
    events = [_down(100.0), _up(160.0), _down(300.0), _up(330.0)]
    # enrich: outage@100 -> Minute 70 (Bucket 60), outage@300 -> Minute 75 (Bucket 60).
    # Beide im selben Bucket -> worst_slot 60, count 2.
    enrich = _enrich_with({100.0: (70, "2026-06-01"), 300.0: (75, "2026-06-02")})

    analysis = analyze_series(
        CaptureMode.REACHABILITY_LATENCY, [_alive(1.0)], events, slot_minutes=60, enrich=enrich
    )

    assert len(analysis.outages) == 2
    assert [(s.minute_of_day, s.outage_count) for s in analysis.heatmap] == [(60, 2)]
    assert analysis.metrics.worst_slot_minute == 60
    # Ranking: 1 Slot, 2 distinkte Tage, laengster Abbruch 60s (160-100).
    assert len(analysis.ranking) == 1
    assert analysis.ranking[0].day_count == 2
    assert analysis.ranking[0].longest_outage_s == 60.0


def test_analyze_with_partial_enrich_keeps_unenriched_in_outages_only() -> None:
    # Nur der erste Outage wird angereichert; der zweite bleibt in outages, faellt
    # aber aus Heatmap/Ranking heraus.
    events = [_down(100.0), _up(160.0), _down(300.0), _up(330.0)]
    enrich = _enrich_with({100.0: (70, "2026-06-01")})  # 300.0 fehlt absichtlich

    analysis = analyze_series(
        CaptureMode.REACHABILITY, [_alive(1.0)], events, slot_minutes=60, enrich=enrich
    )

    assert len(analysis.outages) == 2  # beide gelistet
    enriched = [o for o in analysis.outages if o.minute_of_day is not None]
    unenriched = [o for o in analysis.outages if o.minute_of_day is None]
    assert len(enriched) == 1 and len(unenriched) == 1
    # Heatmap/Ranking nur aus dem angereicherten Outage.
    assert [(s.minute_of_day, s.outage_count) for s in analysis.heatmap] == [(60, 1)]
    assert len(analysis.ranking) == 1
    assert analysis.ranking[0].day_count == 1
