"""Charakterisierung der reinen SLA-Rechenfunktionen ``compute_sla_stats`` /
``build_hourly_chart``.

Erwartete Werte gegen die Altcode-Referenz (``modules/sla.get_sla_stats`` reiner
Anteil + ``_build_hourly_chart``) verifiziert -- bit-identisch. Das TZ-abhaengige
Chart-``datetime`` (``datetime.fromtimestamp`` -> lokale Zeitzone) wird NICHT auf
einen absoluten String festgenagelt (CI-TZ koennte abweichen), nur auf die
TZ-unabhaengigen Felder und die Struktur.
"""

from typing import Any

from domain.monitoring import build_hourly_chart, compute_sla_stats

# (alive, rtt_ms, ts) -- vier Samples in EINER Stunde:
# alive=3/4 -> uptime 75.0; rtts der lebendigen mit rtt>0 = [5,15] -> avg 10.0;
# down_count=1 -> downtime 1*5/60 = 0.0833 -> 0.1; das alive-aber-rtt=0-Sample
# faellt aus dem avg.
_ROWS: list[tuple[float, float, float]] = [
    (1, 5.0, 1_700_000_000.0),
    (1, 15.0, 1_700_000_100.0),
    (0, -1.0, 1_700_000_200.0),
    (1, 0.0, 1_700_000_300.0),
]


def test_compute_sla_stats_full_calculation() -> None:
    stats = compute_sla_stats(_ROWS, 30)
    assert stats["days"] == 30
    assert stats["samples"] == 4
    assert stats["uptime_pct"] == 75.0  # 3/4, 3 Dezimalstellen
    assert stats["avg_rtt_ms"] == 10.0  # mean([5,15]), 2 Dezimalstellen
    assert stats["downtime_mins"] == 0.1  # 1 * 5 / 60 -> 0.0833 -> 0.1 (5s-Annahme)
    assert isinstance(stats["chart"], list)
    assert len(stats["chart"]) == 1  # alle vier Samples in einer Stunde


def test_compute_sla_stats_empty_returns_null_stats() -> None:
    # AS-IS: leere rows -> uptime_pct None (NICHT 0), die uebrigen genullt.
    stats = compute_sla_stats([], 30)
    assert stats == {
        "days": 30,
        "samples": 0,
        "uptime_pct": None,
        "downtime_mins": 0,
        "avg_rtt_ms": 0,
        "chart": [],
    }
    # target_id ist bewusst NICHT im Domaenen-Ergebnis -- das setzt der M.7-Adapter.
    assert "target_id" not in stats


def test_compute_sla_stats_avg_rtt_zero_when_no_positive_rtts() -> None:
    # Nur tote Samples / rtt<=0 -> avg_rtt default 0 (nicht None, nicht Crash).
    rows: list[tuple[float, float, float]] = [
        (0, -1.0, 1_700_000_000.0),
        (1, 0.0, 1_700_000_100.0),
    ]
    stats = compute_sla_stats(rows, 7)
    assert stats["avg_rtt_ms"] == 0
    assert stats["uptime_pct"] == 50.0


def test_build_hourly_chart_single_bucket() -> None:
    chart = build_hourly_chart(_ROWS, 30)
    assert len(chart) == 1
    bucket = chart[0]
    # ts = int(ts // 3600) * 3600 des ersten Samples.
    assert bucket["ts"] == int(1_700_000_000.0 // 3600) * 3600
    assert bucket["uptime_pct"] == 75.0  # 3/4 alive, 1 Dezimalstelle
    assert bucket["avg_rtt_ms"] == 10.0  # Chart-Filter: rtt>0 (kein alive-Filter)
    assert bucket["samples"] == 4
    # datetime ist TZ-abhaengig -> nur Praesenz + Format-Grobform pruefen.
    assert isinstance(bucket["datetime"], str)
    assert ":00" in bucket["datetime"]


def test_build_hourly_chart_groups_by_hour() -> None:
    rows = [*_ROWS, (1, 8.0, 1_700_003_700.0)]  # +1h -> zweiter Bucket
    chart = build_hourly_chart(rows, 30)
    assert len(chart) == 2
    # aufsteigend nach Stunde sortiert.
    assert chart[0]["ts"] < chart[1]["ts"]


def test_build_hourly_chart_empty_returns_empty() -> None:
    assert build_hourly_chart([], 30) == []


def test_chart_rtt_filter_ignores_alive_flag() -> None:
    # BEFUND-Beleg: im Chart zaehlt rtt>0 OHNE alive-Bedingung -- ein TOTES Sample
    # mit positiver rtt geht in den Chart-avg ein (anders als in compute_sla_stats).
    rows: list[tuple[float, float, float]] = [
        (0, 20.0, 1_700_000_000.0),  # tot, aber rtt=20 -> zaehlt im Chart-avg
    ]
    chart = build_hourly_chart(rows, 30)
    assert chart[0]["avg_rtt_ms"] == 20.0
    assert chart[0]["uptime_pct"] == 0.0
    # Gegenprobe: in der Gesamt-Stat faellt dasselbe Sample aus dem avg (alive-Filter).
    stats: dict[str, Any] = compute_sla_stats(rows, 30)
    assert stats["avg_rtt_ms"] == 0
