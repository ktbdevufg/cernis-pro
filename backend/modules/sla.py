"""
CERNIS PRO SLA / Uptime Tracking
Tracks availability per host over time using monitor events.
Calculates uptime%, downtime, and generates chart data.
"""
import sqlite3
import time
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from pathlib import Path

from modules.db_path import DB_PATH  # noqa


def init_sla_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS sla_targets (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        target_id   TEXT UNIQUE,
        label       TEXT,
        host        TEXT,
        enabled     INTEGER DEFAULT 1,
        created_at  TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS sla_samples (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        target_id   TEXT,
        ts          REAL,
        alive       INTEGER,
        rtt_ms      REAL
    );
    CREATE INDEX IF NOT EXISTS idx_sla_samples_target_ts
        ON sla_samples(target_id, ts);
    """)
    conn.commit()
    conn.close()


def record_sample(target_id: str, alive: bool, rtt_ms: float):
    """Record a single uptime sample. Called from monitor module."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute(
        "INSERT INTO sla_samples (target_id, ts, alive, rtt_ms) VALUES (?,?,?,?)",
        (target_id, time.time(), int(alive), rtt_ms)
    )
    # Prune samples older than 90 days
    cutoff = time.time() - 90 * 86400
    conn.execute("DELETE FROM sla_samples WHERE target_id=? AND ts<?", (target_id, cutoff))
    conn.commit()
    conn.close()


def get_sla_stats(target_id: str, days: int = 30) -> dict:
    """Calculate SLA stats for a target over N days."""
    conn = sqlite3.connect(str(DB_PATH))
    cutoff = time.time() - days * 86400
    rows = conn.execute(
        "SELECT alive, rtt_ms, ts FROM sla_samples WHERE target_id=? AND ts>? ORDER BY ts",
        (target_id, cutoff)
    ).fetchall()
    conn.close()

    if not rows:
        return {"target_id": target_id, "days": days, "samples": 0,
                "uptime_pct": None, "downtime_mins": 0, "avg_rtt_ms": 0,
                "chart": []}

    total = len(rows)
    alive_count = sum(1 for r in rows if r[0])
    rtts = [r[1] for r in rows if r[0] and r[1] > 0]
    avg_rtt = round(sum(rtts) / len(rtts), 2) if rtts else 0
    uptime_pct = round(alive_count / total * 100, 3)

    # Estimate downtime in minutes (assuming 5s interval)
    down_count = total - alive_count
    downtime_mins = round(down_count * 5 / 60, 1)

    # Hourly chart data for last N days
    chart = _build_hourly_chart(rows, days)

    return {
        "target_id": target_id,
        "days": days,
        "samples": total,
        "uptime_pct": uptime_pct,
        "downtime_mins": downtime_mins,
        "avg_rtt_ms": avg_rtt,
        "chart": chart,
    }


def _build_hourly_chart(rows: list, days: int) -> list:
    """Aggregate samples into hourly buckets for charting."""
    if not rows:
        return []

    # Group by hour
    buckets: dict[int, list] = {}
    for alive, rtt, ts in rows:
        hour_key = int(ts // 3600) * 3600
        if hour_key not in buckets:
            buckets[hour_key] = []
        buckets[hour_key].append((alive, rtt))

    chart = []
    for hour_ts in sorted(buckets.keys()):
        samples = buckets[hour_ts]
        alive_n = sum(1 for a, _ in samples if a)
        rtts = [r for _, r in samples if r > 0]
        chart.append({
            "ts": hour_ts,
            "datetime": datetime.fromtimestamp(hour_ts).strftime("%d.%m %H:00"),
            "uptime_pct": round(alive_n / len(samples) * 100, 1),
            "avg_rtt_ms": round(sum(rtts) / len(rtts), 1) if rtts else 0,
            "samples": len(samples),
        })

    # Return last 168 hours (7 days) max for chart readability
    return chart[-168:]


def get_all_sla_stats(days: int = 30) -> list[dict]:
    """Get SLA stats for all tracked targets."""
    init_sla_db()
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    # Get all unique target_ids that have samples
    rows = conn.execute(
        "SELECT DISTINCT target_id FROM sla_samples"
    ).fetchall()
    conn.close()
    return [get_sla_stats(r["target_id"], days) for r in rows]
