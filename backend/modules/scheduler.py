"""
CERNIS PRO Scheduled Scans
Runs scans on a schedule using APScheduler.
Stores schedule config in SQLite.
"""
import asyncio
import json
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Callable

try:
    from apscheduler.schedulers.asyncio import AsyncIOScheduler
    from apscheduler.triggers.cron import CronTrigger
    from apscheduler.triggers.interval import IntervalTrigger
    HAS_SCHEDULER = True
except ImportError:
    HAS_SCHEDULER = False

from modules.db_path import DB_PATH  # noqa

_scheduler: Optional["AsyncIOScheduler"] = None
_scan_callback: Optional[Callable] = None


def init_schedule_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_schedules (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT,
            cidr        TEXT,
            profile_id  TEXT,
            schedule    TEXT,
            enabled     INTEGER DEFAULT 1,
            last_run    TEXT,
            next_run    TEXT,
            created_at  TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.commit()
    conn.close()


def get_schedules() -> list[dict]:
    init_schedule_db()
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM scan_schedules ORDER BY id").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_schedule(name: str, cidr: str, profile_id: str, schedule: str) -> int:
    """
    schedule format examples:
    - "interval:30m"   → every 30 minutes
    - "interval:1h"    → every hour
    - "interval:6h"    → every 6 hours
    - "cron:0 2 * * *" → daily at 02:00
    - "cron:0 */6 * * *" → every 6 hours
    """
    init_schedule_db()
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.execute(
        "INSERT INTO scan_schedules (name, cidr, profile_id, schedule, enabled) VALUES (?,?,?,?,1)",
        (name, cidr, profile_id, schedule)
    )
    schedule_id = cursor.lastrowid
    conn.commit()
    conn.close()
    if _scheduler and HAS_SCHEDULER:
        _register_job(schedule_id, cidr, profile_id, schedule)
    return schedule_id


def update_schedule(schedule_id: int, enabled: bool = None, name: str = None):
    conn = sqlite3.connect(str(DB_PATH))
    if enabled is not None:
        conn.execute("UPDATE scan_schedules SET enabled=? WHERE id=?", (int(enabled), schedule_id))
    if name is not None:
        conn.execute("UPDATE scan_schedules SET name=? WHERE id=?", (name, schedule_id))
    conn.commit()
    conn.close()


def delete_schedule(schedule_id: int):
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("DELETE FROM scan_schedules WHERE id=?", (schedule_id,))
    conn.commit()
    conn.close()
    if _scheduler and HAS_SCHEDULER:
        try:
            _scheduler.remove_job(f"scan_{schedule_id}")
        except Exception:
            pass


def _parse_trigger(schedule: str):
    """Parse schedule string into APScheduler trigger."""
    if schedule.startswith("interval:"):
        spec = schedule[9:]
        if spec.endswith("m"):
            return IntervalTrigger(minutes=int(spec[:-1]))
        elif spec.endswith("h"):
            return IntervalTrigger(hours=int(spec[:-1]))
        elif spec.endswith("d"):
            return IntervalTrigger(days=int(spec[:-1]))
    elif schedule.startswith("cron:"):
        cron_expr = schedule[5:]
        parts = cron_expr.split()
        if len(parts) == 5:
            return CronTrigger(
                minute=parts[0], hour=parts[1], day=parts[2],
                month=parts[3], day_of_week=parts[4]
            )
    return IntervalTrigger(hours=24)  # fallback


def _register_job(schedule_id: int, cidr: str, profile_id: str, schedule: str):
    if not _scheduler or not HAS_SCHEDULER or not _scan_callback:
        return
    try:
        trigger = _parse_trigger(schedule)
        _scheduler.add_job(
            _scan_callback,
            trigger=trigger,
            id=f"scan_{schedule_id}",
            kwargs={"cidr": cidr, "profile_id": profile_id, "schedule_id": schedule_id},
            replace_existing=True,
            misfire_grace_time=300,
        )
        # Update next_run
        job = _scheduler.get_job(f"scan_{schedule_id}")
        if job and job.next_run_time:
            conn = sqlite3.connect(str(DB_PATH))
            conn.execute("UPDATE scan_schedules SET next_run=? WHERE id=?",
                         (str(job.next_run_time), schedule_id))
            conn.commit()
            conn.close()
    except Exception as e:
        print(f"Schedule register error: {e}")


def start_scheduler(scan_cb: Callable):
    """Start the scheduler with a callback for running scans."""
    global _scheduler, _scan_callback
    if not HAS_SCHEDULER:
        return

    _scan_callback = scan_cb
    _scheduler = AsyncIOScheduler()
    _scheduler.start()

    # Register all enabled schedules
    for s in get_schedules():
        if s["enabled"]:
            _register_job(s["id"], s["cidr"], s["profile_id"], s["schedule"])


def stop_scheduler():
    global _scheduler
    if _scheduler and HAS_SCHEDULER:
        _scheduler.shutdown(wait=False)
        _scheduler = None
