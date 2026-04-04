"""
CERNIS PRO Persistent Device Database
Tracks every device seen across all scans with First/Last Seen, history.
"""
import sqlite3
import json
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from modules.db_path import DB_PATH  # noqa


def _conn():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_devices_db():
    with _conn() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS devices (
            mac          TEXT PRIMARY KEY,
            vendor       TEXT DEFAULT '',
            label        TEXT DEFAULT '',
            tags         TEXT DEFAULT '[]',
            notes        TEXT DEFAULT '',
            category     TEXT DEFAULT '',
            is_known     INTEGER DEFAULT 0,
            first_seen   TEXT DEFAULT (datetime('now')),
            last_seen    TEXT DEFAULT (datetime('now')),
            last_ip      TEXT DEFAULT '',
            times_seen   INTEGER DEFAULT 1,
            open_ports   TEXT DEFAULT '[]',
            hostname     TEXT DEFAULT '',
            os_guess     TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS device_ip_history (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            mac        TEXT,
            ip         TEXT,
            seen_at    TEXT DEFAULT (datetime('now'))
        );
        """)


def update_device_from_scan(host: dict):
    """Called after each scan for every found host. Updates or creates device entry."""
    mac = (host.get("mac") or "").upper()
    if not mac:
        return

    ip       = host.get("ip", "")
    vendor   = host.get("vendor", "")
    hostname = host.get("hostname", "")
    os_guess = host.get("os_guess", "")
    ports    = json.dumps([p["port"] for p in (host.get("ports") or [])])
    now      = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with _conn() as conn:
        existing = conn.execute("SELECT * FROM devices WHERE mac=?", (mac,)).fetchone()

        if existing:
            conn.execute("""
                UPDATE devices SET
                    last_seen=?, last_ip=?, times_seen=times_seen+1,
                    open_ports=?, hostname=CASE WHEN ?!='' THEN ? ELSE hostname END,
                    os_guess=CASE WHEN ?!='' THEN ? ELSE os_guess END,
                    vendor=CASE WHEN ?!='' THEN ? ELSE vendor END
                WHERE mac=?
            """, (now, ip, ports,
                  hostname, hostname,
                  os_guess, os_guess,
                  vendor, vendor,
                  mac))
        else:
            conn.execute("""
                INSERT INTO devices
                (mac, vendor, label, tags, notes, category, is_known,
                 first_seen, last_seen, last_ip, times_seen, open_ports, hostname, os_guess)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (mac, vendor, "", "[]", "", "", 0, now, now, ip, 1, ports, hostname, os_guess))

        # IP history — only log if IP changed
        last_ip_row = conn.execute(
            "SELECT ip FROM device_ip_history WHERE mac=? ORDER BY id DESC LIMIT 1", (mac,)
        ).fetchone()
        if not last_ip_row or last_ip_row["ip"] != ip:
            conn.execute(
                "INSERT INTO device_ip_history (mac, ip, seen_at) VALUES (?,?,?)",
                (mac, ip, now)
            )


def get_all_devices(filter_known: bool = False) -> list[dict]:
    with _conn() as conn:
        query = "SELECT * FROM devices"
        if filter_known:
            query += " WHERE is_known=1"
        query += " ORDER BY last_seen DESC"
        rows = conn.execute(query).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["tags"] = json.loads(d.get("tags") or "[]")
            d["open_ports"] = json.loads(d.get("open_ports") or "[]")
            result.append(d)
        return result


def get_device(mac: str) -> dict | None:
    with _conn() as conn:
        row = conn.execute("SELECT * FROM devices WHERE mac=?", (mac.upper(),)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["tags"] = json.loads(d.get("tags") or "[]")
        d["open_ports"] = json.loads(d.get("open_ports") or "[]")
        # IP history
        hist = conn.execute(
            "SELECT ip, seen_at FROM device_ip_history WHERE mac=? ORDER BY id DESC LIMIT 20",
            (mac.upper(),)
        ).fetchall()
        d["ip_history"] = [dict(h) for h in hist]
        return d


def update_device_meta(mac: str, label: str = None, tags: list = None,
                        notes: str = None, category: str = None, is_known: bool = None):
    with _conn() as conn:
        parts, params = [], []
        if label    is not None: parts.append("label=?");    params.append(label)
        if tags     is not None: parts.append("tags=?");     params.append(json.dumps(tags))
        if notes    is not None: parts.append("notes=?");    params.append(notes)
        if category is not None: parts.append("category=?"); params.append(category)
        if is_known is not None: parts.append("is_known=?"); params.append(int(is_known))
        if not parts:
            return
        params.append(mac.upper())
        conn.execute(f"UPDATE devices SET {', '.join(parts)} WHERE mac=?", params)


def get_device_stats() -> dict:
    with _conn() as conn:
        total   = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        known   = conn.execute("SELECT COUNT(*) FROM devices WHERE is_known=1").fetchone()[0]
        unknown = conn.execute("SELECT COUNT(*) FROM devices WHERE is_known=0").fetchone()[0]
        # Active in last 24h
        active  = conn.execute(
            "SELECT COUNT(*) FROM devices WHERE last_seen > datetime('now', '-1 day')"
        ).fetchone()[0]
        return {"total": total, "known": known, "unknown": unknown, "active_24h": active}
