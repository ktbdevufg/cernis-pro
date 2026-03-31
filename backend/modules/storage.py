"""Persistent settings storage via SQLite."""
import sqlite3
import json
import os
from pathlib import Path

from modules.db_path import DB_PATH  # noqa


def _get_conn():
    Path(os.path.dirname(DB_PATH)).mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(os.path.abspath(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _get_conn() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS known_devices (
            mac         TEXT PRIMARY KEY,
            label       TEXT DEFAULT '',
            tags        TEXT DEFAULT '[]',
            notes       TEXT DEFAULT '',
            is_known    INTEGER DEFAULT 1,
            first_seen  TEXT DEFAULT (datetime('now')),
            last_seen   TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS scan_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scanned_at  TEXT DEFAULT (datetime('now')),
            cidr        TEXT,
            host_count  INTEGER,
            result_json TEXT
        );
        """)


# ── Generic Settings ──────────────────────────────────────────

def get_setting(key: str, default=None):
    with _get_conn() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        if row:
            try:
                return json.loads(row["value"])
            except Exception:
                return row["value"]
        return default


def set_setting(key: str, value):
    with _get_conn() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
            (key, json.dumps(value))
        )


def get_all_settings() -> dict:
    with _get_conn() as conn:
        rows = conn.execute("SELECT key, value FROM settings").fetchall()
        return {r["key"]: json.loads(r["value"]) for r in rows}


# ── Known Devices ─────────────────────────────────────────────

def get_known_devices() -> list[dict]:
    with _get_conn() as conn:
        rows = conn.execute("SELECT * FROM known_devices").fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["tags"] = json.loads(d["tags"] or "[]")
            result.append(d)
        return result


def upsert_device(mac: str, label: str = None, tags: list = None,
                  notes: str = None, is_known: bool = None):
    with _get_conn() as conn:
        existing = conn.execute(
            "SELECT * FROM known_devices WHERE mac=?", (mac,)
        ).fetchone()

        if existing:
            updates = ["last_seen = datetime('now')"]
            params = []
            if label is not None:
                updates.append("label = ?"); params.append(label)
            if tags is not None:
                updates.append("tags = ?"); params.append(json.dumps(tags))
            if notes is not None:
                updates.append("notes = ?"); params.append(notes)
            if is_known is not None:
                updates.append("is_known = ?"); params.append(int(is_known))
            params.append(mac)
            conn.execute(f"UPDATE known_devices SET {', '.join(updates)} WHERE mac=?", params)
        else:
            conn.execute(
                """INSERT INTO known_devices (mac, label, tags, notes, is_known)
                   VALUES (?, ?, ?, ?, ?)""",
                (mac, label or "", json.dumps(tags or []), notes or "", int(is_known if is_known is not None else True))
            )


def delete_device(mac: str):
    with _get_conn() as conn:
        conn.execute("DELETE FROM known_devices WHERE mac=?", (mac,))


# ── Scan History ──────────────────────────────────────────────

def save_scan(cidr: str, hosts: list):
    with _get_conn() as conn:
        conn.execute(
            "INSERT INTO scan_history (cidr, host_count, result_json) VALUES (?, ?, ?)",
            (cidr, len(hosts), json.dumps(hosts))
        )


def get_scan_history(limit: int = 20) -> list[dict]:
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT id, scanned_at, cidr, host_count FROM scan_history ORDER BY id DESC LIMIT ?",
            (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_scan_by_id(scan_id: int) -> dict | None:
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM scan_history WHERE id=?", (scan_id,)
        ).fetchone()
        if row:
            d = dict(row)
            d["hosts"] = json.loads(d["result_json"] or "[]")
            return d
        return None
