"""
CERNIS PRO Alerting Module
Sends alerts via Email (SMTP) and macOS native notifications (osascript).
Alert rules stored in SQLite.
"""
import sqlite3
import smtplib
import subprocess
import json
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

from modules.db_path import DB_PATH  # noqa


# ── Data structures ───────────────────────────────────────────

@dataclass
class AlertRule:
    id: int
    name: str
    rule_type: str    # "host_down" | "new_device" | "port_change" | "cert_expiry"
    target: str       # IP, "any", or specific host
    threshold: int    # seconds for host_down, days for cert_expiry
    notify_email: bool
    notify_macos: bool
    enabled: bool
    last_triggered: float = 0.0


@dataclass
class AlertEvent:
    rule_id: int
    rule_name: str
    rule_type: str
    target: str
    message: str
    timestamp: float


# ── DB ────────────────────────────────────────────────────────

def init_alerts_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS alert_rules (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        name            TEXT,
        rule_type       TEXT,
        target          TEXT DEFAULT 'any',
        threshold       INTEGER DEFAULT 60,
        notify_email    INTEGER DEFAULT 0,
        notify_macos    INTEGER DEFAULT 1,
        enabled         INTEGER DEFAULT 1,
        last_triggered  REAL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS alert_history (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_id     INTEGER,
        rule_name   TEXT,
        rule_type   TEXT,
        target      TEXT,
        message     TEXT,
        ts          REAL,
        datetime    TEXT
    );
    """)
    conn.commit()
    conn.close()


def get_rules() -> list[dict]:
    init_alerts_db()
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM alert_rules ORDER BY id").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_rule(name: str, rule_type: str, target: str = "any",
             threshold: int = 60, notify_email: bool = False,
             notify_macos: bool = True) -> int:
    init_alerts_db()
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.execute(
        "INSERT INTO alert_rules (name, rule_type, target, threshold, notify_email, notify_macos) VALUES (?,?,?,?,?,?)",
        (name, rule_type, target, threshold, int(notify_email), int(notify_macos))
    )
    rule_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return rule_id


def update_rule(rule_id: int, **kwargs):
    conn = sqlite3.connect(str(DB_PATH))
    allowed = {"name", "enabled", "threshold", "notify_email", "notify_macos", "target"}
    parts = [f"{k}=?" for k in kwargs if k in allowed]
    vals = [v for k, v in kwargs.items() if k in allowed]
    if parts:
        conn.execute(f"UPDATE alert_rules SET {', '.join(parts)} WHERE id=?", vals + [rule_id])
        conn.commit()
    conn.close()


def delete_rule(rule_id: int):
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("DELETE FROM alert_rules WHERE id=?", (rule_id,))
    conn.commit()
    conn.close()


def get_alert_history(limit: int = 50) -> list[dict]:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM alert_history ORDER BY ts DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def _save_alert_event(evt: AlertEvent):
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute(
        "INSERT INTO alert_history (rule_id, rule_name, rule_type, target, message, ts, datetime) VALUES (?,?,?,?,?,?,?)",
        (evt.rule_id, evt.rule_name, evt.rule_type, evt.target, evt.message,
         evt.timestamp, time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(evt.timestamp)))
    )
    conn.execute("UPDATE alert_rules SET last_triggered=? WHERE id=?",
                 (evt.timestamp, evt.rule_id))
    conn.commit()
    conn.close()


# ── Notification channels ─────────────────────────────────────

def notify_macos(title: str, message: str, subtitle: str = ""):
    """Send macOS desktop notification via osascript."""
    try:
        sub = f'subtitle "{subtitle}" ' if subtitle else ""
        script = f'display notification "{message}" with title "{title}" {sub}sound name "Basso"'
        subprocess.run(["osascript", "-e", script], timeout=3, capture_output=True)
    except Exception:
        pass


def notify_email(subject: str, body: str, smtp_config: dict) -> bool:
    """Send email alert via SMTP."""
    try:
        host     = smtp_config.get("host", "")
        port     = int(smtp_config.get("port", 587))
        user     = smtp_config.get("user", "")
        password = smtp_config.get("password", "")
        to_addr  = smtp_config.get("to", "")
        from_addr = smtp_config.get("from", user)

        if not host or not to_addr:
            return False

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[CERNIS PRO] {subject}"
        msg["From"]    = from_addr
        msg["To"]      = to_addr

        # Plain text
        msg.attach(MIMEText(body, "plain"))

        # HTML
        html_body = f"""
        <div style="font-family:monospace;background:#0a0c0f;color:#e8ecf4;padding:20px;border-radius:8px;">
          <h2 style="color:#00d4ff;margin:0 0 12px">⬡ CERNIS PRO Alert</h2>
          <pre style="background:#141820;padding:12px;border-radius:4px;color:#e8ecf4">{body}</pre>
          <p style="color:#4a5a78;font-size:12px;margin-top:12px">CERNIS PRO v1.0.0 · Professional Network Scanner & Monitor</p>
        </div>
        """
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(host, port, timeout=10) as server:
            server.ehlo()
            if port in (587, 25):
                server.starttls()
            if user and password:
                server.login(user, password)
            server.sendmail(from_addr, to_addr, msg.as_string())
        return True
    except Exception as e:
        print(f"Email alert failed: {e}")
        return False


# ── Alert dispatcher ──────────────────────────────────────────

def fire_alert(rule_type: str, target: str, message: str,
               smtp_config: dict = None):
    """
    Check all enabled rules matching rule_type/target and fire notifications.
    Called from monitor.py and other modules.
    """
    init_alerts_db()
    rules = get_rules()
    now = time.time()

    for rule in rules:
        if not rule["enabled"]:
            continue
        if rule["rule_type"] != rule_type:
            continue
        if rule["target"] != "any" and rule["target"] != target:
            continue

        # Cooldown: don't fire same rule more than once per threshold seconds
        cooldown = max(rule["threshold"], 60)
        if now - rule["last_triggered"] < cooldown:
            continue

        title = f"CERNIS PRO — {rule['name']}"

        if rule["notify_macos"]:
            notify_macos(title, message, subtitle=target)

        if rule["notify_email"] and smtp_config:
            body = f"Rule: {rule['name']}\nTarget: {target}\nEvent: {message}\nTime: {time.strftime('%Y-%m-%d %H:%M:%S')}"
            notify_email(rule["name"], body, smtp_config)

        evt = AlertEvent(
            rule_id=rule["id"], rule_name=rule["name"],
            rule_type=rule_type, target=target,
            message=message, timestamp=now,
        )
        _save_alert_event(evt)
