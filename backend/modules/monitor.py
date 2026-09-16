"""
CERNIS PRO Live Connectivity Monitor
Runs as background task, pushes events via WebSocket broadcast.
Tracks WLAN / LAN / Internet independently using interface-bound pings.
"""
import asyncio
import subprocess
import platform
import os
import re
import time
import sqlite3
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path

from modules.db_path import DB_PATH  # noqa
from infrastructure.osascript_escape import escape_applescript_literal

# ── Data structures ───────────────────────────────────────────

@dataclass
class MonitorTarget:
    id: str           # e.g. "wlan", "lan", "internet", or custom ip
    label: str        # display name
    host: str         # IP to ping
    interface: str    # e.g. "en0", "" for default
    enabled: bool     = True

@dataclass
class PingResult:
    target_id: str
    host: str
    alive: bool
    rtt_ms: float     = -1.0
    loss_pct: float   = 0.0
    timestamp: float  = field(default_factory=time.time)

@dataclass
class MonitorEvent:
    target_id: str
    label: str
    event: str        # "up" | "down" | "degraded"
    rtt_ms: float
    timestamp: float  = field(default_factory=time.time)

    def to_dict(self):
        d = asdict(self)
        d["datetime"] = datetime.fromtimestamp(self.timestamp).strftime("%H:%M:%S")
        return d


# ── DB helpers ────────────────────────────────────────────────

def _init_monitor_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS monitor_events (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id TEXT,
            label     TEXT,
            event     TEXT,
            rtt_ms    REAL,
            ts        REAL,
            datetime  TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS rtt_history (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id TEXT,
            rtt_ms    REAL,
            loss_pct  REAL,
            ts        REAL
        )
    """)
    conn.commit()
    conn.close()


def _save_event(evt: MonitorEvent):
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute(
        "INSERT INTO monitor_events (target_id, label, event, rtt_ms, ts, datetime) VALUES (?,?,?,?,?,?)",
        (evt.target_id, evt.label, evt.event, evt.rtt_ms, evt.timestamp,
         datetime.fromtimestamp(evt.timestamp).strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    conn.close()


def _save_rtt(result: PingResult):
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute(
        "INSERT INTO rtt_history (target_id, rtt_ms, loss_pct, ts) VALUES (?,?,?,?)",
        (result.target_id, result.rtt_ms, result.loss_pct, result.timestamp)
    )
    # Keep only last 1000 samples per target
    conn.execute("""
        DELETE FROM rtt_history WHERE id IN (
            SELECT id FROM rtt_history WHERE target_id=?
            ORDER BY ts DESC LIMIT -1 OFFSET 1000
        )
    """, (result.target_id,))
    conn.commit()
    conn.close()


def get_monitor_events(limit: int = 100) -> list[dict]:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM monitor_events ORDER BY ts DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_rtt_history(target_id: str, limit: int = 120) -> list[dict]:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT rtt_ms, loss_pct, ts FROM rtt_history WHERE target_id=? ORDER BY ts DESC LIMIT ?",
        (target_id, limit)
    ).fetchall()
    conn.close()
    return [dict(r) for r in reversed(rows)]


# ── Ping logic ────────────────────────────────────────────────

async def _ping_once(host: str, interface: str = "", timeout: float = 2.0) -> tuple[bool, float]:
    """Returns (alive, rtt_ms). Uses interface binding on macOS."""
    system = platform.system()
    if system == "Windows":
        # Windows: nativer ICMP-Echo statt ping.exe. Lokalisierte ping.exe-Ausgabe
        # (deutsch Zeit<, englisch time=) laesst jeden Regex still scheitern; die
        # native iphlpapi liefert Status/RoundTripTime als Zahl. Der Import steht
        # im Windows-Zweig (auf Nicht-Windows nie erreicht).
        from infrastructure.icmp_windows import icmp_echo

        return await icmp_echo(host, timeout)

    if system == "Darwin":
        cmd = ["ping", "-c", "1", "-W", str(int(timeout * 1000)), "-t", "2"]
        if interface:
            cmd += ["-b", interface]
        cmd += ["--", host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(timeout)), "--", host]

    try:
        # ping wird mit erzwungener C-Locale gestartet, weil lokalisierte
        # ping-Ausgaben (z.B. Zeit= statt time= auf Fedora mit deutscher
        # Locale) das RTT-Parsing sonst scheitern lassen und den Sentinel
        # -1.0 liefern, obwohl der Host erreichbar ist.
        ping_env = {**os.environ, "LC_ALL": "C", "LANG": "C"}
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            env=ping_env,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 1)
        output = stdout.decode("utf-8", errors="replace")
        alive = proc.returncode == 0
        rtt = -1.0
        m = re.search(r"(?:time[=<]([\d.]+)\s*ms|Durchschn.*?=\s*([\d]+)ms)", output, re.I)
        if m:
            rtt = float(m.group(1) or m.group(2) or -1)
        return alive, rtt
    except Exception:
        return False, -1.0


async def _ping_burst(host: str, interface: str = "", count: int = 3) -> PingResult:
    """Send count pings, return aggregated result with loss %."""
    results = []
    for _ in range(count):
        alive, rtt = await _ping_once(host, interface)
        results.append((alive, rtt))
        await asyncio.sleep(0.2)

    alive_count = sum(1 for a, _ in results if a)
    # 0.0 ist eine gueltige RTT (Windows-DWORD RoundTripTime rundet sub-ms auf 0);
    # nur -1.0 ist der Sentinel. Daher r >= 0 statt r > 0, sonst wird eine echte
    # 0.0-Messung faelschlich verworfen und die Aggregation faellt auf -1.0 zurueck.
    rtts = [r for _, r in results if r >= 0]
    loss_pct = (1 - alive_count / count) * 100
    avg_rtt = sum(rtts) / len(rtts) if rtts else -1.0
    return PingResult(
        target_id="",
        host=host,
        alive=alive_count > 0,
        rtt_ms=round(avg_rtt, 2),
        loss_pct=round(loss_pct, 1),
    )


# ── macOS notification ────────────────────────────────────────

def _notify_macos(title: str, message: str):
    try:
        script = f'display notification "{escape_applescript_literal(message)}" with title "{escape_applescript_literal(title)}" sound name "Basso"'
        subprocess.run(["osascript", "-e", script], timeout=3, capture_output=True)
    except Exception:
        pass


# ── Monitor state ─────────────────────────────────────────────

_status: dict[str, bool | None] = {}   # target_id → last known alive state
_subscribers: list = []                 # WebSocket connections to notify


def subscribe(ws):
    _subscribers.append(ws)

def unsubscribe(ws):
    if ws in _subscribers:
        _subscribers.remove(ws)


async def _broadcast(msg: dict):
    dead = []
    for ws in list(_subscribers):
        try:
            await ws.send_json(msg)
        except Exception:
            dead.append(ws)
    for ws in dead:
        unsubscribe(ws)


# ── Main monitor loop ─────────────────────────────────────────

_running = False
_targets: list[MonitorTarget] = []
_interval: int = 5   # seconds between checks


def configure(targets: list[MonitorTarget], interval: int = 5):
    global _targets, _interval
    _targets = targets
    _interval = interval


async def run_monitor():
    global _running
    _running = True
    _init_monitor_db()

    while _running:
        for target in _targets:
            if not target.enabled:
                continue

            result = await _ping_burst(target.host, target.interface, count=3)
            result.target_id = target.id

            _save_rtt(result)

            prev = _status.get(target.id)
            now = result.alive

            # Determine event
            event_type = None
            if prev is None:
                event_type = "up" if now else "down"
            elif prev and not now:
                event_type = "down"
                _notify_macos("CERNIS PRO — Network Alert",
                              f"{target.label} is DOWN")
            elif not prev and now:
                event_type = "up"
                _notify_macos("CERNIS PRO — Network Alert",
                              f"{target.label} is back UP")
            elif now and result.loss_pct > 30:
                event_type = "degraded"

            _status[target.id] = now

            if event_type:
                evt = MonitorEvent(
                    target_id=target.id,
                    label=target.label,
                    event=event_type,
                    rtt_ms=result.rtt_ms,
                )
                _save_event(evt)

            # Broadcast RTT update
            await _broadcast({
                "type": "monitor_update",
                "target_id": target.id,
                "label": target.label,
                "alive": result.alive,
                "rtt_ms": result.rtt_ms,
                "loss_pct": result.loss_pct,
                "event": event_type,
                "ts": result.timestamp,
            })

        await asyncio.sleep(_interval)


def stop_monitor():
    global _running
    _running = False


def get_current_status() -> dict:
    return {
        tid: {"alive": alive, "label": next((t.label for t in _targets if t.id == tid), tid)}
        for tid, alive in _status.items()
    }
