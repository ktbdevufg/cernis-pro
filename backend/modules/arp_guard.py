"""
CERNIS PRO ARP Spoofing / Rogue Device Detection
Watches ARP table for MAC-IP conflicts and unexpected changes.
"""
import asyncio
import sqlite3
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path

from modules.discovery import get_arp_table
from modules.vendor import lookup_vendor

from modules.db_path import DB_PATH  # noqa


@dataclass
class ArpEntry:
    ip: str
    mac: str
    vendor: str = ""
    first_seen: float = 0.0
    last_seen: float = 0.0


@dataclass
class ArpAlert:
    alert_type: str    # "mac_changed" | "ip_conflict" | "new_device"
    ip: str
    old_mac: str
    new_mac: str
    old_vendor: str
    new_vendor: str
    severity: str      # "high" | "medium" | "low"
    timestamp: float = 0.0
    message: str = ""

    def to_dict(self):
        d = asdict(self)
        d["datetime"] = datetime.fromtimestamp(self.timestamp or time.time()).strftime("%H:%M:%S")
        return d


def _init_arp_db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS arp_baseline (
            ip         TEXT PRIMARY KEY,
            mac        TEXT,
            vendor     TEXT,
            first_seen REAL,
            last_seen  REAL
        );
        CREATE TABLE IF NOT EXISTS arp_alerts (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT,
            ip         TEXT,
            old_mac    TEXT,
            new_mac    TEXT,
            old_vendor TEXT,
            new_vendor TEXT,
            severity   TEXT,
            message    TEXT,
            ts         REAL,
            datetime   TEXT
        );
    """)
    conn.commit()
    conn.close()


def _load_baseline() -> dict[str, ArpEntry]:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM arp_baseline").fetchall()
    conn.close()
    return {r["ip"]: ArpEntry(**dict(r)) for r in rows}


def _save_baseline(ip: str, mac: str, vendor: str):
    now = time.time()
    conn = sqlite3.connect(str(DB_PATH))
    existing = conn.execute("SELECT first_seen FROM arp_baseline WHERE ip=?", (ip,)).fetchone()
    first = existing[0] if existing else now
    conn.execute("""
        INSERT OR REPLACE INTO arp_baseline (ip, mac, vendor, first_seen, last_seen)
        VALUES (?,?,?,?,?)
    """, (ip, mac, vendor, first, now))
    conn.commit()
    conn.close()


def _save_alert(alert: ArpAlert):
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        INSERT INTO arp_alerts
        (alert_type, ip, old_mac, new_mac, old_vendor, new_vendor, severity, message, ts, datetime)
        VALUES (?,?,?,?,?,?,?,?,?,?)
    """, (
        alert.alert_type, alert.ip, alert.old_mac, alert.new_mac,
        alert.old_vendor, alert.new_vendor, alert.severity, alert.message,
        alert.timestamp,
        datetime.fromtimestamp(alert.timestamp).strftime("%Y-%m-%d %H:%M:%S")
    ))
    conn.commit()
    conn.close()


def get_arp_alerts(limit: int = 50) -> list[dict]:
    _init_arp_db()
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM arp_alerts ORDER BY ts DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_arp_baseline() -> list[dict]:
    _init_arp_db()
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM arp_baseline ORDER BY ip").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def clear_baseline():
    _init_arp_db()
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("DELETE FROM arp_baseline")
    conn.commit()
    conn.close()


def _scan_arp_sync() -> list[ArpAlert]:
    """Synchronous ARP scan logic — run via asyncio.to_thread()."""
    _init_arp_db()
    baseline = _load_baseline()
    current = get_arp_table()  # {ip: mac}
    alerts = []
    now = time.time()

    # Check IP conflicts: multiple IPs with same MAC
    mac_to_ips: dict[str, list[str]] = {}
    for ip, mac in current.items():
        mac_upper = mac.upper()
        mac_to_ips.setdefault(mac_upper, []).append(ip)

    for mac, ips in mac_to_ips.items():
        if len(ips) > 1:
            vendor = lookup_vendor(mac)
            alert = ArpAlert(
                alert_type="ip_conflict",
                ip=", ".join(ips),
                old_mac="", new_mac=mac,
                old_vendor="", new_vendor=vendor,
                severity="high",
                timestamp=now,
                message=f"MAC {mac} ({vendor}) appears on multiple IPs: {', '.join(ips)}"
            )
            alerts.append(alert)
            _save_alert(alert)

    # Check for MAC changes per IP
    for ip, mac in current.items():
        mac_upper = mac.upper()
        vendor = lookup_vendor(mac_upper)

        if ip in baseline:
            known_mac = baseline[ip].mac.upper()
            if known_mac != mac_upper:
                # MAC changed — potential ARP spoofing
                old_vendor = baseline[ip].vendor
                severity = "high" if old_vendor and vendor != old_vendor else "medium"
                alert = ArpAlert(
                    alert_type="mac_changed",
                    ip=ip,
                    old_mac=baseline[ip].mac,
                    new_mac=mac,
                    old_vendor=old_vendor,
                    new_vendor=vendor,
                    severity=severity,
                    timestamp=now,
                    message=f"IP {ip}: MAC changed from {baseline[ip].mac} ({old_vendor}) to {mac} ({vendor})"
                )
                alerts.append(alert)
                _save_alert(alert)
            _save_baseline(ip, mac_upper, vendor)
        else:
            # New device — just log to baseline
            _save_baseline(ip, mac_upper, vendor)

    return alerts


async def scan_arp_once() -> list[ArpAlert]:
    """Scan current ARP table, compare with baseline, return alerts."""
    return await asyncio.to_thread(_scan_arp_sync)
