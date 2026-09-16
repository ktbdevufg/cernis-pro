"""SQLite-Adapter fuer den Port ``ArpGuardRepository`` (security-Domaene).

Reine Struktur-Migration der Persistenz aus ``modules/arp_guard.py`` (``_init_arp_db`` /
``_load_baseline`` / ``_save_baseline`` / ``_save_alert`` / ``get_arp_alerts`` /
``get_arp_baseline`` / ``clear_baseline`` / ``_clear_alerts``) -- AS-IS,
charakterisierungstreu (SEC.1), KEINE Heilung. Im Stil von
``SqliteScanHistoryRepository`` / ``SqliteDeviceRepository``.

* Schema EXAKT wie der Bestand (PRAGMA-Vertrag gegen das echte ``_init_arp_db``, SEC.4-
  Test): ``arp_baseline`` (ip PK / mac / vendor / first_seen REAL / last_seen REAL) +
  ``arp_alerts`` (id PK AUTOINCREMENT / alert_type / ip / old_mac / new_mac /
  old_vendor / new_vendor / severity / message / ts REAL / datetime TEXT).
* Zeitspalten am RAND (NICHT im Domaenenmodell, SEC.2): ``first_seen``/``last_seen``
  epoch-float; ``ts`` epoch-float + ``datetime`` ISO-Text -- beide gesetzt
  (Altcode-Doppelmuster, wie alert_history).
* ``save_baseline_entry``: INSERT OR REPLACE auf ``ip``; ``first_seen`` bleibt beim
  ersten Sehen erhalten (Altcode ``_save_baseline``: liest existierendes first_seen,
  sonst now), ``last_seen`` = now.
* KEINE Momentaufnahme-Logik hier: ``clear_alerts`` ist nur die Operation; der SEC.5-
  Use-Case ruft sie vor jedem Scan (E.1 lebt im Use-Case).

KEIN ``modules``-Import (DF2: arp-Persistenz wird eigenstaendig in SQLite gehalten, wie
monitor_events/rtt_history) -> kein ADR-0007 fuer security.
"""

import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from domain.security import ArpAlert, ArpEntry
from ports.security import ArpAlertRecord, ArpBaselineRecord


class SqliteArpGuardRepository:
    """Erfuellt das ``ArpGuardRepository``-Protocol strukturell (SQLite)."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._ensure_schema()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _ensure_schema(self) -> None:
        # Schema deckungsgleich Altcode modules/arp_guard._init_arp_db (PRAGMA-Vertrag).
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(
                """
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
                """
            )

    # ── Baseline ────────────────────────────────────────────────────────────

    def load_baseline(self) -> list[ArpEntry]:
        # ZEITFREI fuer RunArpScan/Erkennung (SEC.2): nur ip/mac/vendor.
        with self._connect() as conn:
            rows = conn.execute("SELECT ip, mac, vendor FROM arp_baseline").fetchall()
        return [ArpEntry(ip=r["ip"], mac=r["mac"], vendor=r["vendor"] or "") for r in rows]

    def load_baseline_records(self) -> list[ArpBaselineRecord]:
        # Lese-/Wire-Pfad MIT Zeit: first_seen/last_seen aus den DB-Spalten. ORDER BY ip
        # (Altcode get_arp_baseline).
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT ip, mac, vendor, first_seen, last_seen FROM arp_baseline ORDER BY ip"
            ).fetchall()
        return [
            ArpBaselineRecord(
                ip=r["ip"],
                mac=r["mac"],
                vendor=r["vendor"] or "",
                first_seen=r["first_seen"],
                last_seen=r["last_seen"],
            )
            for r in rows
        ]

    def save_baseline_entry(self, entry: ArpEntry) -> None:
        now = time.time()
        with self._connect() as conn:
            # first_seen beim ersten Sehen erhalten (Altcode _save_baseline-Semantik).
            existing = conn.execute(
                "SELECT first_seen FROM arp_baseline WHERE ip=?", (entry.ip,)
            ).fetchone()
            first = existing[0] if existing else now
            conn.execute(
                """
                INSERT OR REPLACE INTO arp_baseline (ip, mac, vendor, first_seen, last_seen)
                VALUES (?,?,?,?,?)
                """,
                (entry.ip, entry.mac, entry.vendor, first, now),
            )

    def clear_baseline(self) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM arp_baseline")

    # ── Alerts ──────────────────────────────────────────────────────────────

    def save_alert(self, alert: ArpAlert) -> None:
        now = time.time()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO arp_alerts
                (alert_type, ip, old_mac, new_mac, old_vendor, new_vendor,
                 severity, message, ts, datetime)
                VALUES (?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    alert.alert_type,
                    alert.ip,
                    alert.old_mac,
                    alert.new_mac,
                    alert.old_vendor,
                    alert.new_vendor,
                    alert.severity,
                    alert.message,
                    now,
                    datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S"),
                ),
            )

    def recent_alerts(self, limit: int) -> list[ArpAlertRecord]:
        # Lese-/Wire-Pfad MIT Zeit: ts + datetime aus den DB-Spalten (das Frontend
        # rendert datetime). KEIN id (bewusste Streichung, s. ArpAlertRecord-Docstring).
        # ORDER BY ts DESC, id DESC (id nur als deterministischer Tiebreaker bei
        # gleichem ts, nicht im Record).
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM arp_alerts ORDER BY ts DESC, id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [
            ArpAlertRecord(
                alert_type=r["alert_type"],
                ip=r["ip"],
                old_mac=r["old_mac"] or "",
                new_mac=r["new_mac"] or "",
                old_vendor=r["old_vendor"] or "",
                new_vendor=r["new_vendor"] or "",
                severity=r["severity"],
                message=r["message"] or "",
                ts=r["ts"],
                datetime=r["datetime"] or "",
            )
            for r in rows
        ]

    def clear_alerts(self) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM arp_alerts")
