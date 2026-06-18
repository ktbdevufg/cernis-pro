"""SQLite-Adapter fuer ``LoggingEventRepository`` (Tabelle ``monitoring_log_events``).

Persistenz der Ereignis-/Anomalie-Flanken je Logging-Aufgabe (B-I, Retention 1 Jahr),
im Stil von ``SqliteMonitorEventRepository`` / ``SqliteRttHistoryRepository``:
``@contextmanager _connect``, ``_ensure_schema`` im Konstruktor (idempotentes
``CREATE TABLE IF NOT EXISTS``), injizierter ``db_path: Path``, ``sqlite3.Row``.
EIGENE Tabelle, GETRENNT vom Live-Monitor. KEIN ``modules``-Import.

EVENT_TYPE als roher ``str`` (KEIN ``MonitorEventType``): Der Logging-Kern ist vom
Live-Monitor getrennt -- s. Port-Docstring. Die Tabellenspalte ist ``TEXT``, Muster
``monitor_events.event TEXT``; KEINE Enum-Umwandlung beim Lesen (anders als
``SqliteMonitorEventRepository``, das ``MonitorEventType(row["event"])`` hebt).

KEIN TRIM: Append-Store; die Mengenbegrenzung laeuft ueber ``delete_older_than``
(Retention), nicht ueber einen Zeilen-Cap. Index auf ``(task_id, ts)`` fuer
``range``/Retention. Halb-offenes Fenster ``[since, until)`` (s. Port-Docstring).
"""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from domain.monitoring import LoggingEventRow


class SqliteLoggingEventRepository:
    """Erfuellt das ``LoggingEventRepository``-Protocol strukturell (SQLite)."""

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
        # Append-Store + Index auf (task_id, ts). event_type als roher TEXT-Wert.
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS monitoring_log_events (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id    TEXT,
                    event_type TEXT,
                    rtt_ms     REAL,
                    ts         REAL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_monitoring_log_events_task_ts "
                "ON monitoring_log_events (task_id, ts)"
            )

    def save(self, task_id: str, event_type: str, rtt_ms: float, ts: float) -> None:
        # Reines Append (kein Trim). event_type roh als str (s. Modul-Docstring).
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO monitoring_log_events (task_id, event_type, rtt_ms, ts) "
                "VALUES (?, ?, ?, ?)",
                (task_id, event_type, rtt_ms, ts),
            )

    def range(self, task_id: str, since: float, until: float) -> list[LoggingEventRow]:
        # Halb-offenes Fenster [since, until), aufsteigend -- exakt wie LoggingRtt.range.
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT event_type, rtt_ms, ts FROM monitoring_log_events "
                "WHERE task_id = ? AND ts >= ? AND ts < ? ORDER BY ts",
                (task_id, since, until),
            ).fetchall()
        return [
            LoggingEventRow(
                event_type=row["event_type"],
                rtt_ms=row["rtt_ms"],
                ts=row["ts"],
            )
            for row in rows
        ]

    def delete_older_than(self, cutoff_ts: float) -> int:
        # Strikt aelter (ts < cutoff_ts) -- Punkt genau auf dem Cutoff bleibt.
        # Rueckgabe = geloeschte Zeilen.
        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM monitoring_log_events WHERE ts < ?", (cutoff_ts,))
            return cursor.rowcount
