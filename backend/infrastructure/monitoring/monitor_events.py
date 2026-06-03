"""SQLite-Adapter fuer den Port ``MonitorEventRepository`` (Tabelle ``monitor_events``).

Basiert auf ``modules/monitor.py`` (``_save_event`` / ``get_monitor_events`` /
``_init_monitor_db``), im Stil von ``SqliteScanHistoryRepository``. KEIN
``modules``-Import (eigenes Schema).

Schema EXAKT wie der Altcode (``_init_monitor_db``): ``id / target_id / label /
event / rtt_ms / ts / datetime``. Die ``datetime``-Spalte ist eine VORFORMATIERTE
Text-Spalte -- der Altcode schreibt sie beim Insert mit ``"%Y-%m-%d %H:%M:%S"``.

FORMAT-DIVERGENZ-NAHT (M.2-Befund, hier am Adapter-Rand): Derselbe Event-Timestamp
erscheint im Altcode in ZWEI Formaten -- ``"%Y-%m-%d %H:%M:%S"`` in der DB-Spalte
(hier) und ``"%H:%M:%S"`` im WS-Frame (M.9). Die Domaene (``MonitorEvent``) haelt
nur den rohen ``timestamp: float``; jeder Rand formatiert selbst. Dieser Adapter
reproduziert das DB-Format charakterisierungstreu -- er vereinheitlicht NICHT (das
ist eine bewusste spaetere Entscheidung, M.2-Befund).

Reihenfolge (charakterisierungstreu, M.3-Port + M.1): ``recent`` liefert die Events
ABSTEIGEND (neueste zuerst) -- der Altcode ``get_monitor_events`` selektiert
``ORDER BY ts DESC``.
"""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from domain.monitoring import MonitorEvent, MonitorEventType


class SqliteMonitorEventRepository:
    """Erfuellt das ``MonitorEventRepository``-Protocol strukturell (SQLite)."""

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
        # Schema exakt wie der Altcode (_init_monitor_db): monitor_events mit
        # vorformatierter datetime-Text-Spalte.
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS monitor_events (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id TEXT,
                    label     TEXT,
                    event     TEXT,
                    rtt_ms    REAL,
                    ts        REAL,
                    datetime  TEXT
                )
                """
            )

    def save(self, event: MonitorEvent) -> None:
        # datetime-Spalte am Adapter-Rand formatiert (Altcode-Format, s. Docstring).
        formatted = datetime.fromtimestamp(event.timestamp).strftime("%Y-%m-%d %H:%M:%S")
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO monitor_events (target_id, label, event, rtt_ms, ts, datetime) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    event.target_id,
                    event.label,
                    str(event.event),  # StrEnum -> Altcode-String ("up"/"down"/...)
                    event.rtt_ms,
                    event.timestamp,
                    formatted,
                ),
            )

    def recent(self, limit: int) -> list[MonitorEvent]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT target_id, label, event, rtt_ms, ts FROM monitor_events "
                "ORDER BY ts DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            MonitorEvent(
                target_id=row["target_id"],
                label=row["label"],
                event=MonitorEventType(row["event"]),  # str -> StrEnum (Round-trip)
                rtt_ms=row["rtt_ms"],
                timestamp=row["ts"],
            )
            for row in rows
        ]
