"""SQLite-Adapter fuer ``OutboundRecordingRepository`` (Tabelle ``outbound_log_recordings``).

Persistenz der Aussenkontakte-Aufzeichnungs-DEFINITIONEN, im Stil von
``SqliteLoggingTaskRepository`` / ``SqliteRttHistoryRepository``: ``@contextmanager
_connect`` (``sqlite3.Row``, ``with conn``, garantiertes ``close``), ``_ensure_schema``
im Konstruktor (idempotentes ``CREATE TABLE IF NOT EXISTS`` + ``mkdir(parents=True,
exist_ok=True)``), injizierter ``db_path: Path``. KEIN ``modules``-Import; die
``db_path``-Verdrahtung kommt spaeter (E3/E-Root), hier NICHT.

UPSERT (kein reines Append): Der ``state`` einer Aufzeichnung wandert ueber ihre
Lebenszeit -- ``save`` ist darum ``INSERT OR REPLACE`` ueber den PRIMARY KEY ``id``.

ENUM-ROUND-TRIP: Die drei Enums (``mode``/``depth``/``state``) werden als ihr
``str``-Wert gespeichert (``StrEnum`` -> roher String) und beim Lesen via
``RecordingMode(...)`` / ``DetailDepth(...)`` / ``RecordingState(...)`` zurueck in die
Domaenen-Enums gehoben -- Muster ``SqliteLoggingTaskRepository._row_to_task``.
``effective_start``/``max_duration_s`` sind nullable (sqlite gibt ``None`` zurueck).
"""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from domain.outbound_log import (
    DetailDepth,
    OutboundRecording,
    RecordingMode,
    RecordingState,
)


class SqliteOutboundRecordingRepository:
    """Erfuellt das ``OutboundRecordingRepository``-Protocol strukturell (SQLite)."""

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
        # Idempotentes CREATE -- id als PRIMARY KEY traegt den Upsert (INSERT OR
        # REPLACE). Enums liegen als ihr str-Wert (TEXT), effective_start/
        # max_duration_s nullable (s. Domaene: None erlaubt).
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS outbound_log_recordings (
                    id              TEXT PRIMARY KEY,
                    label           TEXT,
                    purpose         TEXT,
                    mode            TEXT,
                    depth           TEXT,
                    state           TEXT,
                    interval_s      INTEGER,
                    created_at      REAL,
                    effective_start REAL,
                    max_duration_s  INTEGER
                )
                """
            )

    def save(self, recording: OutboundRecording) -> None:
        # INSERT OR REPLACE -> Upsert ueber PRIMARY KEY id (neuer state bei jedem
        # Lebenszyklus-Uebergang). Enums als ihr str-Wert (StrEnum -> str).
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO outbound_log_recordings (
                    id, label, purpose, mode, depth, state, interval_s,
                    created_at, effective_start, max_duration_s
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    recording.id,
                    recording.label,
                    recording.purpose,
                    str(recording.mode),
                    str(recording.depth),
                    str(recording.state),
                    recording.interval_s,
                    recording.created_at,
                    recording.effective_start,
                    recording.max_duration_s,
                ),
            )

    def get(self, recording_id: str) -> OutboundRecording | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, label, purpose, mode, depth, state, interval_s, "
                "created_at, effective_start, max_duration_s "
                "FROM outbound_log_recordings WHERE id = ?",
                (recording_id,),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_recording(row)

    def list_all(self) -> list[OutboundRecording]:
        # ORDER BY created_at (aufsteigend) -- s. Port-Docstring.
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, label, purpose, mode, depth, state, interval_s, "
                "created_at, effective_start, max_duration_s "
                "FROM outbound_log_recordings ORDER BY created_at"
            ).fetchall()
        return [self._row_to_recording(row) for row in rows]

    def delete(self, recording_id: str) -> None:
        # Idempotent: unbekannte id -> kein Fehler (DELETE betrifft 0 Zeilen).
        # Nur die Definition -- die Messdaten (Detail/Aggregat) liegen in eigenen Repos.
        with self._connect() as conn:
            conn.execute("DELETE FROM outbound_log_recordings WHERE id = ?", (recording_id,))

    def clear_all(self) -> None:
        # Leert alle Definitionen (nur die eigene Tabelle outbound_log_recordings).
        with self._connect() as conn:
            conn.execute("DELETE FROM outbound_log_recordings")

    @staticmethod
    def _row_to_recording(row: sqlite3.Row) -> OutboundRecording:
        # Enum-Round-trip: gespeicherte Strings zurueck in die Domaenen-Enums
        # (Muster SqliteLoggingTaskRepository._row_to_task).
        return OutboundRecording(
            id=row["id"],
            label=row["label"],
            purpose=row["purpose"],
            mode=RecordingMode(row["mode"]),
            depth=DetailDepth(row["depth"]),
            state=RecordingState(row["state"]),
            interval_s=row["interval_s"],
            created_at=row["created_at"],
            effective_start=row["effective_start"],
            max_duration_s=row["max_duration_s"],
        )
