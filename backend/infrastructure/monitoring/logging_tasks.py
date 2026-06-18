"""SQLite-Adapter fuer ``LoggingTaskRepository`` (Tabelle ``monitoring_log_tasks``).

Persistenz der opt-in Logging-Aufgaben-DEFINITIONEN (B-I), im Stil von
``SqliteRttHistoryRepository``: ``@contextmanager _connect`` mit Transaktion +
garantiertem close, ``_ensure_schema`` im Konstruktor (idempotentes ``CREATE TABLE
IF NOT EXISTS``), injizierter ``db_path: Path``, ``sqlite3.Row``. EIGENE Tabelle,
GETRENNT vom fluechtigen Live-Monitor (``rtt_history``/``monitor_events`` bleiben
unberuehrt). KEIN ``modules``-Import.

UPSERT (kein reines Append): Der ``state`` einer Aufgabe wandert ueber ihre
Lebenszeit -- ``save`` ist darum ``INSERT OR REPLACE`` ueber den PRIMARY KEY ``id``.

ENUM-ROUND-TRIP: Die drei Klassifikations-Enums werden als ihr ``str``-Wert
gespeichert (``StrEnum`` -> roher String) und beim Lesen via ``CaptureMode(...)`` /
``OperationMode(...)`` / ``TaskState(...)`` zurueck in die Domaenen-Enums gehoben --
Muster wie ``SqliteMonitorEventRepository`` (``MonitorEventType(row[...])``).

DB-PFAD: Der Konstruktor nimmt einfach ``db_path: Path`` (Muster
``SqliteRttHistoryRepository``). Die ``get_db_path``-Verdrahtung macht Schritt 3 --
hier NICHT.
"""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from domain.monitoring import (
    CaptureMode,
    LatencyThreshold,
    LoggingTask,
    OperationMode,
    TaskState,
    ThresholdCondition,
)


class SqliteLoggingTaskRepository:
    """Erfuellt das ``LoggingTaskRepository``-Protocol strukturell (SQLite)."""

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
        # REPLACE). Enums liegen als ihr str-Wert (TEXT), die Zeit-/Dauer-Felder
        # nullable (modus-abhaengig: planned_* nur SCHEDULED, max_duration_s nur
        # IMMEDIATE -- Muster LoggingTask).
        #
        # SCHEMA-GUARD fuer effective_start (B-II, ADR 0033): CREATE TABLE bleibt
        # UNVERAENDERT (eine in B-I angelegte Tabelle ist dort ein No-Op -> die neue
        # Spalte fehlte weiter). Darum nach dem CREATE per PRAGMA table_info pruefen
        # und bei Bedarf via ALTER TABLE ADD COLUMN nachruesten -- EXAKT das Muster, mit
        # dem SqliteRttHistoryRepository die alive-Spalte nachruestet. Alt-Zeilen ohne
        # die Spalte bekommen NULL (-> effective_start=None), was fachlich korrekt ist:
        # eine vor B-II angelegte Aufgabe hat keinen persistierten effektiven Start.
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS monitoring_log_tasks (
                    id             TEXT PRIMARY KEY,
                    target_id      TEXT,
                    label          TEXT,
                    purpose        TEXT,
                    capture_mode   TEXT,
                    operation_mode TEXT,
                    state          TEXT,
                    planned_start  REAL,
                    planned_end    REAL,
                    max_duration_s INTEGER,
                    created_at     REAL
                )
                """
            )
            cols = {row["name"] for row in conn.execute("PRAGMA table_info(monitoring_log_tasks)")}
            if "effective_start" not in cols:
                # Alt-Tabelle (B-I) -> Spalte nachruesten (Default NULL = None).
                conn.execute("ALTER TABLE monitoring_log_tasks ADD COLUMN effective_start REAL")
            if "interval_s" not in cols:
                # Schema-Guard fuer interval_s (C-2, exakt wie effective_start): CREATE
                # bleibt unveraendert, eine vor C-2 angelegte Tabelle bekommt die Spalte
                # per ALTER nachgeruestet. ABWEICHUNG zu effective_start: hier DEFAULT 5
                # (statt NULL), denn das Feld ist NICHT nullable (interval_s: int = 5) --
                # Bestandszeilen sollen das heutige dichte Verhalten (5 s) tragen, nicht
                # NULL (das ``_row_to_task`` nicht in ein ``int`` heben koennte).
                conn.execute(
                    "ALTER TABLE monitoring_log_tasks ADD COLUMN interval_s INTEGER DEFAULT 5"
                )
            # SCHEMA-GUARD fuer den Schwellwert (Schnitt 2): EIGENE Tabelle waere
            # Overkill -- eine Aufgabe traegt genau EINEN Schwellwert (1:1), darum fuenf
            # zusaetzliche Spalten in monitoring_log_tasks, je per ALTER nachgeruestet
            # (exakt das effective_start/interval_s-Muster). ABWEICHUNG zu interval_s:
            # hier KEIN Default (also NULL), denn der GANZE Schwellwert ist optional --
            # eine Alt-Zeile (und jede Aufgabe ohne Schwellwert) hat ihn schlicht nicht,
            # alle fuenf Spalten sind dann NULL. Die beiden bool-Kanaele liegen als
            # int 0/1 (sqlite kennt keinen bool-Typ -- Hausmuster int<->bool am Rand,
            # Hub in save()/_row_to_task()).
            if "threshold_condition" not in cols:
                conn.execute("ALTER TABLE monitoring_log_tasks ADD COLUMN threshold_condition TEXT")
            if "threshold_limit_ms" not in cols:
                conn.execute("ALTER TABLE monitoring_log_tasks ADD COLUMN threshold_limit_ms REAL")
            if "threshold_consecutive_n" not in cols:
                conn.execute(
                    "ALTER TABLE monitoring_log_tasks ADD COLUMN threshold_consecutive_n INTEGER"
                )
            if "threshold_notify_desktop" not in cols:
                conn.execute(
                    "ALTER TABLE monitoring_log_tasks ADD COLUMN threshold_notify_desktop INTEGER"
                )
            if "threshold_notify_email" not in cols:
                conn.execute(
                    "ALTER TABLE monitoring_log_tasks ADD COLUMN threshold_notify_email INTEGER"
                )

    def save(self, task: LoggingTask) -> None:
        # INSERT OR REPLACE -> Upsert ueber PRIMARY KEY id (neuer state bei jedem
        # Lebenszyklus-Uebergang). Enums als ihr str-Wert (StrEnum -> str).
        #
        # Schwellwert (Schnitt 2): fehlt er (``threshold is None``), werden alle fuenf
        # Spalten gemeinsam NULL geschrieben -- so bleibt ``threshold_condition`` der
        # verlaessliche Anker fuer "Schwellwert vorhanden?" beim Lesen. Sonst die Enum
        # als ihr str-Wert und die beiden bool-Kanaele als int 0/1 (int<->bool am Rand).
        threshold = task.threshold
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO monitoring_log_tasks (
                    id, target_id, label, purpose, capture_mode, operation_mode,
                    state, planned_start, planned_end, max_duration_s, created_at,
                    effective_start, interval_s,
                    threshold_condition, threshold_limit_ms, threshold_consecutive_n,
                    threshold_notify_desktop, threshold_notify_email
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    task.id,
                    task.target_id,
                    task.label,
                    task.purpose,
                    str(task.capture_mode),
                    str(task.operation_mode),
                    str(task.state),
                    task.planned_start,
                    task.planned_end,
                    task.max_duration_s,
                    task.created_at,
                    task.effective_start,
                    task.interval_s,
                    str(threshold.condition) if threshold is not None else None,
                    threshold.limit_ms if threshold is not None else None,
                    threshold.consecutive_n if threshold is not None else None,
                    int(threshold.notify_desktop) if threshold is not None else None,
                    int(threshold.notify_email) if threshold is not None else None,
                ),
            )

    def get(self, task_id: str) -> LoggingTask | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, target_id, label, purpose, capture_mode, operation_mode, "
                "state, planned_start, planned_end, max_duration_s, created_at, "
                "effective_start, interval_s, "
                "threshold_condition, threshold_limit_ms, threshold_consecutive_n, "
                "threshold_notify_desktop, threshold_notify_email "
                "FROM monitoring_log_tasks WHERE id = ?",
                (task_id,),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_task(row)

    def list_all(self) -> list[LoggingTask]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, target_id, label, purpose, capture_mode, operation_mode, "
                "state, planned_start, planned_end, max_duration_s, created_at, "
                "effective_start, interval_s, "
                "threshold_condition, threshold_limit_ms, threshold_consecutive_n, "
                "threshold_notify_desktop, threshold_notify_email "
                "FROM monitoring_log_tasks ORDER BY created_at"
            ).fetchall()
        return [self._row_to_task(row) for row in rows]

    def delete(self, task_id: str) -> None:
        # Idempotent: unbekannte id -> kein Fehler (DELETE betrifft 0 Zeilen).
        # Nur die Definition -- die Messdaten (RTT/Events) liegen in eigenen Repos.
        with self._connect() as conn:
            conn.execute("DELETE FROM monitoring_log_tasks WHERE id = ?", (task_id,))

    @staticmethod
    def _row_to_task(row: sqlite3.Row) -> LoggingTask:
        # Enum-Round-trip: gespeicherte Strings zurueck in die Domaenen-Enums.
        #
        # Schwellwert (Schnitt 2): ``threshold_condition`` ist der Anker -- ist sie NULL,
        # gab es keinen Schwellwert (-> ``threshold=None``). Andernfalls sind die uebrigen
        # vier Spalten konsistent gesetzt (save() schreibt sie immer GEMEINSAM), darum
        # genuegt der eine NULL-Check. Enum-Round-trip via ``ThresholdCondition(...)``,
        # die int-0/1-Kanaele zurueck nach bool (int<->bool am Rand).
        condition = row["threshold_condition"]
        threshold = (
            None
            if condition is None
            else LatencyThreshold(
                condition=ThresholdCondition(condition),
                limit_ms=row["threshold_limit_ms"],
                consecutive_n=row["threshold_consecutive_n"],
                notify_desktop=bool(row["threshold_notify_desktop"]),
                notify_email=bool(row["threshold_notify_email"]),
            )
        )
        return LoggingTask(
            id=row["id"],
            target_id=row["target_id"],
            label=row["label"],
            purpose=row["purpose"],
            capture_mode=CaptureMode(row["capture_mode"]),
            operation_mode=OperationMode(row["operation_mode"]),
            state=TaskState(row["state"]),
            planned_start=row["planned_start"],
            planned_end=row["planned_end"],
            max_duration_s=row["max_duration_s"],
            created_at=row["created_at"],
            effective_start=row["effective_start"],
            interval_s=row["interval_s"],
            threshold=threshold,
        )
