"""SQLite-Adapter fuer ``LoggingRttRepository`` (Tabelle ``monitoring_log_rtt``).

Persistenz der dichten RTT-Messpunkte je Logging-Aufgabe (B-I, Retention 1 Monat),
im Stil von ``SqliteRttHistoryRepository``: ``@contextmanager _connect``,
``_ensure_schema`` im Konstruktor (idempotentes ``CREATE TABLE IF NOT EXISTS``),
injizierter ``db_path: Path``, ``sqlite3.Row``. EIGENE Tabelle, GETRENNT vom
Live-Monitor. KEIN ``modules``-Import.

KEIN TRIM (Unterschied zu ``rtt_history``): ``SqliteRttHistoryRepository.save`` cappt
pro Target auf 1000 Zeilen -- HIER nicht. Die Mengenbegrenzung laeuft ueber die
zeit-basierte Retention (``delete_older_than``), nicht ueber einen Zeilen-Cap; ``save``
ist reines Append. Index auf ``(task_id, ts)`` fuer ``range``/Retention.

ALIVE als INTEGER (sqlite kennt kein bool): ``int(alive)`` beim Schreiben,
``bool(row["alive"])`` beim Lesen -- Muster ``SqliteRttHistoryRepository``. RTT-Sentinel
``-1.0`` bleibt unveraendert.

FENSTER-SEMANTIK von ``range``: Halb-offen ``ts >= since AND ts < until`` (since
inklusiv, until exklusiv), aufsteigend (``ORDER BY ts``) -- s. Port-Docstring.
"""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from domain.monitoring import LoggingRttSample


class SqliteLoggingRttRepository:
    """Erfuellt das ``LoggingRttRepository``-Protocol strukturell (SQLite)."""

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
        # Append-Store + Index auf (task_id, ts) fuer range/Retention. KEIN Trim.
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS monitoring_log_rtt (
                    id       INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id  TEXT,
                    rtt_ms   REAL,
                    loss_pct REAL,
                    alive    INTEGER,
                    ts       REAL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_monitoring_log_rtt_task_ts "
                "ON monitoring_log_rtt (task_id, ts)"
            )

    def save(self, task_id: str, rtt_ms: float, loss_pct: float, alive: bool, ts: float) -> None:
        # Reines Append (kein Trim) -- die Retention macht delete_older_than.
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO monitoring_log_rtt (task_id, rtt_ms, loss_pct, alive, ts) "
                "VALUES (?, ?, ?, ?, ?)",
                (task_id, rtt_ms, loss_pct, int(alive), ts),
            )

    def range(self, task_id: str, since: float, until: float) -> list[LoggingRttSample]:
        # Halb-offenes Fenster [since, until), aufsteigend (s. Port-Docstring).
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT rtt_ms, loss_pct, alive, ts FROM monitoring_log_rtt "
                "WHERE task_id = ? AND ts >= ? AND ts < ? ORDER BY ts",
                (task_id, since, until),
            ).fetchall()
        return [
            LoggingRttSample(
                rtt_ms=row["rtt_ms"],
                loss_pct=row["loss_pct"],
                alive=bool(row["alive"]),
                ts=row["ts"],
            )
            for row in rows
        ]

    def all_for(self, task_id: str) -> list[LoggingRttSample]:
        # ALLE Messpunkte eines Tasks (kein Zeitfenster), aufsteigend -- Muster wie
        # range, nur ohne die ts-Grenzen (s. Port-Docstring: Retention begrenzt "alle").
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT rtt_ms, loss_pct, alive, ts FROM monitoring_log_rtt "
                "WHERE task_id = ? ORDER BY ts",
                (task_id,),
            ).fetchall()
        return [
            LoggingRttSample(
                rtt_ms=row["rtt_ms"],
                loss_pct=row["loss_pct"],
                alive=bool(row["alive"]),
                ts=row["ts"],
            )
            for row in rows
        ]

    def delete_older_than(self, cutoff_ts: float) -> int:
        # Strikt aelter (ts < cutoff_ts) -- ein Punkt GENAU auf dem Cutoff bleibt
        # (symmetrisch zur since-Inklusivitaet von range). Rueckgabe = geloeschte Zeilen.
        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM monitoring_log_rtt WHERE ts < ?", (cutoff_ts,))
            return cursor.rowcount

    def clear_all(self) -> None:
        # Leert alle dichten RTT-Messpunkte (nur die eigene Tabelle monitoring_log_rtt).
        with self._connect() as conn:
            conn.execute("DELETE FROM monitoring_log_rtt")

    def count(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM monitoring_log_rtt").fetchone()
        return int(row["n"])
