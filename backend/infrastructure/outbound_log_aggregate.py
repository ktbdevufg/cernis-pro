"""SQLite-Adapter fuer ``OutboundAggregateRepository`` (Tabelle ``outbound_log_aggregate``).

Persistenz der verdichteten Aussenkontakte-Datensaetze je ``(recording_id, remote_ip)``,
im Stil von ``SqliteLoggingRttRepository`` / ``SqliteLoggingTaskRepository``:
``@contextmanager _connect`` (``sqlite3.Row``, ``with conn``, garantiertes ``close``),
``_ensure_schema`` im Konstruktor (idempotentes ``CREATE TABLE IF NOT EXISTS`` +
``mkdir(parents=True, exist_ok=True)``), injizierter ``db_path: Path``. KEIN
``modules``-Import; die ``db_path``-Verdrahtung kommt spaeter.

UPSERT ueber den zusammengesetzten PRIMARY KEY ``(recording_id, remote_ip)``: ``upsert``
ist ``INSERT OR REPLACE``, ein zweiter Aufruf derselben Kombination ERSETZT die Zeile
(keine zweite). Der Merge selbst (``domain.merge_contact``) passiert beim Aufrufer.

NULLABLE-FELDER: die Anreicherungsspalten (``remote_port``/``hostname``/``country``/
``operator``/``asn``/``app_name``) duerfen NULL sein; sqlite gibt beim Lesen ``None``
zurueck -> direkt in den ``AggregatedContact``. ``remote_ip`` ist im ``AggregatedContact``
selbst gefuehrt und zugleich Teil des PK -- beim Lesen genuegt die Spalte.
"""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from domain.outbound_log import AggregatedContact


class SqliteOutboundAggregateRepository:
    """Erfuellt das ``OutboundAggregateRepository``-Protocol strukturell (SQLite)."""

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
        # Idempotentes CREATE -- zusammengesetzter PK (recording_id, remote_ip) traegt
        # den Upsert (INSERT OR REPLACE: je Kombination genau eine Zeile).
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS outbound_log_aggregate (
                    recording_id TEXT,
                    remote_ip    TEXT,
                    first_seen   REAL,
                    last_seen    REAL,
                    total_count  INTEGER,
                    peak_count   INTEGER,
                    remote_port  INTEGER,
                    hostname     TEXT,
                    country      TEXT,
                    operator     TEXT,
                    asn          TEXT,
                    app_name     TEXT,
                    PRIMARY KEY (recording_id, remote_ip)
                )
                """
            )

    def upsert(self, recording_id: str, contact: AggregatedContact) -> None:
        # INSERT OR REPLACE ueber den zusammengesetzten PK -> je (recording_id,
        # remote_ip) genau eine Zeile (zweiter upsert ersetzt). NULL-Werte unveraendert.
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO outbound_log_aggregate (
                    recording_id, remote_ip, first_seen, last_seen, total_count,
                    peak_count, remote_port, hostname, country, operator, asn, app_name
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    recording_id,
                    contact.remote_ip,
                    contact.first_seen,
                    contact.last_seen,
                    contact.total_count,
                    contact.peak_count,
                    contact.remote_port,
                    contact.hostname,
                    contact.country,
                    contact.operator,
                    contact.asn,
                    contact.app_name,
                ),
            )

    def get(self, recording_id: str, remote_ip: str) -> AggregatedContact | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT remote_ip, first_seen, last_seen, total_count, peak_count, "
                "remote_port, hostname, country, operator, asn, app_name "
                "FROM outbound_log_aggregate WHERE recording_id = ? AND remote_ip = ?",
                (recording_id, remote_ip),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_contact(row)

    def list_for(self, recording_id: str) -> list[AggregatedContact]:
        # ORDER BY total_count DESC, remote_ip ASC -- lauteste zuerst, stabil
        # (s. Port-Docstring).
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT remote_ip, first_seen, last_seen, total_count, peak_count, "
                "remote_port, hostname, country, operator, asn, app_name "
                "FROM outbound_log_aggregate WHERE recording_id = ? "
                "ORDER BY total_count DESC, remote_ip ASC",
                (recording_id,),
            ).fetchall()
        return [self._row_to_contact(row) for row in rows]

    def delete_for(self, recording_id: str) -> None:
        # Loescht ALLE Aggregate genau dieser recording_id (idempotent: unbekannte id ->
        # 0 Zeilen). Andere Aufzeichnungen bleiben unberuehrt.
        with self._connect() as conn:
            conn.execute(
                "DELETE FROM outbound_log_aggregate WHERE recording_id = ?", (recording_id,)
            )

    def count(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM outbound_log_aggregate").fetchone()
        return int(row["n"])

    def clear_all(self) -> None:
        # Leert alle Aggregate (nur die eigene Tabelle outbound_log_aggregate).
        with self._connect() as conn:
            conn.execute("DELETE FROM outbound_log_aggregate")

    @staticmethod
    def _row_to_contact(row: sqlite3.Row) -> AggregatedContact:
        # NULL aus sqlite -> None direkt in den Datentraeger (kein Cast noetig).
        return AggregatedContact(
            remote_ip=row["remote_ip"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            total_count=row["total_count"],
            peak_count=row["peak_count"],
            remote_port=row["remote_port"],
            hostname=row["hostname"],
            country=row["country"],
            operator=row["operator"],
            asn=row["asn"],
            app_name=row["app_name"],
        )
