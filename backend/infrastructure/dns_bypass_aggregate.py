"""SQLite-Adapter fuer ``DnsBypassAggregateRepository`` (Tabelle ``dns_bypass_aggregate``).

Persistenz der verdichteten DNS-Umgehungs-Datensaetze je ``(recording_id, src_ip,
dst_ip)``, im Stil von ``SqliteOutboundAggregateRepository``: ``@contextmanager
_connect`` (``sqlite3.Row``, ``with conn``, garantiertes ``close``), ``_ensure_schema``
im Konstruktor (idempotentes ``CREATE TABLE IF NOT EXISTS`` + ``mkdir(parents=True,
exist_ok=True)``), injizierter ``db_path: Path``. KEIN ``modules``-Import; die
``db_path``-Verdrahtung kommt spaeter.

UPSERT ueber den zusammengesetzten PRIMARY KEY ``(recording_id, src_ip, dst_ip)``:
``upsert`` ist ``INSERT OR REPLACE``, ein zweiter Aufruf derselben Kombination ERSETZT
die Zeile (keine zweite). Der Merge selbst (``domain.merge_bypass``) passiert beim
Aufrufer.

JSON-ROUND-TRIP: ``sample_qnames`` ist eine Tuple aus (bis zu ``MAX_SAMPLE_QNAMES``)
distinct nicht-leeren qnames. Sie wird als JSON-Text-Liste abgelegt und beim Lesen
zurueck in eine ``tuple[str, ...]`` gehoben -- Erst-Vorkommen-Reihenfolge bleibt so
stabil erhalten (deterministischer Beleg).
"""

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from domain.dns_bypass import AggregatedBypass


class SqliteDnsBypassAggregateRepository:
    """Erfuellt das ``DnsBypassAggregateRepository``-Protocol strukturell (SQLite)."""

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
        # Idempotentes CREATE -- zusammengesetzter PK (recording_id, src_ip, dst_ip) traegt
        # den Upsert (INSERT OR REPLACE: je Kombination genau eine Zeile). sample_qnames
        # als JSON-Text-Liste.
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS dns_bypass_aggregate (
                    recording_id  TEXT,
                    src_ip        TEXT,
                    dst_ip        TEXT,
                    first_seen    REAL,
                    last_seen     REAL,
                    query_count   INTEGER,
                    sample_qnames TEXT,
                    PRIMARY KEY (recording_id, src_ip, dst_ip)
                )
                """
            )

    def upsert(self, recording_id: str, aggregate: AggregatedBypass) -> None:
        # INSERT OR REPLACE ueber den zusammengesetzten PK -> je (recording_id, src_ip,
        # dst_ip) genau eine Zeile (zweiter upsert ersetzt). sample_qnames als JSON.
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO dns_bypass_aggregate (
                    recording_id, src_ip, dst_ip, first_seen, last_seen,
                    query_count, sample_qnames
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    recording_id,
                    aggregate.src_ip,
                    aggregate.dst_ip,
                    aggregate.first_seen,
                    aggregate.last_seen,
                    aggregate.query_count,
                    json.dumps(list(aggregate.sample_qnames)),
                ),
            )

    def get(self, recording_id: str, src_ip: str, dst_ip: str) -> AggregatedBypass | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT src_ip, dst_ip, first_seen, last_seen, query_count, sample_qnames "
                "FROM dns_bypass_aggregate "
                "WHERE recording_id = ? AND src_ip = ? AND dst_ip = ?",
                (recording_id, src_ip, dst_ip),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_aggregate(row)

    def list_for(self, recording_id: str) -> list[AggregatedBypass]:
        # ORDER BY query_count DESC, src_ip ASC, dst_ip ASC -- lauteste zuerst, stabil
        # (s. Port-Docstring).
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT src_ip, dst_ip, first_seen, last_seen, query_count, sample_qnames "
                "FROM dns_bypass_aggregate WHERE recording_id = ? "
                "ORDER BY query_count DESC, src_ip ASC, dst_ip ASC",
                (recording_id,),
            ).fetchall()
        return [self._row_to_aggregate(row) for row in rows]

    def delete_for(self, recording_id: str) -> None:
        # Loescht ALLE Aggregate genau dieser recording_id (idempotent: unbekannte id ->
        # 0 Zeilen). Andere Aufzeichnungen bleiben unberuehrt.
        with self._connect() as conn:
            conn.execute("DELETE FROM dns_bypass_aggregate WHERE recording_id = ?", (recording_id,))

    def count(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM dns_bypass_aggregate").fetchone()
        return int(row["n"])

    def clear_all(self) -> None:
        # Leert alle Aggregate (nur die eigene Tabelle dns_bypass_aggregate).
        with self._connect() as conn:
            conn.execute("DELETE FROM dns_bypass_aggregate")

    @staticmethod
    def _row_to_aggregate(row: sqlite3.Row) -> AggregatedBypass:
        # sample_qnames aus der JSON-Text-Liste zurueck in eine tuple[str, ...].
        return AggregatedBypass(
            src_ip=row["src_ip"],
            dst_ip=row["dst_ip"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            query_count=row["query_count"],
            sample_qnames=tuple(json.loads(row["sample_qnames"])),
        )
