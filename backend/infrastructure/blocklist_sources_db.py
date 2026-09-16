"""SQLite-Adapter fuer ``BlocklistSourceRepository`` (Tabelle ``blocklist_sources``).

Persistenz der Blocklist-Quellen-DEFINITIONEN, im Stil von
``infrastructure/outbound_log_detail.py``: ``@contextmanager _connect``
(``sqlite3.Row``, ``with conn``, garantiertes ``close``), ``_ensure_schema`` im
Konstruktor (idempotentes ``CREATE TABLE IF NOT EXISTS`` + ``mkdir(parents=True,
exist_ok=True)``), injizierter ``db_path: Path``. KEIN ``modules``-Import.

ENUM-ROUND-TRIP: Beim Schreiben werden die Domaenen-Enums als ihr ``str``-Wert abgelegt
(``.value``), beim Lesen ueber die Enum-Konstruktoren zurueckgehoben. ``bool`` als 0/1.
``group`` ist ein SQL-Keyword -> Spalte ``group_name``. ``upsert`` ist
``INSERT OR REPLACE`` (Insert ODER Update ueber den PRIMARY KEY ``id``).
"""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from domain.blocklist import (
    BlocklistFormat,
    BlocklistGroup,
    BlocklistSource,
    BlocklistStatus,
    SourceOrigin,
)


class SqliteBlocklistSourceRepository:
    """Erfuellt das ``BlocklistSourceRepository``-Protocol strukturell (SQLite)."""

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
        # Quellen-Definitionen. ``group`` ist SQL-Keyword -> Spalte group_name.
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS blocklist_sources (
                    id                   TEXT PRIMARY KEY,
                    name                 TEXT,
                    group_name           TEXT,
                    fmt                  TEXT,
                    origin               TEXT,
                    url                  TEXT,
                    license              TEXT,
                    attribution_required INTEGER,
                    enabled              INTEGER,
                    last_fetched_ts      REAL,
                    status               TEXT,
                    entry_count          INTEGER
                )
                """
            )

    def upsert(self, source: BlocklistSource) -> None:
        # INSERT OR REPLACE ueber den PRIMARY KEY id (Insert ODER Update). Enums als
        # .value, bool als 0/1. url/last_fetched_ts/entry_count duerfen None (NULL) sein.
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO blocklist_sources (
                    id, name, group_name, fmt, origin, url, license,
                    attribution_required, enabled, last_fetched_ts, status, entry_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    source.id,
                    source.name,
                    source.group.value,
                    source.fmt.value,
                    source.origin.value,
                    source.url,
                    source.license,
                    int(source.attribution_required),
                    int(source.enabled),
                    source.last_fetched_ts,
                    source.status.value,
                    source.entry_count,
                ),
            )

    def get(self, source_id: str) -> BlocklistSource | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, name, group_name, fmt, origin, url, license, "
                "attribution_required, enabled, last_fetched_ts, status, entry_count "
                "FROM blocklist_sources WHERE id = ?",
                (source_id,),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_source(row)

    def list_all(self) -> list[BlocklistSource]:
        # Sortiert nach group, dann name (aufsteigend) -- s. Port-Docstring.
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, name, group_name, fmt, origin, url, license, "
                "attribution_required, enabled, last_fetched_ts, status, entry_count "
                "FROM blocklist_sources ORDER BY group_name, name"
            ).fetchall()
        return [self._row_to_source(row) for row in rows]

    def delete(self, source_id: str) -> None:
        # Idempotent: unbekannte id trifft 0 Zeilen (kein Fehler).
        with self._connect() as conn:
            conn.execute("DELETE FROM blocklist_sources WHERE id = ?", (source_id,))

    def clear_all(self) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM blocklist_sources")

    @staticmethod
    def _row_to_source(row: sqlite3.Row) -> BlocklistSource:
        # Enum-Strings ueber die Enum-Konstruktoren zurueckheben; 0/1 -> bool.
        return BlocklistSource(
            id=row["id"],
            name=row["name"],
            group=BlocklistGroup(row["group_name"]),
            fmt=BlocklistFormat(row["fmt"]),
            origin=SourceOrigin(row["origin"]),
            url=row["url"],
            license=row["license"],
            attribution_required=bool(row["attribution_required"]),
            enabled=bool(row["enabled"]),
            last_fetched_ts=row["last_fetched_ts"],
            status=BlocklistStatus(row["status"]),
            entry_count=row["entry_count"],
        )
