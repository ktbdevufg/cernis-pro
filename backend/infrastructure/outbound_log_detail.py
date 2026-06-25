"""SQLite-Adapter fuer ``OutboundDetailRepository`` (Tabelle ``outbound_log_detail``).

Persistenz des rohen DETAIL-Zeitverlaufs je Aussenkontakte-Aufzeichnung, im Stil von
``SqliteLoggingRttRepository``: ``@contextmanager _connect`` (``sqlite3.Row``, ``with
conn``, garantiertes ``close``), ``_ensure_schema`` im Konstruktor (idempotentes
``CREATE TABLE IF NOT EXISTS`` + ``mkdir(parents=True, exist_ok=True)``), injizierter
``db_path: Path``. KEIN ``modules``-Import; die ``db_path``-Verdrahtung kommt spaeter.

KEIN TRIM: ``save`` ist reines Append (EIN Messpunkt je Aufruf). Die Mengenbegrenzung
laeuft ueber die zeit-basierte Retention (``delete_older_than``), nicht ueber einen
Zeilen-Cap (Muster ``SqliteLoggingRttRepository``). Index auf ``(recording_id, ts)``
fuer ``range``/Retention.

FENSTER-SEMANTIK von ``range``: Halb-offen ``ts >= since AND ts < until`` (since
inklusiv, until exklusiv), aufsteigend (``ORDER BY ts``) -- s. Port-Docstring.

NULLABLE-FELDER: ``remote_port``/``pid`` (und die Anreicherungs-Strings) duerfen NULL
sein; sqlite gibt dann beim Lesen ``None`` zurueck -> direkt als ``int | None`` bzw.
``str | None`` in den ``OutboundDetailRow`` (kein Cast noetig).
"""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from domain.outbound_log import OutboundDetailRow


class SqliteOutboundDetailRepository:
    """Erfuellt das ``OutboundDetailRepository``-Protocol strukturell (SQLite)."""

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
        # Append-Store + Index auf (recording_id, ts) fuer range/Retention. KEIN Trim.
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS outbound_log_detail (
                    id               INTEGER PRIMARY KEY AUTOINCREMENT,
                    recording_id     TEXT,
                    ts               REAL,
                    remote_ip        TEXT,
                    remote_port      INTEGER,
                    hostname         TEXT,
                    country          TEXT,
                    operator         TEXT,
                    asn              TEXT,
                    app_name         TEXT,
                    pid              INTEGER,
                    connection_count INTEGER
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_outbound_log_detail_rec_ts "
                "ON outbound_log_detail (recording_id, ts)"
            )

    def save(
        self,
        recording_id: str,
        ts: float,
        remote_ip: str,
        remote_port: int | None,
        hostname: str | None,
        country: str | None,
        operator: str | None,
        asn: str | None,
        app_name: str | None,
        pid: int | None,
        connection_count: int,
    ) -> None:
        # Reines Append (kein Trim) -- die Retention macht delete_older_than. NULL-Werte
        # werden unveraendert als NULL abgelegt (kein erfundener Ersatzwert).
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO outbound_log_detail (
                    recording_id, ts, remote_ip, remote_port, hostname, country,
                    operator, asn, app_name, pid, connection_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    recording_id,
                    ts,
                    remote_ip,
                    remote_port,
                    hostname,
                    country,
                    operator,
                    asn,
                    app_name,
                    pid,
                    connection_count,
                ),
            )

    def range(self, recording_id: str, since: float, until: float) -> list[OutboundDetailRow]:
        # Halb-offenes Fenster [since, until), aufsteigend (s. Port-Docstring).
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT ts, remote_ip, remote_port, hostname, country, operator, asn, "
                "app_name, pid, connection_count FROM outbound_log_detail "
                "WHERE recording_id = ? AND ts >= ? AND ts < ? ORDER BY ts",
                (recording_id, since, until),
            ).fetchall()
        return [self._row_to_detail(row) for row in rows]

    def delete_older_than(self, cutoff_ts: float) -> int:
        # Strikt aelter (ts < cutoff_ts) -- ein Punkt GENAU auf dem Cutoff bleibt
        # (symmetrisch zur since-Inklusivitaet von range). Rueckgabe = geloeschte Zeilen.
        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM outbound_log_detail WHERE ts < ?", (cutoff_ts,))
            return cursor.rowcount

    def count(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM outbound_log_detail").fetchone()
        return int(row["n"])

    def clear_all(self) -> None:
        # Leert alle DETAIL-Messpunkte (nur die eigene Tabelle outbound_log_detail).
        with self._connect() as conn:
            conn.execute("DELETE FROM outbound_log_detail")

    @staticmethod
    def _row_to_detail(row: sqlite3.Row) -> OutboundDetailRow:
        # NULL aus sqlite -> None direkt in den Record (kein Cast noetig).
        return OutboundDetailRow(
            ts=row["ts"],
            remote_ip=row["remote_ip"],
            remote_port=row["remote_port"],
            hostname=row["hostname"],
            country=row["country"],
            operator=row["operator"],
            asn=row["asn"],
            app_name=row["app_name"],
            pid=row["pid"],
            connection_count=row["connection_count"],
        )
