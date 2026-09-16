"""SQLite-Adapter fuer ``DnsBypassDetailRepository`` (Tabelle ``dns_bypass_detail``).

Persistenz des rohen DETAIL-Zeitverlaufs je DNS-Umgehungs-Aufzeichnung, im Stil von
``SqliteOutboundDetailRepository``: ``@contextmanager _connect`` (``sqlite3.Row``, ``with
conn``, garantiertes ``close``), ``_ensure_schema`` im Konstruktor (idempotentes ``CREATE
TABLE IF NOT EXISTS`` + ``mkdir(parents=True, exist_ok=True)``), injizierter
``db_path: Path``. KEIN ``modules``-Import; die ``db_path``-Verdrahtung kommt spaeter.

KEIN TRIM: ``save`` ist reines Append (EINE Umgehungs-Anfrage je Aufruf). Die
Mengenbegrenzung laeuft ueber die zeit-basierte Retention (``delete_older_than``), nicht
ueber einen Zeilen-Cap (Muster ``SqliteOutboundDetailRepository``). Index auf
``(recording_id, ts)`` fuer ``range``/Retention.

FENSTER-SEMANTIK von ``range``: Halb-offen ``ts >= since AND ts < until`` (since
inklusiv, until exklusiv), aufsteigend (``ORDER BY ts``) -- s. Port-Docstring.

KEINE NULLABLE-FELDER: ``src_ip``/``dst_ip``/``l4``/``qname`` sind alle nicht-nullbar;
``qname`` darf ``""`` sein (leerer String, kein NULL -- der Sniffer liefert ihn
best-effort).
"""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from domain.dns_bypass import DnsBypassDetailRow


class SqliteDnsBypassDetailRepository:
    """Erfuellt das ``DnsBypassDetailRepository``-Protocol strukturell (SQLite)."""

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
                CREATE TABLE IF NOT EXISTS dns_bypass_detail (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    recording_id TEXT,
                    ts           REAL,
                    src_ip       TEXT,
                    dst_ip       TEXT,
                    l4           TEXT,
                    qname        TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_dns_bypass_detail_rec_ts "
                "ON dns_bypass_detail (recording_id, ts)"
            )

    def save(
        self,
        recording_id: str,
        ts: float,
        src_ip: str,
        dst_ip: str,
        l4: str,
        qname: str,
    ) -> None:
        # Reines Append (kein Trim) -- die Retention macht delete_older_than.
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO dns_bypass_detail (
                    recording_id, ts, src_ip, dst_ip, l4, qname
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (recording_id, ts, src_ip, dst_ip, l4, qname),
            )

    def range(self, recording_id: str, since: float, until: float) -> list[DnsBypassDetailRow]:
        # Halb-offenes Fenster [since, until), aufsteigend (s. Port-Docstring).
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT ts, src_ip, dst_ip, l4, qname FROM dns_bypass_detail "
                "WHERE recording_id = ? AND ts >= ? AND ts < ? ORDER BY ts",
                (recording_id, since, until),
            ).fetchall()
        return [self._row_to_detail(row) for row in rows]

    def delete_older_than(self, cutoff_ts: float) -> int:
        # Strikt aelter (ts < cutoff_ts) -- ein Punkt GENAU auf dem Cutoff bleibt
        # (symmetrisch zur since-Inklusivitaet von range). Rueckgabe = geloeschte Zeilen.
        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM dns_bypass_detail WHERE ts < ?", (cutoff_ts,))
            return cursor.rowcount

    def count(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM dns_bypass_detail").fetchone()
        return int(row["n"])

    def clear_all(self) -> None:
        # Leert alle DETAIL-Messpunkte (nur die eigene Tabelle dns_bypass_detail).
        with self._connect() as conn:
            conn.execute("DELETE FROM dns_bypass_detail")

    @staticmethod
    def _row_to_detail(row: sqlite3.Row) -> DnsBypassDetailRow:
        return DnsBypassDetailRow(
            ts=row["ts"],
            src_ip=row["src_ip"],
            dst_ip=row["dst_ip"],
            l4=row["l4"],
            qname=row["qname"],
        )
