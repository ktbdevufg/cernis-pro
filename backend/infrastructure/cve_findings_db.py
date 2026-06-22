"""SQLite-Adapter fuer die CVE-Befund-Persistenz (``CveFindingRepository``, ADR 0037).

Persistiert je (mac, cve_id, port) EINEN Befund. Upsert-Semantik wie die ARP-Baseline
(``save_baseline_entry``): neuer Schluessel -> INSERT mit ``first_seen_ts``; bekannter
Schluessel -> nur ``last_seen_ts`` + die veraenderlichen NVD-Felder (severity/score/desc/
url/published) aktualisieren, ``first_seen_ts`` BLEIBT (Basis fuers is_new-Flag).

Stil EXAKT wie ``analysis_acknowledgements_db.py``/``analysis_host_history_db.py``:
injizierter ``db_path``, ``_ensure_schema`` im ``__init__``, ``@contextmanager _connect``
mit Transaktion + garantiertem ``close``, ``CREATE TABLE IF NOT EXISTS``. KEIN
``modules``-Import.

KEIN stiller Fallback noetig (S3): hier liegen nur nackte Spalten, kein JSON-Blob, der
korrupt sein koennte. Der Upsert ist deterministisch; ein Lesen liefert die Zeilen 1:1
als ``CveFindingRecord`` zurueck.
"""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from domain.cve.models import CveFindingRecord

__all__ = ["SqliteCveFindingRepository"]


class SqliteCveFindingRepository:
    """Persistiert CVE-Befunde (Identitaet mac+cve_id+port) als Upsert in SQLite."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._ensure_schema()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Connection mit Transaktion (commit/rollback) und garantiertem close."""
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _ensure_schema(self) -> None:
        # Zusammengesetzter PRIMARY KEY (mac, cve_id, port) = die Befund-Identitaet; der
        # Upsert (INSERT .. ON CONFLICT) haengt genau daran. first_seen_ts/last_seen_ts
        # sind epoch-float (REAL). KEIN AUTOINCREMENT-id noetig -- die fachliche Identitaet
        # IST der Schluessel (anders als das append-only ack-Log, das die History haelt).
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS cve_findings (
                    mac           TEXT NOT NULL,
                    cve_id        TEXT NOT NULL,
                    port          INTEGER NOT NULL,
                    severity      TEXT NOT NULL,
                    cvss_score    REAL NOT NULL,
                    description   TEXT NOT NULL,
                    url           TEXT NOT NULL,
                    published     TEXT NOT NULL,
                    ip            TEXT NOT NULL DEFAULT '',
                    service       TEXT NOT NULL DEFAULT '',
                    first_seen_ts REAL NOT NULL,
                    last_seen_ts  REAL NOT NULL,
                    PRIMARY KEY (mac, cve_id, port)
                );
                """
            )

    # ── Schreib-Pfad ──────────────────────────────────────────────────────────

    def upsert(self, record: CveFindingRecord) -> None:
        """Upsert je (mac, cve_id, port): INSERT neu, sonst last_seen + NVD-Felder frisch.

        ``ON CONFLICT (mac, cve_id, port)``: ``first_seen_ts`` wird im UPDATE-Zweig
        BEWUSST NICHT angefasst (bleibt der erste Sicht-Zeitpunkt); ``last_seen_ts`` und
        die veraenderlichen NVD-Felder (Severity/Score kann NVD nachtraeglich aendern)
        werden auf die neuen Werte gesetzt.
        """
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO cve_findings (
                    mac, cve_id, port, severity, cvss_score, description, url,
                    published, ip, service, first_seen_ts, last_seen_ts
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (mac, cve_id, port) DO UPDATE SET
                    severity     = excluded.severity,
                    cvss_score   = excluded.cvss_score,
                    description  = excluded.description,
                    url          = excluded.url,
                    published    = excluded.published,
                    ip           = excluded.ip,
                    service      = excluded.service,
                    last_seen_ts = excluded.last_seen_ts
                """,
                (
                    record.mac,
                    record.cve_id,
                    record.port,
                    record.severity,
                    record.cvss_score,
                    record.description,
                    record.url,
                    record.published,
                    record.ip,
                    record.service,
                    record.first_seen_ts,
                    record.last_seen_ts,
                ),
            )

    def clear_all(self) -> None:
        """Leert alle CVE-Befunde (nur die eigene Tabelle ``cve_findings``)."""
        with self._connect() as conn:
            conn.execute("DELETE FROM cve_findings")

    # ── Lese-Pfad ─────────────────────────────────────────────────────────────

    def list_all(self) -> list[CveFindingRecord]:
        """Alle Befunde ueber alle Hosts (Severity-stark zuerst, dann Score)."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM cve_findings ORDER BY cvss_score DESC, mac, cve_id, port"
            ).fetchall()
        return [self._row_to_record(row) for row in rows]

    def list_for_host(self, mac: str) -> list[CveFindingRecord]:
        """Alle Befunde eines Hosts. Leere MAC -> ``[]`` (kein stabiler Schluessel)."""
        if not mac:
            return []
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM cve_findings WHERE mac = ? ORDER BY cvss_score DESC, cve_id, port",
                (mac,),
            ).fetchall()
        return [self._row_to_record(row) for row in rows]

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> CveFindingRecord:
        return CveFindingRecord(
            mac=row["mac"],
            cve_id=row["cve_id"],
            port=row["port"],
            severity=row["severity"],
            cvss_score=row["cvss_score"],
            description=row["description"],
            url=row["url"],
            published=row["published"],
            ip=row["ip"],
            service=row["service"],
            first_seen_ts=row["first_seen_ts"],
            last_seen_ts=row["last_seen_ts"],
        )
