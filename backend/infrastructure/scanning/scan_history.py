"""SQLite-Adapter fuer den Port ``ScanHistoryRepository``.

Basiert auf der Persistenz-Logik aus ``modules/storage.py`` (``save_scan`` /
``get_scan_history`` / ``get_scan_by_id``), mit den bewussten v2-Schnitten und im
Stil von ``SqliteDeviceRepository``:

* Schema EXAKT wie der Bestand: Tabelle ``scan_history`` mit
  ``id / scanned_at / cidr / host_count / result_json`` -- erfuellt den
  S.1-Round-trip-Contract (``save`` + ``list`` ohne Blob + ``get`` mit Hosts,
  unbekannte ID -> ``None``).
* ``list`` selektiert bewusst NUR ``id, cidr, host_count`` (nicht ``result_json``)
  -- der Host-Blob kommt erst per ``get(scan_id)`` (Charakterisierung S.1:
  ``get_scan_history`` ohne ``result_json``).
* KEIN stiller Fallback bei kaputtem JSON (vgl. Finding S3 / Muster
  ``CorruptDeviceError``): Der Altcode-Ausdruck ``json.loads(result_json or "[]")``
  faengt nur NULL/Leer ab -- ein wirklich kaputtes ``result_json`` wuerde dort
  als ``JSONDecodeError`` durchschlagen. Hier wird daraus ein ``CorruptScanError``
  MIT ``scan_id``-Bezug (statt eines diffusen Tracebacks), und die Form wird
  validiert (Liste von Objekten) -- kein leiser Rueckfall auf ``[]``.
* Die ``EnrichedHost`` <-> JSON-(De-)Serialisierung liegt in der Infrastruktur
  (nicht in der Domaene) und ist VERLUSTFREI. Die Helfer (``host_to_dict`` /
  ``dict_to_host`` / ``CorruptScanError``) sind nach ``_serialization`` gezogen,
  weil mehrere scanning-Adapter sie teilen (``ipv6_enrichment`` braucht denselben
  Rekonstruktor) -- so greift kein Adapter in den privaten Teil eines anderen.

Der DB-Pfad wird injiziert; die Pfad-Aufloesung passiert im Composition Root
(``app.py``, S.6-Verdrahtung), nicht im Adapter. Dieser Adapter importiert KEIN
``modules`` -- die ADR-0007-Ausnahme wird hier nicht gebraucht.
"""

import json
import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path

from domain.scanning import EnrichedHost, ScanRecord, ScanSummary
from infrastructure.scanning._serialization import (
    CorruptScanError,
    dict_to_host,
    host_to_dict,
)

# ``CorruptScanError`` wird aus ``_serialization`` re-exportiert (bestehende
# Importe ``from ...scan_history import CorruptScanError`` bleiben gueltig).
__all__ = ["CorruptScanError", "SqliteScanHistoryRepository"]


class SqliteScanHistoryRepository:
    """Erfuellt das ``ScanHistoryRepository``-Protocol strukturell (SQLite)."""

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
        # Schema exakt wie der Bestand (modules/storage.py): scan_history mit
        # AUTOINCREMENT-id, scanned_at-Default, cidr, host_count, result_json.
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS scan_history (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    scanned_at  TEXT DEFAULT (datetime('now')),
                    cidr        TEXT,
                    host_count  INTEGER,
                    result_json TEXT
                );
                """
            )

    def save(self, cidr: str, hosts: Sequence[EnrichedHost]) -> None:
        payload = json.dumps([host_to_dict(h) for h in hosts])
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO scan_history (cidr, host_count, result_json) VALUES (?, ?, ?)",
                (cidr, len(hosts), payload),
            )

    def clear_all(self) -> None:
        """Leert die gesamte Scan-Historie (nur die eigene Tabelle ``scan_history``)."""
        with self._connect() as conn:
            conn.execute("DELETE FROM scan_history")

    def list(self, limit: int) -> list[ScanSummary]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, cidr, host_count, scanned_at FROM scan_history "
                "ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            ScanSummary(
                scan_id=row["id"],
                cidr=row["cidr"],
                host_count=row["host_count"],
                # ``scanned_at`` ist die ISO-TEXT-Spalte (DEFAULT datetime('now'));
                # ``or ""`` faengt ein theoretisches NULL ab (Domaenen-Default leer).
                scanned_at=row["scanned_at"] or "",
            )
            for row in rows
        ]

    def get(self, scan_id: int) -> ScanRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, cidr, host_count, scanned_at, result_json "
                "FROM scan_history WHERE id = ?",
                (scan_id,),
            ).fetchone()
        if row is None:
            return None
        raw = row["result_json"]
        try:
            decoded = json.loads(raw) if raw else []
        except json.JSONDecodeError as exc:
            raise CorruptScanError(scan_id, raw) from exc
        if not isinstance(decoded, list):
            raise CorruptScanError(scan_id, raw)
        hosts = tuple(dict_to_host(scan_id, item) for item in decoded)
        return ScanRecord(
            scan_id=row["id"],
            cidr=row["cidr"],
            hosts=hosts,
            host_count=row["host_count"],
            scanned_at=row["scanned_at"] or "",
        )
