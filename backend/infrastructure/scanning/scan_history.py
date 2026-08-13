"""SQLite-Adapter fuer den Port ``ScanHistoryRepository``.

Basiert auf der Persistenz-Logik aus ``modules/storage.py`` (``save_scan`` /
``get_scan_history`` / ``get_scan_by_id``), mit den bewussten v2-Schnitten und im
Stil von ``SqliteDeviceRepository``:

* Schema wie der Bestand: Tabelle ``scan_history`` mit
  ``id / scanned_at / cidr / host_count / result_json`` -- erfuellt den
  S.1-Round-trip-Contract (``save`` + ``list`` ohne Blob + ``get`` mit Hosts,
  unbekannte ID -> ``None``). Dazu die additive v2-Spalte ``interception_json``
  (Befund 53): das Ergebnis der EINEN Gegenprobe je Scan. Sie haengt am SCAN,
  nicht am Host -- ein lokal abgefangener Port ist eine Eigenschaft der
  messenden Maschine, nicht eines Ziels. NULL (Altbestand) liest sich als
  "nicht geprueft", was fuer die damaligen Scans genau stimmt.
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

Der Zeitstempel ``scanned_at`` kommt aus dem injizierten ``Clock``-Port (der EINEN
Zeitquelle der Anwendung, timezone-aware UTC), NICHT mehr aus dem SQLite-Schema-
Default ``datetime('now')``: der Default lieferte UTC ohne Zonen-Kennzeichnung, was
das Frontend als Ortszeit fehlinterpretierte. ``save`` setzt den Wert jetzt explizit
als ISO-8601-String MIT Zonen-Offset (``+00:00``). Der Schema-Default bleibt nur als
Sicherheitsnetz stehen, wird durch das explizite INSERT aber nicht mehr benutzt.
"""

import json
import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path

from domain.scanning import EnrichedHost, PortInterception, ScanRecord, ScanSummary
from infrastructure.scanning._serialization import (
    CorruptScanError,
    dict_to_host,
    dict_to_interception,
    host_to_dict,
    interception_to_dict,
)
from ports.devices import Clock

# ``CorruptScanError`` wird aus ``_serialization`` re-exportiert (bestehende
# Importe ``from ...scan_history import CorruptScanError`` bleiben gueltig).
__all__ = ["CorruptScanError", "SqliteScanHistoryRepository"]


class SqliteScanHistoryRepository:
    """Erfuellt das ``ScanHistoryRepository``-Protocol strukturell (SQLite)."""

    def __init__(self, db_path: Path, clock: Clock) -> None:
        self._db_path = db_path
        # Die EINE Zeitquelle (timezone-aware UTC); Verdrahtung im Composition Root.
        self._clock = clock
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
            # SCHEMA-GUARD (additive Migration, Hausmuster wie devices/rtt_history):
            # eine vor der Gegenproben-Etappe (Befund 53) angelegte Tabelle bekommt
            # die Spalte per ALTER nachgeruestet. Kein NOT NULL/DEFAULT: bestehende
            # Zeilen behalten NULL, und NULL liest sich als "nicht geprueft"
            # (``dict_to_interception(None)``) -- was fuer einen Altbestands-Scan
            # genau stimmt, denn damals gab es die Gegenprobe noch nicht.
            cols = {row["name"] for row in conn.execute("PRAGMA table_info(scan_history)")}
            if "interception_json" not in cols:
                conn.execute("ALTER TABLE scan_history ADD COLUMN interception_json TEXT")

    def save(
        self,
        cidr: str,
        hosts: Sequence[EnrichedHost],
        interception: PortInterception,
    ) -> None:
        payload = json.dumps([host_to_dict(h) for h in hosts])
        # Gegenproben-Ergebnis (Befund 53) in eigener Spalte -- NICHT im Host-Blob:
        # es haengt am Scan, nicht am Host, und bleibt so lesbar, ohne den ganzen
        # Blob zu deserialisieren.
        interception_payload = json.dumps(interception_to_dict(interception))
        # scanned_at explizit aus der Clock (timezone-aware UTC) als ISO-8601-String
        # MIT Zonen-Offset (+00:00) -- nicht mehr ueber den Schema-Default datetime('now').
        scanned_at = self._clock.now().isoformat()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO scan_history "
                "(cidr, host_count, result_json, scanned_at, interception_json) "
                "VALUES (?, ?, ?, ?, ?)",
                (cidr, len(hosts), payload, scanned_at, interception_payload),
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
                # ``scanned_at`` ist die ISO-TEXT-Spalte; der Wert kommt aus der Clock
                # (timezone-aware UTC, ISO-8601 mit +00:00), nicht mehr aus dem
                # Schema-Default. ``or ""`` faengt ein theoretisches NULL ab (etwa
                # Altbestand ueber den verbliebenen Default; Domaenen-Default leer).
                scanned_at=row["scanned_at"] or "",
            )
            for row in rows
        ]

    def get(self, scan_id: int) -> ScanRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, cidr, host_count, scanned_at, result_json, interception_json "
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
        # Gegenproben-Ergebnis: NULL/leer (Altbestand vor Befund 53) -> der
        # Domaenen-Default ``checked=False`` = "nicht geprueft". Kaputtes JSON ist
        # dagegen ein Fehler MIT scan_id-Bezug, kein stiller Rueckfall.
        raw_interception = row["interception_json"]
        try:
            decoded_interception = json.loads(raw_interception) if raw_interception else None
        except json.JSONDecodeError as exc:
            raise CorruptScanError(scan_id, raw_interception) from exc
        return ScanRecord(
            scan_id=row["id"],
            cidr=row["cidr"],
            hosts=hosts,
            host_count=row["host_count"],
            scanned_at=row["scanned_at"] or "",
            interception=dict_to_interception(scan_id, decoded_interception),
        )
