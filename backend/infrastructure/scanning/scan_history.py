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
* Die ``EnrichedHost`` <-> JSON-(De-)Serialisierung liegt im Adapter (nicht in der
  Domaene) und ist VERLUSTFREI, inkl. der verschachtelten ``PortInfo`` /
  ``MdnsService`` / ``SsdpService`` und der ``tuple``-Felder (JSON-Listen werden
  beim Lesen wieder zu ``tuple`` normalisiert -- ``MdnsService.properties`` sogar
  als ``tuple[tuple[str, str], ...]``).

Der DB-Pfad wird injiziert; die Pfad-Aufloesung passiert im Composition Root
(``app.py``, S.6-Verdrahtung), nicht im Adapter. Dieser Adapter importiert KEIN
``modules`` -- die ADR-0007-Ausnahme wird hier nicht gebraucht.
"""

import json
import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Any

from domain.scanning import (
    EnrichedHost,
    MdnsService,
    PortInfo,
    ScanRecord,
    ScanSummary,
    SsdpService,
)


class CorruptScanError(Exception):
    """Das gespeicherte ``result_json`` eines Scans ist kein gueltiges JSON-Array.

    Ersetzt den stillen ``or "[]"``-Rueckfall des Altcodes: ein kaputter Blob ist
    ein Fehler MIT ``scan_id``-Bezug (Muster wie ``CorruptDeviceError``).
    """

    def __init__(self, scan_id: int, raw_value: str) -> None:
        self.scan_id = scan_id
        self.raw_value = raw_value
        super().__init__(
            f"Scan {scan_id}: result_json ist kein gueltiges JSON-Array: {raw_value!r}"
        )


def _host_to_dict(host: EnrichedHost) -> dict[str, Any]:
    """EnrichedHost -> JSON-taugliches dict (tuples werden zu Listen)."""
    return asdict(host)


def _str_pairs(raw: Any) -> tuple[tuple[str, str], ...]:
    """JSON-Liste von [key, value]-Paaren -> tuple[tuple[str, str], ...]."""
    return tuple((str(k), str(v)) for k, v in raw)


def _dict_to_host(scan_id: int, data: Any) -> EnrichedHost:
    """JSON-dict -> EnrichedHost, verschachtelte Typen + tuples rekonstruiert."""
    if not isinstance(data, dict):
        raise CorruptScanError(scan_id, json.dumps(data))
    ports = tuple(PortInfo(**p) for p in data.get("ports", ()))
    mdns = tuple(
        MdnsService(
            name=m.get("name", ""),
            type=m.get("type", ""),
            port=m.get("port", 0),
            hostname=m.get("hostname", ""),
            is_ndi=m.get("is_ndi", False),
            properties=_str_pairs(m.get("properties", ())),
        )
        for m in data.get("mdns_services", ())
    )
    ssdp = tuple(SsdpService(**s) for s in data.get("ssdp_services", ()))
    return EnrichedHost(
        ip=data["ip"],
        mac=data["mac"],
        vendor=data.get("vendor", ""),
        rtt_ms=data.get("rtt_ms"),
        hostname=data.get("hostname", ""),
        smb_name=data.get("smb_name", ""),
        smb_domain=data.get("smb_domain", ""),
        os_guess=data.get("os_guess", ""),
        os_accuracy=data.get("os_accuracy", 0),
        scan_method=data.get("scan_method", "socket"),
        ports=ports,
        mdns_services=mdns,
        ssdp_services=ssdp,
        is_ndi=data.get("is_ndi", False),
        is_unknown=data.get("is_unknown", False),
        category=data.get("category", ""),
        label=data.get("label", ""),
        tags=tuple(data.get("tags", ())),
        notes=data.get("notes", ""),
    )


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
        payload = json.dumps([_host_to_dict(h) for h in hosts])
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO scan_history (cidr, host_count, result_json) VALUES (?, ?, ?)",
                (cidr, len(hosts), payload),
            )

    def list(self, limit: int) -> list[ScanSummary]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, cidr, host_count FROM scan_history ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            ScanSummary(scan_id=row["id"], cidr=row["cidr"], host_count=row["host_count"])
            for row in rows
        ]

    def get(self, scan_id: int) -> ScanRecord | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, cidr, result_json FROM scan_history WHERE id = ?",
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
        hosts = tuple(_dict_to_host(scan_id, item) for item in decoded)
        return ScanRecord(scan_id=row["id"], cidr=row["cidr"], hosts=hosts)
