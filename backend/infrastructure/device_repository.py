"""SQLite-Adapter fuer den Port ``DeviceRepository``.

Basiert auf der Persistenz-Logik aus ``modules/devices_db.py``, mit den bewussten
v2-Schnitten:

* NUR zwei Tabellen: ``devices`` + ``device_ip_history``. Die alte
  ``known_devices``-Tabelle wird NICHT angefasst, angelegt oder gelesen
  (sauberer Schnitt -- v2 kennt sie nicht).
* BUG-1-FIX: ``delete`` raeumt BEIDE Tabellen in einer Transaktion -- keine
  Halbloeschung wie im Altcode.
* Reine Persistenz: KEINE Merge-Logik. Das Mergen (``domain.merge_scan``) und die
  History-Regel (``domain.should_append_ip``) sind VORHER im Use-Case (D.5)
  passiert; der Adapter schreibt nur fertige Domaenen-Objekte.
* Zeitstempel als TEXT in fixem ISO-8601-UTC-Format (``timespec="microseconds"``),
  damit ``last_seen``-Vergleiche (Sortierung, ``stats``) lexikografisch =
  chronologisch sind -- das ist der strukturelle Fix des ``active_24h``-
  Zeitzonen-Bugs.
* KEIN stiller Fallback bei kaputtem JSON (vgl. Finding S3): ein nicht
  dekodierbares ``tags``/``open_ports`` ist ein Fehler MIT mac-Bezug.

Der DB-Pfad wird injiziert; die Pfad-Aufloesung passiert im Composition Root
(``app.py``, D.6), nicht im Adapter.
"""

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from domain.devices import Device, DeviceStats, IpHistoryEntry, TrustState, normalize_mac


class CorruptDeviceError(Exception):
    """Eine gespeicherte JSON-Spalte (``tags``/``open_ports``) ist kein gueltiges JSON.

    Ersetzt einen stillen Roh-/Leer-Fallback: ein kaputter Wert ist ein Fehler
    MIT mac- und Spalten-Bezug (Muster wie ``CorruptSettingError`` bei settings).
    """

    def __init__(self, mac: str, column: str, raw_value: str) -> None:
        self.mac = mac
        self.column = column
        self.raw_value = raw_value
        super().__init__(
            f"Geraet {mac!r}: Spalte {column!r} enthaelt kein gueltiges JSON: {raw_value!r}"
        )


def _fmt_dt(value: datetime) -> str:
    """datetime -> fixes ISO-8601-UTC-TEXT (immer 6-stellige Mikrosekunden).

    Naive Eingaben werden als UTC interpretiert (dokumentierte Konvention,
    symmetrisch zu ``_parse_dt``). Das fixe Format macht TEXT-Vergleiche
    lexikografisch chronologisch korrekt.
    """
    aware = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return aware.astimezone(UTC).isoformat(timespec="microseconds")


def _parse_dt(raw: str) -> datetime:
    """ISO-8601-TEXT -> tz-aware datetime. Naive Altdaten gelten als UTC."""
    parsed = datetime.fromisoformat(raw)
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _decode_list(mac: str, column: str, raw: str) -> tuple[Any, ...]:
    """JSON-TEXT -> tuple. Kein stiller Fallback: kaputtes JSON -> Exception."""
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CorruptDeviceError(mac, column, raw) from exc
    if not isinstance(decoded, list):
        raise CorruptDeviceError(mac, column, raw)
    return tuple(decoded)


def _row_to_trust_state(raw: Any) -> TrustState:
    """TEXT-Spalte -> ``TrustState``. NULL/leer -> Default NEUTRAL (defensiv).

    Eine fehlende oder leere Spalte (z. B. eine vor der Migration angelegte
    Zeile, deren ALTER-Default griffe -- hier doppelt abgesichert) faellt auf
    NEUTRAL zurueck. Ein nicht-leerer, aber unbekannter Wert ist hingegen KEIN
    stiller Fallback, sondern ein Fehler ueber ``TrustState(...)`` (Finding S3).
    """
    if raw is None or raw == "":
        return TrustState.NEUTRAL
    return TrustState(raw)


def _row_to_device(row: sqlite3.Row) -> Device:
    mac = row["mac"]
    return Device(
        mac=mac,
        first_seen=_parse_dt(row["first_seen"]),
        last_seen=_parse_dt(row["last_seen"]),
        last_ip=row["last_ip"],
        times_seen=row["times_seen"],
        is_known=bool(row["is_known"]),
        trust_state=_row_to_trust_state(row["trust_state"]),
        vendor=row["vendor"],
        label=row["label"],
        notes=row["notes"],
        category=row["category"],
        hostname=row["hostname"],
        os_guess=row["os_guess"],
        tags=_decode_list(mac, "tags", row["tags"]),
        open_ports=_decode_list(mac, "open_ports", row["open_ports"]),
    )


class SqliteDeviceRepository:
    """Erfuellt das ``DeviceRepository``-Protocol strukturell (SQLite)."""

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
        # Schema wie der Bestand (devices + trust_state = 15 Spalten,
        # device_ip_history) -- known_devices wird bewusst NICHT angelegt.
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS devices (
                    mac          TEXT PRIMARY KEY,
                    vendor       TEXT DEFAULT '',
                    label        TEXT DEFAULT '',
                    tags         TEXT DEFAULT '[]',
                    notes        TEXT DEFAULT '',
                    category     TEXT DEFAULT '',
                    is_known     INTEGER DEFAULT 0,
                    trust_state  TEXT NOT NULL DEFAULT 'neutral',
                    first_seen   TEXT DEFAULT (datetime('now')),
                    last_seen    TEXT DEFAULT (datetime('now')),
                    last_ip      TEXT DEFAULT '',
                    times_seen   INTEGER DEFAULT 1,
                    open_ports   TEXT DEFAULT '[]',
                    hostname     TEXT DEFAULT '',
                    os_guess     TEXT DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS device_ip_history (
                    id       INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac      TEXT,
                    ip       TEXT,
                    seen_at  TEXT DEFAULT (datetime('now'))
                );
                """
            )
            # SCHEMA-GUARD (additive Migration, Hausmuster wie monitoring_log_tasks):
            # eine vor dieser Etappe angelegte devices-Tabelle bekommt trust_state
            # per ALTER nachgeruestet. NOT NULL DEFAULT 'neutral' -> bestehende
            # Zeilen erhalten verlustfrei den Default, kein Datenverlust.
            cols = {row["name"] for row in conn.execute("PRAGMA table_info(devices)")}
            if "trust_state" not in cols:
                conn.execute(
                    "ALTER TABLE devices ADD COLUMN trust_state TEXT NOT NULL DEFAULT 'neutral'"
                )

    def get(self, mac: str) -> Device | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM devices WHERE mac = ?", (normalize_mac(mac),)
            ).fetchone()
        if row is None:
            return None
        return _row_to_device(row)

    def get_all(self, known_only: bool) -> list[Device]:
        query = "SELECT * FROM devices"
        if known_only:
            query += " WHERE is_known = 1"
        query += " ORDER BY last_seen DESC"
        with self._connect() as conn:
            rows = conn.execute(query).fetchall()
        return [_row_to_device(row) for row in rows]

    def save(self, device: Device) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO devices ("
                " mac, vendor, label, tags, notes, category, is_known, trust_state,"
                " first_seen, last_seen, last_ip, times_seen, open_ports, hostname, os_guess"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(mac) DO UPDATE SET"
                " vendor = excluded.vendor, label = excluded.label, tags = excluded.tags,"
                " notes = excluded.notes, category = excluded.category,"
                " is_known = excluded.is_known, trust_state = excluded.trust_state,"
                " first_seen = excluded.first_seen,"
                " last_seen = excluded.last_seen, last_ip = excluded.last_ip,"
                " times_seen = excluded.times_seen, open_ports = excluded.open_ports,"
                " hostname = excluded.hostname, os_guess = excluded.os_guess",
                (
                    device.mac,
                    device.vendor,
                    device.label,
                    json.dumps(list(device.tags)),
                    device.notes,
                    device.category,
                    int(device.is_known),
                    device.trust_state.value,
                    _fmt_dt(device.first_seen),
                    _fmt_dt(device.last_seen),
                    device.last_ip,
                    device.times_seen,
                    json.dumps(list(device.open_ports)),
                    device.hostname,
                    device.os_guess,
                ),
            )

    def delete(self, mac: str) -> None:
        # BUG-1-FIX: beide Tabellen in EINER Transaktion raeumen. Idempotent.
        norm = normalize_mac(mac)
        with self._connect() as conn:
            conn.execute("DELETE FROM devices WHERE mac = ?", (norm,))
            conn.execute("DELETE FROM device_ip_history WHERE mac = ?", (norm,))

    def append_ip_history(self, entry: IpHistoryEntry) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO device_ip_history (mac, ip, seen_at) VALUES (?, ?, ?)",
                (entry.mac, entry.ip, _fmt_dt(entry.seen_at)),
            )

    def get_ip_history(self, mac: str, limit: int = 20) -> list[IpHistoryEntry]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT mac, ip, seen_at FROM device_ip_history WHERE mac = ?"
                " ORDER BY seen_at DESC, id DESC LIMIT ?",
                (normalize_mac(mac), limit),
            ).fetchall()
        return [
            IpHistoryEntry(mac=row["mac"], ip=row["ip"], seen_at=_parse_dt(row["seen_at"]))
            for row in rows
        ]

    def stats(self, active_since: datetime) -> DeviceStats:
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
            known = conn.execute("SELECT COUNT(*) FROM devices WHERE is_known = 1").fetchone()[0]
            active = conn.execute(
                "SELECT COUNT(*) FROM devices WHERE last_seen >= ?",
                (_fmt_dt(active_since),),
            ).fetchone()[0]
        return DeviceStats(total=total, known=known, unknown=total - known, active=active)
