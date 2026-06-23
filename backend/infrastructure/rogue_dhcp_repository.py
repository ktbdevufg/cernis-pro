"""SQLite-Adapter fuer den Port ``RogueDhcpStore`` (diagnostics-Domaene, ADR 0038).

Schmale Persistenz NUR fuer den LETZTEN Rogue-DHCP-Stand: genau EIN Datensatz,
ueberschreibend (kein Verlauf -- YAGNI). Zweck: der spaetere Sicherheitsbericht zeigt den
letzten bekannten Stand mit Datum, ohne selbst einen aktiven (root-pflichtigen) DHCP-Probe
auszuloesen.

Stil EXAKT wie die Vorbild-Adapter (``SqliteSettingsRepository`` /
``SqliteDeviceRepository`` / ``SqliteArpGuardRepository``): eigener ``cernis.db``-
DB-Pfad injiziert (kein Hardcoding -- die Pfad-Aufloesung ueber ``db_path.py`` passiert im
Composition Root, ``app.py``, NICHT im Adapter), ``_ensure_schema`` im Konstruktor
(idempotentes ``CREATE TABLE IF NOT EXISTS``), ``_connect`` als Context-Manager mit
Transaktion (``with conn``) und garantiertem ``close``.

ZWEI bewusste Wahlen, hier dokumentiert:

* SINGLETON-ROW: die Tabelle haelt IMMER nur eine Zeile -- erzwungen ueber einen FESTEN
  Primaerschluessel (``id INTEGER PRIMARY KEY CHECK (id = 1)``) + ``INSERT ... ON CONFLICT
  (id) DO UPDATE`` (UPSERT, Muster ``SqliteSettingsRepository.set``). Jeder ``save_latest``
  ueberschreibt also dieselbe Zeile -- kein Verlauf, kein Aufraeumen noetig. (Es gibt im
  Bestand kein Singleton-Row-Vorbild -- alle anderen Repos halten Mehrzeilen-Tabellen mit
  echtem PK; hier ist die Singleton-Semantik bewusst neu, weil der Auftrag GENAU einen
  ueberschreibenden Datensatz verlangt.)
* SERVER-LISTE ALS JSON-SPALTE (nicht als Detailtabelle): die Vorbilder halten variable
  Listen ebenfalls als JSON-in-TEXT (``SqliteSettingsRepository`` -> JSON; Device
  ``tags``/``open_ports`` -> JSON-Spalte). Eine eigene Detailtabelle waere fuer einen
  einzigen ueberschreibenden Datensatz Overhead (Join + Aufraeumen je Speichern) -- die
  JSON-Spalte ist die schmalere, zum Bestand passende Wahl. Kein stiller Fallback bei
  kaputtem JSON (Finding S3): ein nicht dekodierbarer Wert ist ein Fehler (``CorruptRogue
  DhcpError``), kein leiser Rueckfall (Muster ``CorruptSettingError``/``CorruptDeviceError``).
"""

import json
import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path

from ports.diagnostics import LatestRogueDhcp, RogueDhcpServerRecord

# Fester Primaerschluessel der Singleton-Zeile (es gibt genau diese eine).
_SINGLETON_ID = 1


class CorruptRogueDhcpError(Exception):
    """Die gespeicherte ``servers``/``expected``-JSON-Spalte ist kein gueltiges JSON.

    Ersetzt einen stillen Roh-/Leer-Fallback (Finding S3): ein kaputter Wert ist ein Fehler
    MIT Spalten-Bezug (Muster ``CorruptSettingError``/``CorruptDeviceError``).
    """

    def __init__(self, column: str, raw_value: str) -> None:
        self.column = column
        self.raw_value = raw_value
        super().__init__(f"Spalte {column!r} enthaelt kein gueltiges JSON: {raw_value!r}")


def _decode_json_list(column: str, raw: str) -> list[object]:
    """JSON-TEXT -> Liste. Kein stiller Fallback: kaputtes/typfremdes JSON -> Exception."""
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CorruptRogueDhcpError(column, raw) from exc
    if not isinstance(decoded, list):
        raise CorruptRogueDhcpError(column, raw)
    return decoded


def _row_to_servers(raw: str) -> tuple[RogueDhcpServerRecord, ...]:
    """JSON-Spalte ``servers`` -> ``RogueDhcpServerRecord``-Tupel (mac=None ueberlebt).

    Jeder Eintrag ist ein ``{"ip", "mac", "is_expected"}``-Objekt. ``mac`` bleibt ehrlich
    ``None``, wenn so gespeichert (kein erfundener Wert). Ein typfremder Eintrag ist ein
    Fehler (kein stiller Fallback, S3) -- die Spalte ist von uns geschrieben, ein anderer
    Inhalt ist eine echte Korruption.
    """
    servers: list[RogueDhcpServerRecord] = []
    for item in _decode_json_list("servers", raw):
        if not isinstance(item, dict):
            raise CorruptRogueDhcpError("servers", raw)
        servers.append(
            RogueDhcpServerRecord(
                ip=str(item["ip"]),
                mac=None if item["mac"] is None else str(item["mac"]),
                is_expected=bool(item["is_expected"]),
            )
        )
    return tuple(servers)


class SqliteRogueDhcpRepository:
    """Erfuellt das ``RogueDhcpStore``-Protocol strukturell (SQLite, Singleton-Row)."""

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
        # Idempotentes Schema (Muster der uebrigen SQLite-Repos). Singleton-Row erzwungen
        # ueber den festen PK + CHECK (id = 1): es kann nur die eine Zeile geben. servers/
        # expected als JSON-TEXT (Listen, s. Modul-Docstring), checked_ts als REAL (Unix-ts).
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS rogue_dhcp_latest ("
                "    id            INTEGER PRIMARY KEY CHECK (id = 1),"
                "    servers       TEXT NOT NULL,"
                "    expected      TEXT NOT NULL,"
                "    has_unexpected INTEGER NOT NULL,"
                "    checked_ts    REAL NOT NULL"
                ")"
            )

    def save_latest(
        self,
        result_servers: Sequence[tuple[str, str | None, bool]],
        result_expected: Sequence[str],
        has_unexpected: bool,
        checked_ts: float,
    ) -> None:
        # Genau die eine Singleton-Zeile setzen/ueberschreiben (UPSERT auf den festen PK,
        # Muster SqliteSettingsRepository.set). servers/expected als JSON-TEXT serialisiert
        # (mac=None bleibt JSON-null -> ueberlebt den Round-trip).
        servers_json = json.dumps(
            [
                {"ip": ip, "mac": mac, "is_expected": is_expected}
                for ip, mac, is_expected in result_servers
            ]
        )
        expected_json = json.dumps(list(result_expected))
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO rogue_dhcp_latest"
                " (id, servers, expected, has_unexpected, checked_ts)"
                " VALUES (?, ?, ?, ?, ?)"
                " ON CONFLICT(id) DO UPDATE SET"
                "  servers = excluded.servers, expected = excluded.expected,"
                "  has_unexpected = excluded.has_unexpected, checked_ts = excluded.checked_ts",
                (
                    _SINGLETON_ID,
                    servers_json,
                    expected_json,
                    int(has_unexpected),
                    checked_ts,
                ),
            )

    def load_latest(self) -> LatestRogueDhcp | None:
        # Die eine Singleton-Zeile lesen; leer -> None (noch nie geprueft, ehrliche Leere).
        with self._connect() as conn:
            row = conn.execute(
                "SELECT servers, expected, has_unexpected, checked_ts"
                " FROM rogue_dhcp_latest WHERE id = ?",
                (_SINGLETON_ID,),
            ).fetchone()
        if row is None:
            return None
        expected = tuple(str(item) for item in _decode_json_list("expected", row["expected"]))
        return LatestRogueDhcp(
            servers=_row_to_servers(row["servers"]),
            expected=expected,
            has_unexpected=bool(row["has_unexpected"]),
            checked_ts=row["checked_ts"],
        )
