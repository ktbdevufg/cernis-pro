"""SQLite-Adapter fuer den per-Host-Pruefstand (``CveCheckStateRepository``, ADR 0037).

Haelt pro MAC genau EINEN Stand: wann zuletzt geprueft (``last_checked_ts``) und mit
welchem offenen Port-Set (``checked_ports``). Grundlage der Faelligkeit (Faelle 2+3,
``domain.cve.policy.due_reason``). Upsert auf ``mac`` (PRIMARY KEY).

Das Port-Set wird als sortierte, komma-getrennte Zahlenliste in EINER TEXT-Spalte
gehalten (z. B. "22,80,443"). Bewusst KEIN JSON-Blob: es sind nur Integer, die
serialisierung ist trivial-deterministisch -- ein leeres Set -> leerer String "".

Stil EXAKT wie ``analysis_acknowledgements_db.py``: injizierter ``db_path``,
``_ensure_schema`` im ``__init__``, ``@contextmanager _connect``, ``CREATE TABLE IF NOT
EXISTS``. KEIN ``modules``-Import.

S3-Disziplin: ein leerer Port-String -> leeres Set (legitim, ein Host ohne offene Ports).
Ein nicht-numerisches Fragment in der Spalte (duerfte nie entstehen, da nur ``record``
schreibt) wuerde am ``int()`` LAUT brechen statt leise zu verschlucken -- kein stiller
Fallback. Da der einzige Schreibpfad ``record`` selbst die Zahlen formatiert, ist die
Spalte strukturell sauber; ein Bruch waere ein echter Defekt, kein Datenrand.
"""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import structlog

from domain.cve.models import HostCheckState
from infrastructure._cve_mac import migrate_macs_to_upper, normalize_mac_case

__all__ = ["SqliteCveCheckStateRepository"]

_logger = structlog.get_logger(__name__)


def _ports_to_text(ports: frozenset[int]) -> str:
    """Port-Set -> sortierte komma-getrennte Liste (deterministisch). Leer -> ""."""
    return ",".join(str(p) for p in sorted(ports))


def _text_to_ports(text: str) -> frozenset[int]:
    """Sortierte Liste -> Port-Set. Leerer String -> leeres Set (kein Fehler)."""
    if not text:
        return frozenset()
    return frozenset(int(part) for part in text.split(","))


class SqliteCveCheckStateRepository:
    """Persistiert den per-Host-Pruefstand (last_checked_ts + Port-Set) in SQLite."""

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
        # mac als PRIMARY KEY -> ein Stand je Host (Upsert). ports als TEXT (sortierte
        # Zahlenliste), last_checked_ts als epoch-float (REAL).
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS cve_check_state (
                    mac             TEXT PRIMARY KEY,
                    last_checked_ts REAL NOT NULL,
                    ports           TEXT NOT NULL DEFAULT ''
                );
                """
            )
            # Altbestand EINMALIG auf Grossschreibung heben (Finding 8). Beim zweiten
            # Start findet der Guard nichts mehr -> No-op. Ein Fehlschlag wird LAUT
            # geloggt, laesst den Start aber weiterlaufen: der Adapter ist auch mit
            # unmigriertem Bestand benutzbar (nur die Alt-Zeilen bleiben unerreichbar),
            # ein toter Backend-Start waere der schlechtere Ausgang.
            try:
                migrated = migrate_macs_to_upper(conn, "cve_check_state")
            except Exception as exc:
                _logger.error("cve_checkstate_mac_migration_failed", error=str(exc))
            else:
                if migrated:
                    _logger.info("cve_checkstate_mac_migration_done", rows=migrated)

    def get(self, mac: str) -> HostCheckState | None:
        """Pruefstand einer MAC, oder ``None`` (Fall 1: noch nie geprueft).

        Die MAC wird auf die kanonische Grossschreibung gehoben, bevor gesucht wird --
        so trifft auch eine Anfrage in Scan-Schreibweise (klein) ihren Stand.
        """
        if not mac:
            return None
        with self._connect() as conn:
            row = conn.execute(
                "SELECT mac, last_checked_ts, ports FROM cve_check_state WHERE mac = ?",
                (normalize_mac_case(mac),),
            ).fetchone()
        if row is None:
            return None
        return HostCheckState(
            mac=row["mac"],
            last_checked_ts=row["last_checked_ts"],
            checked_ports=_text_to_ports(row["ports"]),
        )

    def record(self, mac: str, ports: frozenset[int], checked_ts: float) -> None:
        """Setzt/aktualisiert den Pruefstand einer MAC (Upsert auf mac).

        Geschrieben wird die kanonische Grossschreibung -- unabhaengig davon, in welcher
        Form der Worker die MAC aus dem Scan-Bestand hereinreicht.
        """
        mac = normalize_mac_case(mac)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO cve_check_state (mac, last_checked_ts, ports)
                VALUES (?, ?, ?)
                ON CONFLICT (mac) DO UPDATE SET
                    last_checked_ts = excluded.last_checked_ts,
                    ports           = excluded.ports
                """,
                (mac, checked_ts, _ports_to_text(ports)),
            )

    def clear_all(self) -> None:
        """Leert alle Pruefstaende (nur die eigene Tabelle ``cve_check_state``)."""
        with self._connect() as conn:
            conn.execute("DELETE FROM cve_check_state")

    def all_states(self) -> list[HostCheckState]:
        """Alle Pruefstaende (Status-Endpunkt). Leer -> ``[]``."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT mac, last_checked_ts, ports FROM cve_check_state"
            ).fetchall()
        return [
            HostCheckState(
                mac=row["mac"],
                last_checked_ts=row["last_checked_ts"],
                checked_ports=_text_to_ports(row["ports"]),
            )
            for row in rows
        ]
