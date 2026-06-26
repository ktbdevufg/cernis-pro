"""SQLite-Adapter fuer ``BlocklistEntryRepository`` (Tabelle ``blocklist_entries``).

Persistenz der geparsten Blocklist-EINTRAEGE, im Stil von
``infrastructure/outbound_log_detail.py``: ``@contextmanager _connect``
(``sqlite3.Row``, ``with conn``, garantiertes ``close``), ``_ensure_schema`` im
Konstruktor (idempotentes ``CREATE TABLE IF NOT EXISTS`` + ``mkdir(parents=True,
exist_ok=True)``), injizierter ``db_path: Path``. KEIN ``modules``-Import.

KIND-TRENNUNG: Jeder Eintrag ist entweder ``kind='domain'`` (Domain-Suffix-Lookup) oder
``kind='ip_cidr'`` (exakte IP oder echtes Netz). Zwei Indizes tragen die Lookups:
``idx_blocklist_entries_domain`` auf ``(kind, value)`` fuer den Domain-IN-Lookup,
``idx_blocklist_entries_src`` auf ``(source_id)`` fuer ``replace_entries``/``delete_for``/
``count_for``.

CIDR-LOOKUP: Exakte ``/32``-/``/128``-Treffer laufen ueber den indizierten
Gleichheits-Lookup; echte Netze (Eintrag enthaelt ``/``) werden geladen und per
``domain.blocklist.ip_in_cidr`` geprueft. Lineare Pruefung der CIDR-Eintraege ist bei
wenigen tausend Netzen (FireHOL L1) akzeptabel -- einfach und korrekt.

SQL-SICHERHEIT: Der ``IN``-Lookup baut nur die Platzhalter (``?``) als f-string, NIE die
Werte -- die Werte sind ausschliesslich parameter-gebunden.
"""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from domain.blocklist import ip_in_cidr

_KIND_DOMAIN = "domain"
_KIND_IP_CIDR = "ip_cidr"


class SqliteBlocklistEntryRepository:
    """Erfuellt das ``BlocklistEntryRepository``-Protocol strukturell (SQLite)."""

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
        # Eintraege + zwei Indizes: (kind, value) traegt den Domain-Suffix-IN-Lookup,
        # (source_id) traegt replace_entries/delete_for/count_for.
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS blocklist_entries (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_id TEXT,
                    kind      TEXT,
                    value     TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_blocklist_entries_domain "
                "ON blocklist_entries (kind, value)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_blocklist_entries_src "
                "ON blocklist_entries (source_id)"
            )

    def replace_entries(self, source_id: str, domains: list[str], ip_cidrs: list[str]) -> None:
        # Atomarer Austausch in EINER Transaktion: erst alte Eintraege der source_id
        # loeschen, dann die neuen per executemany einfuegen (domains -> kind 'domain',
        # ip_cidrs -> kind 'ip_cidr'). Der with-conn-Block der _connect klammert beides.
        with self._connect() as conn:
            conn.execute("DELETE FROM blocklist_entries WHERE source_id = ?", (source_id,))
            if domains:
                conn.executemany(
                    "INSERT INTO blocklist_entries (source_id, kind, value) VALUES (?, ?, ?)",
                    [(source_id, _KIND_DOMAIN, value) for value in domains],
                )
            if ip_cidrs:
                conn.executemany(
                    "INSERT INTO blocklist_entries (source_id, kind, value) VALUES (?, ?, ?)",
                    [(source_id, _KIND_IP_CIDR, value) for value in ip_cidrs],
                )

    def delete_for(self, source_id: str) -> None:
        # Idempotent: unbekannte source_id trifft 0 Zeilen (kein Fehler).
        with self._connect() as conn:
            conn.execute("DELETE FROM blocklist_entries WHERE source_id = ?", (source_id,))

    def count_for(self, source_id: str) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM blocklist_entries WHERE source_id = ?",
                (source_id,),
            ).fetchone()
        return int(row["n"])

    def lookup_domains(self, candidates: list[str]) -> list[tuple[str, str]]:
        # Set-Lookup ueber (kind, value). Leere Kandidatenliste -> [] (kein leeres IN()).
        # Nur die Platzhalter werden gebaut, die Werte bleiben parameter-gebunden.
        if not candidates:
            return []
        placeholders = ",".join("?" for _ in candidates)
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT source_id, value FROM blocklist_entries "
                f"WHERE kind = '{_KIND_DOMAIN}' AND value IN ({placeholders})",
                candidates,
            ).fetchall()
        return [(row["source_id"], row["value"]) for row in rows]

    def lookup_ips(self, ip: str) -> list[tuple[str, str]]:
        # Zwei Pfade: (1) exakter Gleichheits-Lookup ueber den Index (value gleich der IP
        # selbst oder mit explizitem /32 bzw. /128); (2) echte Netze (value enthaelt '/'
        # und ist kein Host-Praefix) iterierend per domain.blocklist.ip_in_cidr.
        matches: list[tuple[str, str]] = []
        with self._connect() as conn:
            exact_rows = conn.execute(
                "SELECT source_id, value FROM blocklist_entries "
                "WHERE kind = ? AND value IN (?, ?, ?)",
                (_KIND_IP_CIDR, ip, f"{ip}/32", f"{ip}/128"),
            ).fetchall()
            cidr_rows = conn.execute(
                "SELECT source_id, value FROM blocklist_entries "
                "WHERE kind = ? AND value LIKE '%/%'",
                (_KIND_IP_CIDR,),
            ).fetchall()
        for row in exact_rows:
            matches.append((row["source_id"], row["value"]))
        # Echte Netze pruefen; exakte /32|/128 sind oben schon erfasst -> hier ueber-
        # springen, damit ein Treffer nicht doppelt erscheint.
        seen_exact = {row["value"] for row in exact_rows}
        for row in cidr_rows:
            value = row["value"]
            if value in seen_exact:
                continue
            if ip_in_cidr(ip, value):
                matches.append((row["source_id"], value))
        return matches

    def clear_all(self) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM blocklist_entries")
