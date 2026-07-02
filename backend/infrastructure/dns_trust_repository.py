"""SQLite-Adapter fuer ``DnsTrustRepository`` (Tabelle ``dns_trust_servers``, ADR 0043, E2).

Persistenz der nutzer-kuratierten DNS-Server, im Stil von
``SqliteDnsBypassRecordingRepository``: ``@contextmanager _connect`` (``sqlite3.Row``,
``with conn``, garantiertes ``close``), ``_ensure_schema`` im Konstruktor (idempotentes
``CREATE TABLE IF NOT EXISTS`` + ``mkdir(parents=True, exist_ok=True)``), injizierter
``db_path: Path``. KEIN ``modules``-Import; die ``db_path``-Verdrahtung kommt spaeter
(Composition Root), hier NICHT.

UPSERT (kein reines Append): Schluessel ist die ``ip`` (PRIMARY KEY). ``upsert`` ist
``INSERT OR REPLACE`` -- ein zweiter Aufruf derselben ``ip`` ersetzt die Zeile. ``upsert``
schreibt KEINE Uhr: ``first_seen``/``last_seen`` kommen fertig aus dem ``server``.

ENUM-ROUND-TRIP: ``category`` und ``trust_state`` werden als ihr ``str``-Wert gespeichert
(``StrEnum`` -> roher String) und beim Lesen via ``DnsServerCategory(...)`` /
``DnsTrustState(...)`` zurueck in die Domaenen-Enums gehoben -- Muster
``SqliteDnsBypassRecordingRepository._row_to_recording``.

SCHMALER SCHREIBPFAD: ``set_trust`` aendert per ``UPDATE`` NUR ``trust_state`` + ``last_seen``
(Kategorie/``first_seen`` unberuehrt). Eine unbekannte ``ip`` betrifft 0 Zeilen -- ein
definierter No-Op (kein Fehler, kein stilles Anlegen), konsistent mit dem Port-Vertrag.
"""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from domain.dns_trust import (
    DnsServerCategory,
    DnsTrustState,
    TrustedDnsServer,
)


class SqliteDnsTrustRepository:
    """Erfuellt das ``DnsTrustRepository``-Protocol strukturell (SQLite)."""

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
        # Idempotentes CREATE -- ip als PRIMARY KEY traegt den Upsert (INSERT OR REPLACE).
        # category/trust_state liegen als ihr str-Wert (TEXT), first_seen/last_seen als
        # Unix-ts (REAL), display_name/notes als Text (Default "" kommt aus dem Aggregat).
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS dns_trust_servers (
                    ip           TEXT PRIMARY KEY,
                    category     TEXT,
                    trust_state  TEXT,
                    first_seen   REAL,
                    last_seen    REAL,
                    display_name TEXT,
                    notes        TEXT
                )
                """
            )

    def upsert(self, server: TrustedDnsServer) -> None:
        # INSERT OR REPLACE -> Upsert ueber PRIMARY KEY ip. category/trust_state als ihr
        # str-Wert (StrEnum -> str); first_seen/last_seen kommen fertig aus dem server
        # (das Repo bleibt uhrfrei).
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO dns_trust_servers (
                    ip, category, trust_state, first_seen,
                    last_seen, display_name, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    server.ip,
                    str(server.category),
                    str(server.trust_state),
                    server.first_seen,
                    server.last_seen,
                    server.display_name,
                    server.notes,
                ),
            )

    def get(self, ip: str) -> TrustedDnsServer | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT ip, category, trust_state, first_seen, "
                "last_seen, display_name, notes "
                "FROM dns_trust_servers WHERE ip = ?",
                (ip,),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_server(row)

    def list_all(self) -> list[TrustedDnsServer]:
        # ORDER BY first_seen (aufsteigend) -- s. Port-Docstring (speist die UI-Uebersicht).
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT ip, category, trust_state, first_seen, "
                "last_seen, display_name, notes "
                "FROM dns_trust_servers ORDER BY first_seen ASC"
            ).fetchall()
        return [self._row_to_server(row) for row in rows]

    def set_trust(self, ip: str, state: DnsTrustState, now: float) -> None:
        # Schmaler Schreibpfad: NUR trust_state + last_seen aendern (category/first_seen
        # bleiben). Neuer state als sein str-Wert, last_seen auf now. Unbekannte ip ->
        # 0 Zeilen betroffen (definierter No-Op, kein stilles Anlegen).
        with self._connect() as conn:
            conn.execute(
                "UPDATE dns_trust_servers SET trust_state = ?, last_seen = ? WHERE ip = ?",
                (str(state), now, ip),
            )

    def delete(self, ip: str) -> None:
        # Idempotent: unbekannte ip -> kein Fehler (DELETE betrifft 0 Zeilen).
        with self._connect() as conn:
            conn.execute("DELETE FROM dns_trust_servers WHERE ip = ?", (ip,))

    def clear_all(self) -> None:
        # Leert alle kuratierten Server (nur die eigene Tabelle dns_trust_servers).
        with self._connect() as conn:
            conn.execute("DELETE FROM dns_trust_servers")

    @staticmethod
    def _row_to_server(row: sqlite3.Row) -> TrustedDnsServer:
        # Enum-Round-trip: gespeicherte Strings zurueck in die Domaenen-Enums
        # (Muster SqliteDnsBypassRecordingRepository._row_to_recording).
        return TrustedDnsServer(
            ip=row["ip"],
            category=DnsServerCategory(row["category"]),
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            trust_state=DnsTrustState(row["trust_state"]),
            display_name=row["display_name"],
            notes=row["notes"],
        )
