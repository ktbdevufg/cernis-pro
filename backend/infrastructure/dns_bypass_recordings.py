"""SQLite-Adapter fuer ``DnsBypassRecordingRepository`` (Tabelle ``dns_bypass_recordings``).

Persistenz der DNS-Umgehungs-Aufzeichnungs-DEFINITIONEN, im Stil von
``SqliteOutboundRecordingRepository``: ``@contextmanager _connect`` (``sqlite3.Row``,
``with conn``, garantiertes ``close``), ``_ensure_schema`` im Konstruktor (idempotentes
``CREATE TABLE IF NOT EXISTS`` + ``mkdir(parents=True, exist_ok=True)``), injizierter
``db_path: Path``. KEIN ``modules``-Import; die ``db_path``-Verdrahtung kommt spaeter
(Composition Root), hier NICHT.

UPSERT (kein reines Append): Der ``state`` einer Aufzeichnung wandert ueber ihre
Lebenszeit (``CREATED`` -> ``ACTIVE`` -> ``FINISHED``) -- ``save`` ist darum ``INSERT OR
REPLACE`` ueber den PRIMARY KEY ``id``.

ENUM-ROUND-TRIP: Der ``state`` wird als sein ``str``-Wert gespeichert (``StrEnum`` ->
roher String) und beim Lesen via ``DnsBypassRecordingState(...)`` zurueck in das
Domaenen-Enum gehoben -- Muster ``SqliteOutboundRecordingRepository._row_to_recording``.
``effective_start``/``interface`` sind nullable (sqlite gibt ``None`` zurueck).

JSON-ROUND-TRIP: ``expected_servers`` ist eine Tuple aus Strings (Momentaufnahme der
erwarteten Resolver-Menge). Sie wird als JSON-Text-Liste abgelegt und beim Lesen zurueck
in eine ``tuple[str, ...]`` gehoben -- sauber round-trip-bar, statt ein Trenner-Join, der
an ``.`` oder ``:`` in IPv6-Adressen scheitern koennte.
"""

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from domain.dns_bypass import (
    DnsBypassRecording,
    DnsBypassRecordingState,
)


class SqliteDnsBypassRecordingRepository:
    """Erfuellt das ``DnsBypassRecordingRepository``-Protocol strukturell (SQLite)."""

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
        # Idempotentes CREATE -- id als PRIMARY KEY traegt den Upsert (INSERT OR
        # REPLACE). Der state liegt als sein str-Wert (TEXT), effective_start/interface
        # nullable (s. Domaene: None erlaubt), expected_servers als JSON-Text-Liste.
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS dns_bypass_recordings (
                    id               TEXT PRIMARY KEY,
                    label            TEXT,
                    purpose          TEXT,
                    state            TEXT,
                    created_at       REAL,
                    effective_start  REAL,
                    interface        TEXT,
                    expected_servers TEXT
                )
                """
            )

    def save(self, recording: DnsBypassRecording) -> None:
        # INSERT OR REPLACE -> Upsert ueber PRIMARY KEY id (neuer state bei jedem
        # Lebenszyklus-Uebergang). state als sein str-Wert (StrEnum -> str),
        # expected_servers als JSON-Text-Liste.
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO dns_bypass_recordings (
                    id, label, purpose, state, created_at,
                    effective_start, interface, expected_servers
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    recording.id,
                    recording.label,
                    recording.purpose,
                    str(recording.state),
                    recording.created_at,
                    recording.effective_start,
                    recording.interface,
                    json.dumps(list(recording.expected_servers)),
                ),
            )

    def get(self, recording_id: str) -> DnsBypassRecording | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, label, purpose, state, created_at, "
                "effective_start, interface, expected_servers "
                "FROM dns_bypass_recordings WHERE id = ?",
                (recording_id,),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_recording(row)

    def list_all(self) -> list[DnsBypassRecording]:
        # ORDER BY created_at (aufsteigend) -- s. Port-Docstring.
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, label, purpose, state, created_at, "
                "effective_start, interface, expected_servers "
                "FROM dns_bypass_recordings ORDER BY created_at"
            ).fetchall()
        return [self._row_to_recording(row) for row in rows]

    def delete(self, recording_id: str) -> None:
        # Idempotent: unbekannte id -> kein Fehler (DELETE betrifft 0 Zeilen).
        # Nur die Definition -- die Messdaten (Detail/Aggregat) liegen in eigenen Repos.
        with self._connect() as conn:
            conn.execute("DELETE FROM dns_bypass_recordings WHERE id = ?", (recording_id,))

    def clear_all(self) -> None:
        # Leert alle Definitionen (nur die eigene Tabelle dns_bypass_recordings).
        with self._connect() as conn:
            conn.execute("DELETE FROM dns_bypass_recordings")

    @staticmethod
    def _row_to_recording(row: sqlite3.Row) -> DnsBypassRecording:
        # Enum-Round-trip: gespeicherter String zurueck in das Domaenen-Enum
        # (Muster SqliteOutboundRecordingRepository._row_to_recording). expected_servers
        # aus der JSON-Text-Liste zurueck in eine tuple[str, ...].
        return DnsBypassRecording(
            id=row["id"],
            label=row["label"],
            purpose=row["purpose"],
            state=DnsBypassRecordingState(row["state"]),
            created_at=row["created_at"],
            effective_start=row["effective_start"],
            interface=row["interface"],
            expected_servers=tuple(json.loads(row["expected_servers"])),
        )
