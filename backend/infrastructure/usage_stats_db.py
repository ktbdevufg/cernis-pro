"""SQLite-Adapter fuer den Port ``UsageStatsRepository`` (Nutzungs-Ranking).

``SqliteUsageStatsRepository`` zaehlt je stabilem ``feature_id`` die Zahl der Funktions-
Oeffnungen in einer eigenen Tabelle ``usage_stats`` -- STIL EXAKT wie
``settings_repository.py`` / ``analysis_rules_db.py``:

* injizierter ``db_path`` (Pfad-Aufloesung im Composition Root ``app.py``, nicht hier),
* ``_ensure_schema`` im ``__init__``,
* ``@contextmanager _connect`` mit Transaktion (commit/rollback) + garantiertem ``close``,
* ``CREATE TABLE IF NOT EXISTS usage_stats`` -- teilt die ``cernis.db`` mit dem Bestand.

Die Zaehlung ist persistent ueber Neustarts (SQLite-Tabelle). ``increment`` ist ein Upsert
(``INSERT ... ON CONFLICT(feature_id) DO UPDATE``, Muster ``settings_repository.set``):
existiert der Schluessel nicht, wird er mit ``count = 1`` angelegt; sonst um 1 erhoeht. In
BEIDEN Faellen wird ``last_used`` auf JETZT gesetzt (ISO-8601-UTC-Text, Muster ``_fmt_dt``
aus ``device_repository`` / ``default_creds_history_db``).

``top`` sortiert absteigend nach ``count``; Tiebreaker bei Gleichstand ist ``last_used``
absteigend (die juengst genutzte Funktion zuerst) -- so blockiert eine einmalige, alte
Nutzung keinen Rang dauerhaft. ``get_all`` liefert alle Datensaetze ungefiltert.

``feature_id`` ist ein STABILER String-Schluessel vom Frontend (z. B. ``"observe:scan"``).
KEINE Validierung gegen eine feste Liste -- das Backend zaehlt nur (offen fuer neue
Funktionen ohne Backend-Aenderung). Der Adapter importiert KEIN ``modules`` (kein ADR-0007-
Fall; ``db_path`` wird injiziert). UHR am Rand: die Domaene traegt keine Zeit.
"""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from ports.usage import UsageRecord

__all__ = ["SqliteUsageStatsRepository"]


def _fmt_dt(value: datetime) -> str:
    """datetime -> fixes ISO-8601-UTC-TEXT (immer 6-stellige Mikrosekunden).

    Naive Eingaben werden als UTC interpretiert (Muster ``device_repository._fmt_dt``).
    Das fixe Format macht TEXT-Vergleiche lexikografisch chronologisch korrekt -- genau
    das nutzt ``top`` fuer den ``last_used``-Tiebreaker.
    """
    aware = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return aware.astimezone(UTC).isoformat(timespec="microseconds")


class SqliteUsageStatsRepository:
    """Erfuellt das ``UsageStatsRepository``-Protocol strukturell (SQLite)."""

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
        # Eigene Tabelle (NICHT settings zweckentfremdet). feature_id ist der PRIMARY KEY
        # (der stabile Frontend-Schluessel); count startet bei 0 (DEFAULT), last_used ist
        # NULL, bis die Funktion erstmals geoeffnet wurde. Idempotent -- teilt die cernis.db.
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS usage_stats ("
                "    feature_id TEXT PRIMARY KEY,"
                "    count      INTEGER NOT NULL DEFAULT 0,"
                "    last_used  TEXT"
                ")"
            )

    def increment(self, feature_id: str) -> None:
        """Erhoeht den Zaehler fuer ``feature_id`` um 1 und setzt ``last_used`` = jetzt.

        Upsert (Muster ``settings_repository.set``): der erste Aufruf legt den Schluessel
        mit ``count = 1`` an; jeder weitere erhoeht den bestehenden Zaehler. ``last_used``
        wird in beiden Faellen auf den aktuellen ISO-UTC-Zeitstempel gesetzt.
        """
        now = _fmt_dt(datetime.now(UTC))
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO usage_stats (feature_id, count, last_used) VALUES (?, 1, ?) "
                "ON CONFLICT(feature_id) DO UPDATE SET "
                "    count = count + 1,"
                "    last_used = excluded.last_used",
                (feature_id, now),
            )

    def top(self, limit: int = 5) -> list[UsageRecord]:
        """Die ``limit`` meistgeoeffneten Funktionen, absteigend nach ``count``.

        Tiebreaker bei Gleichstand: ``last_used`` absteigend (juengste zuerst) -- das fixe
        ISO-UTC-Textformat macht den lexikografischen ``ORDER BY`` chronologisch korrekt.
        Weniger als ``limit`` Eintraege -> kuerzere Liste; keine -> ``[]``.
        """
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT feature_id, count, last_used FROM usage_stats "
                "ORDER BY count DESC, last_used DESC "
                "LIMIT ?",
                (limit,),
            ).fetchall()
        return [_row_to_record(row) for row in rows]

    def get_all(self) -> list[UsageRecord]:
        """Alle gespeicherten Zaehlstaende (ungefiltert). Leer -> ``[]``."""
        with self._connect() as conn:
            rows = conn.execute("SELECT feature_id, count, last_used FROM usage_stats").fetchall()
        return [_row_to_record(row) for row in rows]


def _row_to_record(row: sqlite3.Row) -> UsageRecord:
    # Row -> ports-Rand-Read-View. last_used bleibt None, falls (theoretisch) NULL.
    return UsageRecord(
        feature_id=row["feature_id"],
        count=row["count"],
        last_used=row["last_used"],
    )
