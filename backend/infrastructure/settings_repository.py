"""SQLite-Adapter fuer den Port ``SettingsRepository``.

Strangler-Fig: nutzt DIESELBE ``settings``-Tabelle in ``cernis.db`` wie der
Altcode (``modules/storage.py``) -- gleiches Schema (``key`` PK, ``value`` als
JSON-in-TEXT), keine Datenmigration. Alt und neu koexistieren auf derselben
Tabelle.

Bewusst NICHT aus dem Altcode uebernommen (dokumentiert in den
Characterization-Tests):

* KEIN stiller Roh-Fallback (Finding S3): schlaegt ``json.loads`` fehl, ist das
  ein FEHLER (``CorruptSettingError``), nicht "gib den Rohstring zurueck".
* ``get_all`` verschluckt einen Nicht-JSON-Wert nicht still und crasht auch
  nicht mit einem nichtssagenden ``JSONDecodeError`` -- es wirft eine klare
  Exception MIT Key-Bezug.

Secret-Keys gehoeren NICHT hierher, sondern in den ``SecretStore`` (6d.2). Dieser
Adapter kennt keine Secret-Logik; die Trennung erzwingt der Use-Case (6e).

Der DB-Pfad wird injiziert (kein Hardcoding) -- die Pfad-Aufloesung ueber
``db_path.py`` passiert im Composition Root (``app.py``), nicht im Adapter.
"""

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from domain.settings import Setting, SettingValue


class CorruptSettingError(Exception):
    """Ein gespeicherter Setting-Wert ist kein gueltiges JSON.

    Ersetzt den stillen Roh-Fallback des Altcodes (Finding S3): ein kaputter
    Wert ist ein Fehler mit Key-Bezug, kein leiser Rueckfall auf den Rohstring.
    """

    def __init__(self, key: str, raw_value: str) -> None:
        self.key = key
        self.raw_value = raw_value
        super().__init__(f"Setting {key!r} enthaelt kein gueltiges JSON: {raw_value!r}")


def _decode(key: str, raw_value: str) -> SettingValue:
    """Dekodiert einen gespeicherten JSON-Wert -- ohne stillen Fallback."""
    try:
        decoded: SettingValue = json.loads(raw_value)
    except json.JSONDecodeError as exc:
        raise CorruptSettingError(key, raw_value) from exc
    return decoded


class SqliteSettingsRepository:
    """Erfuellt das ``SettingsRepository``-Protocol strukturell (SQLite)."""

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
        # Gleiches Schema wie der Altcode -- idempotent, damit alt und neu auf
        # derselben Tabelle koexistieren (Strangler-Fig).
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS settings ("
                "    key   TEXT PRIMARY KEY,"
                "    value TEXT NOT NULL"
                ")"
            )

    def get_all(self) -> dict[str, SettingValue]:
        with self._connect() as conn:
            rows = conn.execute("SELECT key, value FROM settings").fetchall()
        return {row["key"]: _decode(row["key"], row["value"]) for row in rows}

    def get(self, key: str) -> Setting | None:
        with self._connect() as conn:
            row = conn.execute("SELECT key, value FROM settings WHERE key = ?", (key,)).fetchone()
        if row is None:
            return None
        return Setting(key=row["key"], value=_decode(row["key"], row["value"]))

    def set(self, setting: Setting) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (setting.key, json.dumps(setting.value)),
            )

    def delete(self, key: str) -> None:
        # Idempotent: DELETE auf einen fehlenden Key ist kein Fehler.
        with self._connect() as conn:
            conn.execute("DELETE FROM settings WHERE key = ?", (key,))

    def clear_all(self) -> None:
        # Leert alle Settings (nur die eigene Tabelle settings).
        with self._connect() as conn:
            conn.execute("DELETE FROM settings")
