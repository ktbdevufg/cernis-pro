"""SQLite-Adapter fuer den Port ``RttHistoryRepository`` (Altcode-Tabelle ``rtt_history``).

Basiert auf ``modules/monitor.py`` (``_save_rtt`` / ``get_rtt_history`` /
``_init_monitor_db``), im Stil von ``SqliteScanHistoryRepository``: ``@contextmanager
_connect`` mit Transaktion + garantiertem close, ``_ensure_schema`` im Konstruktor,
injizierter DB-Pfad. KEIN ``modules``-Import (eigenes Schema).

SCHEMA-ENTSCHEIDUNG (M.4, v2-Wurzel-Fix): Die Tabelle wird MIT einer ``alive``-Spalte
angelegt -- der Altcode (``_init_monitor_db``) legte sie OHNE an, was die in M.1
dokumentierte gemeinsame Wurzel dreier toter Straenge ist (metrics-``alive``-Block,
homeassistant, influx; sie lesen ``rtt_history.alive``, das es nie gab). ``save``
schreibt ``PingSample.alive`` mit, ``recent`` liest es -> ``PingSample.alive`` wird
korrekt rekonstruiert. Sichtbar wird der Fix, sobald M.8 die Spalte liest.

MIGRATIONS-GUARD (der riskante Pfad): Eine Box, auf der der Altcode-Loop bereits lief,
hat eine ``rtt_history`` OHNE ``alive`` in DERSELBEN ``cernis.db``. ``CREATE TABLE IF
NOT EXISTS`` ist dort ein No-Op -> die Spalte fehlte weiter -> ``save``/``recent``
mit ``alive`` wuerden auf ``no such column: alive`` knallen. Darum prueft
``_ensure_schema`` nach dem CREATE per ``PRAGMA table_info``, ob ``alive`` existiert,
und ergaenzt sie sonst idempotent via ``ALTER TABLE ... ADD COLUMN alive INTEGER
DEFAULT 0``. Alt-Zeilen bekommen den Default ``0`` (-> ``PingSample.alive=False``),
analog dem scanning-Legacy-Blob-``source="ping"``-Default.

Reihenfolge (charakterisierungstreu, M.3-Port + M.1): ``recent`` liefert die Samples
CHRONOLOGISCH AUFSTEIGEND -- der Altcode ``get_rtt_history`` selektiert ``ORDER BY ts
DESC`` und dreht via ``reversed``. RTT-Sentinel ``-1.0`` bleibt unveraendert.
"""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from domain.monitoring import PingSample


class SqliteRttHistoryRepository:
    """Erfuellt das ``RttHistoryRepository``-Protocol strukturell (SQLite)."""

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
        # CREATE mit alive; danach idempotenter ALTER-Guard fuer Alt-Tabellen ohne
        # alive (vom Altcode-Loop angelegt). Reihenfolge wichtig: erst CREATE (No-Op
        # bei Alt-Tabelle), dann PRAGMA-Check + ALTER.
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS rtt_history (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id TEXT,
                    rtt_ms    REAL,
                    loss_pct  REAL,
                    ts        REAL,
                    alive     INTEGER DEFAULT 0
                )
                """
            )
            cols = {row["name"] for row in conn.execute("PRAGMA table_info(rtt_history)")}
            if "alive" not in cols:
                # Alt-Tabelle vom Altcode-Loop -> Spalte nachruesten (Default 0).
                conn.execute("ALTER TABLE rtt_history ADD COLUMN alive INTEGER DEFAULT 0")

    def save(self, sample: PingSample) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO rtt_history (target_id, rtt_ms, loss_pct, ts, alive) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    sample.target_id,
                    sample.rtt_ms,
                    sample.loss_pct,
                    sample.timestamp,
                    int(sample.alive),
                ),
            )
            # 1000-Trim pro Target (Adapter-Mechanik, wie Altcode _save_rtt).
            conn.execute(
                """
                DELETE FROM rtt_history WHERE id IN (
                    SELECT id FROM rtt_history WHERE target_id = ?
                    ORDER BY ts DESC LIMIT -1 OFFSET 1000
                )
                """,
                (sample.target_id,),
            )

    def recent(self, target_id: str, limit: int) -> list[PingSample]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT target_id, rtt_ms, loss_pct, ts, alive FROM rtt_history "
                "WHERE target_id = ? ORDER BY ts DESC LIMIT ?",
                (target_id, limit),
            ).fetchall()
        # ORDER BY ts DESC + reversed -> chronologisch aufsteigend (Altcode-treu).
        return [
            PingSample(
                target_id=row["target_id"],
                host="",  # rtt_history persistiert keinen host -- Domaenen-Default.
                alive=bool(row["alive"]),
                rtt_ms=row["rtt_ms"],
                loss_pct=row["loss_pct"],
                timestamp=row["ts"],
            )
            for row in reversed(rows)
        ]
