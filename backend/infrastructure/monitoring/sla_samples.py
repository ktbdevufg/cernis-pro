"""SQLite-Lese-Adapter fuer den Port ``SlaSampleRepository`` (Altcode-Tabelle
``sla_samples``).

Basiert auf ``modules/sla.py`` (``get_sla_stats``-Query / ``get_all_sla_stats``-
DISTINCT / ``init_sla_db``-Schema), im Stil von ``SqliteRttHistoryRepository``:
``@contextmanager _connect`` mit Transaktion + garantiertem close, ``_ensure_schema``
im Konstruktor, injizierter DB-Pfad. KEIN ``modules``-Import (eigenes Schema).

NUR LESEN. Der Schreibpfad (``record``) fehlt BEWUSST -- ``sla_samples`` wird im
Altcode nie geschrieben (``record_sample`` importiert, nie gerufen). Den Strang zu
beleben ist ein eigener Schritt (M.7b) nach M.9; s. ``ports/monitoring`` und den
M.5-Use-Case. Darum hat dieser Adapter kein INSERT und keinen 90-Tage-Prune.

SCHEMA-ENTSCHEIDUNG (M.7, anders als M.4): ``CREATE TABLE IF NOT EXISTS`` reicht --
KEIN Migrations-Guard noetig. Begruendung: Der Altcode-``init_sla_db`` legt
``sla_samples`` mit GENAU den Spalten an, die hier gelesen werden (``alive``,
``rtt_ms``, ``ts``); es gibt keine fehlende Spalte wie ``rtt_history.alive`` in M.4.
Auf einer Box mit Altcode-Tabelle ist das CREATE ein No-Op und die Spalten passen
exakt -- ein PRAGMA/ALTER-Guard waere ohne Funktion.

BEFUND (toter Altcode-DDL, NICHT reproduziert): Der Altcode-``init_sla_db`` legt
ZUSAETZLICH die Tabelle ``sla_targets`` an, die NIRGENDS gelesen oder geschrieben
wird (reines DDL ohne Nutzung). Der v2-Adapter legt sie NICHT an -- das ist KEINE
Verhaltensabweichung, weil keine Code-Stelle (Alt oder neu) auf ``sla_targets``
zugreift. Toter Ballast, den v2 nicht mitschleppt.

Eine geladene Zeile ist ``(alive, rtt_ms, ts)`` -- exakt das ``domain.SlaSample`` und
die Eingabe der reinen Funktionen ``compute_sla_stats`` / ``build_hourly_chart``
(M.2). ``alive`` ist im Schema INTEGER (0/1); die Domaene wertet es truthy aus --
darum wird der rohe Spaltenwert OHNE Cast durchgereicht (charakterisierungstreu zur
Altcode-Query, die ebenfalls den rohen ``alive``-Wert in die Rechnung gibt).
"""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from domain.monitoring import SlaSample


class SqliteSlaSampleRepository:
    """Erfuellt das ``SlaSampleRepository``-Protocol strukturell (SQLite, nur lesen)."""

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
        # CREATE IF NOT EXISTS reicht (s. Modul-Docstring): die Altcode-Tabelle hat
        # exakt diese Spalten, kein Guard noetig. sla_targets wird bewusst NICHT
        # angelegt (toter Altcode-DDL ohne Nutzung).
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sla_samples (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_id   TEXT,
                    ts          REAL,
                    alive       INTEGER,
                    rtt_ms      REAL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_sla_samples_target_ts ON sla_samples(target_id, ts)"
            )

    def samples_for(self, target_id: str, since: float) -> list[SlaSample]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT alive, rtt_ms, ts FROM sla_samples "
                "WHERE target_id = ? AND ts > ? ORDER BY ts",
                (target_id, since),
            ).fetchall()
        # (alive, rtt_ms, ts) -- Spaltenreihenfolge wie domain.SlaSample. alive roh
        # durchgereicht (Schema-INTEGER, Domaene wertet truthy aus -- Altcode-treu).
        return [(row["alive"], row["rtt_ms"], row["ts"]) for row in rows]

    def target_ids(self) -> list[str]:
        with self._connect() as conn:
            rows = conn.execute("SELECT DISTINCT target_id FROM sla_samples").fetchall()
        return [row["target_id"] for row in rows]

    def clear_all(self) -> None:
        # Leert alle SLA-Samples (nur die eigene Tabelle sla_samples). Das ist
        # ein Loesch-Pfad (Wartung), KEIN Beleben des aufgeschobenen record-
        # Schreibpfads (M.7b) -- die Lese-Natur des Adapters bleibt unberuehrt.
        with self._connect() as conn:
            conn.execute("DELETE FROM sla_samples")
