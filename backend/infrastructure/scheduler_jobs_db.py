"""SQLite-Adapter fuer die Persistenz geplanter Jobs (``ScheduledJobRepository``).

``SqliteScheduledJobRepository`` persistiert die geplanten Jobs der scheduler-Domaene:
Anlegen (``add``) + Lese-Views (``get``/``list_active``/``list_all``) + Zustand/Loeschen
(``update_state``/``delete``/``clear_all``). Die AUTOINCREMENT-id ist die stabile
Identitaet eines Jobs (Vertrag ``ScheduledJob.id``).

Zwei Felder sind in der Domaene OPAQUE bzw. nicht spaltenfaehig und werden hier
serialisiert: ``weekdays`` (eine ``frozenset[int]``) als sortierter CSV-String, ``params``
(eine ``tuple[tuple[str, str], ...]``) als JSON (Liste von 2-Element-Listen). Der Rueckweg
hebt beides 1:1 wieder in die Domaenenform.

Stil EXAKT wie ``dns_watch_acknowledgements_db.py``/``cve_findings_db.py``: injizierter
``db_path``, ``_ensure_schema`` im ``__init__``, ``@contextmanager _connect`` mit
Transaktion + garantiertem ``close``, ``CREATE TABLE IF NOT EXISTS``. KEIN ``modules``-
Import. KEIN ``domain.scheduler.logic``-Import -- dieser Adapter persistiert nur, er
wertet keine Faelligkeit aus.

KEIN stiller Fallback noetig (S3): die Spalten sind nackt. Ein kaputter Wert (etwa eine
nicht-ganzzahlige weekday oder ein nicht-aufloesbares params_json) schlaegt am Rand --
beim Rekonstruieren in ``_row_to_job`` -- LAUT fehl, statt leise auf etwas Falsches
zurueckzufallen. Der ``CHECK(state IN ...)`` haelt die Zustandsspalte auf die drei
legitimen ``JobState``-Werte (Muster des dns_watch action-CHECK).
"""

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from domain.scheduler.models import DailyWindow, JobState, ScheduledJob

__all__ = ["SqliteScheduledJobRepository"]


# ── Serialisierung der opaken/nicht-spaltenfaehigen Felder ────────────────────


def _weekdays_to_csv(weekdays: frozenset[int]) -> str:
    """``weekdays`` -> sortierter CSV-String; leere Menge -> leerer String ``""``."""
    return ",".join(str(day) for day in sorted(weekdays))


def _csv_to_weekdays(weekdays_csv: str) -> frozenset[int]:
    """Rueckweg: leerer String -> ``frozenset()``, sonst die int-Wochentage."""
    if not weekdays_csv:
        return frozenset()
    return frozenset(int(part) for part in weekdays_csv.split(","))


def _params_to_json(params: tuple[tuple[str, str], ...]) -> str:
    """``params`` -> JSON (Liste von 2-Element-Listen ``[[k, v], ...]``)."""
    return json.dumps([[key, value] for key, value in params])


def _json_to_params(params_json: str) -> tuple[tuple[str, str], ...]:
    """Rueckweg: JSON-Liste von 2-Element-Listen -> Tupel-Sequenz von str-Paaren."""
    return tuple((str(key), str(value)) for key, value in json.loads(params_json))


class SqliteScheduledJobRepository:
    """Persistiert geplante Jobs (Identitaet = AUTOINCREMENT-id) in SQLite.

    Injizierter ``db_path``; die Pfad-Aufloesung passiert im Composition Root
    (``app.py``, kommt in Etappe 3), nicht hier. Erfuellt ``ScheduledJobRepository``.
    """

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
        # AUTOINCREMENT-id ist die stabile Identitaet eines Jobs (Vertrag ScheduledJob.id);
        # daran haengen get/update_state/delete. state ist per CHECK auf die drei JobState-
        # Werte eingegrenzt (lauter Fehler statt Muell -- Muster des dns_watch action-CHECK).
        # weekdays_csv leer = "alle Tage" (Domaenen-Konvention DailyWindow.weekdays).
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS scheduler_jobs (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_type      TEXT NOT NULL,
                    params_json   TEXT NOT NULL,
                    start_minute  INTEGER NOT NULL,
                    end_minute    INTEGER NOT NULL,
                    weekdays_csv  TEXT NOT NULL,
                    from_epoch    REAL NOT NULL,
                    until_epoch   REAL NOT NULL,
                    state         TEXT NOT NULL CHECK(state IN ('active','paused','finished'))
                );
                """
            )

    # ── Schreib-Pfad ──────────────────────────────────────────────────────────

    def add(self, job_type: str, params: tuple[tuple[str, str], ...], window: DailyWindow) -> int:
        """Legt einen neuen Job an (``state`` startet ``active``) und liefert die neue id.

        ``params``/``weekdays`` werden serialisiert (s. Modul-Helfer). Die id ist die
        ``cursor.lastrowid`` des INSERT.
        """
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO scheduler_jobs (
                    job_type, params_json, start_minute, end_minute,
                    weekdays_csv, from_epoch, until_epoch, state
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, 'active')
                """,
                (
                    job_type,
                    _params_to_json(params),
                    window.start_minute,
                    window.end_minute,
                    _weekdays_to_csv(window.weekdays),
                    window.from_epoch,
                    window.until_epoch,
                ),
            )
            # lastrowid ist nach erfolgreichem INSERT immer gesetzt; der ``or 0`` ist nur
            # die mypy-Absicherung gegen das ``int | None`` der Signatur.
            return int(cur.lastrowid or 0)

    def update_state(self, job_id: int, state: JobState) -> None:
        """Setzt den Lebenszyklus-Zustand eines Jobs (z. B. active -> paused/finished)."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE scheduler_jobs SET state = ? WHERE id = ?",
                (state.value, job_id),
            )

    def delete(self, job_id: int) -> None:
        """Loescht einen Job (unbekannte id ist ein No-Op, kein Fehler)."""
        with self._connect() as conn:
            conn.execute("DELETE FROM scheduler_jobs WHERE id = ?", (job_id,))

    def clear_all(self) -> None:
        """Leert alle geplanten Jobs (nur die eigene Tabelle ``scheduler_jobs``)."""
        with self._connect() as conn:
            conn.execute("DELETE FROM scheduler_jobs")

    # ── Lese-Pfad ─────────────────────────────────────────────────────────────

    def get(self, job_id: int) -> ScheduledJob | None:
        """Job zur id, oder ``None`` wenn die id unbekannt ist (legitimer Leerzustand)."""
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM scheduler_jobs WHERE id = ?", (job_id,)).fetchone()
        if row is None:
            return None
        return self._row_to_job(row)

    def list_active(self) -> list[ScheduledJob]:
        """Alle Jobs mit ``state == active`` (Worker-Sicht). Keine -> ``[]``."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM scheduler_jobs WHERE state = 'active' ORDER BY id"
            ).fetchall()
        return [self._row_to_job(row) for row in rows]

    def list_all(self) -> list[ScheduledJob]:
        """Alle Jobs ueber alle Zustaende (Verwaltungs-Sicht). Keine -> ``[]``."""
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM scheduler_jobs ORDER BY id").fetchall()
        return [self._row_to_job(row) for row in rows]

    def _row_to_job(self, row: sqlite3.Row) -> ScheduledJob:
        """Rekonstruiert den frozen ``ScheduledJob`` aus einer Zeile (Rueckweg-Serialisierung)."""
        window = DailyWindow(
            start_minute=row["start_minute"],
            end_minute=row["end_minute"],
            weekdays=_csv_to_weekdays(row["weekdays_csv"]),
            from_epoch=row["from_epoch"],
            until_epoch=row["until_epoch"],
        )
        # StrEnum-Hebung am Rand: ein nicht-legitimer Wert (vom CHECK ausgeschlossen)
        # wuerde hier laut fehlschlagen, statt leise durchzulaufen.
        state = JobState(row["state"])
        params = _json_to_params(row["params_json"])
        return ScheduledJob(
            id=row["id"],
            job_type=row["job_type"],
            params=params,
            window=window,
            state=state,
        )
