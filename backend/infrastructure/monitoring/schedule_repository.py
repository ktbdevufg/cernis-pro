"""SQLite-Adapter fuer den Port ``ScheduleRepository`` (Tabelle ``scan_schedules``).

REINE Persistenz, KEINE Job-Engine -- die Altcode-Kopplung (``add_schedule`` ruft
``_register_job``) ist entkoppelt: der Use-Case ``ManageSchedules`` (M.6)
orchestriert Repo + ``ScanJobScheduler``. Im Stil von
``SqliteScanHistoryRepository``: ``@contextmanager _connect`` mit Transaktion +
garantiertem close, ``_ensure_schema`` im Konstruktor, injizierter DB-Pfad. KEIN
``modules``-Import (eigenes Schema).

Schema EXAKT wie der Altcode (``_init_schedule_db``): die NEUN Spalten
``id / name / cidr / profile_id / schedule / enabled (DEFAULT 1) / last_run /
next_run / created_at``. KEIN Migrations-Guard noetig (anders als ``rtt_history``,
dem die ``alive``-Spalte fehlte): die Altcode-Tabelle hat exakt dieselben Spalten,
ein ``CREATE TABLE IF NOT EXISTS`` auf eine vorhandene Alt-Tabelle ist deckungs-
gleich -- kein Schema-Drift.

``list`` gibt rohe ``dict``-Zeilen (alle neun Spalten) -- KEIN Domaenen-Modell, die
CRUD-Response ist ein 1:1-Tabellen-Dump (siehe Port-Docstring). ``add`` speichert
den ``schedule``-String UNGEPARST (das Parsen + Job-Registrieren macht der Use-Case
ueber den ``ScanJobScheduler``); so landet auch ein unparsbarer String in der
Liste, und der best-effort-Pfad in ``ManageSchedules`` entscheidet ueber den Job.

``set_run_times`` (Finding 3) ist der EINZIGE Schreibpfad der beiden Spalten
``last_run``/``next_run``, die bis dahin nur im Schema existierten (keine einzige
Schreibstelle im Backend -> die Liste zeigte dauerhaft leere Zeiten). Es schreibt
fertige ISO-8601-UTC-Strings des Aufrufers, formatiert also selbst nichts -- das
Repo bleibt uhrfrei (die Zeiten entstehen im application-Ring aus der ``Clock``
bzw. aus dem Job-Scheduler-Port).

BEFUND (charakterisierungstreu bewahrt, NICHT in M.6 gefixt): ``update`` mit
``enabled=False`` entfernt NICHT den laufenden Job -- ein deaktiviertes Schedule
laeuft weiter (latenter Altcode-Bug). Das Repo macht nur DB; der Fix waere ein
spaeterer eigener Schritt (``UpdateSchedule`` bekaeme dann den Job-Port dazu).
"""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from ports.devices import Clock


class SqliteScheduleRepository:
    """Erfuellt das ``ScheduleRepository``-Protocol strukturell (SQLite)."""

    def __init__(self, db_path: Path, clock: Clock) -> None:
        self._db_path = db_path
        # Die EINE Zeitquelle (timezone-aware UTC); Verdrahtung im Composition Root.
        self._clock = clock
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
        # Schema exakt wie der Altcode (_init_schedule_db) -- deckungsgleich, daher
        # reines CREATE IF NOT EXISTS, kein ALTER-Guard.
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_schedules (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    name        TEXT,
                    cidr        TEXT,
                    profile_id  TEXT,
                    schedule    TEXT,
                    enabled     INTEGER DEFAULT 1,
                    last_run    TEXT,
                    next_run    TEXT,
                    -- Sicherheitsnetz-Default; der Wert wird in add() explizit aus
                    -- der Clock gesetzt (ISO-8601 UTC mit +00:00), nicht ueber diesen
                    -- Default (UTC ohne Zonen-Kennzeichnung).
                    created_at  TEXT DEFAULT (datetime('now'))
                )
                """
            )

    def list(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM scan_schedules ORDER BY id").fetchall()
        return [dict(row) for row in rows]

    def add(self, name: str, cidr: str, profile_id: str, schedule: str) -> int:
        # created_at explizit aus der Clock (timezone-aware UTC) als ISO-8601-String
        # MIT Zonen-Offset (+00:00) -- nicht mehr ueber den Schema-Default datetime('now').
        created_at = self._clock.now().isoformat()
        with self._connect() as conn:
            cursor = conn.execute(
                "INSERT INTO scan_schedules "
                "(name, cidr, profile_id, schedule, enabled, created_at) "
                "VALUES (?, ?, ?, ?, 1, ?)",
                (name, cidr, profile_id, schedule, created_at),
            )
            schedule_id = cursor.lastrowid
        # lastrowid ist nach erfolgreichem INSERT immer gesetzt (int); der Vertrag
        # garantiert int -- der Cast macht das fuer mypy explizit.
        return int(schedule_id) if schedule_id is not None else -1

    def update(self, schedule_id: int, enabled: bool | None, name: str | None) -> None:
        # Altcode-treu: enabled und name getrennt aktualisiert (None = unveraendert).
        # Entfernt KEINEN Job bei enabled=False (Befund, s. Modul-Docstring).
        with self._connect() as conn:
            if enabled is not None:
                conn.execute(
                    "UPDATE scan_schedules SET enabled=? WHERE id=?",
                    (int(enabled), schedule_id),
                )
            if name is not None:
                conn.execute(
                    "UPDATE scan_schedules SET name=? WHERE id=?",
                    (name, schedule_id),
                )

    def set_run_times(
        self,
        schedule_id: int,
        last_run: str | None,
        next_run: str | None,
    ) -> None:
        # Der EINZIGE Schreibpfad der beiden bis dato toten Spalten (Finding 3).
        # BEIDE Werte werden immer gesetzt -- ``None`` schreibt NULL (explizit
        # "leer"), nicht "unveraendert lassen" wie bei ``update``. Die Zeiten
        # kommen als fertige ISO-8601-UTC-Strings vom Aufrufer (application-Ring);
        # das Repo bleibt uhrfrei -- es formatiert nichts und erfindet nichts.
        with self._connect() as conn:
            conn.execute(
                "UPDATE scan_schedules SET last_run=?, next_run=? WHERE id=?",
                (last_run, next_run, schedule_id),
            )

    def delete(self, schedule_id: int) -> None:
        # Idempotent: DELETE auf eine nicht-existente id ist kein Fehler (0 rows).
        with self._connect() as conn:
            conn.execute("DELETE FROM scan_schedules WHERE id=?", (schedule_id,))

    def clear_all(self) -> None:
        # Leert alle Schedules (nur die eigene Tabelle scan_schedules). REIN
        # Persistenz: entfernt KEINEN laufenden Job (das macht der Use-Case ueber
        # den ScanJobScheduler).
        with self._connect() as conn:
            conn.execute("DELETE FROM scan_schedules")
