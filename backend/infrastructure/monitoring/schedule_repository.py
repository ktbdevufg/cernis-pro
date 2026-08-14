"""SQLite-Adapter fuer den Port ``ScheduleRepository`` (Tabelle ``scan_schedules``).

REINE Persistenz, KEINE Job-Engine -- die Altcode-Kopplung (``add_schedule`` ruft
``_register_job``) ist entkoppelt: der Use-Case ``ManageSchedules`` (M.6)
orchestriert Repo + ``ScanJobScheduler``. Im Stil von
``SqliteScanHistoryRepository``: ``@contextmanager _connect`` mit Transaktion +
garantiertem close, ``_ensure_schema`` im Konstruktor, injizierter DB-Pfad. KEIN
``modules``-Import (eigenes Schema).

Schema: die NEUN Altcode-Spalten (``_init_schedule_db``) ``id / name / cidr /
profile_id / schedule / enabled (DEFAULT 1) / last_run / next_run / created_at``
plus die ZWEI additiven Ergebnis-Spalten ``last_result / last_error`` (S88-P4). Fuer
die neun genuegt weiterhin das reine ``CREATE TABLE IF NOT EXISTS`` (die Altcode-
Tabelle ist deckungsgleich, kein Schema-Drift); die zwei neuen kommen ueber einen
additiven ``ALTER TABLE ... ADD COLUMN``-Guard nach, weil ein ``CREATE IF NOT EXISTS``
auf eine bestehende Tabelle ein No-Op ist (Muster ``SqliteLoggingTaskRepository``).

``last_result`` traegt den AUSGANG des letzten Laufs (``'ok'``/``'failed'``/``NULL``),
``last_error`` den Wortlaut im Fehlerfall. Sie stehen NEBEN ``last_run``, nicht an
dessen Stelle: ``last_run`` sagt, WANN ausgeloest wurde (es wird vor dem Scan
gebucht), die beiden neuen sagen, WIE es ausging. Vor S88-P4 war ein gescheiterter
Lauf von einem geglueckten in der Tabelle nicht zu unterscheiden.

``list`` gibt rohe ``dict``-Zeilen (alle elf Spalten) -- KEIN Domaenen-Modell, die
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
        # Schema wie der Altcode (_init_schedule_db) plus die beiden ADDITIVEN Spalten
        # des Laufergebnisses (S88-P4). Fuer die neun Alt-Spalten genuegt weiterhin das
        # reine CREATE IF NOT EXISTS; die beiden neuen brauchen den ALTER-Guard, weil ein
        # CREATE IF NOT EXISTS auf eine BESTEHENDE Tabelle ein No-Op ist und die Spalten
        # dort sonst nie entstuenden (Muster SqliteLoggingTaskRepository).
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
                    created_at  TEXT DEFAULT (datetime('now')),
                    -- Ausgang des letzten Laufs: 'ok' | 'failed' | NULL (noch nie
                    -- gelaufen). KEIN NOT NULL: SQLite verbietet ADD COLUMN NOT NULL
                    -- ohne Default, und ein Default waere hier eine Luege -- eine
                    -- Bestandszeile hat keinen bekannten Ausgang, sie hat gar keinen.
                    last_result TEXT,
                    -- Wortlaut des Fehlers, falls last_result 'failed' ist; sonst NULL.
                    last_error  TEXT
                )
                """
            )
            # ADDITIVER GUARD (S88-P4): eine vor dieser Fassung angelegte Tabelle bekommt
            # die beiden Spalten hier nachgeruestet -- ohne Default, also NULL. Genau
            # deshalb genuegt der Guard und es braucht KEINE Erhoehung von
            # SCHEMA_VERSION: die Aenderung ist rein additiv und idempotent, sie laeuft
            # damit ueber Fall A der Schemanaht (``schema_aufbauen`` fuehrt die
            # Aufbauschritte in ALLEN Faellen aus). Ein gezaehlter Stand ist erst noetig,
            # wenn eine Aenderung NICHT idempotent nachzuziehen ist (Spalte umbenennen,
            # Tabelle umbauen, Daten umschreiben) -- dann faende sie in MIGRATIONEN statt.
            cols = {row["name"] for row in conn.execute("PRAGMA table_info(scan_schedules)")}
            if "last_result" not in cols:
                conn.execute("ALTER TABLE scan_schedules ADD COLUMN last_result TEXT")
            if "last_error" not in cols:
                conn.execute("ALTER TABLE scan_schedules ADD COLUMN last_error TEXT")

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

    def set_run_result(self, schedule_id: int, result: str, error: str | None) -> None:
        # Der einzige Schreibpfad der beiden Ergebnis-Spalten (S88-P4). BEIDE Werte
        # werden immer gesetzt: ein geglueckter Lauf schreibt ('ok', NULL) und raeumt
        # damit den Wortlaut des vorigen Fehlschlags weg -- ein alter Fehlertext neben
        # einem frischen Erfolg waere schlimmer als gar keiner. Das Repo bewertet nichts;
        # welcher Ausgang vorliegt, entscheidet der Aufrufer.
        with self._connect() as conn:
            conn.execute(
                "UPDATE scan_schedules SET last_result=?, last_error=? WHERE id=?",
                (result, error, schedule_id),
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
