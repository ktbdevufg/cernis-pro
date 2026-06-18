"""Tests fuer ``SqliteLoggingTaskRepository`` (B-I, Tabelle ``monitoring_log_tasks``).

Gegen eine echte temporaere sqlite (``tmp_path``), Muster wie ``test_rtt_history``.
Getestet: (1) Port-Konformitaet, (2) save->get/list-Round-trip inkl. Enum-Round-trip,
(3) UPSERT (zweimal save gleiche id -> 1 Zeile, neuer state), (4) get unbekannt ->
None, (5) Leerzustand list_all -> [] (nicht None), (6) delete (inkl. idempotent),
(7) nullable Zeit-/Dauer-Felder (modus-abhaengig).
"""

import sqlite3
from pathlib import Path

import pytest

from domain.monitoring import (
    CaptureMode,
    LoggingTask,
    OperationMode,
    TaskState,
)
from infrastructure.monitoring.logging_tasks import SqliteLoggingTaskRepository
from ports.monitoring import LoggingTaskRepository


@pytest.fixture
def repo(tmp_path: Path) -> SqliteLoggingTaskRepository:
    return SqliteLoggingTaskRepository(tmp_path / "cernis.db")


def _scheduled_task(
    task_id: str = "t1",
    *,
    state: TaskState = TaskState.CREATED,
) -> LoggingTask:
    return LoggingTask(
        id=task_id,
        target_id="wlan",
        label="WLAN-Langzeit",
        purpose="Stabilitaet ueber Nacht",
        capture_mode=CaptureMode.REACHABILITY_LATENCY,
        operation_mode=OperationMode.SCHEDULED,
        state=state,
        planned_start=100.0,
        planned_end=200.0,
        max_duration_s=None,  # SCHEDULED: keine Maximaldauer
        created_at=50.0,
    )


def _immediate_task(task_id: str = "t2") -> LoggingTask:
    return LoggingTask(
        id=task_id,
        target_id="lan",
        label="LAN-Sofort",
        purpose="Ad-hoc-Messung",
        capture_mode=CaptureMode.REACHABILITY,
        operation_mode=OperationMode.IMMEDIATE,
        state=TaskState.ACTIVE,
        planned_start=None,  # IMMEDIATE: kein festes Fenster
        planned_end=None,
        max_duration_s=3600,
        created_at=70.0,
    )


def test_conforms_to_logging_task_protocol(repo: SqliteLoggingTaskRepository) -> None:
    _: LoggingTaskRepository = repo


def test_save_then_get_roundtrip_with_enums(repo: SqliteLoggingTaskRepository) -> None:
    task = _scheduled_task()
    repo.save(task)
    loaded = repo.get("t1")
    assert loaded == task  # voller Round-trip inkl. Enum-Werte (StrEnum-Gleichheit)
    # Enums kommen als echte Domaenen-Enums zurueck, nicht als rohe Strings.
    assert loaded is not None
    assert isinstance(loaded.capture_mode, CaptureMode)
    assert isinstance(loaded.operation_mode, OperationMode)
    assert isinstance(loaded.state, TaskState)


def test_immediate_task_nullable_fields_roundtrip(repo: SqliteLoggingTaskRepository) -> None:
    task = _immediate_task()
    repo.save(task)
    loaded = repo.get("t2")
    assert loaded == task
    assert loaded is not None
    assert loaded.planned_start is None
    assert loaded.planned_end is None
    assert loaded.max_duration_s == 3600


def test_get_unknown_returns_none(repo: SqliteLoggingTaskRepository) -> None:
    assert repo.get("nope") is None


def test_save_is_upsert_same_id_one_row_new_state(repo: SqliteLoggingTaskRepository) -> None:
    repo.save(_scheduled_task(state=TaskState.CREATED))
    # Zweites save derselben id mit gewechseltem state (Lebenszyklus-Uebergang).
    repo.save(_scheduled_task(state=TaskState.ACTIVE))
    all_tasks = repo.list_all()
    assert len(all_tasks) == 1  # UPSERT: keine zweite Zeile
    assert all_tasks[0].state is TaskState.ACTIVE  # neuer state gewonnen


def test_list_all_empty_is_empty_list(repo: SqliteLoggingTaskRepository) -> None:
    assert repo.list_all() == []  # Leerzustand [], nicht None


def test_list_all_returns_all_tasks(repo: SqliteLoggingTaskRepository) -> None:
    repo.save(_scheduled_task("t1"))
    repo.save(_immediate_task("t2"))
    ids = {t.id for t in repo.list_all()}
    assert ids == {"t1", "t2"}


def test_delete_removes_only_definition(repo: SqliteLoggingTaskRepository) -> None:
    repo.save(_scheduled_task("t1"))
    repo.save(_immediate_task("t2"))
    repo.delete("t1")
    assert repo.get("t1") is None
    assert repo.get("t2") is not None  # andere Aufgabe unberuehrt


def test_delete_unknown_id_is_idempotent(repo: SqliteLoggingTaskRepository) -> None:
    repo.delete("nie-da")  # kein Fehler bei fehlender id
    assert repo.list_all() == []


# ── effective_start (B-II, ADR 0033) ────────────────────────────────────────


def test_effective_start_roundtrip(repo: SqliteLoggingTaskRepository) -> None:
    # Gesetzter effective_start ueberlebt save->get (REAL-Round-trip).
    task = LoggingTask(
        id="t-eff",
        target_id="wlan",
        label="L",
        purpose="P",
        capture_mode=CaptureMode.REACHABILITY,
        operation_mode=OperationMode.IMMEDIATE,
        state=TaskState.ACTIVE,
        planned_start=None,
        planned_end=None,
        max_duration_s=3600,
        created_at=70.0,
        effective_start=12345.0,
    )
    repo.save(task)
    loaded = repo.get("t-eff")
    assert loaded == task
    assert loaded is not None
    assert loaded.effective_start == 12345.0


def test_effective_start_none_roundtrip(repo: SqliteLoggingTaskRepository) -> None:
    # Default-None bleibt None ueber den Round-trip (nicht etwa 0.0).
    repo.save(_scheduled_task("t-none"))
    loaded = repo.get("t-none")
    assert loaded is not None
    assert loaded.effective_start is None


def test_schema_guard_adds_effective_start_to_legacy_table(tmp_path: Path) -> None:
    # Migrations-Guard: eine in B-I (ohne effective_start) angelegte Alt-Tabelle wird
    # beim Repo-Bau idempotent nachgeruestet (PRAGMA-Check + ALTER TABLE), exakt wie
    # der alive-Guard von SqliteRttHistoryRepository.
    db_path = tmp_path / "cernis.db"
    # Alt-Tabelle OHNE effective_start manuell anlegen + eine Zeile setzen.
    conn = sqlite3.connect(db_path)
    with conn:
        conn.execute(
            """
            CREATE TABLE monitoring_log_tasks (
                id             TEXT PRIMARY KEY,
                target_id      TEXT,
                label          TEXT,
                purpose        TEXT,
                capture_mode   TEXT,
                operation_mode TEXT,
                state          TEXT,
                planned_start  REAL,
                planned_end    REAL,
                max_duration_s INTEGER,
                created_at     REAL
            )
            """
        )
        conn.execute(
            "INSERT INTO monitoring_log_tasks (id, target_id, label, purpose, "
            "capture_mode, operation_mode, state, planned_start, planned_end, "
            "max_duration_s, created_at) VALUES "
            "('alt', 'wlan', 'L', 'P', 'reachability', 'scheduled', 'created', "
            "100.0, 200.0, NULL, 50.0)"
        )
    conn.close()

    # Repo-Bau ruestet die Spalte nach.
    repo = SqliteLoggingTaskRepository(db_path)
    cols = {row["name"] for row in _table_info(db_path, "monitoring_log_tasks")}
    assert "effective_start" in cols
    # Die Alt-Zeile ist lesbar, effective_start ist None (Default NULL).
    loaded = repo.get("alt")
    assert loaded is not None
    assert loaded.effective_start is None
    # Und ein neuer save mit gesetztem effective_start funktioniert auf der Tabelle.
    repo.save(_immediate_task_with_effective_start())
    again = repo.get("t-new")
    assert again is not None
    assert again.effective_start == 999.0


def _immediate_task_with_effective_start() -> LoggingTask:
    return LoggingTask(
        id="t-new",
        target_id="lan",
        label="L",
        purpose="P",
        capture_mode=CaptureMode.REACHABILITY,
        operation_mode=OperationMode.IMMEDIATE,
        state=TaskState.ACTIVE,
        planned_start=None,
        planned_end=None,
        max_duration_s=3600,
        created_at=70.0,
        effective_start=999.0,
    )


# ── interval_s (C-2, Mess-Intervall) ────────────────────────────────────────


def test_interval_s_roundtrip(repo: SqliteLoggingTaskRepository) -> None:
    # Ein gesetztes Intervall ueberlebt save->get (INTEGER-Round-trip).
    task = LoggingTask(
        id="t-iv",
        target_id="wlan",
        label="L",
        purpose="P",
        capture_mode=CaptureMode.REACHABILITY_LATENCY,
        operation_mode=OperationMode.IMMEDIATE,
        state=TaskState.ACTIVE,
        planned_start=None,
        planned_end=None,
        max_duration_s=3600,
        created_at=70.0,
        interval_s=60,
    )
    repo.save(task)
    loaded = repo.get("t-iv")
    assert loaded == task
    assert loaded is not None
    assert loaded.interval_s == 60


def test_interval_s_default_roundtrip(repo: SqliteLoggingTaskRepository) -> None:
    # Ohne Angabe traegt der Task den Domaenen-Default 5 -- der ueberlebt den Round-trip.
    repo.save(_scheduled_task("t-iv-default"))
    loaded = repo.get("t-iv-default")
    assert loaded is not None
    assert loaded.interval_s == 5


def test_schema_guard_adds_interval_s_to_legacy_table(tmp_path: Path) -> None:
    # Migrations-Guard fuer interval_s: eine vor C-2 angelegte Tabelle (ohne die Spalte)
    # wird beim Repo-Bau idempotent nachgeruestet -- ABWEICHUNG zu effective_start:
    # DEFAULT 5 (nicht NULL), weil interval_s nicht nullable ist. Bestandszeilen tragen
    # damit das heutige dichte Verhalten (5 s), nicht NULL.
    db_path = tmp_path / "cernis.db"
    # Alt-Tabelle OHNE interval_s (und ohne effective_start) manuell anlegen + Zeile.
    conn = sqlite3.connect(db_path)
    with conn:
        conn.execute(
            """
            CREATE TABLE monitoring_log_tasks (
                id             TEXT PRIMARY KEY,
                target_id      TEXT,
                label          TEXT,
                purpose        TEXT,
                capture_mode   TEXT,
                operation_mode TEXT,
                state          TEXT,
                planned_start  REAL,
                planned_end    REAL,
                max_duration_s INTEGER,
                created_at     REAL
            )
            """
        )
        conn.execute(
            "INSERT INTO monitoring_log_tasks (id, target_id, label, purpose, "
            "capture_mode, operation_mode, state, planned_start, planned_end, "
            "max_duration_s, created_at) VALUES "
            "('alt', 'wlan', 'L', 'P', 'reachability_latency', 'scheduled', 'created', "
            "100.0, 200.0, NULL, 50.0)"
        )
    conn.close()

    # Repo-Bau ruestet die Spalte nach.
    repo = SqliteLoggingTaskRepository(db_path)
    cols = {row["name"] for row in _table_info(db_path, "monitoring_log_tasks")}
    assert "interval_s" in cols
    # Die Alt-Zeile ist lesbar, interval_s ist 5 (DEFAULT 5, NICHT None).
    loaded = repo.get("alt")
    assert loaded is not None
    assert loaded.interval_s == 5


def _table_info(db_path: Path, table: str) -> list[sqlite3.Row]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(f"PRAGMA table_info({table})").fetchall()
    finally:
        conn.close()
