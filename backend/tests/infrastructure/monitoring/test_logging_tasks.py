"""Tests fuer ``SqliteLoggingTaskRepository`` (B-I, Tabelle ``monitoring_log_tasks``).

Gegen eine echte temporaere sqlite (``tmp_path``), Muster wie ``test_rtt_history``.
Getestet: (1) Port-Konformitaet, (2) save->get/list-Round-trip inkl. Enum-Round-trip,
(3) UPSERT (zweimal save gleiche id -> 1 Zeile, neuer state), (4) get unbekannt ->
None, (5) Leerzustand list_all -> [] (nicht None), (6) delete (inkl. idempotent),
(7) nullable Zeit-/Dauer-Felder (modus-abhaengig).
"""

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
