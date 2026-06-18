"""End-to-end-Tests der Logging-Aufgaben-REST-API (B-I Schritt 3) via TestClient.

Echte Sqlite-Logging-Repos auf tmp_path-DBs via ``dependency_overrides`` (kein echtes
cernis.db, kein Bootstrap-Loop -- ``AppConfig()`` hat ``bootstrap_on_startup`` aus).
GETRENNT vom Live-Monitor (status/events/rtt -- eigene Testdatei). Belegt:

* POST /api/monitor/logging      -> 201 + Wire-Form (Zustand created); Modus-Validierung 422.
* GET  /api/monitor/logging      -> Liste der Aufgaben (Wire-Form).
* GET  /api/monitor/logging/{id} -> 404 bei unbekannter id.
* start/pause/resume/stop        -> Zustandsuebergaenge; 409 bei Konflikt/Transition.
* DELETE /api/monitor/logging/{id} -> 204 (idempotent).
* GET  /api/monitor/logging/volume -> count + over_threshold.
"""

from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.monitoring import (
    provide_check_log_volume,
    provide_create_logging_task,
    provide_delete_logging_task,
    provide_get_logging_task_detail,
    provide_get_logging_task_sla,
    provide_list_logging_tasks,
    provide_pause_logging_task,
    provide_resume_logging_task,
    provide_start_logging_task,
    provide_stop_logging_task,
)
from app import create_app
from application.monitoring import (
    CheckLogVolume,
    CreateLoggingTask,
    DeleteLoggingTask,
    GetLoggingTaskDetail,
    GetLoggingTaskSla,
    ListLoggingTasks,
    PauseLoggingTask,
    ResumeLoggingTask,
    StartLoggingTask,
    StopLoggingTask,
)
from infrastructure.config import AppConfig
from infrastructure.monitoring import (
    SqliteLoggingRttRepository,
    SqliteLoggingTaskRepository,
)


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "cernis.db"


def _wired_app(db_path: Path) -> FastAPI:
    tasks = SqliteLoggingTaskRepository(db_path)
    rtt = SqliteLoggingRttRepository(db_path)

    app = create_app(AppConfig())
    app.dependency_overrides[provide_create_logging_task] = lambda: CreateLoggingTask(tasks)
    app.dependency_overrides[provide_list_logging_tasks] = lambda: ListLoggingTasks(tasks)
    app.dependency_overrides[provide_get_logging_task_detail] = lambda: GetLoggingTaskDetail(tasks)
    app.dependency_overrides[provide_start_logging_task] = lambda: StartLoggingTask(tasks)
    app.dependency_overrides[provide_pause_logging_task] = lambda: PauseLoggingTask(tasks)
    app.dependency_overrides[provide_resume_logging_task] = lambda: ResumeLoggingTask(tasks)
    app.dependency_overrides[provide_stop_logging_task] = lambda: StopLoggingTask(tasks)
    app.dependency_overrides[provide_delete_logging_task] = lambda: DeleteLoggingTask(tasks)
    app.dependency_overrides[provide_check_log_volume] = lambda: CheckLogVolume(rtt)
    app.dependency_overrides[provide_get_logging_task_sla] = lambda: GetLoggingTaskSla(tasks, rtt)
    return app


def _create_body(**overrides: Any) -> dict[str, Any]:
    """Valider IMMEDIATE-Create-Body (mit max_duration_s) -- per kwargs ueberschreibbar."""
    body = {
        "target_id": "wlan",
        "label": "Server-Logging",
        "purpose": "Stoerungssuche",
        "capture_mode": "reachability_latency",
        "operation_mode": "immediate",
        "max_duration_s": 3600,
    }
    body.update(overrides)
    return body


# ── POST /api/monitor/logging (Anlage + Modus-Validierung) ──────────────────


def test_create_returns_201_with_created_state(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        resp = client.post("/api/monitor/logging", json=_create_body())
    assert resp.status_code == 201
    body = resp.json()
    assert body["state"] == "created"
    assert body["target_id"] == "wlan"
    assert body["capture_mode"] == "reachability_latency"
    assert body["operation_mode"] == "immediate"
    assert body["max_duration_s"] == 3600
    # Router erzeugt id + created_at.
    assert isinstance(body["id"], str) and body["id"]
    assert isinstance(body["created_at"], float)
    # effective_start (ADR 0033) ist vor dem ersten Start None -- als Schluessel
    # aber vorhanden (das Frontend leitet daraus die IMMEDIATE-Restzeit ab).
    assert body["effective_start"] is None


def test_create_scheduled_with_window(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        resp = client.post(
            "/api/monitor/logging",
            json={
                "target_id": "wlan",
                "label": "L",
                "purpose": "P",
                "capture_mode": "interface_status",
                "operation_mode": "scheduled",
                "planned_start": 100.0,
                "planned_end": 200.0,
            },
        )
    assert resp.status_code == 201
    body = resp.json()
    assert body["operation_mode"] == "scheduled"
    assert (body["planned_start"], body["planned_end"]) == (100.0, 200.0)


def test_create_unknown_capture_mode_is_422(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        resp = client.post("/api/monitor/logging", json=_create_body(capture_mode="bogus"))
    assert resp.status_code == 422


def test_create_scheduled_without_window_is_422(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        resp = client.post(
            "/api/monitor/logging",
            json={
                "target_id": "wlan",
                "label": "L",
                "purpose": "P",
                "capture_mode": "reachability",
                "operation_mode": "scheduled",
            },
        )
    assert resp.status_code == 422


def test_create_immediate_without_duration_is_422(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        resp = client.post(
            "/api/monitor/logging",
            json={
                "target_id": "wlan",
                "label": "L",
                "purpose": "P",
                "capture_mode": "reachability",
                "operation_mode": "immediate",
            },
        )
    assert resp.status_code == 422


def test_create_missing_mandatory_field_is_422(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        resp = client.post("/api/monitor/logging", json={"label": "no target_id"})
    assert resp.status_code == 422


# ── interval_s (C-2, Mess-Intervall) ────────────────────────────────────────


def test_create_with_valid_interval_carries_it(db_path: Path) -> None:
    # Ein gueltiges interval_s (eine der Stufen) landet 1:1 in der Wire-Form.
    with TestClient(_wired_app(db_path)) as client:
        resp = client.post("/api/monitor/logging", json=_create_body(interval_s=60))
    assert resp.status_code == 201
    assert resp.json()["interval_s"] == 60


def test_create_with_invalid_interval_is_422(db_path: Path) -> None:
    # Ein interval_s ausserhalb der erlaubten Stufen {5,15,30,60,300} -> 422 (kein
    # stiller Fallback).
    with TestClient(_wired_app(db_path)) as client:
        resp = client.post("/api/monitor/logging", json=_create_body(interval_s=7))
    assert resp.status_code == 422


def test_create_without_interval_defaults_to_5(db_path: Path) -> None:
    # Ohne Angabe greift der Domaenen-/Use-Case-Default 5 (heutiges dichtes Verhalten).
    # _create_body traegt KEIN interval_s.
    with TestClient(_wired_app(db_path)) as client:
        resp = client.post("/api/monitor/logging", json=_create_body())
    assert resp.status_code == 201
    assert resp.json()["interval_s"] == 5


# ── GET /api/monitor/logging (Liste) + Detail (404) ─────────────────────────


def test_list_empty_is_empty(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        resp = client.get("/api/monitor/logging")
    assert resp.status_code == 200
    assert resp.json() == []


def test_list_after_create(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        client.post("/api/monitor/logging", json=_create_body(label="A"))
        client.post("/api/monitor/logging", json=_create_body(label="B"))
        rows = client.get("/api/monitor/logging").json()
    assert {r["label"] for r in rows} == {"A", "B"}


def test_detail_unknown_is_404(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        resp = client.get("/api/monitor/logging/does-not-exist")
    assert resp.status_code == 404


def test_detail_returns_task(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        tid = client.post("/api/monitor/logging", json=_create_body()).json()["id"]
        resp = client.get(f"/api/monitor/logging/{tid}")
    assert resp.status_code == 200
    assert resp.json()["id"] == tid


# ── Lifecycle: start/pause/resume/stop ──────────────────────────────────────


def test_start_transitions_to_active(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        tid = client.post("/api/monitor/logging", json=_create_body()).json()["id"]
        resp = client.post(f"/api/monitor/logging/{tid}/start")
    assert resp.status_code == 200
    assert resp.json()["state"] == "active"


def test_start_sets_effective_start(db_path: Path) -> None:
    # effective_start (ADR 0033) ist None bei CREATED und wird beim ersten Start
    # auf den Start-ts gesetzt -- der Bezugs-ts der IMMEDIATE-Restzeit im Frontend.
    with TestClient(_wired_app(db_path)) as client:
        created = client.post("/api/monitor/logging", json=_create_body()).json()
        assert created["effective_start"] is None
        started = client.post(f"/api/monitor/logging/{created['id']}/start").json()
    assert isinstance(started["effective_start"], float)
    assert started["effective_start"] > 0


def test_start_unknown_is_404(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        resp = client.post("/api/monitor/logging/nope/start")
    assert resp.status_code == 404


def test_start_conflict_is_409_with_concept_message(db_path: Path) -> None:
    # Zwei Tasks am SELBEN Ziel: der erste laeuft, der zweite kollidiert beim Start.
    with TestClient(_wired_app(db_path)) as client:
        first = client.post("/api/monitor/logging", json=_create_body(target_id="wlan")).json()[
            "id"
        ]
        second = client.post("/api/monitor/logging", json=_create_body(target_id="wlan")).json()[
            "id"
        ]
        client.post(f"/api/monitor/logging/{first}/start")
        resp = client.post(f"/api/monitor/logging/{second}/start")
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    # Konzept-Meldung traegt Ziel + laufende Task.
    assert "wlan" in detail
    assert first in detail


def test_start_twice_is_409_invalid_transition(db_path: Path) -> None:
    # Zweimal start auf DERSELBEN Task -> beim zweiten Mal ist er ACTIVE (kein CREATED).
    with TestClient(_wired_app(db_path)) as client:
        tid = client.post("/api/monitor/logging", json=_create_body()).json()["id"]
        client.post(f"/api/monitor/logging/{tid}/start")
        resp = client.post(f"/api/monitor/logging/{tid}/start")
    assert resp.status_code == 409


def test_pause_resume_stop_cycle(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        tid = client.post("/api/monitor/logging", json=_create_body()).json()["id"]
        client.post(f"/api/monitor/logging/{tid}/start")
        assert client.post(f"/api/monitor/logging/{tid}/pause").json()["state"] == "paused"
        assert client.post(f"/api/monitor/logging/{tid}/resume").json()["state"] == "active"
        assert client.post(f"/api/monitor/logging/{tid}/stop").json()["state"] == "finished"


def test_pause_created_is_409(db_path: Path) -> None:
    # Pause aus CREATED (ohne start) -> InvalidTaskTransition -> 409.
    with TestClient(_wired_app(db_path)) as client:
        tid = client.post("/api/monitor/logging", json=_create_body()).json()["id"]
        resp = client.post(f"/api/monitor/logging/{tid}/pause")
    assert resp.status_code == 409


def test_resume_conflict_is_409(db_path: Path) -> None:
    # paused-Task am Ziel wlan; ein zweiter laeuft dort ACTIVE -> resume kollidiert.
    with TestClient(_wired_app(db_path)) as client:
        paused = client.post("/api/monitor/logging", json=_create_body(target_id="wlan")).json()[
            "id"
        ]
        client.post(f"/api/monitor/logging/{paused}/start")
        client.post(f"/api/monitor/logging/{paused}/pause")
        other = client.post("/api/monitor/logging", json=_create_body(target_id="wlan")).json()[
            "id"
        ]
        client.post(f"/api/monitor/logging/{other}/start")
        resp = client.post(f"/api/monitor/logging/{paused}/resume")
    assert resp.status_code == 409


def test_stop_unknown_is_404(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        resp = client.post("/api/monitor/logging/nope/stop")
    assert resp.status_code == 404


# ── DELETE (204, idempotent) ────────────────────────────────────────────────


def test_delete_returns_204(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        tid = client.post("/api/monitor/logging", json=_create_body()).json()["id"]
        resp = client.delete(f"/api/monitor/logging/{tid}")
    assert resp.status_code == 204
    # Danach nicht mehr auffindbar.
    with TestClient(_wired_app(db_path)) as client:
        assert client.get(f"/api/monitor/logging/{tid}").status_code == 404


def test_delete_unknown_is_idempotent_204(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        resp = client.delete("/api/monitor/logging/never-existed")
    assert resp.status_code == 204


# ── GET /api/monitor/logging/volume ─────────────────────────────────────────


def test_volume_empty_is_zero_under_threshold(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        resp = client.get("/api/monitor/logging/volume")
    assert resp.status_code == 200
    assert resp.json() == {"count": 0, "over_threshold": False}


def test_volume_counts_saved_rtt_points(db_path: Path) -> None:
    # Messpunkte direkt ueber das Repo ablegen (Schreibpfad aus Messungen = B-II);
    # der Endpunkt liest nur den count zurueck.
    rtt = SqliteLoggingRttRepository(db_path)
    rtt.save("t1", 1.0, 0.0, True, 100.0)
    rtt.save("t1", 2.0, 0.0, True, 101.0)
    with TestClient(_wired_app(db_path)) as client:
        resp = client.get("/api/monitor/logging/volume")
    assert resp.json() == {"count": 2, "over_threshold": False}


# ── GET /api/monitor/logging/{id}/sla (C-3) ─────────────────────────────────


def test_sla_returns_stats_for_known_task(db_path: Path) -> None:
    # Task anlegen (id vom Router), dann RTT-Messpunkte direkt ueber das Repo ablegen
    # -- der SLA-Endpunkt rechnet ueber all_for(task_id) die Kennzahlen.
    with TestClient(_wired_app(db_path)) as client:
        tid = client.post("/api/monitor/logging", json=_create_body()).json()["id"]
    rtt = SqliteLoggingRttRepository(db_path)
    rtt.save(tid, 4.0, 0.0, True, 1_700_000_000.0)
    rtt.save(tid, 6.0, 0.0, True, 1_700_000_005.0)
    rtt.save(tid, -1.0, 100.0, False, 1_700_000_010.0)  # ein down
    with TestClient(_wired_app(db_path)) as client:
        resp = client.get(f"/api/monitor/logging/{tid}/sla")
    assert resp.status_code == 200
    body = resp.json()
    assert body["task_id"] == tid
    assert body["samples"] == 3
    assert body["uptime_pct"] == round(2 / 3 * 100, 3)  # 2/3 alive
    assert body["avg_rtt_ms"] == 5.0  # mean([4,6])


def test_sla_empty_yields_null_uptime(db_path: Path) -> None:
    # Task ohne Messpunkte -> Null-Stats (uptime_pct=None -> "noch keine Auswertung").
    with TestClient(_wired_app(db_path)) as client:
        tid = client.post("/api/monitor/logging", json=_create_body()).json()["id"]
        resp = client.get(f"/api/monitor/logging/{tid}/sla")
    assert resp.status_code == 200
    body = resp.json()
    assert body["task_id"] == tid
    assert body["uptime_pct"] is None
    assert body["samples"] == 0


def test_sla_unknown_task_returns_404(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        resp = client.get("/api/monitor/logging/never-existed/sla")
    assert resp.status_code == 404
