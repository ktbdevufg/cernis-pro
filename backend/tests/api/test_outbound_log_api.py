"""End-to-end-Tests der Aussenkontakte-Aufzeichnungs-REST-API (E4) via TestClient.

Echte Sqlite-outbound_log-Repos auf tmp_path-DBs via ``dependency_overrides`` (kein
echtes cernis.db, kein Bootstrap-/Recorder-Loop -- ``AppConfig()`` hat
``bootstrap_on_startup`` aus, exakt das Muster von ``test_logging_api.py``). Belegt:

* POST   /api/outbound/recordings            -> 201 + Wire-Form (Zustand created); 422.
* GET    /api/outbound/recordings            -> Liste der Aufzeichnungen (Wire-Form).
* GET    /api/outbound/recordings/{id}       -> 404 bei unbekannter id.
* start/pause/resume/stop                    -> Zustandsuebergaenge; 409 bei Konflikt/Transition.
* DELETE /api/outbound/recordings/{id}       -> 204 (idempotent).
* aggregate/detail                           -> leere Liste bei unbekannter id.
"""

from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.outbound_log import (
    provide_create_outbound_recording,
    provide_delete_outbound_recording,
    provide_edit_outbound_recording,
    provide_get_outbound_aggregate,
    provide_get_outbound_detail_range,
    provide_get_outbound_recording,
    provide_list_outbound_recordings,
    provide_pause_outbound_recording,
    provide_resume_outbound_recording,
    provide_start_outbound_recording,
    provide_stop_outbound_recording,
)
from app import create_app
from application.outbound_log import (
    CreateOutboundRecording,
    DeleteOutboundRecording,
    EditOutboundRecording,
    GetOutboundAggregate,
    GetOutboundDetailRange,
    GetOutboundRecording,
    ListOutboundRecordings,
    PauseOutboundRecording,
    ResumeOutboundRecording,
    StartOutboundRecording,
    StopOutboundRecording,
)
from infrastructure.config import AppConfig
from infrastructure.outbound_log_aggregate import SqliteOutboundAggregateRepository
from infrastructure.outbound_log_detail import SqliteOutboundDetailRepository
from infrastructure.outbound_log_recordings import SqliteOutboundRecordingRepository


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "cernis.db"


def _wired_app(db_path: Path) -> FastAPI:
    rec = SqliteOutboundRecordingRepository(db_path)
    detail = SqliteOutboundDetailRepository(db_path)
    agg = SqliteOutboundAggregateRepository(db_path)

    app = create_app(AppConfig())
    app.dependency_overrides[provide_create_outbound_recording] = lambda: CreateOutboundRecording(
        rec
    )
    app.dependency_overrides[provide_start_outbound_recording] = lambda: StartOutboundRecording(rec)
    app.dependency_overrides[provide_pause_outbound_recording] = lambda: PauseOutboundRecording(rec)
    app.dependency_overrides[provide_resume_outbound_recording] = lambda: ResumeOutboundRecording(
        rec
    )
    app.dependency_overrides[provide_stop_outbound_recording] = lambda: StopOutboundRecording(rec)
    app.dependency_overrides[provide_edit_outbound_recording] = lambda: EditOutboundRecording(rec)
    app.dependency_overrides[provide_delete_outbound_recording] = lambda: DeleteOutboundRecording(
        rec, detail, agg
    )
    app.dependency_overrides[provide_list_outbound_recordings] = lambda: ListOutboundRecordings(rec)
    app.dependency_overrides[provide_get_outbound_recording] = lambda: GetOutboundRecording(rec)
    app.dependency_overrides[provide_get_outbound_aggregate] = lambda: GetOutboundAggregate(agg)
    app.dependency_overrides[provide_get_outbound_detail_range] = lambda: GetOutboundDetailRange(
        detail
    )
    return app


def _create_body(**overrides: Any) -> dict[str, Any]:
    """Valider AGGREGATE-Create-Body -- per kwargs ueberschreibbar."""
    body: dict[str, Any] = {
        "label": "Aussenkontakte",
        "purpose": "Beobachtung",
        "mode": "aggregate",
        "depth": "anonymous",
        "interval_s": 60,
    }
    body.update(overrides)
    return body


# ── POST (Anlage + Modus-Validierung) ────────────────────────────────────────


def test_create_returns_201_with_created_state(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        resp = client.post("/api/outbound/recordings", json=_create_body())
    assert resp.status_code == 201
    body = resp.json()
    assert body["state"] == "created"
    assert body["label"] == "Aussenkontakte"
    assert body["purpose"] == "Beobachtung"
    assert body["mode"] == "aggregate"
    assert body["depth"] == "anonymous"
    assert body["interval_s"] == 60
    # AGGREGATE erzwingt kein Zeitlimit.
    assert body["max_duration_s"] is None
    # Router erzeugt id + now; effective_start vor dem ersten Start None.
    assert isinstance(body["id"], str) and body["id"]
    assert isinstance(body["created_at"], float)
    assert body["effective_start"] is None


def test_create_detail_sets_24h_cap(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        resp = client.post(
            "/api/outbound/recordings",
            json=_create_body(mode="detail", interval_s=30),
        )
    assert resp.status_code == 201
    body = resp.json()
    assert body["mode"] == "detail"
    # DETAIL ohne max_duration_s -> voller 24-h-Deckel (86400 s).
    assert body["max_duration_s"] == 86400


def test_create_invalid_mode_returns_422(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        resp = client.post("/api/outbound/recordings", json=_create_body(mode="bogus"))
    assert resp.status_code == 422


def test_create_invalid_interval_returns_422(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        resp = client.post("/api/outbound/recordings", json=_create_body(interval_s=45))
    assert resp.status_code == 422


def test_create_duplicate_name_returns_409(db_path: Path) -> None:
    # Getrimmt + zustandsunabhaengig: ein bereits vergebener Name -> 409.
    with TestClient(_wired_app(db_path)) as client:
        assert (
            client.post("/api/outbound/recordings", json=_create_body(label="name")).status_code
            == 201
        )
        resp = client.post("/api/outbound/recordings", json=_create_body(label="name "))
    assert resp.status_code == 409
    assert "name" in resp.json()["detail"]


def test_create_case_variant_name_returns_201(db_path: Path) -> None:
    # Case-sensitiv: "Test3" ist trotz vorhandenem "test3" erlaubt.
    with TestClient(_wired_app(db_path)) as client:
        assert (
            client.post("/api/outbound/recordings", json=_create_body(label="test3")).status_code
            == 201
        )
        resp = client.post("/api/outbound/recordings", json=_create_body(label="Test3"))
    assert resp.status_code == 201


# ── GET (Liste + Einzel-404) ─────────────────────────────────────────────────


def test_list_returns_created_recordings(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        assert client.get("/api/outbound/recordings").json() == []
        client.post("/api/outbound/recordings", json=_create_body(label="A"))
        client.post("/api/outbound/recordings", json=_create_body(label="B"))
        listed = client.get("/api/outbound/recordings").json()
    assert {r["label"] for r in listed} == {"A", "B"}


def test_get_unknown_returns_404(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        resp = client.get("/api/outbound/recordings/does-not-exist")
    assert resp.status_code == 404


# ── Lifecycle (start/pause/resume/stop) ──────────────────────────────────────


def _create_id(client: TestClient, **overrides: Any) -> str:
    resp = client.post("/api/outbound/recordings", json=_create_body(**overrides))
    assert resp.status_code == 201
    rec_id: str = resp.json()["id"]
    return rec_id


def test_start_pause_resume_stop_happy_path(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        rec_id = _create_id(client)
        assert client.post(f"/api/outbound/recordings/{rec_id}/start").json()["state"] == "active"
        assert client.post(f"/api/outbound/recordings/{rec_id}/pause").json()["state"] == "paused"
        assert client.post(f"/api/outbound/recordings/{rec_id}/resume").json()["state"] == "active"
        assert client.post(f"/api/outbound/recordings/{rec_id}/stop").json()["state"] == "finished"


def test_start_unknown_returns_404(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        resp = client.post("/api/outbound/recordings/nope/start")
    assert resp.status_code == 404


def test_start_conflict_returns_409(db_path: Path) -> None:
    # Host-Regel: hoechstens EINE Aufzeichnung gleichzeitig aktiv.
    with TestClient(_wired_app(db_path)) as client:
        first = _create_id(client, label="first")
        second = _create_id(client, label="second")
        assert client.post(f"/api/outbound/recordings/{first}/start").status_code == 200
        resp = client.post(f"/api/outbound/recordings/{second}/start")
    assert resp.status_code == 409
    # Die Konflikt-Meldung traegt die running_id der bereits aktiven Aufzeichnung.
    assert first in resp.json()["detail"]


def test_pause_from_created_returns_409_transition(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        rec_id = _create_id(client)
        resp = client.post(f"/api/outbound/recordings/{rec_id}/pause")
    assert resp.status_code == 409


def test_resume_from_created_returns_409_transition(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        rec_id = _create_id(client)
        resp = client.post(f"/api/outbound/recordings/{rec_id}/resume")
    assert resp.status_code == 409


def test_stop_from_created_returns_409_transition(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        rec_id = _create_id(client)
        resp = client.post(f"/api/outbound/recordings/{rec_id}/stop")
    assert resp.status_code == 409


# ── PUT (Aendern: label/purpose immer, Konfig nur CREATED) ───────────────────


def test_edit_created_returns_200_and_updates_all_fields(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        rec_id = _create_id(client)
        resp = client.put(
            f"/api/outbound/recordings/{rec_id}",
            json=_create_body(
                label="Neu", purpose="Anders", mode="detail", depth="app_resolved", interval_s=300
            ),
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["label"] == "Neu"
    assert body["purpose"] == "Anders"
    assert body["mode"] == "detail"
    assert body["depth"] == "app_resolved"
    assert body["interval_s"] == 300
    assert body["state"] == "created"


def test_edit_unknown_returns_404(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        resp = client.put("/api/outbound/recordings/nope", json=_create_body())
    assert resp.status_code == 404


def test_edit_config_change_on_active_returns_409(db_path: Path) -> None:
    # Aktive Aufzeichnung: Aenderung eines Konfig-Felds (mode) -> 409 (Lock).
    with TestClient(_wired_app(db_path)) as client:
        rec_id = _create_id(client)
        assert client.post(f"/api/outbound/recordings/{rec_id}/start").status_code == 200
        resp = client.put(
            f"/api/outbound/recordings/{rec_id}",
            json=_create_body(mode="detail"),
        )
    assert resp.status_code == 409


def test_edit_label_only_on_active_returns_200(db_path: Path) -> None:
    # Aktive Aufzeichnung: nur label/purpose aendern (Konfig identisch) -> 200, kein Lock.
    with TestClient(_wired_app(db_path)) as client:
        rec_id = _create_id(client)
        assert client.post(f"/api/outbound/recordings/{rec_id}/start").status_code == 200
        resp = client.put(
            f"/api/outbound/recordings/{rec_id}",
            json=_create_body(label="Umbenannt"),
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["label"] == "Umbenannt"
    assert body["state"] == "active"


def test_edit_rename_to_existing_returns_409(db_path: Path) -> None:
    # Umbenennen auf einen von einer ANDEREN Aufzeichnung belegten Namen -> 409.
    with TestClient(_wired_app(db_path)) as client:
        _create_id(client, label="erster")
        second = _create_id(client, label="zweiter")
        resp = client.put(
            f"/api/outbound/recordings/{second}",
            json=_create_body(label="erster"),
        )
    assert resp.status_code == 409


def test_edit_keep_own_name_returns_200(db_path: Path) -> None:
    # Eigener Name unveraendert (exclude_id greift) -> 200, kein Konflikt mit sich selbst.
    with TestClient(_wired_app(db_path)) as client:
        rec_id = _create_id(client, label="behalten")
        resp = client.put(
            f"/api/outbound/recordings/{rec_id}",
            json=_create_body(label="behalten", purpose="Neuer Zweck"),
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["label"] == "behalten"
    assert body["purpose"] == "Neuer Zweck"


def test_edit_invalid_mode_returns_422(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        rec_id = _create_id(client)
        resp = client.put(
            f"/api/outbound/recordings/{rec_id}",
            json=_create_body(mode="bogus"),
        )
    assert resp.status_code == 422


# ── DELETE (idempotent) ──────────────────────────────────────────────────────


def test_delete_returns_204_and_is_idempotent(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        rec_id = _create_id(client)
        assert client.delete(f"/api/outbound/recordings/{rec_id}").status_code == 204
        # Idempotent: erneutes Loeschen (jetzt unbekannte id) ist KEIN Fehler -> 204.
        assert client.delete(f"/api/outbound/recordings/{rec_id}").status_code == 204
        # Danach ist die Definition weg.
        assert client.get(f"/api/outbound/recordings/{rec_id}").status_code == 404


# ── aggregate/detail (leere Liste bei unbekannter id) ────────────────────────


def test_aggregate_unknown_returns_empty_list(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        resp = client.get("/api/outbound/recordings/unknown/aggregate")
    assert resp.status_code == 200
    assert resp.json() == []


def test_detail_unknown_returns_empty_list(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        resp = client.get(
            "/api/outbound/recordings/unknown/detail",
            params={"since": 0.0, "until": 9999999999.0},
        )
    assert resp.status_code == 200
    assert resp.json() == []
