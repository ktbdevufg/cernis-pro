"""End-to-end-Tests der monitoring-REST-API (v2, M.9) gegen app.py via TestClient.

Echte Lese-Adapter auf tmp_path-DBs via ``dependency_overrides`` (kein echtes
cernis.db, kein Bootstrap-Loop -- ``AppConfig()`` hat ``bootstrap_on_startup`` aus).
Belegt die v2-Response-Shapes und die BEWUSSTEN Abweichungen vom M.1-Characterization-
Contract (der gegen ``main`` testet und unangetastet bleibt):

* ``/api/monitor/status`` -> ``{tid: {alive, label}}`` mit label-Anreicherung am Rand
  UND tid-Fallback (Status fuer ein Target, das die TargetSource nicht (mehr) kennt,
  bekommt ``label = tid``).
* ``/api/monitor/events`` -> KEIN ``id`` mehr (v2-Abweichung), aber ``datetime`` (am
  api-Rand aus ``timestamp`` formatiert) + ``ts`` (roh).
* ``/api/monitor/rtt/{id}`` -> ``{rtt_ms, loss_pct, ts}`` (ts aus PingSample.timestamp).
* ``/api/sla`` + ``/api/sla/{id}`` -> SLA-Shape; leere sla_samples-Tabelle -> ``[]``.
* ``/api/schedules`` CRUD -> 9-Spalten-Liste, ``{ok,id}`` / ``{ok}``.
"""

import sqlite3
import time
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.monitoring import (
    provide_get_all_sla_stats,
    provide_get_monitor_events,
    provide_get_rtt_history,
    provide_get_schedules,
    provide_get_sla_stats,
    provide_manage_schedules,
    provide_monitor_status,
    provide_update_schedule,
)
from app import create_app
from application.monitoring import (
    GetAllSlaStats,
    GetMonitorEvents,
    GetRttHistory,
    GetSchedules,
    GetSlaStats,
    ManageSchedules,
    UpdateSchedule,
)
from domain.monitoring import MonitorEvent, MonitorEventType, PingSample
from infrastructure.config import AppConfig
from infrastructure.monitoring import (
    SqliteMonitorEventRepository,
    SqliteRttHistoryRepository,
    SqliteScheduleRepository,
    SqliteSlaSampleRepository,
)

# Fester Timestamp fuer deterministische datetime-Formatierung am api-Rand.
# 1_700_000_000.0 == 2023-11-14 23:13:20 lokal (der genaue String kommt aus
# datetime.fromtimestamp -- der Test berechnet ihn gleich, statt ihn hartzukodieren,
# damit er zeitzonenunabhaengig gegen DENSELBEN Formatter prueft).
_TS = 1_700_000_000.0


async def _scheduled_scan_stub(cidr: str, profile_id: str, schedule_id: int) -> None:
    return None


class _FakeJobScheduler:
    """Fake-``ScanJobScheduler`` -- registriert/entfernt nur in-memory (kein APScheduler)."""

    def __init__(self) -> None:
        self.registered: list[int] = []
        self.unregistered: list[int] = []

    def start(self, callback: Any) -> None: ...

    def stop(self) -> None: ...

    def register(self, schedule: dict[str, Any], callback: Any) -> None:
        self.registered.append(int(schedule["id"]))

    def unregister(self, schedule_id: int) -> None:
        self.unregistered.append(schedule_id)


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "cernis.db"


def _insert_sla_sample(db_path: Path, target_id: str, ts: float, alive: int, rtt_ms: float) -> None:
    # sla_samples hat keinen Schreib-Port (M.7 nur Lese-Seite) -- direkter INSERT,
    # wie der Altcode-Schreibpfad es taete. Die Tabelle legt das Repo beim Bau an.
    SqliteSlaSampleRepository(db_path)  # _ensure_schema
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO sla_samples (target_id, ts, alive, rtt_ms) VALUES (?, ?, ?, ?)",
        (target_id, ts, alive, rtt_ms),
    )
    conn.commit()
    conn.close()


def _wired_app(
    db_path: Path,
    *,
    status: dict[str, dict[str, Any]] | None = None,
    jobs: _FakeJobScheduler | None = None,
) -> FastAPI:
    rtt = SqliteRttHistoryRepository(db_path)
    events = SqliteMonitorEventRepository(db_path)
    sla = SqliteSlaSampleRepository(db_path)
    schedules = SqliteScheduleRepository(db_path)
    job_scheduler = jobs or _FakeJobScheduler()

    app = create_app(AppConfig())
    app.dependency_overrides[provide_monitor_status] = lambda: lambda: status or {}
    app.dependency_overrides[provide_get_monitor_events] = lambda: GetMonitorEvents(events)
    app.dependency_overrides[provide_get_rtt_history] = lambda: GetRttHistory(rtt)
    app.dependency_overrides[provide_get_all_sla_stats] = lambda: GetAllSlaStats(sla)
    app.dependency_overrides[provide_get_sla_stats] = lambda: GetSlaStats(sla)
    app.dependency_overrides[provide_get_schedules] = lambda: GetSchedules(schedules)
    app.dependency_overrides[provide_manage_schedules] = lambda: ManageSchedules(
        schedules, job_scheduler, _scheduled_scan_stub
    )
    app.dependency_overrides[provide_update_schedule] = lambda: UpdateSchedule(schedules)
    return app


# ── /api/monitor/status (label-Anreicherung + tid-Fallback) ─────────────────


def test_status_passthrough_enriched_map() -> None:
    # Der Provider liefert bereits die angereicherte Form (Anreicherung im
    # Composition Root); der Endpunkt reicht sie 1:1 durch.
    status = {"wlan": {"alive": True, "label": "WLAN"}}
    app = create_app(AppConfig())
    app.dependency_overrides[provide_monitor_status] = lambda: lambda: status
    with TestClient(app) as client:
        resp = client.get("/api/monitor/status")
    assert resp.status_code == 200
    assert resp.json() == {"wlan": {"alive": True, "label": "WLAN"}}


# ── /api/monitor/events (KEIN id, MIT datetime) ─────────────────────────────


def test_events_v2_shape_has_no_id_but_datetime(db_path: Path, tmp_path: Path) -> None:
    from datetime import datetime

    events_repo = SqliteMonitorEventRepository(db_path)
    events_repo.save(
        MonitorEvent(
            target_id="wlan",
            label="WLAN",
            event=MonitorEventType.UP,
            rtt_ms=3.0,
            timestamp=_TS,
        )
    )
    with TestClient(_wired_app(db_path)) as client:
        body = client.get("/api/monitor/events").json()

    assert len(body) == 1
    evt = body[0]
    # v2-Abweichung: KEIN id (Altcode-Contract trug die rowid).
    assert "id" not in evt
    # Felder + Wire-Form: ts roh, datetime am Rand formatiert (%Y-%m-%d %H:%M:%S),
    # event als StrEnum-Wert.
    assert evt == {
        "target_id": "wlan",
        "label": "WLAN",
        "event": "up",
        "rtt_ms": 3.0,
        "ts": _TS,
        "datetime": datetime.fromtimestamp(_TS).strftime("%Y-%m-%d %H:%M:%S"),
    }


def test_events_empty_is_empty_list(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        resp = client.get("/api/monitor/events")
    assert resp.status_code == 200
    assert resp.json() == []


def test_events_limit_bounds(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        assert client.get("/api/monitor/events?limit=0").status_code == 422
        assert client.get("/api/monitor/events?limit=5").status_code == 200


# ── /api/monitor/rtt/{id} (ts aus timestamp) ────────────────────────────────


def test_rtt_shape_maps_timestamp_to_ts(db_path: Path) -> None:
    rtt_repo = SqliteRttHistoryRepository(db_path)
    rtt_repo.save(
        PingSample(
            target_id="wlan",
            host="192.168.1.1",
            alive=True,
            rtt_ms=4.2,
            loss_pct=0.0,
            timestamp=_TS,
        )
    )
    with TestClient(_wired_app(db_path)) as client:
        body = client.get("/api/monitor/rtt/wlan").json()
    assert body == [{"rtt_ms": 4.2, "loss_pct": 0.0, "ts": _TS}]


def test_rtt_unknown_target_empty(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        resp = client.get("/api/monitor/rtt/nope")
    assert resp.status_code == 200
    assert resp.json() == []


# ── /api/sla (+ leere Tabelle -> []) ────────────────────────────────────────


def test_sla_all_empty_when_no_samples(db_path: Path) -> None:
    # AS-IS-konform (M.7): sla_samples leer -> []. Kein Schreibpfad (M.7b).
    with TestClient(_wired_app(db_path)) as client:
        resp = client.get("/api/sla")
    assert resp.status_code == 200
    assert resp.json() == []


def test_sla_target_shape_with_target_id(db_path: Path) -> None:
    # GetSlaStats filtert ts > now - days*86400 -> der Sample muss INNERHALB des
    # 30-Tage-Fensters liegen (nicht der feste _TS aus 2023). 1h alt = sicher drin.
    _insert_sla_sample(db_path, "wlan", time.time() - 3600, 1, 3.0)
    with TestClient(_wired_app(db_path)) as client:
        body = client.get("/api/sla/wlan").json()
    # GetSlaStats ergaenzt target_id; die Domaenen-Stats tragen days/samples/...
    assert body["target_id"] == "wlan"
    assert body["days"] == 30
    assert body["samples"] >= 1
    assert "uptime_pct" in body
    assert "chart" in body


def test_sla_all_lists_target_after_sample(db_path: Path) -> None:
    # target_ids() ist DISTINCT ohne Zeitfilter -> der Target taucht auf, egal wie
    # alt der Sample ist; trotzdem frisch, damit GetSlaStats pro id nicht leer rechnet.
    _insert_sla_sample(db_path, "wlan", time.time() - 3600, 1, 3.0)
    with TestClient(_wired_app(db_path)) as client:
        body = client.get("/api/sla").json()
    assert [row["target_id"] for row in body] == ["wlan"]


# ── /api/schedules (CRUD) ───────────────────────────────────────────────────


def test_schedules_get_empty(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        resp = client.get("/api/schedules")
    assert resp.status_code == 200
    assert resp.json() == []


def test_schedule_add_returns_ok_with_id(db_path: Path) -> None:
    jobs = _FakeJobScheduler()
    with TestClient(_wired_app(db_path, jobs=jobs)) as client:
        resp = client.post(
            "/api/schedules",
            json={"name": "Nightly", "cidr": "10.0.0.0/24", "schedule": "interval:1h"},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert isinstance(body["id"], int)
    # Job wurde ueber den (im Composition-Root gebundenen) Callback registriert.
    assert jobs.registered == [body["id"]]


def test_schedule_add_empty_body_uses_defaults(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        resp = client.post("/api/schedules", json={})
    assert resp.status_code == 200
    assert resp.json()["ok"] is True


def test_schedule_add_then_listed_with_nine_columns(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        client.post("/api/schedules", json={"name": "X", "cidr": "10.0.0.0/24"})
        rows = client.get("/api/schedules").json()
    assert len(rows) == 1
    assert set(rows[0].keys()) == {
        "id",
        "name",
        "cidr",
        "profile_id",
        "schedule",
        "enabled",
        "last_run",
        "next_run",
        "created_at",
    }


def test_schedule_patch_returns_ok(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        sid = client.post("/api/schedules", json={"name": "X", "cidr": "10.0.0.0/24"}).json()["id"]
        resp = client.patch(f"/api/schedules/{sid}", json={"enabled": False})
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}


def test_schedule_delete_returns_ok_and_unregisters(db_path: Path) -> None:
    jobs = _FakeJobScheduler()
    with TestClient(_wired_app(db_path, jobs=jobs)) as client:
        sid = client.post("/api/schedules", json={"name": "X", "cidr": "10.0.0.0/24"}).json()["id"]
        resp = client.delete(f"/api/schedules/{sid}")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    assert jobs.unregistered == [sid]
