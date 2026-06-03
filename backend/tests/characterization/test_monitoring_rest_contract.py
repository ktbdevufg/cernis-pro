"""Characterization-Contract der monitoring-nahen REST-Endpunkte (Altcode main.py).

Netzwerk-/DB-frei: die Endpunkt-Funktionen werden auf eine FRISCHE App gehaengt
(``add_api_route``, keine main-Lifespan), ihre Modul-Helfer sind am main-Namespace
gemockt. Festgehalten werden die Response-Shapes von ``/api/monitor/status``,
``/api/monitor/events``, ``/api/monitor/rtt/{id}``, POST/DELETE
``/api/monitor/targets``, ``/api/sla``, ``/api/sla/{id}`` sowie der scan_schedules-
CRUD unter ``/api/schedules`` (GET/POST/PATCH/DELETE).

Bewusst AS-IS eingefroren (toter Strang, NICHT gefixt -- Fix ist M.7-Entscheidung):
``sla_samples`` wird im Loop nie geschrieben, also liefert ``get_all_sla_stats``
bei leerer Tabelle ``[]``. Der Test friert genau das ein (``/api/sla`` == ``[]``).
"""

from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import main

# IST-Shapes der Helfer-Rueckgaben, am main-Namespace gemockt -- so wird die
# Endpunkt->Helfer-Verdrahtung samt Response-Form eingefroren, ohne echte DB.
_EVENT_ROW = {
    "id": 1,
    "target_id": "wlan",
    "label": "WLAN",
    "event": "up",
    "rtt_ms": 3.0,
    "ts": 1_700_000_000.0,
    "datetime": "2026-05-28 12:00:00",
}
_RTT_ROW = {"rtt_ms": 3.0, "loss_pct": 0.0, "ts": 1_700_000_000.0}
_STATUS = {"wlan": {"alive": True, "label": "WLAN"}}
_SLA_STAT = {
    "target_id": "wlan",
    "days": 30,
    "samples": 0,
    "uptime_pct": None,
    "downtime_mins": 0,
    "avg_rtt_ms": 0,
    "chart": [],
}
_SCHEDULE_ROW = {
    "id": 1,
    "name": "Nightly",
    "cidr": "192.168.1.0/24",
    "profile_id": "standard",
    "schedule": "cron:0 2 * * *",
    "enabled": 1,
    "last_run": None,
    "next_run": None,
    "created_at": "2026-05-28 12:00:00",
}


@pytest.fixture
def rest_client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setattr(main, "get_current_status", lambda: _STATUS)
    monkeypatch.setattr(main, "get_monitor_events", lambda limit=100: [_EVENT_ROW])
    monkeypatch.setattr(main, "get_rtt_history", lambda target_id, limit=120: [_RTT_ROW])

    # targets: Settings-Persistenz + Live-Reconfigure am main-Namespace neutralisiert.
    settings_store: dict[str, Any] = {}
    monkeypatch.setattr(
        main, "get_setting", lambda key, default=None: settings_store.get(key, default)
    )
    monkeypatch.setattr(
        main, "set_setting", lambda key, value: settings_store.__setitem__(key, value)
    )
    monkeypatch.setattr(main, "_build_monitor_targets", lambda: [])
    monkeypatch.setattr(main, "configure_monitor", lambda targets, interval=5: None)

    # sla: AS-IS -- leere sla_samples-Tabelle -> get_all_sla_stats == []
    monkeypatch.setattr(main, "get_all_sla_stats", lambda days=30: [])
    monkeypatch.setattr(main, "get_sla_stats", lambda target_id, days=30: _SLA_STAT)

    # schedules: CRUD-Helfer gemockt, IST-Rueckgaben festgehalten.
    monkeypatch.setattr(main, "get_schedules", lambda: [_SCHEDULE_ROW])
    monkeypatch.setattr(main, "add_schedule", lambda name, cidr, profile_id, schedule: 7)
    monkeypatch.setattr(main, "update_schedule", lambda schedule_id, enabled=None, name=None: None)
    monkeypatch.setattr(main, "delete_schedule", lambda schedule_id: None)

    fresh = FastAPI()
    fresh.add_api_route("/api/monitor/status", main.api_monitor_status, methods=["GET"])
    fresh.add_api_route("/api/monitor/events", main.api_monitor_events, methods=["GET"])
    fresh.add_api_route("/api/monitor/rtt/{target_id}", main.api_monitor_rtt, methods=["GET"])
    fresh.add_api_route("/api/monitor/targets", main.api_add_monitor_target, methods=["POST"])
    fresh.add_api_route(
        "/api/monitor/targets/{target_id}",
        main.api_remove_monitor_target,
        methods=["DELETE"],
    )
    fresh.add_api_route("/api/sla", main.api_sla_all, methods=["GET"])
    fresh.add_api_route("/api/sla/{target_id}", main.api_sla_target, methods=["GET"])
    fresh.add_api_route("/api/schedules", main.api_get_schedules, methods=["GET"])
    fresh.add_api_route("/api/schedules", main.api_add_schedule, methods=["POST"])
    fresh.add_api_route("/api/schedules/{schedule_id}", main.api_update_schedule, methods=["PATCH"])
    fresh.add_api_route(
        "/api/schedules/{schedule_id}", main.api_delete_schedule, methods=["DELETE"]
    )
    # raise_server_exceptions=False: der ungeschuetzte KeyError in
    # api_add_monitor_target soll als 500-Response sichtbar werden (AS-IS),
    # nicht in den Test propagieren.
    return TestClient(fresh, raise_server_exceptions=False)


# ── monitor ───────────────────────────────────────────────────


def test_monitor_status_returns_inmemory_map(rest_client: TestClient) -> None:
    resp = rest_client.get("/api/monitor/status")
    assert resp.status_code == 200
    assert resp.json() == {"wlan": {"alive": True, "label": "WLAN"}}


def test_monitor_events_returns_event_rows(rest_client: TestClient) -> None:
    resp = rest_client.get("/api/monitor/events")
    assert resp.status_code == 200
    assert resp.json() == [_EVENT_ROW]


def test_monitor_events_respects_limit_bounds(rest_client: TestClient) -> None:
    # ge=1, le=1000 (Query-Constraints) -> 0 ist 422
    assert rest_client.get("/api/monitor/events?limit=0").status_code == 422
    assert rest_client.get("/api/monitor/events?limit=5").status_code == 200


def test_monitor_rtt_returns_rtt_rows(rest_client: TestClient) -> None:
    resp = rest_client.get("/api/monitor/rtt/wlan")
    assert resp.status_code == 200
    assert resp.json() == [_RTT_ROW]


def test_add_monitor_target_returns_ok(rest_client: TestClient) -> None:
    resp = rest_client.post(
        "/api/monitor/targets",
        json={"id": "gw", "label": "Gateway", "host": "192.168.1.1"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}


def test_add_monitor_target_missing_key_yields_500(rest_client: TestClient) -> None:
    # payload["id"]/["label"]/["host"] sind Pflicht via KeyError -> 500 (AS-IS,
    # kein Pydantic-Modell, kein 422). Friert das ungeschuetzte Verhalten ein.
    resp = rest_client.post("/api/monitor/targets", json={"id": "gw"})
    assert resp.status_code == 500


def test_remove_monitor_target_returns_ok(rest_client: TestClient) -> None:
    resp = rest_client.delete("/api/monitor/targets/gw")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}


# ── sla (toter Strang AS-IS) ──────────────────────────────────


def test_sla_all_empty_when_no_samples(rest_client: TestClient) -> None:
    # AS-IS: sla_samples wird nie geschrieben -> leere Liste. NICHT gefixt (M.7).
    resp = rest_client.get("/api/sla")
    assert resp.status_code == 200
    assert resp.json() == []


def test_sla_target_returns_zeroed_stats(rest_client: TestClient) -> None:
    resp = rest_client.get("/api/sla/wlan")
    assert resp.status_code == 200
    assert resp.json() == _SLA_STAT


# ── schedules ─────────────────────────────────────────────────


def test_get_schedules_lists_rows(rest_client: TestClient) -> None:
    resp = rest_client.get("/api/schedules")
    assert resp.status_code == 200
    assert resp.json() == [_SCHEDULE_ROW]


def test_add_schedule_returns_ok_with_id(rest_client: TestClient) -> None:
    resp = rest_client.post("/api/schedules", json={"name": "X", "cidr": "10.0.0.0/24"})
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "id": 7}


def test_add_schedule_accepts_empty_body_with_defaults(rest_client: TestClient) -> None:
    # payload.get(...)-Defaults -> leerer Body ist gueltig (AS-IS).
    resp = rest_client.post("/api/schedules", json={})
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "id": 7}


def test_patch_schedule_returns_ok(rest_client: TestClient) -> None:
    resp = rest_client.patch("/api/schedules/1", json={"enabled": False})
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}


def test_delete_schedule_returns_ok(rest_client: TestClient) -> None:
    resp = rest_client.delete("/api/schedules/1")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
