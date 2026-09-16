"""End-to-end-Tests des Serien-Auswertungs-Endpunkts (Block 3c) via TestClient.

GET /api/monitor/logging/{id}/series. Echte Sqlite-Logging-Repos auf tmp_path-DBs via
``dependency_overrides`` (Muster ``test_logging_api.py``): Task ueber den Router anlegen,
dann Event-Flanken + RTT-Messpunkte direkt ueber die Repos ablegen -- der Endpunkt
reicht sie in die reine, zeitfreie ``analyze_series`` und projiziert das Ergebnis.

Die ZEITFREIEN Felder (metrics ohne worst_slot, outages start/end/duration, has_latency)
werden HART geprueft. Die zeitzonen-ABHAENGIGEN Felder (minute_of_day/day_key und damit
heatmap/ranking/worst_slot) leitet der Test aus DEMSELBEN lokalen
``datetime.fromtimestamp`` ab wie der Router-enrich -- so bleibt der Test unabhaengig von
der Zeitzone des Testlaufs (genau die Trennung, die die Aggregation zeitfrei haelt).
"""

from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.monitoring import (
    provide_create_logging_task,
    provide_get_logging_task_detail,
    provide_get_logging_task_events,
    provide_get_logging_task_rtt,
)
from app import create_app
from application.monitoring import (
    CreateLoggingTask,
    GetLoggingTaskDetail,
    GetLoggingTaskEvents,
    GetLoggingTaskRtt,
)
from domain.monitoring import CaptureMode
from infrastructure.config import AppConfig
from infrastructure.monitoring import (
    SqliteLoggingEventRepository,
    SqliteLoggingRttRepository,
    SqliteLoggingTaskRepository,
)


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "cernis.db"


def _wired_app(db_path: Path) -> FastAPI:
    tasks = SqliteLoggingTaskRepository(db_path)
    rtt = SqliteLoggingRttRepository(db_path)
    events = SqliteLoggingEventRepository(db_path)

    app = create_app(AppConfig())
    # Auch der Create-Pfad muss auf DIESELBE tmp-DB zeigen (sonst landet der per POST
    # angelegte Task in der echten cernis.db und der Lese-Client findet ihn nicht).
    app.dependency_overrides[provide_create_logging_task] = lambda: CreateLoggingTask(tasks)
    app.dependency_overrides[provide_get_logging_task_detail] = lambda: GetLoggingTaskDetail(tasks)
    app.dependency_overrides[provide_get_logging_task_events] = lambda: GetLoggingTaskEvents(
        tasks, events
    )
    app.dependency_overrides[provide_get_logging_task_rtt] = lambda: GetLoggingTaskRtt(tasks, rtt)
    return app


def _create_body(**overrides: Any) -> dict[str, Any]:
    """Valider IMMEDIATE-Create-Body (mit max_duration_s) -- per kwargs ueberschreibbar."""
    body = {
        "target_id": "wlan",
        "label": "Serie",
        "purpose": "Stoerungssuche",
        "capture_mode": "reachability_latency",
        "operation_mode": "immediate",
        "max_duration_s": 3600,
    }
    body.update(overrides)
    return body


def _expected_local_minute(ts: float) -> int:
    """Spiegelt die Router-enrich-Rechnung: lokale Stunde*60 + Minute aus ``ts``."""
    local = datetime.fromtimestamp(ts)
    return local.hour * 60 + local.minute


def _expected_local_day_key(ts: float) -> str:
    """Spiegelt die Router-enrich-Rechnung: lokales ISO-Datum aus ``ts``."""
    return datetime.fromtimestamp(ts).date().isoformat()


def _slot_of(minute_of_day: int, slot_minutes: int) -> int:
    """Untere Bucket-Grenze (wie ``series_analysis._slot_of``)."""
    return (minute_of_day // slot_minutes) * slot_minutes


# ── 404 ─────────────────────────────────────────────────────────────────────


def test_series_unknown_task_returns_404(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        resp = client.get("/api/monitor/logging/never-existed/series")
    assert resp.status_code == 404


# ── glueckliche Bahn (REACHABILITY_LATENCY, has_latency True) ────────────────


def test_series_known_task_with_outages(db_path: Path) -> None:
    # Task anlegen (id vom Router), dann zwei down/up-Paare + RTT-Samples ablegen.
    with TestClient(_wired_app(db_path)) as client:
        tid = client.post("/api/monitor/logging", json=_create_body()).json()["id"]

    down1, up1 = 1_700_000_000.0, 1_700_000_010.0  # Abbruch 10 s
    down2, up2 = 1_700_000_100.0, 1_700_000_130.0  # Abbruch 30 s
    events = SqliteLoggingEventRepository(db_path)
    events.save(tid, "down", -1.0, down1)
    events.save(tid, "up", 5.0, up1)
    events.save(tid, "down", -1.0, down2)
    events.save(tid, "up", 6.0, up2)
    # RTT-Samples: 3 alive, 1 down -> availability 75 %.
    rtt = SqliteLoggingRttRepository(db_path)
    rtt.save(tid, 4.0, 0.0, True, down1)
    rtt.save(tid, 5.0, 0.0, True, up1)
    rtt.save(tid, -1.0, 100.0, False, down2)
    rtt.save(tid, 6.0, 0.0, True, up2)

    with TestClient(_wired_app(db_path)) as client:
        resp = client.get(f"/api/monitor/logging/{tid}/series")
    assert resp.status_code == 200
    body = resp.json()

    # REACHABILITY_LATENCY -> has_latency True.
    assert body["has_latency"] is True

    # metrics: 2 Abbrueche, mittlere Dauer (10+30)/2 = 20, availability 3/4 alive -> 75.
    assert body["metrics"]["outage_count"] == 2
    assert body["metrics"]["avg_outage_s"] == 20.0
    assert body["metrics"]["availability_pct"] == 75.0

    # outages: beide geschlossen, roh durchgereicht (keine Rundung). minute_of_day/
    # day_key gegen die lokale enrich-Rechnung (zeitzonenunabhaengig abgeleitet).
    assert body["outages"] == [
        {
            "start_ts": down1,
            "end_ts": up1,
            "duration_s": 10.0,
            "minute_of_day": _expected_local_minute(down1),
            "day_key": _expected_local_day_key(down1),
        },
        {
            "start_ts": down2,
            "end_ts": up2,
            "duration_s": 30.0,
            "minute_of_day": _expected_local_minute(down2),
            "day_key": _expected_local_day_key(down2),
        },
    ]

    # heatmap: je Abbruch ein Eintrag im Default-Slot (slot_minutes=10), nach
    # minute_of_day sortiert. Aus den beiden start_ts abgeleitet.
    slot1 = _slot_of(_expected_local_minute(down1), 10)
    slot2 = _slot_of(_expected_local_minute(down2), 10)
    expected_heat: dict[int, int] = {}
    for slot in (slot1, slot2):
        expected_heat[slot] = expected_heat.get(slot, 0) + 1
    assert body["heatmap"] == [
        {"minute_of_day": slot, "outage_count": count}
        for slot, count in sorted(expected_heat.items())
    ]

    # ranking: longest_outage_s ist die laengste Dauer je Slot. day_count >= 1.
    for entry in body["ranking"]:
        assert entry["day_count"] >= 1
        assert entry["longest_outage_s"] > 0


def test_series_open_outage_at_end_carries_null_end_ts(db_path: Path) -> None:
    # Ein down ohne folgendes up -> offener Abbruch (end_ts None), Dauer bis letztem ts.
    with TestClient(_wired_app(db_path)) as client:
        tid = client.post("/api/monitor/logging", json=_create_body()).json()["id"]
    down = 1_700_000_000.0
    events = SqliteLoggingEventRepository(db_path)
    events.save(tid, "down", -1.0, down)

    with TestClient(_wired_app(db_path)) as client:
        resp = client.get(f"/api/monitor/logging/{tid}/series")
    assert resp.status_code == 200
    outages = resp.json()["outages"]
    assert len(outages) == 1
    assert outages[0]["start_ts"] == down
    assert outages[0]["end_ts"] is None
    assert outages[0]["duration_s"] == 0.0  # letzter bekannter Event-ts == down


# ── latency_slots: Wire-Form der Latenz-Achse ───────────────────────────────


def test_series_latency_slots_in_wire_form(db_path: Path) -> None:
    # RTT-Samples mit echten ts -> latency_slots in der Wire-Form mit den vier Feldern.
    # Sentinel/dead-Sample wird aus der Latenz-Aggregation ausgespart.
    with TestClient(_wired_app(db_path)) as client:
        tid = client.post("/api/monitor/logging", json=_create_body()).json()["id"]

    ts = 1_700_000_000.0  # alle Samples in dieselbe Minute -> EIN latency_slot
    rtt = SqliteLoggingRttRepository(db_path)
    rtt.save(tid, 10.0, 0.0, True, ts)
    rtt.save(tid, 30.0, 0.0, True, ts + 1)
    rtt.save(tid, -1.0, 100.0, False, ts + 2)  # Sentinel -> ausgespart

    with TestClient(_wired_app(db_path)) as client:
        resp = client.get(f"/api/monitor/logging/{tid}/series?slot_minutes=60")
    assert resp.status_code == 200
    slots = resp.json()["latency_slots"]

    expected_slot = _slot_of(_expected_local_minute(ts), 60)
    assert slots == [
        {
            "minute_of_day": expected_slot,
            "sample_count": 2,  # der Sentinel zaehlt nicht
            "p95_rtt_ms": 30.0,  # n=2: Index = ceil(1.9)-1 = 1 -> 30.0
            "max_rtt_ms": 30.0,
        }
    ]


# ── REACHABILITY (has_latency False) ────────────────────────────────────────


def test_series_reachability_has_no_latency(db_path: Path) -> None:
    # capture_mode reachability -> has_latency False. Ohne Daten leere Sichten.
    with TestClient(_wired_app(db_path)) as client:
        tid = client.post(
            "/api/monitor/logging", json=_create_body(capture_mode="reachability")
        ).json()["id"]
        resp = client.get(f"/api/monitor/logging/{tid}/series")
    assert resp.status_code == 200
    body = resp.json()
    assert body["has_latency"] is False
    # Keine Events/Samples -> leere Outages/Heatmap/Ranking, availability 100 (ehrlich leer).
    assert body["outages"] == []
    assert body["heatmap"] == []
    assert body["ranking"] == []
    assert body["latency_slots"] == []
    assert body["metrics"]["outage_count"] == 0
    assert body["metrics"]["avg_outage_s"] == 0.0
    assert body["metrics"]["availability_pct"] == 100.0
    assert body["metrics"]["worst_slot_minute"] is None


# ── since/until + slot_minutes-Durchreichung am Router-Rand ──────────────────


class _SpyDetail:
    """``GetLoggingTaskDetail``-Spy: liefert einen Stub-Task mit capture_mode.

    Das ``capture_mode`` muss ein echtes ``CaptureMode`` sein (``analyze_series``
    vergleicht es mit ``CaptureMode.REACHABILITY_LATENCY``); die since/until-Naht prueft
    nicht die Aggregation, darum genuegt der Minimal-Stub-Task.
    """

    def __call__(self, task_id: str) -> Any:
        class _Task:
            capture_mode = CaptureMode.REACHABILITY

        return _Task()


class _SpyEvents:
    """``GetLoggingTaskEvents``-Spy: zeichnet since/until auf, gibt leere Liste."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def __call__(
        self, task_id: str, since: float | None = None, until: float | None = None
    ) -> list[Any]:
        self.calls.append({"task_id": task_id, "since": since, "until": until})
        return []


class _SpyRtt:
    """``GetLoggingTaskRtt``-Spy: zeichnet since/until auf, gibt leere Liste."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def __call__(
        self, task_id: str, since: float | None = None, until: float | None = None
    ) -> list[Any]:
        self.calls.append({"task_id": task_id, "since": since, "until": until})
        return []


def _app_with_spies(detail: _SpyDetail, events: _SpyEvents, rtt: _SpyRtt) -> FastAPI:
    app = create_app(AppConfig())
    app.dependency_overrides[provide_get_logging_task_detail] = lambda: detail
    app.dependency_overrides[provide_get_logging_task_events] = lambda: events
    app.dependency_overrides[provide_get_logging_task_rtt] = lambda: rtt
    return app


def test_series_passes_since_and_until_through_to_use_cases() -> None:
    events, rtt = _SpyEvents(), _SpyRtt()
    with TestClient(_app_with_spies(_SpyDetail(), events, rtt)) as client:
        resp = client.get("/api/monitor/logging/t1/series?since=100.5&until=200.5")
    assert resp.status_code == 200
    assert events.calls == [{"task_id": "t1", "since": 100.5, "until": 200.5}]
    assert rtt.calls == [{"task_id": "t1", "since": 100.5, "until": 200.5}]


def test_series_without_query_passes_none_through() -> None:
    events, rtt = _SpyEvents(), _SpyRtt()
    with TestClient(_app_with_spies(_SpyDetail(), events, rtt)) as client:
        resp = client.get("/api/monitor/logging/t1/series")
    assert resp.status_code == 200
    assert events.calls == [{"task_id": "t1", "since": None, "until": None}]
    assert rtt.calls == [{"task_id": "t1", "since": None, "until": None}]


def test_series_slot_minutes_out_of_range_is_422() -> None:
    events, rtt = _SpyEvents(), _SpyRtt()
    with TestClient(_app_with_spies(_SpyDetail(), events, rtt)) as client:
        too_big = client.get("/api/monitor/logging/t1/series?slot_minutes=61")
        too_small = client.get("/api/monitor/logging/t1/series?slot_minutes=0")
    assert too_big.status_code == 422
    assert too_small.status_code == 422
