"""End-to-end-Tests des Verhaltensprofil-Endpunkts (Block 4, Etappe 2) via TestClient.

GET /api/monitor/logging/{id}/behavior. Echte Sqlite-Logging-Repos auf tmp_path-DBs via
``dependency_overrides`` (Muster ``test_logging_series_api.py``): Task ueber den Router
anlegen, dann RTT-Messpunkte direkt ueber das Repo ablegen -- der Endpunkt reicht sie in
die reine, zeitfreie ``analyze_behavior`` und projiziert das Ergebnis. Die Ziele-Achse ist
bewusst auf spaeter verschoben (host-globaler Außenkontakte-Lesepfad, keine geraetegenaue
Zuordnung -- siehe Endpunkt-Docstring), darum hier nicht geprueft.

Die ZEITFREIEN Felder (recorded_days/has_enough_data/deviation_count) werden HART geprueft.
Die zeitzonen-ABHAENGIGEN Felder (weekday/slot_start aus minute_of_day) leitet der Test aus
DEMSELBEN lokalen ``datetime.fromtimestamp`` ab wie der Router-enrich -- so bleibt der Test
unabhaengig von der Zeitzone des Testlaufs (genau die Trennung, die die Aggregation
zeitfrei haelt).
"""

from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.monitoring import (
    provide_create_logging_task,
    provide_get_logging_task_detail,
    provide_get_logging_task_rtt,
)
from app import create_app
from application.monitoring import (
    CreateLoggingTask,
    GetLoggingTaskDetail,
    GetLoggingTaskRtt,
)
from domain.monitoring import CaptureMode
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
    # Auch der Create-Pfad muss auf DIESELBE tmp-DB zeigen (sonst landet der per POST
    # angelegte Task in der echten cernis.db und der Lese-Client findet ihn nicht).
    app.dependency_overrides[provide_create_logging_task] = lambda: CreateLoggingTask(tasks)
    app.dependency_overrides[provide_get_logging_task_detail] = lambda: GetLoggingTaskDetail(tasks)
    app.dependency_overrides[provide_get_logging_task_rtt] = lambda: GetLoggingTaskRtt(tasks, rtt)
    return app


def _create_body(**overrides: Any) -> dict[str, Any]:
    """Valider IMMEDIATE-Create-Body (mit max_duration_s) -- per kwargs ueberschreibbar."""
    body = {
        "target_id": "wlan",
        "label": "Profil",
        "purpose": "Verhaltensanalyse",
        "capture_mode": "reachability_latency",
        "operation_mode": "immediate",
        "max_duration_s": 3600,
    }
    body.update(overrides)
    return body


def _expected_weekday(ts: float) -> int:
    """Spiegelt die Router-enrich-Rechnung: lokaler Wochentag aus ``ts`` (0..6, Mo=0)."""
    return datetime.fromtimestamp(ts).date().weekday()


def _expected_slot_start(ts: float, slot_minutes: int) -> int:
    """Spiegelt enrich + Bucketung: (lokale minute_of_day // slot) * slot."""
    local = datetime.fromtimestamp(ts)
    minute_of_day = local.hour * 60 + local.minute
    return (minute_of_day // slot_minutes) * slot_minutes


# ── 404 ─────────────────────────────────────────────────────────────────────


def test_behavior_unknown_task_returns_404(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        resp = client.get("/api/monitor/logging/never-existed/behavior")
    assert resp.status_code == 404


# ── zu wenig Daten: has_enough_data False, Listen trotzdem da ────────────────


def test_behavior_too_few_days_has_enough_data_false(db_path: Path) -> None:
    # Default min_days=14; mit Aktivitaet an EINEM Tag (ein voll belegter Tag <14)
    # ist has_enough_data False -- day_band/week_heatmap aber trotzdem befuellt.
    with TestClient(_wired_app(db_path)) as client:
        tid = client.post("/api/monitor/logging", json=_create_body()).json()["id"]

    rtt = SqliteLoggingRttRepository(db_path)
    base = datetime(2026, 6, 1, 0, 30, 0)  # Montag, lokale Naive-Zeit
    # Ein alive-Sample je Stunde -> alle 24 Stunden-Slots belegt -> Tag zaehlt als 1 Tag.
    for hour in range(24):
        ts = (base + timedelta(hours=hour)).timestamp()
        rtt.save(tid, 5.0, 0.0, True, ts)

    with TestClient(_wired_app(db_path)) as client:
        resp = client.get(f"/api/monitor/logging/{tid}/behavior")
    assert resp.status_code == 200
    body = resp.json()

    assert body["recorded_days"] == 1
    assert body["has_enough_data"] is False
    # Listen trotzdem befuellt (Anzeige entscheidet das Frontend).
    assert len(body["day_band"]) == 24
    assert len(body["week_heatmap"]) == 24
    # Ein Wochentag (Montag), 24 Slots -- jeder Slot-Eintrag traegt die vier Felder.
    for slot in body["week_heatmap"]:
        assert set(slot) == {"weekday", "slot_start", "activity_count", "is_deviation"}
        assert slot["weekday"] == _expected_weekday(base.timestamp())
    for slot in body["day_band"]:
        assert set(slot) == {"slot_start", "activity_count", "is_deviation"}


# ── genug Daten: has_enough_data True, deviation_count stimmt ─────────────────


def test_behavior_enough_days_with_deviation(db_path: Path) -> None:
    # 14 verschiedene Tage mit je einem festen "regulaeren" Slot (08:00) -> recorded_days
    # reicht nur, wenn jeder Tag die Belegungsschwelle erreicht. day_min_coverage=0.5
    # bei slot_minutes=60 -> 12 von 24 Slots muessen belegt sein. Also je Tag 12 Stunden
    # belegen; an EINEM Tag zusaetzlich ein einzelner Nacht-Ausreisser (03:00) als
    # Abweichung an einem sonst leeren Slot.
    with TestClient(_wired_app(db_path)) as client:
        tid = client.post("/api/monitor/logging", json=_create_body()).json()["id"]

    rtt = SqliteLoggingRttRepository(db_path)
    deviation_ts: float | None = None
    for day in range(14):
        day_base = datetime(2026, 6, 1, 0, 0, 0) + timedelta(days=day)
        # 12 belegte Stunden-Slots (08:00..19:00) -> coverage 12/24 = 0.5 (>= Schwelle).
        for hour in range(8, 20):
            ts = (day_base + timedelta(hours=hour)).timestamp()
            rtt.save(tid, 5.0, 0.0, True, ts)
        if day == 0:
            # Nacht-Ausreisser an einem sonst leeren 03:00-Slot. Die 14 Kalendertage
            # ueberlappen Wochentage (nur 7), darum traegt der Ausreisser-Wochentag
            # auch seine regulaeren 08..19-Slots -- sein Median liegt also nicht bei 0.
            # Damit der Ausreisser ROBUST ueber der Schwelle (count > deviation_factor*median)
            # liegt, fuellen wir die 03:00-Stunde dicht (20 Samples verschiedener Minuten
            # desselben Stunden-Slots) -> hoher count, der jeden plausiblen Median ueberschreitet.
            deviation_ts = (day_base + timedelta(hours=3)).timestamp()
            for minute in range(20):
                ts = (day_base + timedelta(hours=3, minutes=minute)).timestamp()
                rtt.save(tid, 5.0, 0.0, True, ts)

    assert deviation_ts is not None
    with TestClient(_wired_app(db_path)) as client:
        resp = client.get(f"/api/monitor/logging/{tid}/behavior?slot_minutes=60")
    assert resp.status_code == 200
    body = resp.json()

    assert body["recorded_days"] == 14
    assert body["has_enough_data"] is True

    # deviation_count = Summe is_deviation ueber die Wochen-Heatmap. Der dicht belegte
    # 03:00-Ausreisser liegt deutlich ueber dem typischen Wert seines Wochentags -> Abweichung.
    dev_weekday = _expected_weekday(deviation_ts)
    dev_slot = _expected_slot_start(deviation_ts, 60)
    flagged = [
        s
        for s in body["week_heatmap"]
        if s["weekday"] == dev_weekday and s["slot_start"] == dev_slot
    ]
    assert len(flagged) == 1
    assert flagged[0]["is_deviation"] is True
    # deviation_count zaehlt mindestens diesen einen markierten Slot.
    assert body["deviation_count"] >= 1
    assert body["deviation_count"] == sum(1 for s in body["week_heatmap"] if s["is_deviation"])


# ── since/until grenzt den Zeitraum ein ──────────────────────────────────────


def test_behavior_since_until_limits_range(db_path: Path) -> None:
    # Samples an zwei getrennten Tagen; since/until schneidet auf den ersten Tag.
    with TestClient(_wired_app(db_path)) as client:
        tid = client.post("/api/monitor/logging", json=_create_body()).json()["id"]

    rtt = SqliteLoggingRttRepository(db_path)
    day1 = datetime(2026, 6, 1, 12, 0, 0).timestamp()
    day2 = datetime(2026, 6, 5, 12, 0, 0).timestamp()
    rtt.save(tid, 5.0, 0.0, True, day1)
    rtt.save(tid, 5.0, 0.0, True, day2)

    # Voller Zeitraum: beide Tage tragen Aktivitaet -> beide Slots in der Heatmap.
    with TestClient(_wired_app(db_path)) as client:
        full = client.get(f"/api/monitor/logging/{tid}/behavior").json()
    # Eingrenzen auf [day1, day1+1h): nur der erste Tag faellt hinein.
    with TestClient(_wired_app(db_path)) as client:
        limited = client.get(
            f"/api/monitor/logging/{tid}/behavior?since={day1}&until={day1 + 3600}"
        ).json()

    # Volle Sicht: zwei distinkte (weekday, slot) -- die beiden Tage liegen auf
    # unterschiedlichen Wochentagen/derselben Stunde.
    assert len(full["week_heatmap"]) == 2
    # Eingegrenzte Sicht: nur der erste Tag, also genau ein Heatmap-Slot.
    assert len(limited["week_heatmap"]) == 1
    assert limited["week_heatmap"][0]["weekday"] == _expected_weekday(day1)
    assert limited["week_heatmap"][0]["slot_start"] == _expected_slot_start(day1, 60)


# ── slot_minutes-Validierung (Stil wie series) ───────────────────────────────


def test_behavior_slot_minutes_valid(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        tid = client.post("/api/monitor/logging", json=_create_body()).json()["id"]
        ok_low = client.get(f"/api/monitor/logging/{tid}/behavior?slot_minutes=15")
        ok_high = client.get(f"/api/monitor/logging/{tid}/behavior?slot_minutes=60")
    assert ok_low.status_code == 200
    assert ok_high.status_code == 200


def test_behavior_slot_minutes_out_of_range_is_422(db_path: Path) -> None:
    with TestClient(_wired_app(db_path)) as client:
        tid = client.post("/api/monitor/logging", json=_create_body()).json()["id"]
        too_small = client.get(f"/api/monitor/logging/{tid}/behavior?slot_minutes=14")
        too_big = client.get(f"/api/monitor/logging/{tid}/behavior?slot_minutes=61")
        garbage = client.get(f"/api/monitor/logging/{tid}/behavior?slot_minutes=abc")
    assert too_small.status_code == 422
    assert too_big.status_code == 422
    assert garbage.status_code == 422


# ── since/until-Durchreichung an den RTT-Use-Case (Spy, Stil wie series) ─────


class _SpyDetail:
    """``GetLoggingTaskDetail``-Spy: liefert einen Stub-Task (kein 404)."""

    def __call__(self, task_id: str) -> Any:
        class _Task:
            capture_mode = CaptureMode.REACHABILITY_LATENCY

        return _Task()


class _SpyRtt:
    """``GetLoggingTaskRtt``-Spy: zeichnet since/until auf, gibt leere Liste."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def __call__(
        self, task_id: str, since: float | None = None, until: float | None = None
    ) -> list[Any]:
        self.calls.append({"task_id": task_id, "since": since, "until": until})
        return []


def _app_with_spies(detail: _SpyDetail, rtt: _SpyRtt) -> FastAPI:
    app = create_app(AppConfig())
    app.dependency_overrides[provide_get_logging_task_detail] = lambda: detail
    app.dependency_overrides[provide_get_logging_task_rtt] = lambda: rtt
    return app


def test_behavior_passes_since_and_until_through_to_rtt() -> None:
    rtt = _SpyRtt()
    with TestClient(_app_with_spies(_SpyDetail(), rtt)) as client:
        resp = client.get("/api/monitor/logging/t1/behavior?since=100.5&until=200.5")
    assert resp.status_code == 200
    assert rtt.calls == [{"task_id": "t1", "since": 100.5, "until": 200.5}]


def test_behavior_without_query_passes_none_through() -> None:
    rtt = _SpyRtt()
    with TestClient(_app_with_spies(_SpyDetail(), rtt)) as client:
        resp = client.get("/api/monitor/logging/t1/behavior")
    assert resp.status_code == 200
    assert rtt.calls == [{"task_id": "t1", "since": None, "until": None}]
