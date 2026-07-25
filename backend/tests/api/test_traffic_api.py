"""End-to-end-Tests des traffic-Routers (v2, T.4b-2) gegen app.py via TestClient.

Belegt: ``GET /api/traffic`` serialisiert die App-Uebersicht inkl. eingebetteter
Verbindungen (Runner via ``dependency_overrides`` durch einen Fake ersetzt -- kein
echtes psutil/ss); die Durchsatz-Felder sind ``null`` ohne Raten (ehrliche Stufe 1)
bzw. gesetzt mit Raten. ``POST /api/traffic/poll/start|stop`` liefern ``{ok: True}``
ueber die Runner-Callables. Der echte asyncio-Task-Lebenszyklus wird NICHT hier,
sondern im Laufzeit-Smoke geprueft (TestClient ohne bootstrap -> keine echten Tasks).
"""

import sys
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.traffic import (
    provide_list_app_traffic,
    provide_poll_error,
    provide_start_poll,
    provide_stop_poll,
)
from app import create_app
from domain.traffic import Connection, Endpoint, aggregate_by_app
from infrastructure.config import AppConfig


@pytest.fixture
def app() -> Iterator[FastAPI]:
    yield create_app(AppConfig())


def _conn(
    app_name: str | None, *, send: float | None = None, recv: float | None = None
) -> Connection:
    return Connection(
        l4="tcp",
        status="established",
        local=Endpoint(ip="10.0.0.1", port=443),
        remote=Endpoint(ip="1.1.1.1", port=443),
        pid=10 if app_name else None,
        app_name=app_name,
        send_rate_bps=send,
        recv_rate_bps=recv,
    )


def test_traffic_wire_form_stage1_rates_null(app: FastAPI) -> None:
    """``/api/traffic`` liefert App-Uebersicht; ohne Raten sind die *_rate_bps null."""

    async def _fake_runner() -> list[Any]:
        return aggregate_by_app([_conn("firefox"), _conn(None)])

    app.dependency_overrides[provide_list_app_traffic] = lambda: _fake_runner

    with TestClient(app) as client:
        response = client.get("/api/traffic")

    assert response.status_code == 200
    body = response.json()
    by_name = {a["app_name"]: a for a in body}
    assert "firefox" in by_name
    # None-Gruppe (rootless) ist als app_name=null vorhanden.
    assert None in by_name
    conn = by_name["firefox"]["connections"][0]
    assert conn["send_rate_bps"] is None
    assert conn["recv_rate_bps"] is None
    assert conn["local"] == {"ip": "10.0.0.1", "port": 443}


def test_traffic_wire_form_with_rates(app: FastAPI) -> None:
    """Mit Raten angereichert -> *_rate_bps gesetzt, total_* summiert."""

    async def _fake_runner() -> list[Any]:
        return aggregate_by_app([_conn("firefox", send=100.0, recv=10.0)])

    app.dependency_overrides[provide_list_app_traffic] = lambda: _fake_runner

    with TestClient(app) as client:
        response = client.get("/api/traffic")

    body = response.json()
    app_entry = body[0]
    assert app_entry["connections"][0]["send_rate_bps"] == 100.0
    assert app_entry["total_send_rate_bps"] == 100.0
    assert app_entry["total_recv_rate_bps"] == 10.0


def test_poll_start_returns_ok(app: FastAPI) -> None:
    calls: list[str] = []

    def _fake_start() -> dict[str, Any]:
        calls.append("start")
        return {"ok": True}

    app.dependency_overrides[provide_start_poll] = lambda: _fake_start

    with TestClient(app) as client:
        response = client.post("/api/traffic/poll/start")

    assert response.status_code == 200
    assert response.json() == {"ok": True}
    assert calls == ["start"]


def test_poll_stop_returns_ok(app: FastAPI) -> None:
    calls: list[str] = []

    def _fake_stop() -> None:
        calls.append("stop")

    app.dependency_overrides[provide_stop_poll] = lambda: _fake_stop

    with TestClient(app) as client:
        response = client.post("/api/traffic/poll/stop")

    assert response.status_code == 200
    assert response.json() == {"ok": True}
    assert calls == ["stop"]


# ── GET /api/traffic/permission: Zustand der Durchsatz-Sicht ────────────────
# Wichtig ist hier die ECHTE Verdrahtung aus app.py (kein Fake fuer den
# Rechte-Adapter): auf Linux muss der Durchsatz als messbar gemeldet werden --
# das ist der Kern von Finding 5.


def test_permission_endpunkt_liefert_form(app: FastAPI) -> None:
    with TestClient(app) as client:
        antwort = client.get("/api/traffic/permission")

    assert antwort.status_code == 200
    daten = antwort.json()
    assert set(daten) == {"ok", "error", "state"}


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux-Verhalten")
def test_permission_auf_linux_ist_granted_ohne_root(app: FastAPI) -> None:
    """Rootless auf Linux -> ok=true/granted, KEIN Rechte-Hinweis (Finding 5).

    Laeuft der Test ausnahmsweise als Root, gilt dasselbe Ergebnis -- die
    Aussage haengt nicht mehr an der Kennung.
    """
    with TestClient(app) as client:
        daten = client.get("/api/traffic/permission").json()

    assert daten["ok"] is True
    assert daten["state"] == "granted"
    assert not daten["error"]


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux-Verhalten")
def test_permission_text_raet_nie_zu_sudo(app: FastAPI) -> None:
    """Kein sudo/Root-Rat mehr in der Wire-Form (Finding 6, Karls Entscheidung S57)."""
    with TestClient(app) as client:
        daten = client.get("/api/traffic/permission").json()

    text = (daten["error"] or "").lower()
    for verboten in ("sudo", "root", "cernis-backend"):
        assert verboten not in text


def test_permission_meldet_laufenden_messfehler(app: FastAPI) -> None:
    """Ein gescheiterter Messlauf schlaegt auf ok=false durch (keine stille Null)."""
    app.dependency_overrides[provide_poll_error] = lambda: (
        lambda: "Werkzeug 'ss' nicht gefunden (Paket iproute2)"
    )
    with TestClient(app) as client:
        daten = client.get("/api/traffic/permission").json()

    assert daten["ok"] is False
    assert "iproute2" in daten["error"]
    assert daten["state"] == "needs_privileges"
