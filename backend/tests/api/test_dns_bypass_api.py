"""End-to-end-Test der dns_bypass-API (ADR 0042, Etappe 4b) gegen app.py via TestClient.

Deckt alle vier Endpunkte ueber Fake-Runner (via ``dependency_overrides``, Muster
``test_dns_watch_api.py``/``test_outbound_api.py``) ab -- geprueft wird der Wire-Vertrag,
NICHT die echten Quellen (kein Sniff, kein asyncio-Loop):

* ``GET /api/dns-bypass``        -> die schon api-projizierte ``DnsBypassOverviewOut``.
* ``GET /api/dns-bypass/status`` -> die ``DnsBypassStatusOut``-Form.
* ``POST /api/dns-bypass/start`` -> Fehlertext der Quelle -> ``{"ok": false, "error": ...}``
  (HTTP 200, S3-ehrlich); Erfolg (None) -> ``{"ok": true}``.
* ``POST /api/dns-bypass/stop``  -> ``{"ok": true}``.
"""

from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.dns_bypass import (
    DnsBypassFindingOut,
    DnsBypassOverviewOut,
    DnsBypassStatusOut,
    provide_dns_bypass_start,
    provide_dns_bypass_status,
    provide_dns_bypass_stop,
    provide_dns_bypass_view,
)
from app import create_app
from infrastructure.config import AppConfig


class _FakeViewRunner:
    """Fake-Lese-Runner: liefert eine feste, schon api-projizierte Sicht (keine Quellen)."""

    def __init__(self, overview: DnsBypassOverviewOut) -> None:
        self._overview = overview
        self.calls = 0

    async def __call__(self) -> DnsBypassOverviewOut:
        self.calls += 1
        return self._overview


class _FakeStatusRunner:
    """Fake-Status-Runner: liefert einen festen Recorder-Zustand."""

    def __init__(self, status: DnsBypassStatusOut) -> None:
        self._status = status

    def __call__(self) -> DnsBypassStatusOut:
        return self._status


class _FakeStartRunner:
    """Fake-Start-Runner: gibt einen festen Rueckgabewert (None = ok, sonst Fehlertext)."""

    def __init__(self, result: str | None) -> None:
        self._result = result
        self.calls: list[str | None] = []

    def __call__(self, interface: str | None) -> str | None:
        self.calls.append(interface)
        return self._result


class _FakeStopRunner:
    """Fake-Stop-Runner: zaehlt die Aufrufe (Rueckgabe None)."""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self) -> None:
        self.calls += 1


@pytest.fixture
def app() -> Iterator[FastAPI]:
    """Frisch gebaute App (Lifespan via TestClient pro Test -- kein Loop noetig)."""
    yield create_app(AppConfig())


# ── GET: Wire-Vertrag der verdichteten Sicht ───────────────────────────────────


def test_get_dns_bypass_liefert_200_und_json_form(app: FastAPI) -> None:
    """``/api/dns-bypass`` -> HTTP 200 + erwartete JSON-Form (findings[] + Zaehler + Status)."""
    overview = DnsBypassOverviewOut(
        findings=[
            DnsBypassFindingOut(
                src_ip="192.168.1.50",
                device_name="Wohnzimmer-TV",
                is_self=True,
                dst_ip="1.1.1.1",
                is_doh=True,
                doh_source_name="Bekannte DoH-Anbieter (IP)",
                query_count=7,
                sample_qnames=["cloudflare-dns.com"],
            ),
            DnsBypassFindingOut(
                src_ip="192.168.1.99",
                device_name=None,
                dst_ip="9.9.9.9",
                is_doh=False,
                doh_source_name=None,
                query_count=2,
                sample_qnames=[],
            ),
        ],
        expected_servers=["192.168.1.1"],
        queries_total=12,
        bypass_total=9,
        expected_total=3,
        bypass_devices=2,
        recording=True,
    )
    runner = _FakeViewRunner(overview)
    app.dependency_overrides[provide_dns_bypass_view] = lambda: runner

    with TestClient(app) as client:
        response = client.get("/api/dns-bypass")

    assert response.status_code == 200
    assert runner.calls == 1
    assert response.json() == {
        "findings": [
            {
                "src_ip": "192.168.1.50",
                "device_name": "Wohnzimmer-TV",
                "is_self": True,
                "dst_ip": "1.1.1.1",
                "is_doh": True,
                "doh_source_name": "Bekannte DoH-Anbieter (IP)",
                "query_count": 7,
                "sample_qnames": ["cloudflare-dns.com"],
            },
            {
                "src_ip": "192.168.1.99",
                "device_name": None,
                "is_self": False,
                "dst_ip": "9.9.9.9",
                "is_doh": False,
                "doh_source_name": None,
                "query_count": 2,
                "sample_qnames": [],
            },
        ],
        "expected_servers": ["192.168.1.1"],
        "queries_total": 12,
        "bypass_total": 9,
        "expected_total": 3,
        "bypass_devices": 2,
        "recording": True,
    }


def test_get_dns_bypass_leere_sicht_ist_ehrlich(app: FastAPI) -> None:
    """Ohne Umgehungen + ohne Aufzeichnung -> 200, leere findings, ``recording=false``."""
    overview = DnsBypassOverviewOut(
        findings=[],
        expected_servers=[],
        queries_total=0,
        bypass_total=0,
        expected_total=0,
        bypass_devices=0,
        recording=False,
    )
    app.dependency_overrides[provide_dns_bypass_view] = lambda: _FakeViewRunner(overview)

    with TestClient(app) as client:
        response = client.get("/api/dns-bypass")

    assert response.status_code == 200
    assert response.json() == {
        "findings": [],
        "expected_servers": [],
        "queries_total": 0,
        "bypass_total": 0,
        "expected_total": 0,
        "bypass_devices": 0,
        "recording": False,
    }


# ── GET status: billiger Poll ──────────────────────────────────────────────────


def test_status_liefert_form(app: FastAPI) -> None:
    """``/api/dns-bypass/status`` -> HTTP 200 + ``{recording, collected_queries}``."""
    status = DnsBypassStatusOut(recording=True, collected_queries=42)
    app.dependency_overrides[provide_dns_bypass_status] = lambda: _FakeStatusRunner(status)

    with TestClient(app) as client:
        response = client.get("/api/dns-bypass/status")

    assert response.status_code == 200
    assert response.json() == {"recording": True, "collected_queries": 42}


# ── POST start: ehrliche Fehlermeldung statt 500 ───────────────────────────────


def test_start_ok_liefert_ok_true(app: FastAPI) -> None:
    """Erfolgreicher Start (Runner gibt None) -> ``{"ok": true}``; Interface wird gereicht."""
    runner = _FakeStartRunner(result=None)
    app.dependency_overrides[provide_dns_bypass_start] = lambda: runner

    with TestClient(app) as client:
        response = client.post("/api/dns-bypass/start", json={"interface": "eth0"})

    assert response.status_code == 200
    assert response.json() == {"ok": True}
    assert runner.calls == ["eth0"]


def test_start_ohne_body_nutzt_none_interface(app: FastAPI) -> None:
    """Ohne Body -> ``interface=None`` (Default), Start ok."""
    runner = _FakeStartRunner(result=None)
    app.dependency_overrides[provide_dns_bypass_start] = lambda: runner

    with TestClient(app) as client:
        response = client.post("/api/dns-bypass/start", json={})

    assert response.status_code == 200
    assert response.json() == {"ok": True}
    assert runner.calls == [None]


def test_start_fehlertext_liefert_ok_false_mit_200(app: FastAPI) -> None:
    """Fehlgeschlagener Start (Runner gibt Text) -> HTTP 200 + ``{"ok": false, "error": ...}``."""
    runner = _FakeStartRunner(result="keine Rechte fuer den DNS-Helfer")
    app.dependency_overrides[provide_dns_bypass_start] = lambda: runner

    with TestClient(app) as client:
        response = client.post("/api/dns-bypass/start", json={"interface": None})

    assert response.status_code == 200
    assert response.json() == {"ok": False, "error": "keine Rechte fuer den DNS-Helfer"}


# ── POST stop ──────────────────────────────────────────────────────────────────


def test_stop_liefert_ok_true(app: FastAPI) -> None:
    """``/api/dns-bypass/stop`` -> HTTP 200 + ``{"ok": true}``; Runner wird aufgerufen."""
    runner = _FakeStopRunner()
    app.dependency_overrides[provide_dns_bypass_stop] = lambda: runner

    with TestClient(app) as client:
        response = client.post("/api/dns-bypass/stop")

    assert response.status_code == 200
    assert response.json() == {"ok": True}
    assert runner.calls == 1
