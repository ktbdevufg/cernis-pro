"""End-to-end-Test der outbound-API (Block 2, Etappe 2b) gegen app.py via TestClient.

Deckt ``GET /api/outbound/contacts`` ab. Der injizierte Aussenkontakt-Runner wird
via ``dependency_overrides`` durch ein Fake-Double ersetzt, das eine feste, bereits
projizierte ``OutboundOverviewOut`` liefert -- keine echten Quellen (traffic/resolver/
sni), kein Loop, deterministisch (Muster wie der Fake-Runner in
``test_maintenance_api.py``). Geprueft wird der Wire-Vertrag: HTTP 200 und die JSON-Form
(``contacts[]`` mit allen Feldern + ``host_scope``).
"""

from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.outbound import OutboundContactOut, OutboundOverviewOut, provide_outbound_contacts
from app import create_app
from infrastructure.config import AppConfig


class _FakeOutboundContactsRunner:
    """Fake-Runner: liefert eine feste, schon api-projizierte Sicht (keine echten Quellen)."""

    def __init__(self, overview: OutboundOverviewOut) -> None:
        self._overview = overview
        self.calls = 0

    async def __call__(self) -> OutboundOverviewOut:
        self.calls += 1
        return self._overview


@pytest.fixture
def app() -> Iterator[FastAPI]:
    """Frisch gebaute App (Lifespan via TestClient pro Test -- kein Loop noetig)."""
    yield create_app(AppConfig())


def test_get_contacts_liefert_200_und_json_form(app: FastAPI) -> None:
    """``/api/outbound/contacts`` -> HTTP 200 + erwartete JSON-Form (contacts[], host_scope)."""
    overview = OutboundOverviewOut(
        contacts=[
            OutboundContactOut(
                remote_ip="93.184.216.34",
                remote_port=443,
                hostname="example.com",
                country="US",
                operator="EdgeCast",
                asn="AS15133",
                app_name="firefox",
                pid=4242,
                connection_count=3,
            ),
            OutboundContactOut(
                remote_ip="10.0.0.2",
                remote_port=None,
                hostname=None,
                country=None,
                operator=None,
                asn=None,
                app_name=None,
                pid=None,
                connection_count=1,
            ),
        ],
        host_scope="local_host",
    )
    runner = _FakeOutboundContactsRunner(overview)
    app.dependency_overrides[provide_outbound_contacts] = lambda: runner

    with TestClient(app) as client:
        response = client.get("/api/outbound/contacts")

    assert response.status_code == 200
    assert runner.calls == 1
    assert response.json() == {
        "contacts": [
            {
                "remote_ip": "93.184.216.34",
                "remote_port": 443,
                "hostname": "example.com",
                "country": "US",
                "operator": "EdgeCast",
                "asn": "AS15133",
                "app_name": "firefox",
                "pid": 4242,
                "connection_count": 3,
            },
            {
                "remote_ip": "10.0.0.2",
                "remote_port": None,
                "hostname": None,
                "country": None,
                "operator": None,
                "asn": None,
                "app_name": None,
                "pid": None,
                "connection_count": 1,
            },
        ],
        "host_scope": "local_host",
    }


def test_get_contacts_leere_sicht_liefert_leere_liste(app: FastAPI) -> None:
    """Ohne Aussenkontakte -> 200 + leere ``contacts``-Liste, ``host_scope`` ehrlich gesetzt."""
    runner = _FakeOutboundContactsRunner(OutboundOverviewOut(contacts=[], host_scope="local_host"))
    app.dependency_overrides[provide_outbound_contacts] = lambda: runner

    with TestClient(app) as client:
        response = client.get("/api/outbound/contacts")

    assert response.status_code == 200
    assert response.json() == {"contacts": [], "host_scope": "local_host"}
