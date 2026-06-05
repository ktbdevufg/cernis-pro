"""End-to-end-Tests des interfaces-Routers (v2, I.3) gegen app.py via TestClient.

Belegt, dass ``GET /api/interfaces`` die erwartete Wire-Form liefert: der
``ListInterfaces``-Use-Case wird via ``dependency_overrides`` durch einen Fake
ersetzt (kein echtes ``ip``-Tooling), und der Router serialisiert das
``NetworkInterface`` in die rueckwaertskompatible Feldform plus die additiven
Felder ``is_primary``/``type``/``status`` und die abgeleiteten ``subnet_cidr``/
``network``/``broadcast``.
"""

from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.interfaces import provide_list_interfaces
from app import create_app
from domain.interfaces import NetworkInterface
from infrastructure.config import AppConfig


@pytest.fixture
def app() -> Iterator[FastAPI]:
    yield create_app(AppConfig())


def test_interfaces_liefert_wire_form_und_abgeleitete_felder(app: FastAPI) -> None:
    """``/api/interfaces`` liefert Pflichtfelder + abgeleitete CIDRs + Klassifikation."""

    async def _fake_list() -> list[NetworkInterface]:
        return [
            NetworkInterface(
                name="eth0",
                ipv4="192.168.1.10",
                ipv4_prefix=24,
                ipv6_link_local="fe80::1",
                mac="aa:bb:cc:dd:ee:ff",
                gateway="192.168.1.1",
                mtu=1500,
                network_cidr="192.168.1.0/24",
                host_count=254,
                type="ethernet",
                status="up",
                is_primary=True,
            )
        ]

    app.dependency_overrides[provide_list_interfaces] = lambda: _fake_list

    with TestClient(app) as client:
        response = client.get("/api/interfaces")

    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, list)
    iface = body[0]
    # Pflichtfelder (Wire-Kompat, das FE liest sie).
    for field in (
        "name",
        "ipv4",
        "ipv4_prefix",
        "mac",
        "gateway",
        "mtu",
        "network_cidr",
        "host_count",
    ):
        assert field in iface
    # Abgeleitete Anzeige-Felder (aus ipv4/prefix).
    assert iface["subnet_cidr"] == "192.168.1.10/24"
    assert iface["network"] == "192.168.1.0/24"
    assert iface["broadcast"] == "192.168.1.255"
    # Additiv: serverseitige Klassifikation.
    assert iface["is_primary"] is True
    assert iface["type"] == "ethernet"
    assert iface["status"] == "up"


def test_interfaces_leere_liste(app: FastAPI) -> None:
    """Keine Interfaces -> leere Liste, HTTP 200 (kein Fehler)."""

    async def _fake_empty() -> list[NetworkInterface]:
        return []

    app.dependency_overrides[provide_list_interfaces] = lambda: _fake_empty

    with TestClient(app) as client:
        response = client.get("/api/interfaces")

    assert response.status_code == 200
    assert response.json() == []
