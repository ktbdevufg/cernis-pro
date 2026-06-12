"""End-to-end-Test des resolver-Routers (Teilschritt 3) gegen app.py via TestClient.

Belegt: ``GET /api/resolve`` serialisiert das RemoteEndpointFacts-Aggregat in die Wire-Form
``{value, source}`` je Feld, mit verschachteltem ``tls_cert`` und ``country_conflict`` als
bool. Der Use-Case-Runner ist via ``dependency_overrides`` durch einen Fake ersetzt -- KEIN
echter Adapter, kein dig/RDAP/TLS/CSV. Zusaetzlich: fehlende Geo/ASN-CSV ->
ResolverDataMissing -> 503 (globaler Handler im Composition Root).
"""

from collections.abc import Iterator
from dataclasses import replace
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.resolver import provide_resolve_endpoint
from app import create_app
from domain.resolver import (
    RemoteEndpointFacts,
    ResolverFact,
    SourceTag,
    TlsCertDetails,
)
from infrastructure.resolver.errors import ResolverDataMissing


@pytest.fixture
def app() -> Iterator[FastAPI]:
    yield create_app()


def _sample_facts() -> RemoteEndpointFacts:
    """Ein vollstaendig befuelltes Aggregat -- deckt alle Wire-Felder + tls_cert ab."""
    cert = TlsCertDetails(
        subject_cn="host.example.com",
        san=("host.example.com", "www.example.com"),
        issuer="ACME CA",
        valid_from="Jan  1 00:00:00 2025 GMT",
        valid_until="Jan  1 00:00:00 2026 GMT",
        serial="0A0B",
        fingerprint_sha256="AB:CD",
        self_signed=False,
    )
    return RemoteEndpointFacts(
        ptr=ResolverFact(value="host.example.com", source=SourceTag.DNS),
        forward_confirmed=ResolverFact(value=True, source=SourceTag.DNS),
        tls_cert=ResolverFact(value=cert, source=SourceTag.TLS),
        dyndns=ResolverFact(value=None, source=SourceTag.DNS),
        org=ResolverFact(value="ACME Networks", source=SourceTag.RDAP),
        netname=ResolverFact(value="ACME-NET", source=SourceTag.RDAP),
        net_range=ResolverFact(value="1.2.0.0 - 1.2.255.255", source=SourceTag.RDAP),
        asn=ResolverFact(value="64500", source=SourceTag.GEODB),
        asn_org=ResolverFact(value="ACME Networks", source=SourceTag.RDAP),
        abuse_contact=ResolverFact(value="abuse@acme.test", source=SourceTag.RDAP),
        country_rdap_net=ResolverFact(value="DE", source=SourceTag.RDAP),
        country_org_address=ResolverFact(value=None, source=SourceTag.RDAP),
        country_geodb=ResolverFact(value="DE", source=SourceTag.GEODB),
        service_hint=ResolverFact(value="https", source=SourceTag.DNS),
        banner=ResolverFact(value=None, source=SourceTag.DNS),
        country_conflict=False,
    )


def test_resolve_wire_form(app: FastAPI) -> None:
    """``GET /api/resolve`` serialisiert das Aggregat als {value, source} + verschachteltes tls."""

    captured: dict[str, Any] = {}

    async def _fake_runner(ip: str, port: int | None) -> Any:
        captured["ip"] = ip
        captured["port"] = port
        return _sample_facts()

    app.dependency_overrides[provide_resolve_endpoint] = lambda: _fake_runner

    with TestClient(app) as client:
        response = client.get("/api/resolve", params={"ip": "1.2.3.4", "port": 443})

    assert response.status_code == 200
    assert captured == {"ip": "1.2.3.4", "port": 443}
    body = response.json()

    # Skalare Fakten als {value, source}
    assert body["ptr"] == {"value": "host.example.com", "source": "dns"}
    assert body["forward_confirmed"] == {"value": True, "source": "dns"}
    assert body["org"] == {"value": "ACME Networks", "source": "rdap"}
    assert body["asn"] == {"value": "64500", "source": "geodb"}
    assert body["asn_org"] == {"value": "ACME Networks", "source": "rdap"}
    assert body["country_geodb"] == {"value": "DE", "source": "geodb"}
    assert body["country_org_address"] == {"value": None, "source": "rdap"}
    assert body["service_hint"] == {"value": "https", "source": "dns"}
    assert body["banner"] == {"value": None, "source": "dns"}
    assert body["dyndns"] == {"value": None, "source": "dns"}

    # country_conflict ist ein reines bool (kein {value, source})
    assert body["country_conflict"] is False

    # tls_cert: verschachteltes Objekt unter value, source "tls"
    assert body["tls_cert"]["source"] == "tls"
    assert body["tls_cert"]["value"] == {
        "subject_cn": "host.example.com",
        "san": ["host.example.com", "www.example.com"],
        "issuer": "ACME CA",
        "valid_from": "Jan  1 00:00:00 2025 GMT",
        "valid_until": "Jan  1 00:00:00 2026 GMT",
        "serial": "0A0B",
        "fingerprint_sha256": "AB:CD",
        "self_signed": False,
    }


def test_resolve_ohne_port_tls_null(app: FastAPI) -> None:
    """Ohne ``port`` ist tls_cert.value null und der Runner bekommt port=None."""

    captured: dict[str, Any] = {}

    async def _fake_runner(ip: str, port: int | None) -> Any:
        captured["port"] = port
        # Use-Case wuerde ohne Port kein TLS holen -> value None; hier nachstellen.
        return replace(
            _sample_facts(),
            tls_cert=ResolverFact(value=None, source=SourceTag.TLS),
        )

    app.dependency_overrides[provide_resolve_endpoint] = lambda: _fake_runner

    with TestClient(app) as client:
        response = client.get("/api/resolve", params={"ip": "1.2.3.4"})

    assert response.status_code == 200
    assert captured["port"] is None
    assert response.json()["tls_cert"] == {"value": None, "source": "tls"}


def test_resolve_data_missing_503(app: FastAPI) -> None:
    """Fehlende Geo/ASN-CSV (ResolverDataMissing) -> 503 (globaler Handler)."""

    async def _fake_runner(ip: str, port: int | None) -> Any:
        raise ResolverDataMissing("/data/asn-country-ipv4.csv")

    app.dependency_overrides[provide_resolve_endpoint] = lambda: _fake_runner

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/api/resolve", params={"ip": "1.2.3.4"})

    assert response.status_code == 503
    assert "asn-country-ipv4.csv" in response.json()["detail"]
