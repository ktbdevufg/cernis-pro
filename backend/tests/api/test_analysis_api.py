"""End-to-end-Test des analysis-Routers (AN.3) gegen app.py via TestClient.

Belegt: ``GET /api/analysis`` serialisiert die Beobachtungen des AnalyzeRunners (Runner via
``dependency_overrides`` durch einen Fake ersetzt -- KEIN echter Adapter, KEIN echtes psutil).
Eine kontrollierte ResolvedObservation-Liste ergibt die erwartete dict-Liste inkl.
``help_url``; eine leere Liste ergibt ``[]``.
"""

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.analysis import provide_analyze
from app import create_app
from infrastructure.config import AppConfig


@pytest.fixture
def app() -> Iterator[FastAPI]:
    yield create_app(AppConfig())


class _FakeObservation:
    """Minimaler Stand-in fuer domain.analysis.Observation (nur die Wire-Felder)."""

    def __init__(
        self,
        *,
        rule_id: str,
        severity: str,
        title: str,
        detail: str,
        help_kind: str,
        subject: str,
        kind: str,
    ) -> None:
        self.rule_id = rule_id
        self.severity = severity
        self.title = title
        self.detail = detail
        self.help_kind = help_kind
        self.subject = subject
        self.kind = kind


class _FakeResolved:
    """Minimaler Stand-in fuer application.ResolvedObservation (.observation + .help_url)."""

    def __init__(self, observation: _FakeObservation, help_url: str) -> None:
        self.observation = observation
        self.help_url = help_url


def test_analysis_wire_form(app: FastAPI) -> None:
    """``GET /api/analysis`` serialisiert die Beobachtungen inkl. ``help_url``."""

    resolved = [
        _FakeResolved(
            _FakeObservation(
                rule_id="remote_access_port",
                severity="notable",
                title="Verbindung zu einem Fernzugriffs-Port",
                detail="Verbindung zu 1.2.3.4:22 nutzt einen typischen Fernzugriffs-Port (22).",
                help_kind="remote_access_port",
                subject="1.2.3.4:22",
                kind="connection_remote_port",
            ),
            help_url="https://example.test/remote-access",
        ),
    ]

    async def _fake_runner() -> list[Any]:
        return resolved

    app.dependency_overrides[provide_analyze] = lambda: _fake_runner

    with TestClient(app) as client:
        response = client.get("/api/analysis")

    assert response.status_code == 200
    assert response.json() == [
        {
            "rule_id": "remote_access_port",
            "severity": "notable",
            "title": "Verbindung zu einem Fernzugriffs-Port",
            "detail": "Verbindung zu 1.2.3.4:22 nutzt einen typischen Fernzugriffs-Port (22).",
            "help_kind": "remote_access_port",
            "subject": "1.2.3.4:22",
            "kind": "connection_remote_port",
            "help_url": "https://example.test/remote-access",
        }
    ]


def test_analysis_empty_is_empty_list(app: FastAPI) -> None:
    """Leere Lage -> ``[]`` (kein Fehler)."""

    async def _fake_runner() -> list[Any]:
        return []

    app.dependency_overrides[provide_analyze] = lambda: _fake_runner

    with TestClient(app) as client:
        response = client.get("/api/analysis")

    assert response.status_code == 200
    assert response.json() == []


# ── GET /api/analysis/service (Stueck 1, ADR 0027) ────────────────────────────
# Der Service-Lookup ist im Composition Root real verdrahtet (service_for_port als
# ServiceLookupRunner) -- diese Tests laufen gegen die echte Verdrahtung, KEIN Fake.


def test_service_lookup_bekannter_port(app: FastAPI) -> None:
    """Gueltiger, gelisteter Port -> {"port": N, "service": "<name>"}."""
    with TestClient(app) as client:
        response = client.get("/api/analysis/service", params={"port": 3306})
    assert response.status_code == 200
    assert response.json() == {"port": 3306, "service": "mysql"}


def test_service_lookup_unbekannter_port_service_none(app: FastAPI) -> None:
    """Gueltiger, aber nicht gelisteter Port -> service null (Leer-Zustand, kein Fehler)."""
    with TestClient(app) as client:
        response = client.get("/api/analysis/service", params={"port": 49152})
    assert response.status_code == 200
    assert response.json() == {"port": 49152, "service": None}


@pytest.mark.parametrize("port", [0, 65536, 99999, -1])
def test_service_lookup_ungueltiger_port_422(app: FastAPI, port: int) -> None:
    """Port ausserhalb 1-65535 -> HTTP 422 (FastAPI-Query-Constraint, KEIN stiller Fallback)."""
    with TestClient(app) as client:
        response = client.get("/api/analysis/service", params={"port": port})
    assert response.status_code == 422


def test_service_lookup_fehlender_port_422(app: FastAPI) -> None:
    """Fehlender ``port``-Query -> HTTP 422 (Pflicht-Query ohne Default)."""
    with TestClient(app) as client:
        response = client.get("/api/analysis/service")
    assert response.status_code == 422
