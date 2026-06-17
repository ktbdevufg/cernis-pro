"""End-to-end-Test von ``POST /api/analysis/acknowledge`` (ADR 0031) via TestClient.

Belegt den Schreibpfad gegen ein echtes tmp_path-DB-Repo (kein Fake -- so wird der
Adapter-Schreibpfad mitgeprueft): ack/unack schreiben eine Log-Zeile (sichtbar ueber
``acknowledged_ports``), und Muell (ungueltiger port/severity/action) -> 422. Der Runner
wird -- analog app.py -- ueber ``dependency_overrides`` auf ein tmp-DB-Repo verdrahtet
(der api-Ring bleibt repo-frei, der record-Pass-Through passiert im Test-Runner wie im
Composition Root).
"""

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.analysis import provide_acknowledge
from app import create_app
from infrastructure.analysis_acknowledgements_db import SqliteAcknowledgementRepository
from infrastructure.config import AppConfig

MAC = "AA:BB:CC:DD:EE:01"


@pytest.fixture
def context(tmp_path: Path) -> Iterator[tuple[FastAPI, SqliteAcknowledgementRepository]]:
    application = create_app(AppConfig())
    repo = SqliteAcknowledgementRepository(tmp_path / "cernis.db")
    # Acknowledge-Runner wie im Composition Root: Pass-Through an record(...).
    application.dependency_overrides[provide_acknowledge] = lambda: repo.record
    yield application, repo


def _body(**over: object) -> dict[str, object]:
    base: dict[str, object] = {
        "mac": MAC,
        "port": 3306,
        "severity": "notable",
        "action": "ack",
    }
    base.update(over)
    return base


# ── Schreibpfad (ack/unack) ───────────────────────────────────────────────────


def test_ack_writes_and_is_visible(
    context: tuple[FastAPI, SqliteAcknowledgementRepository],
) -> None:
    application, repo = context
    client = TestClient(application)
    resp = client.post("/api/analysis/acknowledge", json=_body())
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    assert repo.acknowledged_ports(MAC) == {3306}


def test_unack_after_ack_clears(
    context: tuple[FastAPI, SqliteAcknowledgementRepository],
) -> None:
    application, repo = context
    client = TestClient(application)
    client.post("/api/analysis/acknowledge", json=_body(action="ack"))
    resp = client.post("/api/analysis/acknowledge", json=_body(action="unack"))
    assert resp.status_code == 200
    assert repo.acknowledged_ports(MAC) == set()


# ── Validierung (422 bei Muell) ───────────────────────────────────────────────


def test_port_out_of_range_is_422(
    context: tuple[FastAPI, SqliteAcknowledgementRepository],
) -> None:
    application, _ = context
    client = TestClient(application)
    assert client.post("/api/analysis/acknowledge", json=_body(port=0)).status_code == 422
    assert client.post("/api/analysis/acknowledge", json=_body(port=70000)).status_code == 422


def test_invalid_action_is_422(
    context: tuple[FastAPI, SqliteAcknowledgementRepository],
) -> None:
    application, _ = context
    client = TestClient(application)
    resp = client.post("/api/analysis/acknowledge", json=_body(action="loeschen"))
    assert resp.status_code == 422


def test_invalid_severity_is_422(
    context: tuple[FastAPI, SqliteAcknowledgementRepository],
) -> None:
    application, _ = context
    client = TestClient(application)
    resp = client.post("/api/analysis/acknowledge", json=_body(severity="apokalyptisch"))
    assert resp.status_code == 422
