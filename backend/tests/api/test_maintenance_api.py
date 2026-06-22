"""End-to-end-Tests der maintenance-API (Etappe 3) gegen app.py via TestClient.

Deckt die zwei Wartungs-Endpunkte (Daten loeschen) ab. Die injizierten Runner
werden via ``dependency_overrides`` durch Fake-Doubles ersetzt, die NUR
protokollieren, dass ``run()`` bzw. ``run(include_secrets=...)`` gerufen wurde --
keine echte Loeschung, kein echtes Repo (deterministisch, Muster wie der
``url_opener``-Spy in ``test_system_api.py``). Geprueft wird der Wire-Vertrag
(HTTP 200 + ``{"ok": true}``) und die korrekte Durchreichung von
``include_secrets`` (Default ``False``; ``True`` wenn im Body gesetzt).
"""

from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.maintenance import (
    provide_factory_reset,
    provide_reset_scan_data,
)
from app import create_app
from infrastructure.config import AppConfig


class _FakeResetScanDataRunner:
    """Fake-Stufe-1-Runner: protokolliert nur den ``run()``-Aufruf."""

    def __init__(self) -> None:
        self.calls = 0

    def run(self) -> None:
        self.calls += 1


class _FakeFactoryResetRunner:
    """Fake-Stufe-2-Runner: protokolliert die ``include_secrets``-Argumente je Aufruf."""

    def __init__(self) -> None:
        self.calls: list[bool] = []

    def run(self, *, include_secrets: bool = False) -> None:
        self.calls.append(include_secrets)


@pytest.fixture
def app() -> Iterator[FastAPI]:
    """Frisch gebaute App (Lifespan via TestClient pro Test -- kein Loop noetig)."""
    yield create_app(AppConfig())


def test_reset_scan_data_liefert_200_und_ruft_run(app: FastAPI) -> None:
    """``/api/maintenance/reset-scan-data`` -> HTTP 200 + ``{ok: True}`` UND ``run()`` gerufen."""
    runner = _FakeResetScanDataRunner()
    app.dependency_overrides[provide_reset_scan_data] = lambda: runner

    with TestClient(app) as client:
        response = client.post("/api/maintenance/reset-scan-data")

    assert response.status_code == 200
    assert response.json() == {"ok": True}
    assert runner.calls == 1


def test_factory_reset_default_haelt_include_secrets_false(app: FastAPI) -> None:
    """Ohne Body-Feld -> ``include_secrets=False`` (Default) durchgereicht; 200 + ``{ok: True}``."""
    runner = _FakeFactoryResetRunner()
    app.dependency_overrides[provide_factory_reset] = lambda: runner

    with TestClient(app) as client:
        response = client.post("/api/maintenance/factory-reset", json={})

    assert response.status_code == 200
    assert response.json() == {"ok": True}
    assert runner.calls == [False]


def test_factory_reset_reicht_include_secrets_true_durch(app: FastAPI) -> None:
    """``{include_secrets: true}`` im Body -> der Runner bekommt ``True``; 200 + ``{ok: True}``."""
    runner = _FakeFactoryResetRunner()
    app.dependency_overrides[provide_factory_reset] = lambda: runner

    with TestClient(app) as client:
        response = client.post("/api/maintenance/factory-reset", json={"include_secrets": True})

    assert response.status_code == 200
    assert response.json() == {"ok": True}
    assert runner.calls == [True]
