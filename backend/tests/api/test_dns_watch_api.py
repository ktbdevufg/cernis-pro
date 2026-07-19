"""End-to-end-Test der dns_watch-API (Block 2, Etappe 2d-3) gegen app.py via TestClient.

Deckt ``GET /api/dns-watch`` (Lese-Runner als Fake-Double, geprueft wird der Wire-Vertrag
der ``DnsWatchOverviewOut``) und ``POST /api/dns-watch/acknowledge`` ab. Der Schreibpfad
laeuft -- wie ``test_analysis_acknowledge_api.py`` -- gegen ein echtes tmp_path-DB-Repo
(so wird der Adapter-Schreibpfad mitgeprueft), der Runner wird analog app.py per
``dependency_overrides`` verdrahtet. Muell (ungueltige ``action``) -> 422.
"""

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.dns_watch import (
    DnsContactOut,
    DnsWatchOverviewOut,
    provide_dns_watch,
    provide_dns_watch_acknowledge,
)
from app import create_app
from infrastructure.clock import SystemClock
from infrastructure.config import AppConfig
from infrastructure.dns_watch_acknowledgements_db import (
    SqliteDnsWatchAcknowledgementRepository,
)

IP = "1.2.3.4"


class _FakeDnsWatchRunner:
    """Fake-Runner: liefert eine feste, schon api-projizierte Sicht (keine echten Quellen)."""

    def __init__(self, overview: DnsWatchOverviewOut) -> None:
        self._overview = overview
        self.calls = 0

    async def __call__(self) -> DnsWatchOverviewOut:
        self.calls += 1
        return self._overview


@pytest.fixture
def app() -> Iterator[FastAPI]:
    """Frisch gebaute App (Lifespan via TestClient pro Test -- kein Loop noetig)."""
    yield create_app(AppConfig())


# ── GET: Wire-Vertrag der Overview ─────────────────────────────────────────────


def test_get_dns_watch_liefert_200_und_json_form(app: FastAPI) -> None:
    """``/api/dns-watch`` -> HTTP 200 + erwartete JSON-Form (contacts[], counts, Listen)."""
    overview = DnsWatchOverviewOut(
        contacts=[
            DnsContactOut(
                remote_ip="8.8.8.8",
                remote_port=53,
                category="offen",
                hostname="dns.google",
                app_name="firefox",
                pid=4242,
                connection_count=3,
                acknowledged=False,
            ),
            DnsContactOut(
                remote_ip="10.0.0.1",
                remote_port=53,
                category="erwartungsgemaess",
                hostname=None,
                app_name=None,
                pid=None,
                connection_count=1,
                acknowledged=True,
            ),
        ],
        host_scope="local_host",
        counts={"erwartungsgemaess": 1, "offen": 1, "moegliche_doh": 0},
        expected_servers=["10.0.0.1"],
        doh_providers=["1.1.1.1", "8.8.8.8"],
    )
    runner = _FakeDnsWatchRunner(overview)
    app.dependency_overrides[provide_dns_watch] = lambda: runner

    with TestClient(app) as client:
        response = client.get("/api/dns-watch")

    assert response.status_code == 200
    assert runner.calls == 1
    assert response.json() == {
        "contacts": [
            {
                "remote_ip": "8.8.8.8",
                "remote_port": 53,
                "category": "offen",
                "hostname": "dns.google",
                "app_name": "firefox",
                "pid": 4242,
                "connection_count": 3,
                "acknowledged": False,
            },
            {
                "remote_ip": "10.0.0.1",
                "remote_port": 53,
                "category": "erwartungsgemaess",
                "hostname": None,
                "app_name": None,
                "pid": None,
                "connection_count": 1,
                "acknowledged": True,
            },
        ],
        "host_scope": "local_host",
        "counts": {"erwartungsgemaess": 1, "offen": 1, "moegliche_doh": 0},
        "expected_servers": ["10.0.0.1"],
        "doh_providers": ["1.1.1.1", "8.8.8.8"],
    }


def test_get_dns_watch_leere_sicht_liefert_leere_liste(app: FastAPI) -> None:
    """Ohne Befunde -> 200 + leere ``contacts``, ``host_scope`` ehrlich gesetzt."""
    overview = DnsWatchOverviewOut(
        contacts=[],
        host_scope="local_host",
        counts={"erwartungsgemaess": 0, "offen": 0, "moegliche_doh": 0},
        expected_servers=[],
        doh_providers=[],
    )
    runner = _FakeDnsWatchRunner(overview)
    app.dependency_overrides[provide_dns_watch] = lambda: runner

    with TestClient(app) as client:
        response = client.get("/api/dns-watch")

    assert response.status_code == 200
    assert response.json() == {
        "contacts": [],
        "host_scope": "local_host",
        "counts": {"erwartungsgemaess": 0, "offen": 0, "moegliche_doh": 0},
        "expected_servers": [],
        "doh_providers": [],
    }


# ── POST acknowledge: Schreibpfad gegen echtes tmp-DB-Repo ─────────────────────


@pytest.fixture
def ack_context(
    app: FastAPI, tmp_path: Path
) -> tuple[FastAPI, SqliteDnsWatchAcknowledgementRepository]:
    repo = SqliteDnsWatchAcknowledgementRepository(tmp_path / "cernis.db", SystemClock())
    # Acknowledge-Runner wie im Composition Root: Pass-Through an record(...).
    app.dependency_overrides[provide_dns_watch_acknowledge] = lambda: repo.record
    return app, repo


def _body(**over: object) -> dict[str, object]:
    base: dict[str, object] = {"remote_ip": IP, "category": "offen", "action": "ack"}
    base.update(over)
    return base


def test_ack_schreibt_und_ist_sichtbar(
    ack_context: tuple[FastAPI, SqliteDnsWatchAcknowledgementRepository],
) -> None:
    application, repo = ack_context
    client = TestClient(application)
    resp = client.post("/api/dns-watch/acknowledge", json=_body())
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    assert repo.acknowledged_keys() == {f"{IP}:offen"}


def test_unack_nach_ack_hebt_auf(
    ack_context: tuple[FastAPI, SqliteDnsWatchAcknowledgementRepository],
) -> None:
    application, repo = ack_context
    client = TestClient(application)
    client.post("/api/dns-watch/acknowledge", json=_body(action="ack"))
    resp = client.post("/api/dns-watch/acknowledge", json=_body(action="unack"))
    assert resp.status_code == 200
    assert repo.acknowledged_keys() == set()


def test_invalide_action_ist_422(
    ack_context: tuple[FastAPI, SqliteDnsWatchAcknowledgementRepository],
) -> None:
    application, _ = ack_context
    client = TestClient(application)
    resp = client.post("/api/dns-watch/acknowledge", json=_body(action="loeschen"))
    assert resp.status_code == 422
