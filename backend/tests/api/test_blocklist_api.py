"""End-to-end-Tests der blocklist-API gegen app.py via TestClient.

Die injizierten Composition-Root-Runner werden via ``dependency_overrides`` durch
schlanke Fakes ersetzt (Muster ``test_maintenance_api.py``): geprueft wird der
Wire-Vertrag jedes Endpunkts (Happy-Path + 422/404), das /settings-GET+PUT-Roundtrip,
der /sources/upload-Pfad und /match end-to-end. Kein echtes Repo, kein Netz.
"""

from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.blocklist import (
    AddSourceBody,
    AddSourceOut,
    ContactMatchOut,
    HealthIssueOut,
    HealthOut,
    MatchBody,
    MatchOut,
    MatchResultsOut,
    RefreshDueOut,
    RefreshOut,
    SettingsBody,
    SettingsOut,
    SourceOut,
    UpdateSourceBody,
    UploadSourceBody,
    UploadSourceOut,
    provide_add_source,
    provide_delete_source,
    provide_health,
    provide_list_sources,
    provide_match,
    provide_read_settings,
    provide_refresh_due,
    provide_refresh_source,
    provide_reset_defaults,
    provide_update_source,
    provide_upload_source,
    provide_write_settings,
)
from app import create_app
from application.blocklist import BlocklistError, strictness_from_wire
from infrastructure.config import AppConfig


@pytest.fixture
def app() -> Iterator[FastAPI]:
    yield create_app(AppConfig())


def _source_out(source_id: str = "src") -> SourceOut:
    return SourceOut(
        id=source_id,
        name="Test",
        group="threat",
        fmt="domain_list",
        origin="user_url",
        url="https://x.test/l",
        license="unknown",
        attribution_required=False,
        enabled=True,
        last_fetched_ts=None,
        status="never",
        entry_count=None,
    )


def test_get_sources_liefert_liste(app: FastAPI) -> None:
    app.dependency_overrides[provide_list_sources] = lambda: lambda: [_source_out()]
    with TestClient(app) as client:
        response = client.get("/api/blocklist/sources")
    assert response.status_code == 200
    assert response.json()[0]["id"] == "src"


def test_post_sources_happy_und_422(app: FastAPI) -> None:
    def _runner(body: AddSourceBody) -> AddSourceOut:
        # echte Hebung nachbilden: ungueltige Gruppe -> ValueError -> 422.
        if body.group not in ("threat", "tracker_ads"):
            raise ValueError("Unbekannte Gruppe")
        return AddSourceOut(source_id="my_liste", license_hint="MIT")

    app.dependency_overrides[provide_add_source] = lambda: _runner
    with TestClient(app) as client:
        ok = client.post(
            "/api/blocklist/sources",
            json={
                "name": "My Liste",
                "url": "https://x.test/l",
                "group": "threat",
                "fmt": "domain_list",
            },
        )
        bad = client.post(
            "/api/blocklist/sources",
            json={"name": "X", "url": "https://x.test/l", "group": "boese", "fmt": "domain_list"},
        )
    assert ok.status_code == 200
    assert ok.json() == {"source_id": "my_liste", "license_hint": "MIT"}
    assert bad.status_code == 422


def test_post_sources_upload(app: FastAPI) -> None:
    def _runner(body: UploadSourceBody) -> UploadSourceOut:
        return UploadSourceOut(source_id="upl", entry_count=len(body.content.split()))

    app.dependency_overrides[provide_upload_source] = lambda: _runner
    with TestClient(app) as client:
        response = client.post(
            "/api/blocklist/sources/upload",
            json={"name": "U", "group": "threat", "fmt": "domain_list", "content": "a.b\nc.d"},
        )
    assert response.status_code == 200
    assert response.json() == {"source_id": "upl", "entry_count": 2}


def test_patch_source_404_bei_unbekannt(app: FastAPI) -> None:
    def _runner(source_id: str, body: UpdateSourceBody) -> None:
        if source_id == "gibt_es_nicht":
            raise KeyError("unbekannt")

    app.dependency_overrides[provide_update_source] = lambda: _runner
    with TestClient(app) as client:
        ok = client.patch("/api/blocklist/sources/src", json={"enabled": False})
        missing = client.patch("/api/blocklist/sources/gibt_es_nicht", json={"enabled": False})
    assert ok.status_code == 200
    assert ok.json() == {"ok": True}
    assert missing.status_code == 404


def test_delete_source(app: FastAPI) -> None:
    seen: list[str] = []
    app.dependency_overrides[provide_delete_source] = lambda: seen.append
    with TestClient(app) as client:
        response = client.delete("/api/blocklist/sources/src")
    assert response.status_code == 200
    assert response.json() == {"ok": True}
    assert seen == ["src"]


def test_refresh_source_happy_und_404(app: FastAPI) -> None:
    def _runner(source_id: str) -> RefreshOut:
        if source_id == "upl":
            raise KeyError("Upload ohne url")
        return RefreshOut(source_id=source_id, ok=True, entry_count=5, error=None)

    app.dependency_overrides[provide_refresh_source] = lambda: _runner
    with TestClient(app) as client:
        ok = client.post("/api/blocklist/sources/src/refresh")
        missing = client.post("/api/blocklist/sources/upl/refresh")
    assert ok.status_code == 200
    assert ok.json() == {"source_id": "src", "ok": True, "entry_count": 5, "error": None}
    assert missing.status_code == 404


def test_refresh_due(app: FastAPI) -> None:
    out = RefreshDueOut(results=[RefreshOut(source_id="a", ok=True, entry_count=1, error=None)])
    app.dependency_overrides[provide_refresh_due] = lambda: lambda: out
    with TestClient(app) as client:
        response = client.post("/api/blocklist/refresh-due")
    assert response.status_code == 200
    assert response.json()["results"][0]["source_id"] == "a"


def test_reset_defaults(app: FastAPI) -> None:
    calls: list[int] = []
    app.dependency_overrides[provide_reset_defaults] = lambda: lambda: calls.append(1)
    with TestClient(app) as client:
        response = client.post("/api/blocklist/reset-defaults")
    assert response.status_code == 200
    assert response.json() == {"ok": True}
    assert calls == [1]


def test_get_health(app: FastAPI) -> None:
    out = HealthOut(
        issues=[
            HealthIssueOut(
                source_id="broken", name="B", group="threat", suggested_replacement_id="ok"
            )
        ]
    )
    app.dependency_overrides[provide_health] = lambda: lambda: out
    with TestClient(app) as client:
        response = client.get("/api/blocklist/health")
    assert response.status_code == 200
    assert response.json()["issues"][0]["suggested_replacement_id"] == "ok"


def test_settings_get_und_put_roundtrip(app: FastAPI) -> None:
    state = SettingsOut(
        strictness="recommended",
        refresh_interval_days=7,
        group_tracker_ads_enabled=True,
        group_threat_enabled=True,
    )

    def _read() -> SettingsOut:
        return state

    def _write(body: SettingsBody) -> None:
        if body.strictness is not None:
            # Wie der echte Composition-Root-Runner: BlocklistError -> ValueError (422).
            try:
                strictness_from_wire(body.strictness)
            except BlocklistError as exc:
                raise ValueError(str(exc)) from exc
            state.strictness = body.strictness
        if body.refresh_interval_days is not None:
            state.refresh_interval_days = body.refresh_interval_days

    app.dependency_overrides[provide_read_settings] = lambda: _read
    app.dependency_overrides[provide_write_settings] = lambda: _write
    with TestClient(app) as client:
        before = client.get("/api/blocklist/settings")
        put = client.put(
            "/api/blocklist/settings",
            json={"strictness": "all", "refresh_interval_days": 3},
        )
        after = client.get("/api/blocklist/settings")
        bad = client.put("/api/blocklist/settings", json={"strictness": "boese"})
    assert before.json()["strictness"] == "recommended"
    assert put.status_code == 200
    assert after.json()["strictness"] == "all"
    assert after.json()["refresh_interval_days"] == 3
    assert bad.status_code == 422


def test_match_end_to_end_und_422(app: FastAPI) -> None:
    def _runner(body: MatchBody) -> MatchResultsOut:
        if body.strictness is not None:
            # Wie der echte Composition-Root-Runner: BlocklistError -> ValueError (422).
            try:
                strictness_from_wire(body.strictness)
            except BlocklistError as exc:
                raise ValueError(str(exc)) from exc
        return MatchResultsOut(
            results=[
                ContactMatchOut(
                    remote_ip=c.remote_ip,
                    hostname=c.hostname,
                    matches=[
                        MatchOut(
                            source_id="threat_dom",
                            source_name="T",
                            group="threat",
                            matched_on="example.com",
                        )
                    ],
                )
                for c in body.contacts
            ]
        )

    app.dependency_overrides[provide_match] = lambda: _runner
    with TestClient(app) as client:
        ok = client.post(
            "/api/blocklist/match",
            json={"contacts": [{"remote_ip": "1.2.3.4", "hostname": "sub.example.com"}]},
        )
        bad = client.post(
            "/api/blocklist/match",
            json={"contacts": [], "strictness": "boese"},
        )
    assert ok.status_code == 200
    assert ok.json()["results"][0]["matches"][0]["source_id"] == "threat_dom"
    assert bad.status_code == 422
