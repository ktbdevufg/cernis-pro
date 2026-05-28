"""Ziel-Tests des traversal-sicheren Frontend-Servings in app.py (P2.1c).

Das Frontend-Dir wird ueber ``AppConfig.frontend_dir`` (= Env CERNIS_FRONTEND_DIR)
auf ein tmp_path-Frontend injiziert -- kein Schreiben in den Repo-Quellbaum. Kern
ist die Sicherheits-Regression gegen das Altcode-Finding S6: KEIN Ausbruch aus dem
Frontend-Verzeichnis ueber Path-Traversal.
"""

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app as app_module
from infrastructure.config import AppConfig

# Eindeutiger Inhalt einer Datei AUSSERHALB des Frontend-Dirs -- darf ueber keinen
# Traversal-Pfad ausgeliefert werden.
SENTINEL = "TOP-SECRET-SENTINEL-7f3a9c"
INDEX_HTML = "<!doctype html><title>CERNIS SPA</title><div id=root></div>"
APP_JS = "console.log('cernis-app');"


@pytest.fixture
def frontend_dir(tmp_path: Path) -> Path:
    """Minimales tmp-Frontend + eine Sentinel-Datei eine Ebene darueber."""
    fe = tmp_path / "frontend"
    (fe / "assets").mkdir(parents=True)
    (fe / "index.html").write_text(INDEX_HTML)
    (fe / "assets" / "app.js").write_text(APP_JS)
    # Sentinel als Geschwister des Frontend-Dirs (tmp_path/secret.txt).
    (tmp_path / "secret.txt").write_text(SENTINEL)
    return fe


@pytest.fixture
def client(frontend_dir: Path) -> Iterator[TestClient]:
    app = app_module.create_app(AppConfig(frontend_dir=str(frontend_dir)))
    with TestClient(app) as test_client:
        yield test_client


# ── Normales Serving ──────────────────────────────────────────────────────


def test_root_serves_index(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "CERNIS SPA" in response.text


def test_spa_route_falls_back_to_index(client: TestClient) -> None:
    # Nicht existente Client-Route (kein /api/, kein /ws/) -> SPA-Fallback.
    response = client.get("/settings")
    assert response.status_code == 200
    assert "CERNIS SPA" in response.text


def test_existing_asset_is_served(client: TestClient) -> None:
    response = client.get("/assets/app.js")
    assert response.status_code == 200
    assert APP_JS in response.text


# ── API/WS werden nicht verschluckt ───────────────────────────────────────


def test_unmatched_api_path_is_404(client: TestClient) -> None:
    response = client.get("/api/does-not-exist")
    assert response.status_code == 404
    assert "CERNIS SPA" not in response.text  # kein index.html-Fallback fuer api/


def test_unmatched_ws_path_is_404(client: TestClient) -> None:
    assert client.get("/ws/does-not-exist").status_code == 404


# ── Sicherheits-Regression: kein Path-Traversal (Finding S6) ──────────────


@pytest.mark.parametrize(
    "path",
    [
        "/../secret.txt",
        "/../../secret.txt",
        "/%2e%2e/secret.txt",
        "/..%2fsecret.txt",
        "/%2e%2e%2fsecret.txt",
        "/../../../../../../etc/passwd",
    ],
)
def test_traversal_never_escapes_frontend_dir(client: TestClient, path: str) -> None:
    response = client.get(path)
    # Niemals Inhalt ausserhalb des Frontend-Dirs; 404 oder index.html-Fallback ok.
    assert SENTINEL not in response.text
    assert "root:" not in response.text  # /etc/passwd-Marker taucht nie auf
    assert response.status_code in (200, 404)


# ── Kein Frontend-Dir -> API-only ─────────────────────────────────────────


def test_api_only_when_no_frontend(monkeypatch: pytest.MonkeyPatch) -> None:
    # Resolver auf None zwingen -> keine Serving-Routen, aber API laeuft weiter.
    monkeypatch.setattr(app_module, "_resolve_frontend_dir", lambda _configured: None)
    app = app_module.create_app(AppConfig())
    with TestClient(app) as test_client:
        assert test_client.get("/health").status_code == 200
        # Ohne Frontend-Mount gibt es keinen Catch-all -> SPA-Route ist 404.
        assert test_client.get("/some-spa-route").status_code == 404
