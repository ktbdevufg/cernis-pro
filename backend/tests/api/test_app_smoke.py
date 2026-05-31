"""Smoke-Test: App bootet (Lifespan) und /health antwortet."""

from fastapi.testclient import TestClient

from app import create_app
from infrastructure.config import AppConfig


def test_health_ok(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "cernis-pro"
    assert body["version"] == "2.0.0.dev0"


def test_scanning_routes_registered() -> None:
    """create_app verdrahtet die scanning-Domaene fehlerfrei: REST + WS sind da.

    Beweist, dass die 8-Adapter-Verdrahtung + der WS-Handler-Bau im Composition
    Root ohne Fehler durchlaufen und die Routen registriert sind (S.6).
    """
    app = create_app(AppConfig())
    paths = {getattr(route, "path", None) for route in app.routes}
    assert "/api/history" in paths
    assert "/api/history/{scan_id}" in paths
    assert "/api/vendor/{mac}" in paths
    assert "/ws/scan" in paths  # WebSocket-Route im Composition Root verdrahtet
