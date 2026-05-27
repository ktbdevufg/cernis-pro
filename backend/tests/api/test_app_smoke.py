"""Smoke-Test: App bootet (Lifespan) und /health antwortet."""

from fastapi.testclient import TestClient


def test_health_ok(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "cernis-pro"
    assert body["version"] == "2.0.0.dev0"
