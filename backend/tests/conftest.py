"""Gemeinsame pytest-Fixtures."""

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from app import create_app
from infrastructure.config import AppConfig


@pytest.fixture
def client() -> Iterator[TestClient]:
    """TestClient gegen eine frisch gebaute App-Instanz.

    Der Kontextmanager triggert den Lifespan (startup/shutdown), sodass der
    Smoke-Test zugleich das Hochfahren der App abdeckt.
    """
    app = create_app(AppConfig())
    with TestClient(app) as test_client:
        yield test_client
