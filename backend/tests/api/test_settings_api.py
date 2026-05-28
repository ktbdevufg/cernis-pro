"""End-to-end-Tests der settings-API (v2) gegen app.py via TestClient.

Echte Adapter mit Test-Backends, via ``dependency_overrides`` eingehaengt:
``SqliteSettingsRepository`` auf einer tmp_path-DB, ``KeyringSecretStore`` auf
einem keyring-Fake (``set_keyring``). Kein echtes OS-Keystore, keine echte
cernis.db. Kern: die Variante-B-Trennung ueber HTTP und dass Secret-Klartext
NIE ueber GET nach aussen gelangt (Regression gegen den Altcode-Bug S3).
"""

from collections.abc import Iterator
from pathlib import Path

import keyring
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from keyring.backend import KeyringBackend
from keyring.errors import KeyringError, PasswordDeleteError

from api.settings import (
    provide_get_settings,
    provide_update_secret,
    provide_update_setting,
)
from app import create_app
from application.settings import GetSettings, UpdateSecret, UpdateSetting
from domain.settings import REDACTED
from infrastructure.config import AppConfig
from infrastructure.secret_store import KeyringSecretStore
from infrastructure.settings_repository import SqliteSettingsRepository

SECRET_KEY = "shodan_api_key"
PLAIN_KEY = "theme"


class _InMemoryKeyring(KeyringBackend):
    """Funktionierendes keyring-Fake-Backend (dict)."""

    def __init__(self) -> None:
        super().__init__()  # type: ignore[no-untyped-call]
        self._store: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self._store.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self._store[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        try:
            del self._store[(service, username)]
        except KeyError as exc:
            raise PasswordDeleteError("not set") from exc


class _FailingKeyring(KeyringBackend):
    """keyring-Fake, das bei jeder Operation einen Backend-Fehler wirft."""

    def __init__(self) -> None:
        super().__init__()  # type: ignore[no-untyped-call]

    def get_password(self, service: str, username: str) -> str | None:
        raise KeyringError("backend down")

    def set_password(self, service: str, username: str, password: str) -> None:
        raise KeyringError("backend down")

    def delete_password(self, service: str, username: str) -> None:
        raise KeyringError("backend down")


@pytest.fixture
def _restore_keyring() -> Iterator[None]:
    original = keyring.get_keyring()
    try:
        yield
    finally:
        keyring.set_keyring(original)


@pytest.fixture
def repo(tmp_path: Path) -> SqliteSettingsRepository:
    return SqliteSettingsRepository(tmp_path / "cernis.db")


@pytest.fixture
def secrets(_restore_keyring: None) -> KeyringSecretStore:
    keyring.set_keyring(_InMemoryKeyring())
    return KeyringSecretStore(service="test-service")


def _wired_app(repo: SqliteSettingsRepository, secrets: KeyringSecretStore) -> FastAPI:
    app = create_app(AppConfig())
    app.dependency_overrides[provide_get_settings] = lambda: GetSettings(repo, secrets)
    app.dependency_overrides[provide_update_setting] = lambda: UpdateSetting(repo)
    app.dependency_overrides[provide_update_secret] = lambda: UpdateSecret(secrets)
    return app


@pytest.fixture
def client(repo: SqliteSettingsRepository, secrets: KeyringSecretStore) -> Iterator[TestClient]:
    with TestClient(_wired_app(repo, secrets)) as test_client:
        yield test_client


# ── Nicht-Secrets ─────────────────────────────────────────────────────────


def test_put_non_secret_then_get_shows_value(client: TestClient) -> None:
    assert client.put(f"/api/settings/{PLAIN_KEY}", json={"value": "dark"}).status_code == 200
    body = client.get("/api/settings").json()
    assert body[PLAIN_KEY] == "dark"


# ── Secrets: maskiert im GET, real im Store ───────────────────────────────


def test_put_secret_then_get_redacted_and_value_stored(
    client: TestClient, secrets: KeyringSecretStore
) -> None:
    assert (
        client.put(f"/api/settings/secrets/{SECRET_KEY}", json={"value": "supersecret"}).status_code
        == 200
    )
    body = client.get("/api/settings").json()
    assert body[SECRET_KEY] == REDACTED
    assert "supersecret" not in str(body)
    # Der echte Wert liegt im SecretStore (separat verifiziert).
    assert secrets.get(SECRET_KEY) == "supersecret"


def test_unset_secret_is_omitted_in_get(client: TestClient) -> None:
    body = client.get("/api/settings").json()
    assert SECRET_KEY not in body


# ── Variante-B-Routing: falsches Backend -> 400 ───────────────────────────


def test_put_secret_key_via_setting_path_is_rejected(client: TestClient) -> None:
    response = client.put(f"/api/settings/{SECRET_KEY}", json={"value": "x"})
    assert response.status_code == 400


def test_put_non_secret_key_via_secret_path_is_rejected(client: TestClient) -> None:
    response = client.put(f"/api/settings/secrets/{PLAIN_KEY}", json={"value": "x"})
    assert response.status_code == 400


# ── Keystore-Ausfall -> 503, kein 200 (ADR 0001) ──────────────────────────


def test_get_returns_503_when_secret_backend_unavailable(
    repo: SqliteSettingsRepository, _restore_keyring: None
) -> None:
    keyring.set_keyring(_FailingKeyring())
    secrets = KeyringSecretStore(service="test-service")
    with TestClient(_wired_app(repo, secrets)) as test_client:
        response = test_client.get("/api/settings")
    assert response.status_code == 503


# ── Regression gegen Altcode-Bug S3: GET leakt nie den Shodan-Key ─────────


def test_get_never_leaks_shodan_key_plaintext(
    client: TestClient, secrets: KeyringSecretStore
) -> None:
    client.put(f"/api/settings/secrets/{SECRET_KEY}", json={"value": "leaktest123"})
    raw = client.get("/api/settings").text
    assert "leaktest123" not in raw  # Klartext taucht NIE auf
    assert REDACTED in raw  # stattdessen maskiert
