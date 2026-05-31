"""Tests fuer den ``KeyringSecretStore``-Adapter.

Testet NICHT gegen das echte OS-Backend. Stattdessen wird per
``keyring.set_keyring()`` ein In-Memory-Fake (bzw. ein bewusst werfendes
Backend) gesetzt und nach jedem Test wieder zuruckgesetzt. Kern der
Behauptungen: die ADR-0001-Trennung -- "nicht gesetzt" (None/idempotent) VS
"Backend kaputt" (Exception), nie ein stiller None-/False-/Klartext-Fallback.
"""

from collections.abc import Iterator

import keyring
import pytest
from keyring.backend import KeyringBackend
from keyring.errors import KeyringError, PasswordDeleteError

from infrastructure.secret_store import (
    KeyringSecretStore,
    SecretStoreUnavailableError,
)
from ports.settings import SecretStore


class _InMemoryKeyring(KeyringBackend):
    """Funktionierendes Fake-Backend: haelt Secrets in einem dict."""

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
            # Wie reale Backends: nicht vorhanden -> PasswordDeleteError.
            raise PasswordDeleteError("not set") from exc


class _FailingKeyring(KeyringBackend):
    """Kaputtes Fake-Backend: jede Operation wirft einen Backend-Fehler."""

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
    """Sichert das globale keyring-Backend und stellt es nach dem Test wieder her."""
    original = keyring.get_keyring()
    try:
        yield
    finally:
        keyring.set_keyring(original)


@pytest.fixture
def store(_restore_keyring: None) -> KeyringSecretStore:
    """Store gegen ein frisches In-Memory-Backend."""
    keyring.set_keyring(_InMemoryKeyring())
    return KeyringSecretStore(service="test-service")


@pytest.fixture
def failing_store(_restore_keyring: None) -> KeyringSecretStore:
    """Store gegen ein Backend, das bei jeder Operation wirft."""
    keyring.set_keyring(_FailingKeyring())
    return KeyringSecretStore(service="test-service")


# ── Struktureller Vertrag ─────────────────────────────────────────────────


def test_conforms_to_secret_store_protocol(store: KeyringSecretStore) -> None:
    # Statische Vertragspruefung (mypy): erfuellt das Protocol strukturell,
    # ohne @runtime_checkable / isinstance.
    _: SecretStore = store


# ── Round-trip: set / get / exists / delete ───────────────────────────────


def test_set_then_get_roundtrips(store: KeyringSecretStore) -> None:
    store.set("shodan_api_key", "geheim123")
    assert store.get("shodan_api_key") == "geheim123"


def test_set_overwrites_existing(store: KeyringSecretStore) -> None:
    store.set("k", "alt")
    store.set("k", "neu")
    assert store.get("k") == "neu"


def test_exists_true_after_set(store: KeyringSecretStore) -> None:
    store.set("k", "v")
    assert store.exists("k") is True


def test_delete_removes_secret(store: KeyringSecretStore) -> None:
    store.set("k", "v")
    store.delete("k")
    assert store.get("k") is None
    assert store.exists("k") is False


# ── Negativ-/Randfaelle: "nicht gesetzt" ist legitim ──────────────────────


def test_get_unset_returns_none(store: KeyringSecretStore) -> None:
    assert store.get("missing") is None


def test_exists_false_when_unset(store: KeyringSecretStore) -> None:
    assert store.exists("missing") is False


def test_delete_unset_is_idempotent(store: KeyringSecretStore) -> None:
    # Kein Fehler bei fehlendem Key.
    store.delete("missing")


# ── Backend-Fehler: Exception statt stillem None/False (ADR 0001) ─────────


def test_get_raises_on_backend_error_no_fake_none(
    failing_store: KeyringSecretStore,
) -> None:
    with pytest.raises(SecretStoreUnavailableError) as exc_info:
        failing_store.get("k")
    assert exc_info.value.operation == "get"
    assert exc_info.value.key == "k"


def test_set_raises_on_backend_error(
    failing_store: KeyringSecretStore,
) -> None:
    with pytest.raises(SecretStoreUnavailableError) as exc_info:
        failing_store.set("k", "v")
    assert exc_info.value.operation == "set"


def test_delete_raises_on_backend_error_not_idempotent(
    failing_store: KeyringSecretStore,
) -> None:
    # Backend kaputt ist KEIN "nicht vorhanden" -> kein stilles No-op.
    with pytest.raises(SecretStoreUnavailableError) as exc_info:
        failing_store.delete("k")
    assert exc_info.value.operation == "delete"


def test_exists_raises_on_backend_error_no_fake_false(
    failing_store: KeyringSecretStore,
) -> None:
    with pytest.raises(SecretStoreUnavailableError):
        failing_store.exists("k")
