"""Tests der settings-Use-Cases gegen In-Memory-Fakes der Ports.

Kein echtes SQLite/keyring noetig -- wir testen gegen die Protocols, also
reichen in-memory dicts. Kern der Behauptungen: die Variante-B-Trennung
(ein Key landet nie im falschen Backend) und dass Secret-Klartext nie nach
aussen gelangt.
"""

import pytest

from application.settings import (
    GetSettings,
    NotASecretKeyError,
    SecretKeyNotAllowedError,
    UpdateSecret,
    UpdateSetting,
)
from domain.settings import REDACTED, Setting, SettingValue
from ports.settings import SecretStore, SettingsRepository

# Echte Secret-/Nicht-Secret-Keys aus der Domaene (domain.settings.SECRET_KEYS).
SECRET_KEY = "shodan_api_key"
OTHER_SECRET_KEY = "fritz_password"
PLAIN_KEY = "theme"


class FakeSettingsRepository:
    """In-Memory-Implementierung des SettingsRepository-Protocols."""

    def __init__(self) -> None:
        self._data: dict[str, SettingValue] = {}

    def get_all(self) -> dict[str, SettingValue]:
        return dict(self._data)

    def get(self, key: str) -> Setting | None:
        if key not in self._data:
            return None
        return Setting(key=key, value=self._data[key])

    def set(self, setting: Setting) -> None:
        self._data[setting.key] = setting.value

    def delete(self, key: str) -> None:
        self._data.pop(key, None)


class FakeSecretStore:
    """In-Memory-Implementierung des SecretStore-Protocols."""

    def __init__(self) -> None:
        self._data: dict[str, str] = {}

    def get(self, key: str) -> str | None:
        return self._data.get(key)

    def set(self, key: str, value: str) -> None:
        self._data[key] = value

    def delete(self, key: str) -> None:
        self._data.pop(key, None)

    def exists(self, key: str) -> bool:
        return key in self._data


@pytest.fixture
def repo() -> FakeSettingsRepository:
    return FakeSettingsRepository()


@pytest.fixture
def secrets() -> FakeSecretStore:
    return FakeSecretStore()


# ── Struktureller Vertrag: Fakes erfuellen die Ports ──────────────────────


def test_fakes_conform_to_ports() -> None:
    # Statische Vertragspruefung (mypy): die Fakes sind gueltige Stand-ins.
    _r: SettingsRepository = FakeSettingsRepository()
    _s: SecretStore = FakeSecretStore()


# ── GetSettings ───────────────────────────────────────────────────────────


def test_get_settings_passes_through_non_secrets(
    repo: FakeSettingsRepository, secrets: FakeSecretStore
) -> None:
    repo.set(Setting(key=PLAIN_KEY, value="dark"))
    repo.set(Setting(key="port", value=8080))
    result = GetSettings(repo, secrets)()
    assert result == {PLAIN_KEY: "dark", "port": 8080}


def test_get_settings_masks_set_secret_and_never_leaks_plaintext(
    repo: FakeSettingsRepository, secrets: FakeSecretStore
) -> None:
    secrets.set(SECRET_KEY, "supersecret")
    result = GetSettings(repo, secrets)()
    assert result[SECRET_KEY] == REDACTED
    assert "supersecret" not in result.values()


def test_get_settings_omits_unset_secret(
    repo: FakeSettingsRepository, secrets: FakeSecretStore
) -> None:
    # Kein Secret gesetzt -> Key fehlt im Ergebnis (Frontend: "nicht gesetzt").
    result = GetSettings(repo, secrets)()
    assert SECRET_KEY not in result


def test_get_settings_defensively_redacts_secret_leaked_into_repo(
    repo: FakeSettingsRepository, secrets: FakeSecretStore
) -> None:
    # Selbst wenn ein Secret faelschlich im Repository landet, maskiert die
    # defensive redact()-Schicht es -- Klartext verlaesst die App nie.
    repo.set(Setting(key=OTHER_SECRET_KEY, value="leaked"))
    result = GetSettings(repo, secrets)()
    assert result[OTHER_SECRET_KEY] == REDACTED
    assert "leaked" not in result.values()


# ── UpdateSetting ─────────────────────────────────────────────────────────


def test_update_setting_writes_non_secret(repo: FakeSettingsRepository) -> None:
    UpdateSetting(repo)(PLAIN_KEY, "dark")
    stored = repo.get(PLAIN_KEY)
    assert stored == Setting(key=PLAIN_KEY, value="dark")


def test_update_setting_rejects_secret_key_and_writes_nothing(
    repo: FakeSettingsRepository,
) -> None:
    with pytest.raises(SecretKeyNotAllowedError) as exc_info:
        UpdateSetting(repo)(SECRET_KEY, "supersecret")
    assert exc_info.value.key == SECRET_KEY
    assert repo.get_all() == {}  # nichts geschrieben


def test_update_setting_rejects_empty_key_via_domain_validation(
    repo: FakeSettingsRepository,
) -> None:
    # Setting.__post_init__ greift: leerer Key ist unzulaessig.
    with pytest.raises(ValueError):
        UpdateSetting(repo)("   ", "x")


# ── UpdateSecret ──────────────────────────────────────────────────────────


def test_update_secret_sets_value_in_secret_store(
    secrets: FakeSecretStore,
) -> None:
    UpdateSecret(secrets)(SECRET_KEY, "supersecret")
    assert secrets.get(SECRET_KEY) == "supersecret"
    assert secrets.exists(SECRET_KEY) is True


def test_update_secret_empty_value_deletes(secrets: FakeSecretStore) -> None:
    secrets.set(SECRET_KEY, "supersecret")
    UpdateSecret(secrets)(SECRET_KEY, "")
    assert secrets.exists(SECRET_KEY) is False


def test_update_secret_none_value_deletes(secrets: FakeSecretStore) -> None:
    secrets.set(SECRET_KEY, "supersecret")
    UpdateSecret(secrets)(SECRET_KEY, None)
    assert secrets.exists(SECRET_KEY) is False


def test_update_secret_delete_unset_is_idempotent(
    secrets: FakeSecretStore,
) -> None:
    # Leerer Wert auf nicht gesetztem Secret -> kein Fehler (idempotent).
    UpdateSecret(secrets)(OTHER_SECRET_KEY, "")
    assert secrets.exists(OTHER_SECRET_KEY) is False


def test_update_secret_rejects_non_secret_key_and_writes_nothing(
    secrets: FakeSecretStore,
) -> None:
    with pytest.raises(NotASecretKeyError) as exc_info:
        UpdateSecret(secrets)(PLAIN_KEY, "x")
    assert exc_info.value.key == PLAIN_KEY
    assert secrets.exists(PLAIN_KEY) is False
