"""Use-Cases der settings-Domaene (Variante B: getrennte Ablagen).

Orchestrieren Domaene + Ports. Kennen ``domain/`` und ``ports/``, NIEMALS
``infrastructure/`` (maschinell per import-linter erzwungen). Beide Ports kommen
per Constructor-Injection als Protocol-Typ herein -- nie ein konkreter Adapter.
Kein State ueber Aufrufe hinaus, keine Framework-Imports (kein FastAPI/Pydantic).

Hier wird die Variante-B-Trennung sichtbar verdrahtet: ein Key landet nie im
falschen Backend, und Secret-Klartext verlaesst die App nie.
"""

from application.settings.errors import NotASecretKeyError, SecretKeyNotAllowedError
from domain.settings import (
    REDACTED,
    SECRET_KEYS,
    Setting,
    SettingValue,
    is_secret,
    redact,
)
from ports.settings import SecretStore, SettingsRepository


class GetSettings:
    """Liest alle Settings fuer die Ausgabe nach aussen -- nie Secret-Klartext."""

    def __init__(self, repository: SettingsRepository, secret_store: SecretStore) -> None:
        self._repository = repository
        self._secret_store = secret_store

    def __call__(self) -> dict[str, SettingValue]:
        result: dict[str, SettingValue] = dict(self._repository.get_all())
        # Gesetzte Secrets als REDACTED ergaenzen; nicht gesetzte weglassen
        # (das Frontend zeigt dann "nicht gesetzt"). exists() beruehrt keinen
        # Klartext.
        for key in SECRET_KEYS:
            if self._secret_store.exists(key):
                result[key] = REDACTED
        # Defensive Schicht: maskiert auch ein Secret, das faelschlich im
        # Repository gelandet waere -- Klartext verlaesst die App nie.
        return redact(result)


class UpdateSetting:
    """Schreibt ein NICHT-geheimes Setting; lehnt Secret-Keys ab."""

    def __init__(self, repository: SettingsRepository) -> None:
        self._repository = repository

    def __call__(self, key: str, value: SettingValue) -> None:
        if is_secret(key):
            raise SecretKeyNotAllowedError(key)
        # Setting(...) validiert den Key (nicht leer) in __post_init__.
        self._repository.set(Setting(key=key, value=value))


class UpdateSecret:
    """Setzt oder loescht ein Secret; nur echte Secret-Keys erlaubt."""

    def __init__(self, secret_store: SecretStore) -> None:
        self._secret_store = secret_store

    def __call__(self, key: str, value: str | None) -> None:
        if not is_secret(key):
            raise NotASecretKeyError(key)
        if value:
            self._secret_store.set(key, value)
        else:
            # Leerer Wert oder None -> loeschen (idempotent).
            self._secret_store.delete(key)
