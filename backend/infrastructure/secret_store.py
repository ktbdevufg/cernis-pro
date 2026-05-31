"""SecretStore-Adapter ueber den OS-Keystore (``keyring`` / libsecret).

Erfuellt den Port ``SecretStore`` aus ``ports/settings.py``. Variante B:
eigenstaendige Secret-Ablage im OS-Keystore, getrennt vom
``SettingsRepository``. Unter Linux libsecret (GNOME Keyring/KWallet) ueber die
``keyring``-Lib.

ADR 0001 -- KEINE stillen Fallbacks. Die App ist NICHT fuer Headless konzipiert:
kein Datei-Fallback, kein Plaintext-Fallback. Genau die Vermischung, die der
Altcode ``modules/crypto.py`` betrieben hat (``encrypt`` gab bei Fehler den
KLARTEXT zurueck, ``decrypt`` schluckte Fehler zu ``""``), wird hier bewusst
NICHT gemacht.

Zwei Zustaende sauber getrennt:

* "Key nicht gesetzt" -> ``None`` (``get``) bzw. No-op (``delete``) -- legitim.
* "Backend kaputt" (Secret Service nicht erreichbar, gesperrt, Init-Fehler)
  -> ``SecretStoreUnavailableError`` -- niemals ``None``/``False`` vortaeuschen,
  niemals Klartext-Fallback.
"""

import keyring
from keyring.errors import KeyringError, PasswordDeleteError

DEFAULT_SERVICE = "cernis-pro"


class SecretStoreUnavailableError(Exception):
    """Der OS-Keystore (Secret-Backend) ist nicht erreichbar/funktionsfaehig.

    Umschliesst den zugrunde liegenden ``keyring``-Fehler (ADR 0001): ein
    Backend-Fehler ist ein Fehler, kein leiser Rueckfall auf ``None``/``False``
    oder Klartext. Die Nachricht enthaelt nur Operation und Key -- nie das
    Secret selbst.
    """

    def __init__(self, operation: str, key: str) -> None:
        self.operation = operation
        self.key = key
        super().__init__(f"Secret-Backend nicht verfuegbar bei {operation!r} fuer Key {key!r}")


class KeyringSecretStore:
    """Erfuellt das ``SecretStore``-Protocol strukturell (OS-Keystore via keyring).

    ``service`` ist der Namespace im Keystore (Default ``"cernis-pro"``) und
    wird injiziert, nicht in den Methoden hartkodiert.
    """

    def __init__(self, service: str = DEFAULT_SERVICE) -> None:
        self._service = service

    def get(self, key: str) -> str | None:
        """Klartext des Secrets, oder ``None`` NUR bei "nicht gesetzt".

        Bei einem Backend-Fehler -> ``SecretStoreUnavailableError``; niemals
        ``None`` (das wuerde "nicht gesetzt" vortaeuschen) und niemals ein
        Klartext-Fallback. Der Rueckgabewert ist Klartext und darf NIE ueber
        einen GET-Endpunkt nach aussen gelangen.
        """
        try:
            return keyring.get_password(self._service, key)
        except KeyringError as exc:
            raise SecretStoreUnavailableError("get", key) from exc

    def set(self, key: str, value: str) -> None:
        """Speichert den Klartext eines Secrets im OS-Keystore."""
        try:
            keyring.set_password(self._service, key, value)
        except KeyringError as exc:
            raise SecretStoreUnavailableError("set", key) from exc

    def delete(self, key: str) -> None:
        """Loescht ein Secret. "Nicht vorhanden" ist idempotent (kein Fehler).

        ``keyring`` signalisiert ein nicht vorhandenes Secret ueber
        ``PasswordDeleteError`` -- das wird als No-op behandelt. Ein echter
        Backend-Fehler bleibt ein Fehler (``SecretStoreUnavailableError``).
        """
        try:
            keyring.delete_password(self._service, key)
        except PasswordDeleteError:
            # 'nicht vorhanden' -> idempotent.
            pass
        except KeyringError as exc:
            raise SecretStoreUnavailableError("delete", key) from exc

    def exists(self, key: str) -> bool:
        """Ob ein Secret gesetzt ist -- gibt nur ``bool`` zurueck, nie Klartext.

        Backend-Fehler propagieren ueber ``get`` als
        ``SecretStoreUnavailableError``; es wird NICHT ``False`` vorgetaeuscht.
        """
        return self.get(key) is not None
