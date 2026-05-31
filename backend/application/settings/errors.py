"""Application-Exceptions der settings-Use-Cases.

Eigene Fehlerklassen OHNE HTTP-Details -- das Mapping auf Statuscodes passiert
spaeter in ``api/`` (6f). Die beiden Routing-Fehler sichern die Variante-B-
Trennung application-seitig ab: ein Key darf nur ueber den fuer ihn richtigen
Pfad geschrieben werden, nie ins falsche Backend.
"""


class SettingsApplicationError(Exception):
    """Basis fuer Fehler der settings-Use-Cases (gemeinsamer Aufhaenger fuer api/)."""


class SecretKeyNotAllowedError(SettingsApplicationError):
    """Ein Secret-Key wurde ueber den Nicht-Secret-Pfad (UpdateSetting) versucht.

    Secrets gehen ausschliesslich ueber ``UpdateSecret`` in den ``SecretStore``,
    nie ueber das ``SettingsRepository``.
    """

    def __init__(self, key: str) -> None:
        self.key = key
        super().__init__(
            f"Key {key!r} ist ein Secret und darf nicht ueber UpdateSetting "
            f"geschrieben werden -- nutze UpdateSecret."
        )


class NotASecretKeyError(SettingsApplicationError):
    """Ein Nicht-Secret-Key wurde ueber den Secret-Pfad (UpdateSecret) versucht.

    Verhindert, dass ein beliebiger Key im OS-Keystore landet.
    """

    def __init__(self, key: str) -> None:
        self.key = key
        super().__init__(
            f"Key {key!r} ist kein Secret und darf nicht ueber UpdateSecret "
            f"in den Keystore geschrieben werden."
        )
