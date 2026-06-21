"""Application-Exceptions der devices-Use-Cases.

Eigene Fehlerklassen OHNE HTTP-Details -- das Mapping auf Statuscodes passiert
in ``api/`` (D.6).
"""


class DevicesApplicationError(Exception):
    """Basis fuer Fehler der devices-Use-Cases (gemeinsamer Aufhaenger fuer api/)."""


class DeviceNotFoundError(DevicesApplicationError):
    """Ein Geraet zu einer MAC existiert nicht.

    Bewusste Abweichung vom Altcode: ``update_device_meta`` war dort ein stiller
    No-op auf unbekannte MAC (reines SQL-UPDATE ohne Treffer). v2 macht das
    explizit -- ein Update auf ein nicht existierendes Geraet ist ein Fehler.
    Loeschen bleibt hingegen idempotent (kein Fehler bei unbekannter MAC).
    """

    def __init__(self, mac: str) -> None:
        self.mac = mac
        super().__init__(f"Kein Geraet mit MAC {mac!r}")


class InvalidTrustStateError(DevicesApplicationError):
    """Ein uebergebener ``trust_state``-Wert ist keiner der erlaubten Zustaende.

    Der api-Ring darf den ``domain``-Ring nicht importieren (import-linter), kann
    also nicht selbst gegen ``TrustState`` validieren. Deshalb nimmt der Use-Case
    auch einen rohen ``str`` entgegen und hebt ihn intern via ``TrustState(...)``;
    ein ungueltiger Wert ist KEIN stiller Fallback, sondern dieser Fehler -- den
    der Router auf HTTP 422 abbildet.
    """

    def __init__(self, value: str) -> None:
        self.value = value
        super().__init__(f"Ungueltiger trust_state {value!r}")
