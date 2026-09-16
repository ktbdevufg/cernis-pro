"""Ports der settings-Domaene: Vertraege fuer Persistenz und Secret-Ablage.

Zwei getrennte Vertraege (Variante B -- getrennte Ablagen):

* ``SettingsRepository`` -- reine Key-Value-Persistenz fuer NICHT-geheime
  Settings. Liefert und nimmt Rohwerte; der Secret-Klartext laeuft hier NIE
  durch.
* ``SecretStore`` -- eigenstaendiger Ablageort fuer Secrets (OS-Keystore-Adapter
  folgt in 6d). Sein Klartext-Rueckgabewert darf NIE ueber einen GET-Endpunkt
  nach aussen gelangen.

Die Ports tragen KEINE Policy, nur Mechanik. Die Redaction-Policy liegt als reine
Funktion in ``domain/settings`` (``redact()``, ``is_secret()``); das Maskieren
passiert spaeter im Use-Case (6e), nicht hier und nicht in der Infrastruktur.

Bewusste Entscheidung: KEIN ``@runtime_checkable``. Die Vertragspruefung laeuft
statisch ueber mypy und ueber die Verdrahtung im Composition Root (``app.py``),
nicht zur Laufzeit per ``isinstance``.

Import von ``domain`` ist erlaubt -- der import-linter-Contract verbietet nur die
Gegenrichtung (domain -> ports) sowie Importe aus ``infrastructure``/``api``.
"""

from typing import Protocol

from domain.settings import Setting, SettingValue


class SettingsRepository(Protocol):
    """Persistenz fuer NICHT-geheime Settings -- liefert/nimmt Rohwerte.

    Reine Mechanik ohne Redaction-Policy. Secrets gehoeren NICHT hierher,
    sondern in den ``SecretStore``.
    """

    def get_all(self) -> dict[str, SettingValue]:
        """Alle gespeicherten Settings als ``{key: value}``.

        Ein leerer Store liefert ein leeres ``dict`` -- niemals ``None``.
        """
        ...

    def get(self, key: str) -> Setting | None:
        """Ein einzelnes Setting, oder ``None`` wenn nicht vorhanden.

        ``None`` ist hier ein legitimer Zustand ("Key nicht gesetzt"), kein
        Fehler.
        """
        ...

    def set(self, setting: Setting) -> None:
        """Speichert ein Setting.

        Nimmt bewusst das Domaenen-Objekt ``Setting`` (nicht ``key``/``value``
        einzeln), damit dessen ``__post_init__``-Validierung greift.
        """
        ...

    def delete(self, key: str) -> None:
        """Loescht ein Setting. Idempotent -- kein Fehler bei fehlendem Key."""
        ...

    def clear_all(self) -> None:
        """Leert alle Settings (nur die eigene Tabelle)."""
        ...


class SecretStore(Protocol):
    """Eigenstaendige Secret-Ablage (ADR 0001: KEINE stillen Fallbacks).

    Trennt zwei Fehlerzustaende, die der Altcode vermischt hat:

    * "Key nicht gesetzt" -> ``None`` (legitimer Zustand).
    * "Backend/Krypto kaputt" -> Exception (ADR 0001) -- niemals ``None`` und
      niemals ein Klartext-Fallback.

    Der Klartext-Rueckgabewert von ``get()`` darf NIE ueber einen GET-Endpunkt
    nach aussen gelangen.
    """

    def get(self, key: str) -> str | None:
        """Klartext des Secrets, oder ``None`` NUR bei "nicht gesetzt".

        Bei einem Krypto-/Backend-FEHLER wird eine Exception geworfen -- niemals
        ``None`` (das wuerde "nicht gesetzt" vortaeuschen) und niemals ein
        Klartext-Fallback (ADR 0001, keine stillen Fallbacks).

        Der Rueckgabewert ist Klartext und darf NIE ueber einen GET-Endpunkt
        nach aussen gelangen.
        """
        ...

    def set(self, key: str, value: str) -> None:
        """Speichert den Klartext eines Secrets unter ``key``."""
        ...

    def delete(self, key: str) -> None:
        """Loescht ein Secret. Idempotent -- kein Fehler bei fehlendem Key."""
        ...

    def exists(self, key: str) -> bool:
        """Ob ein Secret gesetzt ist -- OHNE den Klartext zu beruehren.

        Speist die GET-/Redaction-Logik in 6e: Praesenz pruefen, ohne das
        Secret zu entschluesseln oder nach aussen zu reichen.
        """
        ...
