"""Adapter fuer ``SmtpConfigPort`` -- laedt die SMTP-Config aus settings + crypto.

Spiegelt die Altcode-Lese-/Decrypt-Sequenz (main.py ``/test``): ``smtp_config`` ist
ein dict im SettingsRepository (KEIN Secret-Store-Eintrag), nur das ``password``-Feld
INNERHALB ist crypto-verschluesselt. Der Adapter liest das dict ueber den MIGRIERTEN
``ports/settings.SettingsRepository``-Port, casted ``port`` zu int und entschluesselt
``password`` via ``infrastructure.crypto.secret_cipher``. Der A.5-Use-Case sieht weder
settings noch crypto -- er ruft nur ``load()``.

crypto-Bezug: NUR ``secret_cipher.decrypt``/``encrypt`` -- ein Infrastruktur-interner
Import (``infrastructure.alerting`` -> ``infrastructure.crypto``), kein ``modules``-Bezug
mehr. Das smtp_config-Setting laeuft ueber den migrierten settings-Port.

``from_addr``-Default (in B verifiziert): der Altcode nutzt ``smtp_config.get("from",
user)`` -- fehlt ``from``, faellt es auf ``user`` zurueck. Diesen Default setzt das
Mapping hier.

KEIN STILLER FALLBACK BEI DECRYPT (ADR 0001; v2-Neubau von crypto): Der frueher hier
verankerte Altcode-S3-Strang -- ``decrypt`` lieferte bei kaputtem Cipher ``""``, der
Adapter loggte eine Warnung und machte mit leerem Passwort weiter -- ist AUFGEHOBEN.
``secret_cipher.decrypt`` wirft jetzt ``DecryptionError`` statt still ``""`` zu liefern.
Der Adapter faengt diese Ausnahme, loggt sie MIT dem echten Fehler und reicht sie NICHT
als leeres Passwort weiter: eine nicht entschluesselbare ``smtp_config`` ist eine KAPUTTE
Konfiguration, KEIN Zustand ohne Passwort. Er re-raist die Ausnahme, damit der ehrliche
Fehlzustand am Port-Vertrag sichtbar wird (der Aufrufer wuerde sonst mit leerem Passwort
mailen -- genau der stille Fehlschlag, den v2 beseitigt). ``None`` bleibt reserviert fuer
"nicht konfiguriert"; leeres Passwort fuer "kein Passwort gesetzt"; ein kaputter Cipher
ist keines von beidem.
"""

from typing import Any

import structlog

from domain.alerting import SmtpConfig
from domain.settings import Setting
from infrastructure.crypto.secret_cipher import DecryptionError, decrypt, encrypt
from ports.settings import SettingsRepository

_logger = structlog.get_logger(__name__)

_SMTP_CONFIG_KEY = "smtp_config"

# Sentinel, den GET ``/smtp`` als redigiertes Passwort liefert und PUT als "PW
# unveraendert" interpretiert -- exakt 8x U+2022 BULLET (A.1-Wortlaut, main.py:1075/1081).
_PASSWORD_SENTINEL = "•" * 8


class SettingsSmtpConfigAdapter:
    """Erfuellt das ``SmtpConfigPort``-Protocol strukturell (settings + crypto)."""

    def __init__(self, settings: SettingsRepository) -> None:
        self._settings = settings

    def _raw_dict(self) -> dict[str, Any] | None:
        """Gemeinsamer Helfer: das rohe ``smtp_config``-dict oder ``None``."""
        setting = self._settings.get(_SMTP_CONFIG_KEY)
        if setting is None or not isinstance(setting.value, dict) or not setting.value:
            return None
        return setting.value

    def load(self) -> SmtpConfig | None:
        raw = self._raw_dict()
        if raw is None:
            return None

        user = str(raw.get("user", ""))
        return SmtpConfig(
            host=str(raw.get("host", "")),
            port=self._coerce_port(raw.get("port", 587)),
            user=user,
            password=self._decrypt_password(raw.get("password", "")),
            # from_addr faellt wie Altcode auf user zurueck, wenn "from" fehlt/leer.
            from_addr=str(raw.get("from") or user),
            to=str(raw.get("to", "")),
        )

    def load_raw(self) -> dict[str, Any] | None:
        """Das ROHE ``smtp_config``-dict (Passwort als CIPHER, NICHT entschluesselt).

        Fuer Anzeige/Redaktion/host-to-Pruefung am api-Rand. Eine flache Kopie, damit
        der Aufrufer das gespeicherte dict nicht versehentlich mutiert.
        """
        raw = self._raw_dict()
        return dict(raw) if raw is not None else None

    def save(self, config: dict[str, Any]) -> None:
        """Speichert die SMTP-Config; Sentinel-Logik + ``crypto.encrypt`` aufs Passwort.

        SENTINEL-VERTRAG (v2-HEILUNG des Altcode-Bugs S7): Der Altcode (main.py:1080-1086)
        uebernahm beim Sentinel den alten CIPHER und schickte ihn dann DOCH durch
        ``encrypt`` -- ``crypto.encrypt`` ist nicht idempotent (kein ``enc:``-Check), also
        wurde doppelt verschluesselt und das PW bei jedem PW-erhaltenden Edit korrumpiert.
        v2 trennt sauber:

            password == SENTINEL  -> alten Cipher UNVERAENDERT uebernehmen (KEIN encrypt)
            password truthy        -> genau 1x encrypt(neues_klartext_pw)
            sonst                   -> ""

        Verhalten = was der Altcode MEINTE; der Doppel-encrypt entfaellt. Dokumentiert
        als Finding S7 in docs/pre_release_202605.md.
        """
        payload = dict(config)  # nicht das Aufrufer-dict mutieren
        new_password = payload.get("password", "")

        if new_password == _PASSWORD_SENTINEL:
            # PW unveraendert: alten Cipher 1:1 uebernehmen, NICHT re-encrypten.
            existing = self._raw_dict() or {}
            payload["password"] = existing.get("password", "")
        elif new_password:
            # Echtes neues Klartext-PW -> genau 1x verschluesseln.
            payload["password"] = encrypt(str(new_password))
        else:
            payload["password"] = ""

        self._settings.set(Setting(key=_SMTP_CONFIG_KEY, value=payload))

    @staticmethod
    def _coerce_port(value: Any) -> int:
        # Altcode: int(smtp_config.get("port", 587)) -- der Wert kann als str "587"
        # im dict liegen (Frontend) -> int-Cast am Rand.
        try:
            return int(value)
        except (TypeError, ValueError):
            return 587

    def _decrypt_password(self, cipher: Any) -> str:
        cipher_str = str(cipher) if cipher else ""
        if not cipher_str:
            return ""
        try:
            return decrypt(cipher_str)
        except DecryptionError:
            # KEIN stiller Fallback: der Cipher ist vorhanden, laesst sich aber nicht
            # entschluesseln (kaputt, fremder Schluessel, kein enc:-Praefix). Das ist
            # eine KAPUTTE Konfiguration, kein leeres Passwort -- mit dem echten Fehler
            # loggen und weiterreichen, statt still mit "" zu mailen.
            _logger.error("smtp_password_decrypt_failed")
            raise
