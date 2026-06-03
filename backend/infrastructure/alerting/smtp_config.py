"""Adapter fuer ``SmtpConfigPort`` -- laedt die SMTP-Config aus settings + crypto.

Spiegelt die Altcode-Lese-/Decrypt-Sequenz (main.py ``/test``): ``smtp_config`` ist
ein dict im SettingsRepository (KEIN Secret-Store-Eintrag), nur das ``password``-Feld
INNERHALB ist crypto-verschluesselt. Der Adapter liest das dict ueber den MIGRIERTEN
``ports/settings.SettingsRepository``-Port, casted ``port`` zu int und entschluesselt
``password`` via ``modules.crypto.decrypt``. Der A.5-Use-Case sieht weder settings
noch crypto -- er ruft nur ``load()``.

modules-Bezug: NUR ``crypto.decrypt`` (durch ADR-0007 ``infrastructure.alerting.** ->
modules`` gedeckt). Das smtp_config-Setting laeuft ueber den migrierten settings-Port,
NICHT ueber modules.storage.

``from_addr``-Default (in B verifiziert): der Altcode nutzt ``smtp_config.get("from",
user)`` -- fehlt ``from``, faellt es auf ``user`` zurueck. Diesen Default setzt das
Mapping hier.

AUFLAGE 1 (v2-Sichtbarmachung eines Altcode-S3-Strangs, KEIN Verhaltens-Fix):
``crypto.decrypt`` gibt bei kaputtem/ungueltigem Cipher ``""`` zurueck (Altcode-S3-
Fallback, modules/crypto.py:76 ``except (InvalidToken, Exception): return ""``). Der
Adapter macht daraus NICHTS anderes -- ``SmtpConfig.password`` wird dann ``""``,
exakt Altcode-treu, das Mail-Verhalten bleibt identisch. ABER: wenn ein
nicht-leerer ``password``-Cipher vorlag und decrypt ``""`` lieferte, wird ein
``structlog.warning("smtp_password_decrypt_empty")`` geloggt -- der stille Fehlschlag
wird SICHTBAR gemacht (robust UND sichtbar), ohne das Verhalten zu aendern.
"""

from typing import Any

import structlog

from domain.alerting import SmtpConfig
from modules.crypto import decrypt
from ports.settings import SettingsRepository

_logger = structlog.get_logger(__name__)

_SMTP_CONFIG_KEY = "smtp_config"


class SettingsSmtpConfigAdapter:
    """Erfuellt das ``SmtpConfigPort``-Protocol strukturell (settings + crypto)."""

    def __init__(self, settings: SettingsRepository) -> None:
        self._settings = settings

    def load(self) -> SmtpConfig | None:
        setting = self._settings.get(_SMTP_CONFIG_KEY)
        if setting is None or not isinstance(setting.value, dict):
            # Nicht konfiguriert (kein Setting / leeres-oder-falsch-typisiertes dict).
            return None
        raw: dict[str, Any] = setting.value
        if not raw:
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
        # decrypt ist untypisiertes modules -> expliziter Vertrags-Cast zu str.
        plaintext = str(decrypt(cipher_str))
        if not plaintext:
            # AUFLAGE 1: decrypt lieferte "" trotz vorhandenem Cipher (Altcode-S3-
            # Fallback bei kaputtem/ungueltigem Cipher). Verhalten Altcode-treu ("")
            # -- aber sichtbar geloggt statt still.
            _logger.warning("smtp_password_decrypt_empty")
        return plaintext
