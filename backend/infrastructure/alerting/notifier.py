"""Adapter fuer ``AlertNotifierPort`` -- eigener alerting-Notifier (macos + E-Mail).

EIGENER alerting-Notifier, KEINE monitoring-Wiederverwendung (independence: der
monitoring-Notifier hat eine andere Signatur -- ``notify(MonitorEvent)`` -- und
gehoert monitoring). Beide Methoden ``async``; das blockierende osascript-Subprocess
bzw. der SMTP-Versand laufen ueber ``run_in_executor``, damit kein Event-Loop
blockiert.

v2-NEUBAU (A.8): Der frueher hier verankerte ``modules``-Bezug ist WEG. Der Adapter
delegiert jetzt an den migrierten v2-Kern:
* ``email`` -> ``infrastructure.alerting.email_sender.notify_email_with_log`` (SMTP
  mit PFLICHT-TLS, kein Klartext-Rueckfall, ``finally``-Verbindungsabbau -- die zwei
  belegten Sicherheitsfehler des Altcode sind dort geheilt). Gibt IMMER
  ``{"success": bool, "log": list[str]}`` zurueck, wird zu ``EmailResult`` gemappt.
* ``macos`` -> ``infrastructure.alerting.desktop_notifier.notify_macos`` (osascript
  mit ``escape_applescript_literal`` gegen AppleScript-Injection). Der unerwartete
  Fehler wird hier per ``structlog.warning`` protokolliert statt still verschluckt
  (bewusste Abweichung vom Altcode-``except: pass``, E.4 -- robust UND sichtbar).

PLATTFORM (port-treu): osascript ist macOS-only. Auf Linux wirft
``desktop_notifier.notify_macos`` ``FileNotFoundError`` -- hier gefangen + geloggt,
der vom Port vorgesehene "kein Notification-Backend"-no-op-Zustand.
"""

import asyncio

import structlog

from domain.alerting import EmailResult, SmtpConfig
from infrastructure.alerting.desktop_notifier import notify_macos
from infrastructure.alerting.email_sender import notify_email_with_log

_logger = structlog.get_logger(__name__)


class AlertNotifierAdapter:
    """Erfuellt das ``AlertNotifierPort``-Protocol strukturell (osascript + SMTP)."""

    async def macos(self, title: str, message: str, subtitle: str = "") -> None:
        """Desktop-Notification via osascript (best-effort, Linux-no-op).

        Blockierendes Subprocess -> ``run_in_executor``. Ein unerwarteter Fehler
        (inkl. ``FileNotFoundError`` auf Linux) wird geloggt, NICHT geschluckt
        (bewusste Abweichung von Altcode-E.4 ``except: pass``) und NICHT geworfen.
        """
        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(None, notify_macos, title, message, subtitle)
        except Exception:
            # Best-effort: nie ein Aufrufer-Fehler. MIT Log (kein stiller S3-Fang, E.4).
            _logger.warning("alert_macos_notify_failed", title=title)

    async def email(self, subject: str, body: str, config: SmtpConfig) -> EmailResult:
        """Sendet eine E-Mail ueber ``email_sender.notify_email_with_log``.

        Gibt IMMER ein ``EmailResult`` zurueck (der Sender faengt jeden SMTP-Fehler
        intern und protokolliert ihn in ``log``). ``EmailResult.success`` ist exakt
        der Sender-``success``-Wert -- ``True`` nur bei tatsaechlichem Versand ueber
        eine verschluesselte Verbindung. Blockierender SMTP-Versand ->
        ``run_in_executor``.
        """
        smtp_config = self._to_smtp_dict(config)
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None, lambda: notify_email_with_log(subject, body, smtp_config)
        )
        return EmailResult(success=bool(result["success"]), log=list(result["log"]))

    @staticmethod
    def _to_smtp_dict(config: SmtpConfig) -> dict[str, object]:
        # SmtpConfig wieder zu den Keys auseinandernehmen, die notify_email_with_log
        # liest (host/port/user/password/to/from).
        return {
            "host": config.host,
            "port": config.port,
            "user": config.user,
            "password": config.password,
            "from": config.from_addr,
            "to": config.to,
        }
