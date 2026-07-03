"""Adapter fuer ``AlertNotifierPort`` -- eigener alerting-Notifier (macos + E-Mail).

EIGENER alerting-Notifier, KEINE monitoring-Wiederverwendung (independence: der
monitoring-Notifier hat eine andere Signatur -- ``notify(MonitorEvent)`` -- und
gehoert monitoring). Beide Methoden ``async``; das blockierende osascript-Subprocess
bzw. der SMTP-Versand laufen ueber ``run_in_executor``, damit kein Event-Loop
blockiert.

modules-Bezug (durch ADR-0007 ``infrastructure.alerting.** -> modules`` gedeckt):
* ``email`` ist ein duenner Wrapper um ``modules.alerting.notify_email_with_log``
  (gibt IMMER ``{"success": bool, "log": [str]}`` zurueck, wirft nie) -- 1:1
  uebernommen, nur zu ``EmailResult`` gemappt. Die ``SmtpConfig`` wird wieder zum
  smtp_config-dict auseinandergenommen (die Keys, die der Altcode liest:
  host/port/user/password/to/from).
* ``macos`` baut das osascript EIGENSTAENDIG (NICHT der monitor._notify_macos): die
  Altcode-``modules.alerting.notify_macos`` traegt ``subtitle`` + ``except: pass``
  (E.4). Hier reproduzieren wir den osascript-Aufruf, ABER mit der EINEN bewussten
  Abweichung von E.4: ein unerwarteter Fehler wird per ``structlog.warning``
  protokolliert statt still verschluckt (robust UND sichtbar -- kein S3-Fang ohne
  Log). Das Mail-/Notify-VERHALTEN bleibt identisch (Linux: osascript fehlt ->
  no-op), nur der Fehlschlag ist sichtbar.

PLATTFORM (port-treu): osascript ist macOS-only. Auf Linux wirft
``subprocess.run(["osascript", ...])`` ``FileNotFoundError`` -- hier gefangen +
geloggt, der vom Port vorgesehene "kein Notification-Backend"-no-op-Zustand.
"""

import asyncio
import subprocess

import structlog

from domain.alerting import EmailResult, SmtpConfig
from infrastructure.osascript_escape import escape_applescript_literal
from modules.alerting import notify_email_with_log

_logger = structlog.get_logger(__name__)

# osascript-Timeout wie Altcode modules.alerting.notify_macos (3 s).
_OSASCRIPT_TIMEOUT = 3


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
            await loop.run_in_executor(None, self._run_osascript, title, message, subtitle)
        except Exception:
            # Best-effort: nie ein Aufrufer-Fehler. MIT Log (kein stiller S3-Fang, E.4).
            _logger.warning("alert_macos_notify_failed", title=title)

    @staticmethod
    def _run_osascript(title: str, message: str, subtitle: str) -> None:
        # Wortlaut wie Altcode modules.alerting.notify_macos. Die eingebetteten Werte
        # werden fuer das AppleScript-Literal escaped (kein Ausbruch per "), die
        # Programmstruktur bleibt identisch.
        title_e = escape_applescript_literal(title)
        message_e = escape_applescript_literal(message)
        subtitle_e = escape_applescript_literal(subtitle)
        sub = f'subtitle "{subtitle_e}" ' if subtitle else ""
        script = (
            f'display notification "{message_e}" with title "{title_e}" {sub}sound name "Basso"'
        )
        # Arg-Liste ohne shell=True -> keine Shell-Injection (Altcode-treu).
        subprocess.run(
            ["osascript", "-e", script],
            timeout=_OSASCRIPT_TIMEOUT,
            capture_output=True,
        )

    async def email(self, subject: str, body: str, config: SmtpConfig) -> EmailResult:
        """Sendet eine E-Mail ueber ``modules.alerting.notify_email_with_log``.

        Gibt IMMER ein ``EmailResult`` zurueck (der Altcode-Wrapper faengt jeden
        SMTP-Fehler intern und protokolliert ihn in ``log``). ``EmailResult.success``
        ist exakt der Altcode-``success``-Wert. Blockierender SMTP-Versand ->
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
