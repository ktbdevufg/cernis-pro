"""Use-Cases der alerting-Domaene.

Kennen NUR ``domain/alerting`` + ``ports/alerting`` -- NIE infrastructure/api und NIE
settings/crypto direkt (die Kopplung daran lebt in den A.4-Adaptern hinter den Ports).

Drei Gruppen:

* **Rule-CRUD + History** -- duenne Pass-Throughs ueber den ``AlertRuleRepository``
  (Muster ``GetSchedules``/``ManageSchedules``). Die int<->bool-Konvertierung der Flags
  ist am Adapter-Rand erledigt (A.4); die Use-Cases sehen ``AlertRule`` mit ``bool``.
* **SendTestAlert** -- der A.6-``/test``-Pfad: laedt die ``SmtpConfig`` ueber den
  ``SmtpConfigPort`` und mailt ueber den ``AlertNotifierPort``. Gibt ``EmailResult |
  None`` (``None`` = nicht konfiguriert).
* **RaiseAlert** -- ersetzt den Altcode-``fire_alert`` STRUKTURELL (AS-IS migriert).
  KEIN Trigger in A.5: RaiseAlert wird hier NICHT an den monitor-Loop verdrahtet (das
  ist A.7). Er existiert + ist getestet, wird aber von niemandem ausser dem Test
  gerufen -- exakt wie ``fire_alert`` heute tot ist. Bewusst: A.5 migriert die Logik,
  A.7 macht den Trigger live.

NAHT SendTestAlert / 400 (Designfrage A.5): ``SmtpConfigPort.load()`` gibt ``None`` NUR
bei voellig fehlendem/leerem ``smtp_config`` -- bei ``{host:"", to:""}`` baut es eine
``SmtpConfig`` mit leeren Strings (empirisch belegt). Die Altcode-400-Bedingung ist
aber "host ODER to leer" (A.1). Diese host/to-Pruefung ist ein HTTP-Belang und sitzt am
A.6-Rand, NICHT hier: ``SendTestAlert`` gibt ``None`` (nicht konfiguriert) oder das
``EmailResult``; A.6 mappt ``None``/leeres-host-to -> 400, ``success`` -> 200/503.

now-Quelle RaiseAlert (Designfrage A.5): ``time.time()`` direkt mit Methoden-Parameter-
Override -- Muster ``GetSlaStats`` (M.7: epoch-float-Zeit direkt im Use-Case, kein
Clock-Port fuer einen schmalen Schritt; der devices-``Clock`` liefert ``datetime``, das
passt zur Cooldown-``float``-Rechnung nicht). Der Test injiziert ``now`` deterministisch.
"""

import time
from typing import Any

from domain.alerting import (
    AlertEvent,
    AlertRule,
    EmailResult,
    SmtpConfig,
    select_rules_to_fire,
)
from ports.alerting import AlertNotifierPort, AlertRuleRepository, SmtpConfigPort

# ── Rule-CRUD + History (Pass-Through) ────────────────────────


class GetAlertRules:
    """Liefert alle Alert-Regeln (Pass-Through, nur Repo)."""

    def __init__(self, repository: AlertRuleRepository) -> None:
        self._repository = repository

    def __call__(self) -> list[AlertRule]:
        return self._repository.get_rules()


class AddAlertRule:
    """Legt eine Regel an und gibt ihre neue ``id`` zurueck (Pass-Through)."""

    def __init__(self, repository: AlertRuleRepository) -> None:
        self._repository = repository

    def __call__(
        self,
        name: str,
        rule_type: str,
        target: str,
        threshold: int,
        notify_email: bool,
        notify_macos: bool,
    ) -> int:
        return self._repository.add(
            name=name,
            rule_type=rule_type,
            target=target,
            threshold=threshold,
            notify_email=notify_email,
            notify_macos=notify_macos,
        )


class UpdateAlertRule:
    """Aktualisiert die gesetzten Felder einer Regel (Pass-Through, Whitelist im Repo)."""

    def __init__(self, repository: AlertRuleRepository) -> None:
        self._repository = repository

    def __call__(
        self,
        rule_id: int,
        *,
        name: str | None = None,
        target: str | None = None,
        threshold: int | None = None,
        notify_email: bool | None = None,
        notify_macos: bool | None = None,
        enabled: bool | None = None,
    ) -> None:
        self._repository.update(
            rule_id,
            name=name,
            target=target,
            threshold=threshold,
            notify_email=notify_email,
            notify_macos=notify_macos,
            enabled=enabled,
        )


class DeleteAlertRule:
    """Loescht eine Regel (Pass-Through, idempotent im Repo)."""

    def __init__(self, repository: AlertRuleRepository) -> None:
        self._repository = repository

    def __call__(self, rule_id: int) -> None:
        self._repository.delete(rule_id)


class GetAlertHistory:
    """Liefert die juengsten History-Ereignisse, neueste zuerst (Pass-Through)."""

    def __init__(self, repository: AlertRuleRepository) -> None:
        self._repository = repository

    def __call__(self, limit: int = 50) -> list[AlertEvent]:
        return self._repository.recent(limit)


# ── SendTestAlert (A.6-/test-Pfad) ────────────────────────────


class SendTestAlert:
    """Versendet eine Test-E-Mail ueber die konfigurierte SMTP-Config.

    Laedt die ``SmtpConfig`` (``SmtpConfigPort.load()``) und mailt ueber den
    ``AlertNotifierPort``. Gibt ``None`` wenn nicht konfiguriert (``load()`` is ``None``)
    -- dann KEIN E-Mail-Versuch; sonst das ``EmailResult`` des Versuchs. Die 400-vs-503-
    Statuscode-Logik (host/to leer vs. Versandfehler) macht der A.6-Rand (s. Modul-
    Docstring).
    """

    # Wortlaut wie der Altcode-/test-Endpunkt (main.py api_test_alert).
    _SUBJECT = "Test Alert"

    def __init__(self, smtp_config: SmtpConfigPort, notifier: AlertNotifierPort) -> None:
        self._smtp_config = smtp_config
        self._notifier = notifier

    async def __call__(self) -> EmailResult | None:
        config = self._smtp_config.load()
        if config is None:
            return None
        body = "Test alert from CERNIS PRO\nThis confirms your SMTP configuration is working."
        return await self._notifier.email(self._SUBJECT, body, config)


# ── SMTP-Config GET/PUT (A.4b-Naht) ───────────────────────────


class GetSmtpConfigRaw:
    """Liefert das ROHE smtp_config-dict (Passwort als Cipher), oder ``None``.

    Pass-Through ueber ``SmtpConfigPort.load_raw``. Der api-Rand (A.6) redigiert das
    Passwort selbst zu ``••••••••`` -- der Cipher darf den Rand erreichen, der Klartext
    nie (dafuer ist ``SmtpConfigPort.load`` fuer den Versand da).
    """

    def __init__(self, smtp_config: SmtpConfigPort) -> None:
        self._smtp_config = smtp_config

    def __call__(self) -> dict[str, Any] | None:
        return self._smtp_config.load_raw()


class SaveSmtpConfig:
    """Speichert die SMTP-Config (Pass-Through; Sentinel-/encrypt-Logik im Adapter)."""

    def __init__(self, smtp_config: SmtpConfigPort) -> None:
        self._smtp_config = smtp_config

    def __call__(self, config: dict[str, Any]) -> None:
        self._smtp_config.save(config)


# ── RaiseAlert (ersetzt fire_alert, AS-IS; KEIN Trigger in A.5) ──


class RaiseAlert:
    """Feuert alle passenden Regeln fuer ein Ereignis (ersetzt Altcode ``fire_alert``).

    Orchestriert: ``repo.get_rules()`` -> ``select_rules_to_fire`` (A.2, reine Auswahl
    inkl. Cooldown) -> pro selektierter Regel die Kanaele (``macos`` immer wenn
    ``notify_macos``; ``email`` nur wenn ``notify_email`` UND eine ``SmtpConfig``
    vorhanden) -> ``repo.save_event`` (schreibt History + setzt ``last_triggered``,
    A.4). Seiteneffektfrei bis auf die Ports.

    KEIN Trigger in A.5 (s. Modul-Docstring): existiert + getestet, aber von niemandem
    ausser dem Test gerufen -- A.7 macht den Trigger live.

    Wortlaut/Reihenfolge 1:1 Altcode ``fire_alert`` (modules/alerting.py Z.296-311):
    Titel ``"CERNIS PRO — <name>"``, macos mit ``subtitle=target``, email-Body
    mehrzeilig; ``AlertEvent.timestamp = now``. SmtpConfig wird EINMAL geladen (nicht
    pro Regel), nur wenn ueberhaupt eine email-Regel feuern koennte -- der Notifier
    bekommt sie als Parameter.
    """

    def __init__(
        self,
        repository: AlertRuleRepository,
        notifier: AlertNotifierPort,
        smtp_config: SmtpConfigPort,
    ) -> None:
        self._repository = repository
        self._notifier = notifier
        self._smtp_config = smtp_config

    async def __call__(
        self,
        rule_type: str,
        target: str,
        message: str,
        now: float | None = None,
    ) -> None:
        fire_time = time.time() if now is None else now
        rules = self._repository.get_rules()
        selected = select_rules_to_fire(rules, rule_type, target, fire_time)
        if not selected:
            return

        # SmtpConfig nur laden, wenn ueberhaupt eine email-Regel feuert (spart den
        # settings/crypto-Zugriff, wenn niemand mailt). Einmal fuer alle Regeln.
        config: SmtpConfig | None = None
        if any(rule.notify_email for rule in selected):
            config = self._smtp_config.load()

        for rule in selected:
            title = f"CERNIS PRO — {rule.name}"
            if rule.notify_macos:
                await self._notifier.macos(title, message, subtitle=target)
            if rule.notify_email and config is not None:
                body = (
                    f"Rule: {rule.name}\n"
                    f"Target: {target}\n"
                    f"Event: {message}\n"
                    f"Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(fire_time))}"
                )
                await self._notifier.email(rule.name, body, config)

            event = AlertEvent(
                rule_id=rule.id,
                rule_name=rule.name,
                rule_type=rule_type,
                target=target,
                message=message,
                timestamp=fire_time,
            )
            self._repository.save_event(event)
