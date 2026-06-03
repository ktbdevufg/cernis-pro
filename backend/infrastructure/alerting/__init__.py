"""Adapter der alerting-Domaene: Rule-Repo (SQLite), Notifier (osascript + SMTP),
SmtpConfig (settings + crypto)."""

from infrastructure.alerting.notifier import AlertNotifierAdapter
from infrastructure.alerting.rule_repository import SqliteAlertRuleRepository
from infrastructure.alerting.smtp_config import SettingsSmtpConfigAdapter

__all__ = [
    "AlertNotifierAdapter",
    "SettingsSmtpConfigAdapter",
    "SqliteAlertRuleRepository",
]
