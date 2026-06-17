"""Tests fuer die Provider-Stack-Factories ``_build_configured_provider`` /
``_build_filtered_provider`` (Composition Root, ADR 0029).

Die Kette Composite -> Configured (-> Filtered) lag frueher ZWEIMAL inline im
Composition Root (im ``_analyze_snapshot`` MIT Filter, im ``/rules/all``-Runner OHNE
Filter). ADR 0029 extrahiert sie in zwei freie Funktionen -- Single Source. Diese Tests
belegen, dass beide Funktionen das identische Verhalten der beiden alten Inline-Stellen
liefern: die GEFILTERTE Variante nimmt per Setting deaktivierte Regel-IDs heraus, die
UNGEFILTERTE laesst sie drin (die UI muss sie weiter sehen, um sie wieder einschaltbar
zu machen).

Wie die uebrigen wiring-Tests werden die privaten app-Funktionen direkt aus ``app``
importiert; als Quellen dienen die ECHTEN Repos (``SqliteUserRuleRepository`` /
``SqliteSettingsRepository``) auf einer ``tmp_path``-DB.
"""

from pathlib import Path

import pytest

from app import (
    _DISABLED_RULES_KEY,
    _build_configured_provider,
    _build_filtered_provider,
)
from domain.settings import Setting
from infrastructure.analysis_rules_db import SqliteUserRuleRepository
from infrastructure.settings_repository import SqliteSettingsRepository

# Eine Built-in-Regel-ID, die in beiden Provider-Stacks auftaucht (kein User-Setup
# noetig -- der BuiltinRuleProvider liefert sie immer). Wird in einem Test deaktiviert.
_BUILTIN_RULE_ID = "host_backdoor_port"


@pytest.fixture
def rules(tmp_path: Path) -> SqliteUserRuleRepository:
    return SqliteUserRuleRepository(tmp_path / "cernis.db")


@pytest.fixture
def settings(tmp_path: Path) -> SqliteSettingsRepository:
    return SqliteSettingsRepository(tmp_path / "cernis.db")


def test_configured_provider_contains_builtin_rules(
    rules: SqliteUserRuleRepository, settings: SqliteSettingsRepository
) -> None:
    """Die ungefilterte Variante liefert die Built-in-Regeln (frische DB, kein Setting)."""
    ids = {rule.id for rule in _build_configured_provider(rules, settings).get_rules()}
    assert _BUILTIN_RULE_ID in ids


def test_filtered_and_configured_identical_without_disabled_setting(
    rules: SqliteUserRuleRepository, settings: SqliteSettingsRepository
) -> None:
    """Ohne Deaktivierungs-Setting liefern beide Varianten dieselbe Regelmenge.

    Der Filter ist dann ein No-Op ("nichts deaktiviert"); die gefilterte und die
    ungefilterte Kette muessen exakt dieselben rule_ids liefern.
    """
    configured = {r.id for r in _build_configured_provider(rules, settings).get_rules()}
    filtered = {r.id for r in _build_filtered_provider(rules, settings).get_rules()}
    assert configured == filtered


def test_disabled_rule_removed_only_from_filtered_variant(
    rules: SqliteUserRuleRepository, settings: SqliteSettingsRepository
) -> None:
    """Eine deaktivierte Regel verschwindet NUR aus der gefilterten Variante.

    Das ist der Kern-Unterschied der beiden alten Inline-Stellen: die Engine (gefiltert)
    sieht die Regel nicht mehr, der UI-Endpunkt (ungefiltert) weiterhin -- sonst koennte
    die UI sie nie wieder einschalten.
    """
    settings.set(Setting(key=_DISABLED_RULES_KEY, value=[_BUILTIN_RULE_ID]))

    configured = {r.id for r in _build_configured_provider(rules, settings).get_rules()}
    filtered = {r.id for r in _build_filtered_provider(rules, settings).get_rules()}

    assert _BUILTIN_RULE_ID in configured  # ungefiltert: UI sieht die Regel weiter
    assert _BUILTIN_RULE_ID not in filtered  # gefiltert: die Engine ueberspringt sie
