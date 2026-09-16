"""Verhaltens-/Strukturtest der analysis-Adapter (AN.3).

Belegt fuer die zwei zustandslosen Adapter:

* ``BuiltinRuleProvider`` liefert exakt die eingebauten ``DEFAULT_RULES`` und erfuellt
  ``ports.analysis.RuleProvider`` (Konformitaet rein statisch ueber mypy, Muster
  ``test_analysis_ports.py``).
* ``StaticHelpLinkResolver`` deckt GENAU die aktuellen HelpKinds mit nicht-leeren
  https-URLs ab und erfuellt ``ports.analysis.HelpLinkResolver`` (ebenfalls statisch).

KEIN ``@runtime_checkable`` an den Ports -> bewusst KEIN ``isinstance``-Check; die
Konformitaet traegt mypy, nicht die Laufzeit.
"""

from typing import get_args

from domain.analysis import DEFAULT_RULES, HelpKind
from infrastructure.analysis import BuiltinRuleProvider, StaticHelpLinkResolver
from ports.analysis import HelpLinkResolver, RuleProvider

# ── Statische Konformitaet: mypy prueft die Zuweisung an den Port-Typ ───────────


def _assert_rule_provider(_: RuleProvider) -> None: ...
def _assert_help_resolver(_: HelpLinkResolver) -> None: ...


def test_adapters_satisfy_ports_statically() -> None:
    """mypy-Beweis: beide Adapter genuegen ihrem Port (Konformitaet rein statisch)."""
    _assert_rule_provider(BuiltinRuleProvider())
    _assert_help_resolver(StaticHelpLinkResolver())


# ── BuiltinRuleProvider ─────────────────────────────────────────────────────────


def test_builtin_rule_provider_returns_default_rules() -> None:
    """``get_rules()`` liefert exakt die eingebauten ``DEFAULT_RULES``."""
    assert BuiltinRuleProvider().get_rules() == DEFAULT_RULES


# ── StaticHelpLinkResolver ──────────────────────────────────────────────────────


def test_static_help_resolver_covers_all_help_kinds() -> None:
    """Jeder aktuelle HelpKind -> nicht-leere https-URL (Tabelle deckt GENAU sie ab).

    ``HelpKind`` ist eine geschlossene Literal-Union; ein nicht modellierter Wert ist nicht
    testbar. Stattdessen pruefen wir gegen die echten Literal-Werte, dass die Tabelle GENAU
    diese abdeckt -- waechst die Union, faellt dieser Test (gewollt: neuer Kind braucht
    eine neue URL).
    """
    resolver = StaticHelpLinkResolver()
    kinds = get_args(HelpKind.__value__)
    assert set(kinds) == {
        "process_suspicious_path",
        "process_masquerade",
        "remote_access_port",
        "high_connection_count",
        "new_host",
        "many_high_ports",
        "backdoor_port",
    }
    for kind in kinds:
        url = resolver.resolve(kind)
        assert url.startswith("https://"), f"{kind!r} liefert keine https-URL: {url!r}"
