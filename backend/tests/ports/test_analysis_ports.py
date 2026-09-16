"""Strukturtest der analysis-Ports (AN.2): Fakes erfuellen die Protocols.

Reine ``typing.Protocol``-Vertraege haben kein Verhalten -- der Verhaltenstest kommt mit
den Adaptern (AN.3+). Hier wird NUR die strukturelle Konformitaet geprueft, im Muster von
``test_scanning_ports.py``:

* **statisch (mypy):** Jede ``_assert_*``-Funktion nimmt den Port-TYP als Parameter und
  bekommt die Fake-Instanz uebergeben. Erfuellt ein Fake das Protocol nicht (falsche
  Signatur, fehlende Methode), schlaegt ``uv run mypy`` fehl -- das ist die eigentliche
  Pruefung.
* **dynamisch (pytest):** Ein minimaler Smoke ruft jede Methode einmal auf und prueft,
  dass die erwarteten (synchronen) Rueckgaben herauskommen.

KEIN ``@runtime_checkable`` an den Ports -> bewusst KEIN ``isinstance``-Check fuer die
Konformitaet; die traegt mypy, nicht die Laufzeit.
"""

from pathlib import Path

from domain.analysis import DEFAULT_RULES, HelpKind, Rule
from infrastructure.analysis_rules_db import SqliteUserRuleRepository
from ports.analysis import HelpLinkResolver, RuleProvider, UserRuleStore

# ── Fakes: minimale, vertragstreue Implementierungen ────────────────────────


class _FakeRuleProvider:
    def get_rules(self) -> tuple[Rule, ...]:
        return DEFAULT_RULES


class _FakeHelpLinkResolver:
    def resolve(self, help_kind: HelpKind) -> str:
        if help_kind == "remote_access_port":
            return "https://example.test/remote-access"
        return ""  # unbekannt -> Leer-Zustand, kein Fehler


# ── Statische Konformitaet: mypy prueft die Zuweisung an den Port-Typ ───────


def _assert_rule_provider(_: RuleProvider) -> None: ...
def _assert_help_resolver(_: HelpLinkResolver) -> None: ...
def _assert_user_rule_store(_: UserRuleStore) -> None: ...


def test_fakes_satisfy_ports_statically() -> None:
    """mypy-Beweis: jeder Fake genuegt seinem Port (Konformitaet rein statisch)."""
    _assert_rule_provider(_FakeRuleProvider())
    _assert_help_resolver(_FakeHelpLinkResolver())


def test_db_adapter_satisfies_user_rule_store_statically(tmp_path: Path) -> None:
    """mypy-Beweis: der SQLite-Adapter erfuellt den UserRuleStore-Verwaltungs-Port (A.2)."""
    _assert_user_rule_store(SqliteUserRuleRepository(tmp_path / "cernis.db"))


# ── Dynamischer Smoke: Methoden synchron aufrufbar, erwartete Typen ─────────


def test_rule_provider_is_sync_and_returns_rules() -> None:
    provider: RuleProvider = _FakeRuleProvider()
    rules = provider.get_rules()
    assert rules == DEFAULT_RULES
    assert all(isinstance(r, Rule) for r in rules)


def test_help_resolver_is_sync_and_resolves() -> None:
    resolver: HelpLinkResolver = _FakeHelpLinkResolver()
    assert resolver.resolve("remote_access_port").startswith("https://")
    # Unbekannter/nicht hinterlegter Kind -> "" (Leer-Zustand, kein Fehler).
    assert resolver.resolve("high_connection_count") == ""
