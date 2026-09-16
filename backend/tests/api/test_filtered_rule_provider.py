"""Tests fuer den Filter-Wrapper ``_FilteredRuleProvider`` (Composition Root, ADR 0023).

``_FilteredRuleProvider`` sitzt im Composition Root VOR dem ``_CompositeRuleProvider``
und entfernt per Settings deaktivierte Regel-IDs aus dem inneren Provider. Geprueft wird
das defensive Lese-Verhalten der Deaktivierungs-Liste (Settings-Key
``analysis_disabled_rules``):

* fehlender Key / Nicht-Listen-Wert -> "nichts deaktiviert" (alle Regeln bleiben),
* gemischte Listen -> nur String-IDs filtern,
* kaputtes JSON in der DB -> fail-safe "alle Regeln an" (kein Crash, S3-konform).

``_FilteredRuleProvider`` ist eine private app-Klasse und wird -- wie in den uebrigen
wiring-Tests (``test_analysis_wiring.py``) -- direkt aus ``app`` importiert. Als innerer
Provider dient ein Fake mit festem ``Rule``-Tuple; als Settings-Quelle der ECHTE
``SqliteSettingsRepository`` auf einer ``tmp_path``-DB, damit der Test auch das echte
Decode-/CorruptSettingError-Verhalten abdeckt (Roh-Wert direkt in die Tabelle wie in
``test_settings_repository.py``).
"""

import sqlite3
from pathlib import Path

import pytest

from app import _DISABLED_RULES_KEY, _CompositeRuleProvider, _FilteredRuleProvider
from domain.analysis.rules import Rule
from domain.settings import Setting
from infrastructure.settings_repository import SqliteSettingsRepository


def _rule(rule_id: str) -> Rule:
    """Minimal gueltige ``Rule`` (Pflichtfelder wie in test_analysis_engine.py)."""
    return Rule(
        id=rule_id,
        severity="info",
        help_kind="new_host",
        kind="host_new",
        title=f"Regel {rule_id}",
        detail_template="{subject} -- {value}",
    )


# Festes Tuple mehrerer Regeln mit unterschiedlichen IDs -- der Fake-Inner liefert es
# unveraendert; die Tests pruefen, WAS davon durch den Filter kommt.
_RULES: tuple[Rule, ...] = (
    _rule("alpha"),
    _rule("beta"),
    _rule("gamma"),
)


class _FakeInnerProvider(_CompositeRuleProvider):
    """Innerer ``RuleProvider`` mit festem Regel-Tuple (Stelle des Composite).

    Erbt von ``_CompositeRuleProvider`` (wie ``_HistoryKnowsX(_FakeHostHistoryRepo)``
    in test_analysis_wiring.py), damit der statische ``inner``-Typ von
    ``_FilteredRuleProvider`` erfuellt ist; ``get_rules`` ist ueberschrieben und liefert
    das feste Tuple ohne echte Sub-Provider."""

    def __init__(self) -> None:
        super().__init__()  # keine Sub-Provider -- get_rules ist ueberschrieben

    def get_rules(self) -> tuple[Rule, ...]:
        return _RULES


@pytest.fixture
def settings_repo(tmp_path: Path) -> SqliteSettingsRepository:
    """Frisches, echtes Settings-Repository gegen eine temporaere DB."""
    return SqliteSettingsRepository(tmp_path / "cernis.db")


def _ids(rules: tuple[Rule, ...]) -> list[str]:
    return [r.id for r in rules]


def _insert_raw(db_path: Path, key: str, raw_value: str) -> None:
    """Schiebt einen Nicht-JSON-Rohwert direkt in die settings-Tabelle (umgeht den
    Adapter), um kaputtes JSON in der DB zu simulieren -- Muster aus
    test_settings_repository.py."""
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("INSERT INTO settings (key, value) VALUES (?, ?)", (key, raw_value))
        conn.commit()
    finally:
        conn.close()


# ── 1. Kein Key gesetzt -> alle Rules kommen durch ────────────────────────────


def test_no_key_passes_all_rules_in_order(settings_repo: SqliteSettingsRepository) -> None:
    provider = _FilteredRuleProvider(_FakeInnerProvider(), settings_repo)
    # Frische DB ohne Key -> nichts deaktiviert, Reihenfolge unveraendert.
    assert _ids(provider.get_rules()) == ["alpha", "beta", "gamma"]


# ── 2. Genau eine vorhandene rule_id deaktiviert -> diese fehlt, Rest unveraendert ──


def test_single_known_id_is_filtered_rest_unchanged(
    settings_repo: SqliteSettingsRepository,
) -> None:
    settings_repo.set(Setting(key=_DISABLED_RULES_KEY, value=["beta"]))
    provider = _FilteredRuleProvider(_FakeInnerProvider(), settings_repo)
    assert _ids(provider.get_rules()) == ["alpha", "gamma"]


# ── 3. Unbekannte rule_id -> kein Effekt ──────────────────────────────────────


def test_unknown_id_has_no_effect(settings_repo: SqliteSettingsRepository) -> None:
    settings_repo.set(Setting(key=_DISABLED_RULES_KEY, value=["existiert_nicht"]))
    provider = _FilteredRuleProvider(_FakeInnerProvider(), settings_repo)
    assert _ids(provider.get_rules()) == ["alpha", "beta", "gamma"]


# ── 4. Nicht-Listen-Wert -> Leer-Zustand, alle Rules bleiben ──────────────────


@pytest.mark.parametrize("non_list_value", [{"a": 1}, 42, "beta", True])
def test_non_list_value_keeps_all_rules(
    settings_repo: SqliteSettingsRepository, non_list_value: object
) -> None:
    # dict, int, String, bool -- keiner ist eine Liste -> "nichts deaktiviert".
    settings_repo.set(Setting(key=_DISABLED_RULES_KEY, value=non_list_value))  # type: ignore[arg-type]
    provider = _FilteredRuleProvider(_FakeInnerProvider(), settings_repo)
    assert _ids(provider.get_rules()) == ["alpha", "beta", "gamma"]


# ── 5. Gemischte Liste (Strings + Zahlen) -> nur String-IDs filtern ───────────


def test_mixed_type_list_filters_only_string_ids(
    settings_repo: SqliteSettingsRepository,
) -> None:
    # "alpha" greift; die Zahl 7 ist keine rule_id und wird ignoriert (nicht gefiltert,
    # nicht gecrasht). "gamma" greift ebenfalls -> nur "beta" bleibt.
    settings_repo.set(Setting(key=_DISABLED_RULES_KEY, value=["alpha", 7, "gamma"]))
    provider = _FilteredRuleProvider(_FakeInnerProvider(), settings_repo)
    assert _ids(provider.get_rules()) == ["beta"]


# ── 6. Kaputtes JSON in der DB -> fail-safe "alle Rules" (kein Crash) ──────────


def test_corrupt_json_falls_back_to_all_rules_without_crash(
    settings_repo: SqliteSettingsRepository, tmp_path: Path
) -> None:
    # Roh-/Nicht-JSON-Wert direkt in die Tabelle -> repo.get() wirft CorruptSettingError.
    _insert_raw(tmp_path / "cernis.db", _DISABLED_RULES_KEY, "roh_plaintext")
    provider = _FilteredRuleProvider(_FakeInnerProvider(), settings_repo)

    rules = provider.get_rules()

    # Fail-safe: trotz kaputtem Wert bleiben ALLE Regeln an (kein Crash, kein Filter).
    # Der Warn-Log (``analysis_disabled_rules_corrupt``) wird hier NICHT per
    # structlog-Capture nachgewiesen: app.py konfiguriert structlog mit
    # ``cache_logger_on_first_use=True`` (infrastructure/logging.py), wodurch der
    # gecachte app-Logger sich von ``capture_logs`` nicht zuverlaessig abfangen
    # laesst. Geprueft wird daher der Verhaltens-Nachweis -- alle Rules trotz
    # kaputtem Wert; das Log-Verhalten ist in app.py belegt.
    assert _ids(rules) == ["alpha", "beta", "gamma"]
