"""Tests fuer ``GET /api/analysis/rules/all`` (ADR 0028, Schnitt 5a-Nachtrag).

Der Endpunkt liefert ALLE aktuell aktiven Regeln (Built-in + User) NACH der 5a-Injektion
(Schwelle/Portlisten, ADR 0027), aber VOR dem Deaktivierungs-Filter (ADR 0023) -- jede
Regel im bestehenden Wire-Format (``_rule_to_dict``) PLUS dem Feld ``disabled: bool``. Das
Flag kommt aus derselben defensiven Lese-Quelle wie der Filter (``_read_disabled_rule_ids``).

Zwei Ebenen werden geprueft:

* Der Composition-Root-Baustein, der ``_list_all_rules`` zusammensetzt (``configured`` vor
  dem Filter + disabled-Menge), gegen ein Fake-Settings-Repo -- belegt Quelle, disabled-Flag,
  5a-Injektion und defensives Verhalten ohne echte DB.
* Der api-Rand via TestClient (verdrahteter Fake-Runner, Muster ``test_analysis_rules_api``)
  -- belegt die Serialisierung inkl. ``disabled`` und die Gegenprobe zu ``/analysis/rules``.
"""

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.analysis import (
    provide_list_all_rules,
    provide_list_user_rules,
)
from app import (
    _CompositeRuleProvider,
    _ConfiguredRuleProvider,
    _read_disabled_rule_ids,
    create_app,
)
from domain.analysis import Rule
from infrastructure.analysis import BuiltinRuleProvider
from infrastructure.config import AppConfig

from .test_analysis_configured_rules import _FakeSettings


def _all_rules_with_disabled(settings: _FakeSettings) -> list[tuple[Rule, bool]]:
    """Baut die ``_list_all_rules``-Logik aus dem Composition Root nach (ADR 0028).

    Quelle ist ``configured`` (Composite-Defaults + 5a-Injektion), bewusst OHNE den
    ``_FilteredRuleProvider`` -- die deaktivierten Regeln bleiben drin, nur mit
    ``disabled=True`` markiert. Das ``disabled``-Flag kommt aus derselben freien Funktion,
    die auch der Filter nutzt.
    """
    composite = _CompositeRuleProvider(BuiltinRuleProvider())
    configured = _ConfiguredRuleProvider(composite, settings)
    disabled = _read_disabled_rule_ids(settings)
    return [(rule, rule.id in disabled) for rule in configured.get_rules()]


# ── Composition-Root-Baustein ─────────────────────────────────────────────────


def test_liefert_builtin_regeln_nicht_nur_user() -> None:
    """Gegenprobe zu /analysis/rules: die Built-in-Defaults sind enthalten."""
    pairs = _all_rules_with_disabled(_FakeSettings())
    ids = {rule.id for rule, _ in pairs}
    # Mehrere eingebaute Regeln muessen vorkommen (kein leeres "nur User"-Set).
    assert {"host_remote_access_port", "host_many_high_ports", "host_backdoor_port"} <= ids


def test_disabled_flag_genau_fuer_gelistete_id() -> None:
    """analysis_disabled_rules gesetzt -> genau die gelistete id ist disabled=True."""
    settings = _FakeSettings({"analysis_disabled_rules": ["host_backdoor_port"]})
    pairs = _all_rules_with_disabled(settings)
    flags = {rule.id: disabled for rule, disabled in pairs}
    assert flags["host_backdoor_port"] is True
    # Alle anderen sind aktiv.
    assert all(not disabled for rule, disabled in pairs if rule.id != "host_backdoor_port")


def test_5a_injektion_sichtbar_in_der_liste() -> None:
    """analysis_suspicious_ports gesetzt -> host_remote_access_port traegt diese Ports.

    Belegt, dass die Quelle ``configured`` (nach 5a-Injektion) ist und nicht der rohe
    Composite mit den Built-in-Default-Ports.
    """
    settings = _FakeSettings({"analysis_suspicious_ports": [4444, 5555]})
    pairs = _all_rules_with_disabled(settings)
    rule = next(rule for rule, _ in pairs if rule.id == "host_remote_access_port")
    assert rule.ports == frozenset({4444, 5555})


def test_defensiv_kaputtes_disabled_json_alle_aktiv(caplog: pytest.LogCaptureFixture) -> None:
    """Kaputtes analysis_disabled_rules-JSON -> alle Regeln disabled=False (kein 500)."""
    settings = _FakeSettings(corrupt={"analysis_disabled_rules"})
    pairs = _all_rules_with_disabled(settings)
    assert pairs  # nicht leer
    assert all(not disabled for _, disabled in pairs)  # fail-safe: alles aktiv


# ── api-Rand via TestClient ───────────────────────────────────────────────────


@pytest.fixture
def app() -> Iterator[FastAPI]:
    """App mit verdrahteten Fake-Runnern fuer /rules/all und /rules (Gegenprobe).

    Der api-Ring bleibt domain-frei: der Runner liefert ``(Rule, disabled)``-Paare bzw.
    rohe ``Rule``-Objekte, das Bauen passiert hier wie im Composition Root. Eine eingebaute
    Default-Regel steht fuer beide zur Verfuegung; /rules listet aber NUR die User-Regel.
    """
    application = create_app(AppConfig())

    user_rule = Rule(
        id="my_remote",
        severity="notable",
        help_kind="remote_access_port",
        kind="connection_remote_port",
        title="Eigene Fernzugriffs-Ports",
        detail_template="Verbindung zu {subject} ({value}).",
        ports=frozenset({4444}),
    )
    builtin = next(r for r in BuiltinRuleProvider().get_rules() if r.id == "host_backdoor_port")

    # /rules/all: Built-in (disabled) + User-Regel (aktiv).
    def _all() -> list[tuple[Any, bool]]:
        return [(builtin, True), (user_rule, False)]

    application.dependency_overrides[provide_list_all_rules] = lambda: _all
    # /rules: NUR die eigene Regel (Gegenprobe -- keine Built-ins).
    application.dependency_overrides[provide_list_user_rules] = lambda: lambda: [user_rule]
    yield application


def test_endpunkt_serialisiert_disabled_feld(app: FastAPI) -> None:
    """GET /analysis/rules/all -> Wire-Format + disabled je Regel."""
    with TestClient(app) as client:
        response = client.get("/api/analysis/rules/all")
        assert response.status_code == 200
        rules = response.json()
        by_id = {rule["id"]: rule for rule in rules}

        assert by_id["host_backdoor_port"]["disabled"] is True
        assert by_id["my_remote"]["disabled"] is False
        # Bestehendes Wire-Format bleibt vollstaendig (kein zweites Format).
        assert by_id["my_remote"]["ports"] == [4444]
        assert by_id["my_remote"]["severity"] == "notable"


def test_gegenprobe_rules_nur_user(app: FastAPI) -> None:
    """/analysis/rules listet nur die User-Regel, /rules/all auch die Built-in."""
    with TestClient(app) as client:
        only_user = {rule["id"] for rule in client.get("/api/analysis/rules").json()}
        all_rules = {rule["id"] for rule in client.get("/api/analysis/rules/all").json()}

        assert only_user == {"my_remote"}
        assert "host_backdoor_port" in all_rules  # nur in /rules/all
        assert only_user < all_rules
