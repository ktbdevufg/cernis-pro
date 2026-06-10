"""Tests des AnalyzeSnapshot-Use-Case gegen In-Memory-Fakes der Ports.

Keine echten Adapter -- wir testen gegen die Protocols (``RuleProvider``/
``HelpLinkResolver``). Kern der Behauptungen: ``AnalyzeSnapshot`` holt die Regeln genau
einmal, wertet den Snapshot ueber die reine Domaene aus, behaelt die deterministische
Reihenfolge bei und buendelt je Beobachtung die vom Resolver gelieferte Hilfe-URL --
ohne die domain-Observation zu veraendern. Synchron (kein I/O -> kein async).
"""

from typing import ClassVar

from application.analysis import AnalyzeSnapshot, ResolvedObservation
from domain.analysis import (
    DEFAULT_RULES,
    HelpKind,
    ObservedConnection,
    ObservedProcess,
    Rule,
    Snapshot,
    evaluate,
)

# ── In-Memory-Fakes der Ports ────────────────────────────────────────────────


class FakeRuleProvider:
    """Liefert eine kontrollierte Regelliste und zaehlt die Aufrufe."""

    def __init__(self, rules: tuple[Rule, ...] = DEFAULT_RULES) -> None:
        self._rules = rules
        self.calls = 0

    def get_rules(self) -> tuple[Rule, ...]:
        self.calls += 1
        return self._rules


class FakeHelpLinkResolver:
    """Bildet HelpKind -> Test-URL ab; unbekannter Kind -> "" (Leer-Zustand)."""

    _URLS: ClassVar[dict[str, str]] = {
        "process_suspicious_path": "https://help.test/process-path",
        "remote_access_port": "https://help.test/remote-access",
        # "high_connection_count" BEWUSST nicht hinterlegt -> "" testen.
    }

    def resolve(self, help_kind: HelpKind) -> str:
        return self._URLS.get(help_kind, "")


# ── Helfer ──────────────────────────────────────────────────────────────────


def _conn(
    *,
    pid: int | None = None,
    remote_ip: str | None = None,
    remote_port: int | None = None,
) -> ObservedConnection:
    return ObservedConnection(
        app_name="app",
        pid=pid,
        remote_ip=remote_ip,
        remote_port=remote_port,
        l4="tcp",
        status="ESTABLISHED",
    )


# ── Tests ────────────────────────────────────────────────────────────────────


def test_leerer_snapshot_liefert_leere_liste() -> None:
    uc = AnalyzeSnapshot(rules=FakeRuleProvider(), help_links=FakeHelpLinkResolver())
    assert uc(Snapshot()) == []


def test_get_rules_genau_einmal_aufgerufen() -> None:
    provider = FakeRuleProvider()
    uc = AnalyzeSnapshot(rules=provider, help_links=FakeHelpLinkResolver())
    uc(Snapshot())
    assert provider.calls == 1


def test_observation_um_passende_help_url_angereichert() -> None:
    # remote_access_port-Treffer -> bekannte URL.
    snap = Snapshot(connections=(_conn(remote_ip="1.2.3.4", remote_port=5900),))
    uc = AnalyzeSnapshot(rules=FakeRuleProvider(), help_links=FakeHelpLinkResolver())
    result = uc(snap)
    assert len(result) == 1
    assert isinstance(result[0], ResolvedObservation)
    assert result[0].observation.help_kind == "remote_access_port"
    assert result[0].help_url == "https://help.test/remote-access"


def test_unbekannter_help_kind_liefert_leere_url() -> None:
    # high_connection_count ist im Fake-Resolver NICHT hinterlegt -> "".
    conns = tuple(_conn(pid=7, remote_ip="9.9.9.9", remote_port=443) for _ in range(51))
    snap = Snapshot(connections=conns)
    uc = AnalyzeSnapshot(rules=FakeRuleProvider(), help_links=FakeHelpLinkResolver())
    result = [r for r in uc(snap) if r.observation.help_kind == "high_connection_count"]
    assert len(result) == 1
    assert result[0].help_url == ""


def test_reihenfolge_bleibt_deterministisch_wie_evaluate() -> None:
    # Mischung aus allen drei Regeln -> Reihenfolge identisch zu evaluate (nicht umsortiert).
    many = tuple(_conn(pid=42, remote_ip="9.9.9.9", remote_port=443) for _ in range(51))
    snap = Snapshot(
        processes=(ObservedProcess(pid=2, name="x", exe_path="/tmp/a"),),
        connections=(_conn(remote_ip="8.8.8.8", remote_port=3389), *many),
    )
    uc = AnalyzeSnapshot(rules=FakeRuleProvider(), help_links=FakeHelpLinkResolver())
    result = uc(snap)
    expected = evaluate(snap, DEFAULT_RULES)
    assert [r.observation for r in result] == expected


def test_domain_observation_unveraendert() -> None:
    # Vertrag: die eingebettete Observation ist wertgleich zu der von evaluate --
    # der Use-Case veraendert die domain-Observation NICHT (domain bleibt URL-frei).
    snap = Snapshot(connections=(_conn(remote_ip="1.2.3.4", remote_port=22),))
    uc = AnalyzeSnapshot(rules=FakeRuleProvider(), help_links=FakeHelpLinkResolver())
    result = uc(snap)
    expected = evaluate(snap, DEFAULT_RULES)
    assert len(result) == 1
    assert result[0].observation == expected[0]
