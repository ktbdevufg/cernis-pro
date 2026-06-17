"""Tests fuer ``_severity_for_host`` / ``_observed_host`` (Composition Root, ADR 0029).

``_severity_for_host`` bewertet EINEN Live-Host (Achse B) gegen die konfigurierten
Regeln und liefert die hoechste Auffaelligkeit (``"critical"``/``"notable"``) oder
``None`` (nur ``"info"``/keine Host-Befunde). Geprueft mit einem ECHTEN
``AnalyzeSnapshot`` ueber einem Fake-``RuleProvider`` (festes ``Rule``-Tuple) und dem
zustandslosen ``StaticHelpLinkResolver`` -- so laeuft die echte Engine, nur die Regeln
sind kontrolliert.

Wie die uebrigen wiring-Tests werden die privaten app-Funktionen direkt aus ``app``
importiert.
"""

from app import _observed_host, _severity_for_host
from application.analysis import AnalyzeSnapshot
from domain.analysis.rules import Rule
from domain.scanning import EnrichedHost, PortInfo
from infrastructure.analysis import StaticHelpLinkResolver


class _FakeRuleProvider:
    """Innerer ``RuleProvider`` mit festem Regel-Tuple (erfuellt den Port strukturell)."""

    def __init__(self, rules: tuple[Rule, ...]) -> None:
        self._rules = rules

    def get_rules(self) -> tuple[Rule, ...]:
        return self._rules


def _analyze(*rules: Rule) -> AnalyzeSnapshot:
    return AnalyzeSnapshot(_FakeRuleProvider(rules), StaticHelpLinkResolver())


def _host(ip: str = "192.168.1.10", *ports: int) -> EnrichedHost:
    return EnrichedHost(
        ip=ip,
        mac="AA:BB:CC:DD:EE:01",
        ports=tuple(PortInfo(port=p, state="open", service="") for p in ports),
    )


def _host_rule(rule_id: str, severity: str, ports: frozenset[int]) -> Rule:
    """Eine ``host_remote_port``-Regel mit kontrollierter Severity + Portmenge."""
    return Rule(
        id=rule_id,
        severity=severity,  # type: ignore[arg-type]
        help_kind="remote_access_port",
        kind="host_remote_port",
        title=f"Regel {rule_id}",
        detail_template="{subject} -- {value}",
        ports=ports,
    )


def test_no_rules_yields_none() -> None:
    """Keine Regeln -> keine Befunde -> None."""
    assert _severity_for_host(_host("192.168.1.10", 22), True, _analyze()) is None


def test_only_info_finding_yields_none() -> None:
    """Eine info-Host-Regel trifft -> ist KEINE Achse-B-Auffaelligkeit -> None."""
    rule = _host_rule("info_rule", "info", frozenset({22}))
    assert _severity_for_host(_host("192.168.1.10", 22), True, _analyze(rule)) is None


def test_notable_finding_yields_notable() -> None:
    notable = _host_rule("notable_rule", "notable", frozenset({3389}))
    assert _severity_for_host(_host("192.168.1.10", 3389), True, _analyze(notable)) == "notable"


def test_critical_finding_yields_critical() -> None:
    critical = _host_rule("critical_rule", "critical", frozenset({4444}))
    assert _severity_for_host(_host("192.168.1.10", 4444), True, _analyze(critical)) == "critical"


def test_highest_severity_wins() -> None:
    """Treffen mehrere Host-Regeln, gewinnt die hoechste (critical vor notable)."""
    notable = _host_rule("notable_rule", "notable", frozenset({3389}))
    critical = _host_rule("critical_rule", "critical", frozenset({4444}))
    # Host haelt BEIDE Ports offen -> beide Regeln treffen -> critical gewinnt.
    host = _host("192.168.1.10", 3389, 4444)
    assert _severity_for_host(host, True, _analyze(notable, critical)) == "critical"


def test_info_alongside_notable_does_not_lower_result() -> None:
    """info-Befund neben einem notable-Befund -> notable (info wird ignoriert, nicht gewertet)."""
    info = _host_rule("info_rule", "info", frozenset({22}))
    notable = _host_rule("notable_rule", "notable", frozenset({3389}))
    host = _host("192.168.1.10", 22, 3389)
    assert _severity_for_host(host, True, _analyze(info, notable)) == "notable"


def test_host_without_ip_is_skipped() -> None:
    """Host ohne ip -> kein bewertbares Subjekt -> None (auch wenn eine Regel passte)."""
    critical = _host_rule("critical_rule", "critical", frozenset({4444}))
    host = _host("", 4444)
    assert _severity_for_host(host, True, _analyze(critical)) is None


def test_non_host_findings_are_ignored() -> None:
    """Nur Host-Befunde (kind beginnt mit ``host_``) zaehlen fuer Achse B.

    Eine Nicht-Host-Regel (hier ``connection_remote_port``) wuerde auf dem Host-only-
    Snapshot ohnehin nicht treffen (keine connections) -- der Filter haelt das Ergebnis
    aber auch dann sauber, wenn kuenftig nicht-Host-Befunde auftauchen.
    """
    conn_rule = Rule(
        id="conn_rule",
        severity="critical",
        help_kind="remote_access_port",
        kind="connection_remote_port",
        title="Verbindungsregel",
        detail_template="{subject} -- {value}",
        ports=frozenset({4444}),
    )
    assert _severity_for_host(_host("192.168.1.10", 4444), True, _analyze(conn_rule)) is None


def test_observed_host_projects_open_ports_only() -> None:
    """``_observed_host`` nimmt nur Ports mit state=="open" und reicht is_known durch."""
    host = EnrichedHost(
        ip="192.168.1.20",
        mac="AA:BB:CC:DD:EE:02",
        hostname="box",
        vendor="ACME",
        ports=(
            PortInfo(port=22, state="open", service="ssh"),
            PortInfo(port=80, state="closed", service="http"),
        ),
    )
    observed = _observed_host(host, is_known=False)
    assert observed.ip == "192.168.1.20"
    assert observed.hostname == "box"
    assert observed.vendor == "ACME"
    assert observed.open_ports == frozenset({22})  # 80 ist closed -> raus
    assert observed.is_known is False
