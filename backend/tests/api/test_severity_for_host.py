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

from app import _flagged_ports_for_host, _observed_host, _severity_for_host
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


# ── _flagged_ports_for_host (Mengenschnitt je Stufe, ADR 0030) ────────────────


def _port_count_rule(rule_id: str, severity: str, threshold: int) -> Rule:
    """Eine anzahlbasierte ``host_port_count``-Regel (traegt NICHT zu flagged_ports bei)."""
    return Rule(
        id=rule_id,
        severity=severity,  # type: ignore[arg-type]
        help_kind="remote_access_port",
        kind="host_port_count",
        title=f"Regel {rule_id}",
        detail_template="{subject} -- {value}",
        threshold=threshold,
    )


def test_flagged_ports_empty_form_without_match() -> None:
    """Keine portbasierte Regel trifft -> leere Form, jede Stufe vorhanden."""
    notable = _host_rule("notable_rule", "notable", frozenset({3389}))
    host = _host("192.168.1.10", 22)  # 3389 nicht offen
    provider = _FakeRuleProvider((notable,))
    assert _flagged_ports_for_host(host, provider) == {"critical": [], "notable": []}


def test_flagged_ports_intersection_notable() -> None:
    """Auffaelliger offener Port -> notable-Schnitt, sortiert; nicht getroffene Ports raus."""
    notable = _host_rule("notable_rule", "notable", frozenset({22, 3389}))
    host = _host("192.168.1.10", 3389, 80)  # nur 3389 ist in der Regel-Portmenge
    provider = _FakeRuleProvider((notable,))
    assert _flagged_ports_for_host(host, provider) == {"critical": [], "notable": [3389]}


def test_flagged_ports_intersection_critical() -> None:
    """Backdoor-Port -> critical-Schnitt."""
    critical = _host_rule("critical_rule", "critical", frozenset({4444}))
    host = _host("192.168.1.10", 4444)
    provider = _FakeRuleProvider((critical,))
    assert _flagged_ports_for_host(host, provider) == {"critical": [4444], "notable": []}


def test_flagged_ports_unions_multiple_rules_same_severity() -> None:
    """Mehrere Regeln gleicher Stufe -> Union der Schnitte, sortiert."""
    a = _host_rule("a", "notable", frozenset({3389}))
    b = _host_rule("b", "notable", frozenset({5900}))
    host = _host("192.168.1.10", 3389, 5900, 22)
    provider = _FakeRuleProvider((a, b))
    assert _flagged_ports_for_host(host, provider) == {"critical": [], "notable": [3389, 5900]}


def test_flagged_ports_groups_by_severity() -> None:
    """critical und notable getrennt gruppiert."""
    notable = _host_rule("notable_rule", "notable", frozenset({3389}))
    critical = _host_rule("critical_rule", "critical", frozenset({4444}))
    host = _host("192.168.1.10", 3389, 4444)
    provider = _FakeRuleProvider((notable, critical))
    assert _flagged_ports_for_host(host, provider) == {
        "critical": [4444],
        "notable": [3389],
    }


def test_flagged_ports_only_open_ports_count() -> None:
    """Nur Ports mit state=="open" zaehlen -- dieselbe "offen"-Projektion wie _observed_host."""
    notable = _host_rule("notable_rule", "notable", frozenset({22, 80}))
    host = EnrichedHost(
        ip="192.168.1.10",
        mac="AA:BB:CC:DD:EE:01",
        ports=(
            PortInfo(port=22, state="open", service=""),
            PortInfo(port=80, state="closed", service=""),  # geschlossen -> nicht geflaggt
        ),
    )
    provider = _FakeRuleProvider((notable,))
    assert _flagged_ports_for_host(host, provider) == {"critical": [], "notable": [22]}


def test_flagged_ports_port_count_rule_does_not_contribute() -> None:
    """Eine anzahlbasierte host_port_count-Regel erzeugt KEINE flagged_ports.

    Sie traegt nur zu analysis_severity bei (kein "schuldiger" Port); flagged_ports bleibt
    leer (ADR 0030: nur host_remote_port-Regeln sind portbasiert).
    """
    count_rule = _port_count_rule("count_rule", "notable", threshold=1)
    host = _host("192.168.1.10", 22, 80, 443)  # genug Ports, dass die Regel feuert
    provider = _FakeRuleProvider((count_rule,))
    assert _flagged_ports_for_host(host, provider) == {"critical": [], "notable": []}


def test_flagged_ports_host_without_ip_is_empty() -> None:
    """Host ohne ip -> leere Form (kein bewertbares Subjekt, Linie wie _severity_for_host)."""
    critical = _host_rule("critical_rule", "critical", frozenset({4444}))
    host = _host("", 4444)
    provider = _FakeRuleProvider((critical,))
    assert _flagged_ports_for_host(host, provider) == {"critical": [], "notable": []}


def test_axis_b_consistency_critical_port_implies_critical_severity() -> None:
    """Konsistenz-Invariante (ADR 0030): flagged_ports["critical"] nicht leer

    => analysis_severity == "critical". Beide aus DEMSELBEN Provider/derselben offen-
    Projektion gebildet -- sie duerfen nicht auseinanderlaufen. Hier mit echtem Engine-Lauf
    (Severity) UND Mengenschnitt (flagged) ueber demselben Regel-Tuple geprueft.
    """
    critical = _host_rule("critical_rule", "critical", frozenset({4444}))
    notable = _host_rule("notable_rule", "notable", frozenset({3389}))
    host = _host("192.168.1.10", 4444, 3389)
    provider = _FakeRuleProvider((critical, notable))
    flagged = _flagged_ports_for_host(host, provider)
    severity = _severity_for_host(host, True, AnalyzeSnapshot(provider, StaticHelpLinkResolver()))
    assert flagged["critical"]  # nicht leer
    assert severity == "critical"  # => Host-Maximum critical (Invariante haelt)


# ── Acknowledge-Filter (ADR 0031): quittierte Ports zaehlen nicht fuer Bewertung ──


def test_acked_port_not_flagged() -> None:
    """Quittierter Port faellt aus flagged_ports raus (Bewertung reduziert)."""
    notable = _host_rule("notable_rule", "notable", frozenset({3389}))
    host = _host("192.168.1.10", 3389)
    provider = _FakeRuleProvider((notable,))
    # ohne acked: 3389 ist geflaggt; mit acked={3389}: leer.
    assert _flagged_ports_for_host(host, provider) == {"critical": [], "notable": [3389]}
    assert _flagged_ports_for_host(host, provider, frozenset({3389})) == {
        "critical": [],
        "notable": [],
    }


def test_acked_port_does_not_raise_severity() -> None:
    """Quittierter Port zaehlt nicht mehr fuer analysis_severity -> None."""
    critical = _host_rule("critical_rule", "critical", frozenset({4444}))
    host = _host("192.168.1.10", 4444)
    analyze = _analyze(critical)
    # ohne acked: critical; mit acked={4444}: keine Auffaelligkeit mehr.
    assert _severity_for_host(host, True, analyze) == "critical"
    assert _severity_for_host(host, True, analyze, frozenset({4444})) is None


def test_unacked_suspicious_port_still_fires() -> None:
    """Frage-1-B-Garantie (ADR 0031): ein NICHT-quittierter auffaelliger Port am selben

    Host loest weiter aus -- nur der quittierte Port (3306) ist still, der neue (4444) bleibt
    scharf. Port-genaue Granularitaet, nicht host-genau.
    """
    backdoor = _host_rule("backdoor", "critical", frozenset({4444}))
    db_rule = _host_rule("db", "notable", frozenset({3306}))
    host = _host("192.168.1.10", 3306, 4444)
    provider = _FakeRuleProvider((backdoor, db_rule))
    analyze = AnalyzeSnapshot(provider, StaticHelpLinkResolver())
    acked = frozenset({3306})  # nur 3306 quittiert
    flagged = _flagged_ports_for_host(host, provider, acked)
    severity = _severity_for_host(host, True, analyze, acked)
    assert flagged == {"critical": [4444], "notable": []}  # 3306 still, 4444 weiter scharf
    assert severity == "critical"  # der neue Port loest weiter aus
