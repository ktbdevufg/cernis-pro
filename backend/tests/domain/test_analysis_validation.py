"""Unit-Tests der analysis-Regel-Validierung -- reine Logik, kein I/O, keine Uhr.

Prueft ``validate_rules``: strukturelle Maengel (-> "error"), Redundanz (Duplikat /
echte Port-Teilmenge -> "warning"), Determinismus und stabile Sortierung nach
``(rule_id, code)``. Alle Werte kommen als Parameter herein -> rein deterministisch.

GETRENNTE SEVERITY-KONZEPTE: error/warning bewertet die REGEL, info/notable (in
rules.py) die BEOBACHTUNG -- diese Tests fassen ausschliesslich die Regel-Bewertung an.

MUTATIONSPROBEN (durchgefuehrt waehrend der Entwicklung, hier dokumentiert): Fuer die
kritischsten Vertraege wurde EINE Mutation am Domaenen-Code probiert und ROT bestaetigt,
dann zurueckgesetzt -- der Test faengt den jeweiligen Vertrag also wirklich:

* (threshold-Pruefung) In ``validation._structural_issues`` ``rule.threshold <= 0`` auf
  ``rule.threshold < 0`` verfaelscht (Off-by-one) ->
  ``test_strukturell_non_positive_threshold_bei_null`` ROT (Schwelle == 0 wuerde
  faelschlich durchgehen). Zurueckgesetzt.
* (Subset-Pruefung) In ``validation._proper_port_subset`` ``candidate.ports < other.ports``
  auf ``candidate.ports <= other.ports`` verfaelscht (echte -> beliebige Teilmenge) ->
  ``test_subset_gleiche_menge_ist_duplicate_kein_subset`` ROT (gleiche Menge wuerde
  faelschlich ZUSAETZLICH als subset gemeldet). Zurueckgesetzt.
"""

from domain.analysis import (
    DEFAULT_RULES,
    Rule,
    RuleIssue,
    validate_rules,
)

# ── Helfer ──────────────────────────────────────────────────────────────────


def _rule(
    *,
    id: str = "r",
    kind: str = "connection_remote_port",
    title: str = "Titel",
    severity: str = "notable",
    help_kind: str = "remote_access_port",
    ports: frozenset[int] | None = None,
    threshold: int = 0,
    path_prefixes: tuple[str, ...] = (),
) -> Rule:
    """Baut eine ``Rule`` mit sinnvollen Defaults -- Tests setzen nur das Relevante."""
    return Rule(
        id=id,
        severity=severity,  # type: ignore[arg-type]
        help_kind=help_kind,  # type: ignore[arg-type]
        kind=kind,  # type: ignore[arg-type]
        title=title,
        detail_template="{subject} {value}",
        ports=frozenset() if ports is None else ports,
        threshold=threshold,
        path_prefixes=path_prefixes,
    )


def _codes(issues: list[RuleIssue]) -> list[str]:
    return [issue.code for issue in issues]


# ── Strukturell: ein error-Fall pro code ────────────────────────────────────


def test_strukturell_empty_ports() -> None:
    issues = validate_rules([_rule(kind="connection_remote_port", ports=frozenset())], [])
    assert _codes(issues) == ["empty_ports"]
    assert issues[0].severity == "error"


def test_strukturell_non_positive_threshold_bei_null() -> None:
    # MUTATIONSPROBE: "<= 0" -> "< 0" verfaelscht macht genau diesen Test ROT.
    rule = _rule(
        id="cnt",
        kind="pid_connection_count",
        help_kind="high_connection_count",
        severity="info",
        threshold=0,
    )
    issues = validate_rules([rule], [])
    assert _codes(issues) == ["non_positive_threshold"]
    assert issues[0].severity == "error"


def test_strukturell_empty_path_prefixes() -> None:
    rule = _rule(
        id="tmp",
        kind="process_temp_path",
        help_kind="process_suspicious_path",
        path_prefixes=(),
    )
    issues = validate_rules([rule], [])
    assert _codes(issues) == ["empty_path_prefixes"]
    assert issues[0].severity == "error"


def test_strukturell_empty_title() -> None:
    rule = _rule(id="hat-id", title="", ports=frozenset({22}))
    issues = validate_rules([rule], [])
    assert _codes(issues) == ["empty_title"]
    assert issues[0].severity == "error"


def test_strukturell_empty_id() -> None:
    rule = _rule(id="", ports=frozenset({22}))
    issues = validate_rules([rule], [])
    assert _codes(issues) == ["empty_id"]
    assert issues[0].severity == "error"


def test_strukturell_gueltige_regel_kein_error() -> None:
    rule = _rule(id="ok", ports=frozenset({4711}))
    assert validate_rules([rule], []) == []


def test_mehrere_maengel_einer_regel_mehrere_issues() -> None:
    # Leere id UND leerer Titel UND leere Ports -> drei Issues.
    rule = _rule(id="", title="", kind="connection_remote_port", ports=frozenset())
    issues = validate_rules([rule], [])
    assert _codes(issues) == ["empty_id", "empty_ports", "empty_title"]
    assert all(issue.severity == "error" for issue in issues)


# ── Redundanz: Duplikat ─────────────────────────────────────────────────────


def test_duplicate_gegen_existing_default() -> None:
    # remote_access_port aus DEFAULT_RULES nutzt {22, 3389, 5800, 5900}. Eine neue Regel
    # mit gleicher Portmenge (aber anderer id/title) ist parameter-aequivalent.
    new = _rule(
        id="meine-ports", title="Andere Beschreibung", ports=frozenset({22, 3389, 5800, 5900})
    )
    issues = validate_rules([new], DEFAULT_RULES)
    assert _codes(issues) == ["duplicate"]
    assert issues[0].severity == "warning"
    assert issues[0].rule_id == "meine-ports"


def test_duplicate_new_vs_new_nur_ein_issue_groesseres_id() -> None:
    a = _rule(id="aaa", ports=frozenset({1234}))
    b = _rule(id="bbb", ports=frozenset({1234}))
    issues = validate_rules([a, b], [])
    # Genau EIN duplicate, fuer das lexikographisch groessere id "bbb".
    assert _codes(issues) == ["duplicate"]
    assert issues[0].rule_id == "bbb"


def test_aequivalenz_ignoriert_id_und_title() -> None:
    # Gleiche Parameter, andere id/title/help_kind/severity -> trotzdem Duplikat.
    existing = _rule(id="alt", title="Alt", severity="info", ports=frozenset({9000}))
    new = _rule(id="neu", title="Neu", severity="notable", ports=frozenset({9000}))
    issues = validate_rules([new], [existing])
    assert _codes(issues) == ["duplicate"]


# ── Redundanz: Port-Subset ──────────────────────────────────────────────────


def test_port_subset_echte_teilmenge() -> None:
    existing = _rule(id="alt", ports=frozenset({22, 3389, 5900}))
    new = _rule(id="neu", ports=frozenset({22}))
    issues = validate_rules([new], [existing])
    assert _codes(issues) == ["port_subset_of_existing"]
    assert issues[0].severity == "warning"


def test_subset_gleiche_menge_ist_duplicate_kein_subset() -> None:
    # MUTATIONSPROBE: "<" -> "<=" in _proper_port_subset macht genau diesen Test ROT
    # (gleiche Menge wuerde dann zusaetzlich faelschlich als subset gemeldet).
    existing = _rule(id="alt", ports=frozenset({22, 3389, 5900}))
    new = _rule(id="neu", ports=frozenset({22, 3389, 5900}))
    issues = validate_rules([new], [existing])
    assert _codes(issues) == ["duplicate"]


# ── Randfaelle & Determinismus ──────────────────────────────────────────────


def test_leere_eingabe() -> None:
    assert validate_rules((), ()) == []
    assert validate_rules((), DEFAULT_RULES) == []


def test_saubere_neue_regel_kein_issue() -> None:
    # Frische Portmenge, nicht in DEFAULT_RULES, keine Teilmenge davon.
    new = _rule(id="frisch", ports=frozenset({12345, 23456}))
    assert validate_rules([new], DEFAULT_RULES) == []


def test_determinismus_zweimal_identisch() -> None:
    a = _rule(id="aaa", ports=frozenset({1234}))
    b = _rule(id="bbb", ports=frozenset({1234}))
    first = validate_rules([a, b], DEFAULT_RULES)
    second = validate_rules([a, b], DEFAULT_RULES)
    assert first == second


def test_sortierung_nach_rule_id_und_code() -> None:
    # Eine Regel mit mehreren Maengeln und eine zweite Regel: die Liste muss
    # nach (rule_id, code) sortiert sein.
    kaputt = _rule(id="zzz", title="", kind="connection_remote_port", ports=frozenset())
    auch = _rule(id="aaa", title="", ports=frozenset({4711}))
    issues = validate_rules([kaputt, auch], [])
    keys = [(issue.rule_id, issue.code) for issue in issues]
    assert keys == sorted(keys)
    # Konkret: "aaa"/empty_title zuerst, dann die beiden "zzz"-Codes alphabetisch.
    assert keys == [("aaa", "empty_title"), ("zzz", "empty_ports"), ("zzz", "empty_title")]
