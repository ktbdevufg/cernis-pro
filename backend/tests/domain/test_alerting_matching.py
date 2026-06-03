"""Charakterisierung der alerting-Regel-Auswahl ``select_rules_to_fire`` (Domaene).

Dieselbe Wahrheitstabelle wie der A.1-Charakterisierer (``fire_alert``), aber gegen
die REINE Funktion: kein I/O, kein Mock noetig, ``now`` als Parameter. Jede der vier
Filterstufen mit GEGENPROBE-Paar (waehlt-aus <-> waehlt-nicht-aus), plus
Cooldown-Floor ``max(threshold,60)`` und strikte ``<``-Grenze -- gleiche Schaerfe wie
A.1. Das ist der VERTRAG der Domaene; A.1 bleibt unberuehrt (testet weiter
``modules.alerting`` AS-IS, den Altcode-int-Pfad).
"""

from domain.alerting import AlertRule, select_rules_to_fire


def _rule(
    *,
    rule_id: int = 1,
    name: str = "R",
    rule_type: str = "host_down",
    target: str = "any",
    threshold: int = 60,
    notify_email: bool = False,
    notify_macos: bool = True,
    enabled: bool = True,
    last_triggered: float = 0.0,
) -> AlertRule:
    return AlertRule(
        id=rule_id,
        name=name,
        rule_type=rule_type,
        target=target,
        threshold=threshold,
        notify_email=notify_email,
        notify_macos=notify_macos,
        enabled=enabled,
        last_triggered=last_triggered,
    )


# ── erster Match (last_triggered=0.0) ─────────────────────────


def test_selects_rule_on_first_match() -> None:
    # last_triggered=0.0 -> now - 0 >> Cooldown -> waehlt aus.
    rule = _rule()
    assert select_rules_to_fire([rule], "host_down", "192.168.1.1", now=1000.0) == [rule]


def test_empty_rules_selects_nothing() -> None:
    assert select_rules_to_fire([], "host_down", "192.168.1.1", now=1000.0) == []


# ── Stufe (a) — enabled: Gegenprobe-Paar ──────────────────────


def test_enabled_rule_is_selected() -> None:
    # Gegenprobe: identische Regel, enabled=True -> ausgewaehlt.
    rule = _rule(enabled=True)
    assert select_rules_to_fire([rule], "host_down", "192.168.1.1", now=1000.0) == [rule]


def test_disabled_rule_is_not_selected() -> None:
    # Identisch, NUR enabled=False -> nicht ausgewaehlt.
    rule = _rule(enabled=False)
    assert select_rules_to_fire([rule], "host_down", "192.168.1.1", now=1000.0) == []


# ── Stufe (b) — rule_type: Gegenprobe-Paar ────────────────────


def test_matching_rule_type_is_selected() -> None:
    rule = _rule(rule_type="host_down")
    assert select_rules_to_fire([rule], "host_down", "192.168.1.1", now=1000.0) == [rule]


def test_rule_type_mismatch_is_not_selected() -> None:
    # Identisch, NUR der gefeuerte rule_type weicht ab -> nicht ausgewaehlt.
    rule = _rule(rule_type="host_down")
    assert select_rules_to_fire([rule], "new_device", "192.168.1.1", now=1000.0) == []


def test_unknown_rule_type_does_not_crash_and_matches_nothing() -> None:
    # ENTSCHEIDUNG str (nicht StrEnum): unbekannter rule_type matcht nichts, kein Crash.
    rule = _rule(rule_type="something_unknown")
    assert select_rules_to_fire([rule], "host_down", "192.168.1.1", now=1000.0) == []
    # Aber wenn das Ereignis denselben unbekannten Typ traegt, matcht es (freier str).
    assert select_rules_to_fire([rule], "something_unknown", "192.168.1.1", now=1000.0) == [rule]


# ── Stufe (c) — target: beide Richtungen ──────────────────────


def test_target_any_matches_everything() -> None:
    rule = _rule(target="any")
    assert select_rules_to_fire([rule], "host_down", "10.99.99.99", now=1000.0) == [rule]


def test_specific_target_matches_exactly() -> None:
    rule = _rule(target="192.168.1.1")
    # Falsches Ziel -> nicht ausgewaehlt.
    assert select_rules_to_fire([rule], "host_down", "192.168.1.2", now=1000.0) == []
    # Exaktes Ziel -> ausgewaehlt.
    assert select_rules_to_fire([rule], "host_down", "192.168.1.1", now=1000.0) == [rule]


# ── Stufe (d) — Cooldown: Floor + strikte <-Grenze ────────────


def test_cooldown_within_window_blocks_selection() -> None:
    # threshold=120 -> Cooldown 120s. last_triggered=1000, now=1060 (+60 < 120) -> raus.
    rule = _rule(threshold=120, last_triggered=1000.0)
    assert select_rules_to_fire([rule], "host_down", "192.168.1.1", now=1060.0) == []


def test_cooldown_after_window_allows_selection() -> None:
    # Gegenprobe: now=1121 (+121 > 120) -> wieder ausgewaehlt.
    rule = _rule(threshold=120, last_triggered=1000.0)
    assert select_rules_to_fire([rule], "host_down", "192.168.1.1", now=1121.0) == [rule]


def test_cooldown_floor_overrides_low_threshold() -> None:
    # KERN-PROBE des Floors: threshold=10, last_triggered=1000, now=1030 (+30s).
    # 30 > threshold(10), aber 30 < Floor(60) -> NICHT ausgewaehlt. Beweist
    # max(threshold,60). Bei <60 wuerde die Regel hier faelschlich gewaehlt.
    rule = _rule(threshold=10, last_triggered=1000.0)
    assert select_rules_to_fire([rule], "host_down", "192.168.1.1", now=1030.0) == []
    # +61s: jetzt > Floor(60) -> ausgewaehlt.
    assert select_rules_to_fire([rule], "host_down", "192.168.1.1", now=1061.0) == [rule]


def test_cooldown_boundary_is_strict_less_than() -> None:
    # Grenzvertrag: STRIKT <. Bei GENAU cooldown Sekunden Abstand ist 120 < 120 falsch
    # -> NICHT geblockt -> ausgewaehlt. Fixiert die <-vs-<=-Grenze.
    rule = _rule(threshold=120, last_triggered=1000.0)
    assert select_rules_to_fire([rule], "host_down", "192.168.1.1", now=1120.0) == [rule]


# ── Mehrere Regeln: Reihenfolge + selektives Filtern ──────────


def test_selects_subset_in_input_order() -> None:
    # Drei Regeln: nur die passenden in Eingangsreihenfolge.
    r1 = _rule(rule_id=1, rule_type="host_down", target="any")
    r2 = _rule(rule_id=2, rule_type="new_device", target="any")  # Typ passt nicht
    r3 = _rule(rule_id=3, rule_type="host_down", target="192.168.1.1")  # exaktes Ziel
    r4 = _rule(rule_id=4, rule_type="host_down", target="10.0.0.9")  # falsches Ziel
    selected = select_rules_to_fire([r1, r2, r3, r4], "host_down", "192.168.1.1", now=1000.0)
    assert selected == [r1, r3]
