"""Validierung benutzer-eigener analysis-Regeln -- reine Domaenenlogik (ADR 0002).

Benutzer duerfen spaeter (A.2) eigene ``Rule``-Objekte anlegen. BEVOR eine solche
Regel gespeichert wird, prueft ``validate_rules`` sie -- deterministisch, ohne I/O,
ohne Uhr, ohne Framework (stdlib + dataclasses + typing). Die Domaene liest dabei NIE
selbst eine Quelle: der bekannte Regel-Bestand kommt als PARAMETER herein
(Reinheit ueber Parameter-Injektion).

ZWEI GETRENNTE SEVERITY-KONZEPTE, BEWUSST NICHT VERMISCHT:

* ``Severity`` (in ``rules.py``: "info"/"notable"/"critical") bewertet eine BEOBACHTUNG
  -- wie sehr ein beobachtetes Objekt auffaellt. Wertneutral, analysis urteilt nie.
* ``IssueSeverity`` (hier: "error"/"warning") bewertet die REGEL SELBST -- ob sie
  objektiv kaputt ("error", kann nie sinnvoll feuern) oder nur redundant ("warning",
  funktioniert, ist nur unschoen) ist.

Diese beiden Konzepte werden NICHT vermischt: ein ``RuleIssue`` ist ein BEFUND ueber
eine Regel, KEIN Urteil ueber ein Beobachtungs-Objekt.

ROTE LINIE (Vision): nicht urteilen, nur strukturell pruefen. ``validate_rules`` meldet
ausschliesslich objektiv Kaputtes (error) und objektiv Redundantes (warning) -- KEINE
Geschmacksurteile darueber, ob eine Regel "sinnvoll" ist.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from domain.analysis.rules import Rule

# Bewertet die REGEL (kaputt/redundant), NICHT eine Beobachtung. BEWUSST getrennt von
# ``Severity`` ("info"/"notable"/"critical") aus rules.py: error/warning sagt etwas ueber
# die Regel, info/notable/critical sagt etwas ueber ein beobachtetes Objekt. Die zwei
# werden nie vermischt.
type IssueSeverity = Literal["error", "warning"]


@dataclass(frozen=True)
class RuleIssue:
    """Ein BEFUND ueber eine Regel -- KEIN Urteil ueber ein Beobachtungs-Objekt (frozen).

    ``severity`` ist ``IssueSeverity`` ("error"/"warning"), bewertet also die REGEL
    (kaputt bzw. redundant), nicht eine Beobachtung. ``code`` ist ein stabiler
    Maschinen-Code (z. B. "empty_ports", "duplicate"), ``message`` die menschenlesbare,
    neutrale Begruendung (Deutsch). ``rule_id`` benennt die betroffene neue Regel.
    """

    rule_id: str
    severity: IssueSeverity
    code: str
    message: str


def validate_rules(new_rules: Sequence[Rule], existing_rules: Sequence[Rule]) -> list[RuleIssue]:
    """Pruefe NEUE Regeln strukturell und auf Redundanz -- gibt Befunde als Liste zurueck.

    Geprueft werden NUR die ``new_rules``: (1) jede fuer sich strukturell (kaputte
    Parameter -> "error"), (2) gegen ``existing_rules`` UND gegen die uebrigen
    ``new_rules`` auf Duplikat/Ueberlappung (redundant -> "warning"). ``existing_rules``
    ist der bereits bekannte Bestand (Defaults + gespeicherte) und kommt als PARAMETER
    herein -- die Domaene liest NIE selbst eine Quelle.

    Befunde sind RUECKGABEWERTE, keine Exceptions: diese Funktion wirft NIE. Der Adapter
    (A.2) entscheidet, was "error"/"warning" praktisch bedeutet.

    DETERMINISMUS: das Ergebnis ist stabil sortiert nach ``(rule_id, code)``. Gleiche
    Eingabe liefert dieselbe Ausgabe. Leere Liste = alles in Ordnung.
    """
    issues: list[RuleIssue] = []

    for rule in new_rules:
        issues.extend(_structural_issues(rule))

    # Redundanz: jede neue Regel gegen Bestand UND gegen die anderen neuen Regeln.
    issues.extend(_redundancy_issues(new_rules, existing_rules))

    issues.sort(key=lambda issue: (issue.rule_id, issue.code))
    return issues


def _structural_issues(rule: Rule) -> list[RuleIssue]:
    """Strukturelle Maengel EINER Regel -> je Mangel ein "error"-RuleIssue.

    Erfasst Regeln, die NIE sinnvoll feuern koennen, weil ihre Parameter leer/unsinnig
    sind. Mehrere Maengel einer Regel ergeben mehrere Issues (je Mangel eines).
    ``kind == "process_masquerade"`` braucht keine Parameter -- dafuer keine Pruefung
    ausser id/title.
    """
    found: list[RuleIssue] = []

    if not rule.id:
        found.append(
            RuleIssue(
                rule_id=rule.id,
                severity="error",
                code="empty_id",
                message="Die Regel hat keine id.",
            )
        )
    if not rule.title:
        found.append(
            RuleIssue(
                rule_id=rule.id,
                severity="error",
                code="empty_title",
                message="Die Regel hat keinen Titel.",
            )
        )

    if rule.kind == "connection_remote_port" and not rule.ports:
        found.append(
            RuleIssue(
                rule_id=rule.id,
                severity="error",
                code="empty_ports",
                message="Die Port-Regel hat keine Ports -- sie kann nie zutreffen.",
            )
        )
    elif rule.kind == "pid_connection_count" and rule.threshold <= 0:
        found.append(
            RuleIssue(
                rule_id=rule.id,
                severity="error",
                code="non_positive_threshold",
                message="Die Verbindungszahl-Regel hat eine Schwelle <= 0 "
                "-- sie wuerde immer oder nie zutreffen.",
            )
        )
    elif rule.kind == "process_temp_path" and not rule.path_prefixes:
        found.append(
            RuleIssue(
                rule_id=rule.id,
                severity="error",
                code="empty_path_prefixes",
                message="Die Pfad-Regel hat keine Praefixe -- sie kann nie zutreffen.",
            )
        )

    return found


def _redundancy_issues(
    new_rules: Sequence[Rule], existing_rules: Sequence[Rule]
) -> list[RuleIssue]:
    """Redundanz-Befunde der neuen Regeln -> "warning"-RuleIssue.

    DUPLICATE: eine neue Regel ist parameter-aequivalent zu einer existing-Regel ODER zu
    einer anderen neuen Regel (gleiches kind UND gleiche fachliche Parameter; id/title/
    help_kind/severity zaehlen NICHT zur Aequivalenz). Bei new-vs-new wird nur das
    lexikographisch groessere id als Duplikat gemeldet -- genau EIN Issue pro Paar.

    PORT_SUBSET: eine neue connection_remote_port-Regel, deren ports-Menge eine ECHTE
    Teilmenge der ports einer existing/anderen Regel ist (alle ihre Ports schon
    abgedeckt). Bei GLEICHER Menge greift bereits "duplicate" -- daher nur echte Teilmenge.
    """
    found: list[RuleIssue] = []

    for index, rule in enumerate(new_rules):
        # Duplikat gegen den Bestand: irgendeine existing-Regel ist aequivalent.
        if any(_equivalent(rule, other) for other in existing_rules):
            found.append(_duplicate_issue(rule.id))
        else:
            # Duplikat gegen andere neue Regeln: nur melden, wenn diese Regel das
            # lexikographisch GROESSERE id im Paar haelt -> genau ein Issue pro Paar.
            duplicate_of_smaller_new = any(
                _equivalent(rule, other.rule) and other.rule.id < rule.id
                for other in _enumerate_others(new_rules, index)
            )
            if duplicate_of_smaller_new:
                found.append(_duplicate_issue(rule.id))

        # Echte Teilmenge gegen Bestand ODER andere neue Regel.
        if rule.kind == "connection_remote_port" and rule.ports:
            covered = any(_proper_port_subset(rule, other) for other in existing_rules) or any(
                _proper_port_subset(rule, other.rule)
                for other in _enumerate_others(new_rules, index)
            )
            if covered:
                found.append(
                    RuleIssue(
                        rule_id=rule.id,
                        severity="warning",
                        code="port_subset_of_existing",
                        message="Alle Ports dieser Regel sind bereits von einer "
                        "anderen Regel abgedeckt.",
                    )
                )

    return found


@dataclass(frozen=True)
class _Enumerated:
    """Eine neue Regel mit ihrem Index -- Helfer fuer new-vs-new-Vergleiche."""

    index: int
    rule: Rule


def _enumerate_others(new_rules: Sequence[Rule], skip_index: int) -> list[_Enumerated]:
    """Alle neuen Regeln ausser der an ``skip_index`` -- als (index, rule)-Paare."""
    return [
        _Enumerated(index=other_index, rule=other)
        for other_index, other in enumerate(new_rules)
        if other_index != skip_index
    ]


def _duplicate_issue(rule_id: str) -> RuleIssue:
    """Ein "duplicate"-RuleIssue fuer die gegebene Regel-id."""
    return RuleIssue(
        rule_id=rule_id,
        severity="warning",
        code="duplicate",
        message="Eine Regel mit denselben fachlichen Parametern existiert bereits.",
    )


def _equivalent(left: Rule, right: Rule) -> bool:
    """Parameter-Aequivalenz zweier Regeln -- gleiches kind UND gleiche Fachparameter.

    id/title/help_kind/severity zaehlen NICHT: zwei Regeln, die dasselbe pruefen, sind
    redundant, auch wenn sie anders heissen. Verglichen werden je nach ``kind`` die
    fachlich relevanten Parameter (ports / threshold / path_prefixes). Eine Regel ist
    NICHT zu sich selbst aequivalent zu pruefen -- das stellen die Aufrufer sicher.
    """
    if left.kind != right.kind:
        return False

    if left.kind == "connection_remote_port":
        return left.ports == right.ports
    if left.kind == "pid_connection_count":
        return left.threshold == right.threshold
    if left.kind == "process_temp_path":
        return set(left.path_prefixes) == set(right.path_prefixes)
    # process_masquerade braucht keine Parameter -- gleiches kind genuegt.
    return True


def _proper_port_subset(candidate: Rule, other: Rule) -> bool:
    """Sind ``candidate``s Ports eine ECHTE Teilmenge der Ports von ``other``?

    Nur fuer ``connection_remote_port``-Regeln sinnvoll. ECHTE Teilmenge (``<``): bei
    GLEICHER Menge ist es ein Duplikat, kein Subset -- so vermeiden wir doppelte Meldung.
    """
    if other.kind != "connection_remote_port":
        return False
    return candidate.ports < other.ports
