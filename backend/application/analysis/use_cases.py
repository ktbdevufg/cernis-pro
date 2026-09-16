"""Use-Case der analysis-Domaene -- Snapshot auswerten + Hilfe-URLs anreichern.

Orchestriert die reine Domaene (``evaluate``) + die Ports (``RuleProvider``/
``HelpLinkResolver``). Kennt ``domain/`` und ``ports/``, NIEMALS ``infrastructure/``
(maschinell per import-linter erzwungen). Ports kommen per Constructor-Injection als
Protocol-Typ herein -- nie ein konkreter Adapter.

Der Use-Case bleibt duenn und frei von Fremd-Domaenen-Kopplung: er bekommt den fertigen
``Snapshot`` als PARAMETER herein und baut ihn NICHT selbst aus traffic/process/scanning
(diese Projektion ist Sache des Composition Root, AN.3). Hier passiert nur:
Regeln holen -> Domaene auswerten -> jede Beobachtung um ihre Hilfe-URL buendeln.
"""

from collections.abc import Sequence
from dataclasses import dataclass

from domain.analysis import Observation, Rule, RuleIssue, Snapshot, evaluate
from ports.analysis import HelpLinkResolver, RuleProvider, UserRuleStore


@dataclass(frozen=True)
class ResolvedObservation:
    """Eine Beobachtung samt aufgeloester Hilfe-URL -- die Ergebnis-Form des Use-Case.

    application darf eine eigene Ergebnis-Form definieren -- sie ist Teil des
    Use-Case-Vertrags, nicht der Domaene. Die ``domain.analysis.Observation`` bleibt
    dabei unangetastet (sie ist eingebettet, nicht kopiert/veraendert): der domain-Ring
    bleibt URL-frei (Vision 6.4 -- die URL ist Infrastruktur). ``help_url`` ist ``""``,
    wenn der Resolver fuer den ``help_kind`` nichts hinterlegt hat (Leer-Zustand).
    """

    observation: Observation
    help_url: str


class AnalyzeSnapshot:
    """Wertet einen Snapshot aus und reichert jede Beobachtung um ihre Hilfe-URL an.

    Duenn (Muster ``ListProcesses``/``ListAppTraffic``): orchestriert Domaene + Ports,
    keine Eigenlogik. Synchron -- ``evaluate`` ist rein, beide Ports sind synchrone
    In-Memory-Lookups: es gibt kein I/O, also ehrlich kein ``async``.
    """

    def __init__(self, rules: RuleProvider, help_links: HelpLinkResolver) -> None:
        self._rules = rules
        self._help_links = help_links

    def __call__(self, snapshot: Snapshot) -> list[ResolvedObservation]:
        """Regeln holen, Snapshot auswerten, je Beobachtung die Hilfe-URL anhaengen.

        Die Reihenfolge der Beobachtungen ist die von ``evaluate`` (bereits
        deterministisch sortiert) und wird NICHT umsortiert. Ein leeres
        ``evaluate``-Ergebnis -> ``[]``.
        """
        rules = self._rules.get_rules()
        observations = evaluate(snapshot, rules)
        return [
            ResolvedObservation(
                observation=obs,
                help_url=self._help_links.resolve(obs.help_kind),
            )
            for obs in observations
        ]


class AddUserRules:
    """Speichert benutzer-eigene Regeln gestuft -- duenn ueber den ``UserRuleStore``-Port.

    Kennt den Adapter NUR ueber den schmalen ``ports.analysis.UserRuleStore``-Vertrag
    (Protocol-Injektion, nie ein konkreter Adapter -- Schichtung). Der Use-Case enthaelt
    KEINE Eigenlogik: er reicht die neuen Regeln an den Store durch und gibt dessen
    ``RuleIssue``-Befunde zurueck. Die gestufte Semantik (error -> nichts gespeichert; nur
    warning -> gespeichert + warnings gemeldet) liegt im Adapter (validiert ueber die reine
    Domaenenfunktion); der api-Rand uebersetzt ``error`` in HTTP 422.

    Synchron: der Store ist ein lokaler SQLite-Zugriff ohne Loop-/Netz-I/O -- ehrlich kein
    ``async``.
    """

    def __init__(self, repo: UserRuleStore) -> None:
        self._repo = repo

    def __call__(self, new_rules: Sequence[Rule]) -> list[RuleIssue]:
        return self._repo.add_rules(new_rules)


class ListUserRules:
    """Listet die GESPEICHERTEN eigenen Regeln (ohne die Defaults) -- duenner Pass-Through.

    Der Nutzer verwaltet seine EIGENEN Regeln; die eingebauten ``DEFAULT_RULES`` sind nicht
    Teil dieser Liste (sie kommen additiv erst im Composite-Lesepfad der Engine dazu, AN-A.2).
    Synchron wie ``AddUserRules`` (lokaler SQLite-Zugriff).
    """

    def __init__(self, repo: UserRuleStore) -> None:
        self._repo = repo

    def __call__(self) -> tuple[Rule, ...]:
        return self._repo.get_rules()
