"""Die analysis-Domaene: Snapshot, Regeln-als-Daten und die RuleEngine.

analysis ist die interpretierende Domaene -- sie nimmt einen neutralen Schnappschuss
der Lage (``Snapshot``), laesst eine RuleEngine deklarative Regeln (``Rule``,
``DEFAULT_RULES``) darueber laufen und produziert wertneutrale Beobachtungen
(``Observation``) mit zugeordnetem Hilfe-Typ. ZEIGEN + EINORDNEN, NIE URTEILEN.
"""

from domain.analysis.engine import evaluate
from domain.analysis.models import (
    ObservedConnection,
    ObservedHost,
    ObservedProcess,
    Snapshot,
)
from domain.analysis.rules import (
    DEFAULT_RULES,
    HelpKind,
    Observation,
    Rule,
    RuleKind,
    Severity,
)

__all__ = [
    "DEFAULT_RULES",
    "HelpKind",
    "Observation",
    "ObservedConnection",
    "ObservedHost",
    "ObservedProcess",
    "Rule",
    "RuleKind",
    "Severity",
    "Snapshot",
    "evaluate",
]
