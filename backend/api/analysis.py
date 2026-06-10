"""FastAPI-Router der analysis-Domaene (v2, AN.3), Route ``GET /api/analysis``.

Aeusserer Ring: nimmt HTTP entgegen und ruft ausschliesslich ``application/`` (import-linter:
api -> nur application). Konkrete Adapter und ``domain``/``application``-Typen werden hier
NICHT importiert -- der Runner kommt per FastAPI-Dependency herein (Verdrahtung im Composition
Root ``app.py``), und die Ergebnis-Objekte werden ueber Attribut-Zugriff zu JSON serialisiert
(Typ ``Any``, Muster wie ``api/process._process_to_dict``).

``GET /api/analysis`` liefert die aktuellen Beobachtungen der Lage (ZEIGEN + EINORDNEN, NIE
URTEILEN). Der Runner baut den Snapshot frisch aus traffic+process (Projektion im Composition
Root), wertet ihn aus und liefert die rohen ResolvedObservation-Objekte; dieser Rand
serialisiert sie. Eine leere Lage -> ``[]`` (kein Fehler).

VERWALTUNG EIGENER REGELN (A.2) -- ``/api/analysis/rules`` (GET/POST/DELETE):

* ``GET    /api/analysis/rules``           -- listet die GESPEICHERTEN eigenen Regeln (NICHT
  die Defaults) ueber ``ListUserRules``; dieser Rand serialisiert die rohen ``Rule``-Objekte
  per Attribut-Zugriff (Typ ``Any``, kein domain-Import).
* ``POST   /api/analysis/rules``           -- nimmt eine Liste schmaler Request-DTOs
  (``UserRuleBody``, ein api-eigenes pydantic-Modell -- NICHT die ``domain.Rule``). Der
  api-Ring bleibt domain-frei: das Bauen der ``domain.Rule`` + der Aufruf von ``AddUserRules``
  passiert in einem Composition-Root-Runner (``AddUserRulesRunner``), der das DTO annimmt
  (Muster wie ``_analyze_snapshot``). Liefert der Runner einen ``error``-Issue -> HTTP 422
  mit den Issues im Body, NICHTS gespeichert. Nur ``warning`` (oder leer) -> HTTP 201 mit
  den (ggf. leeren) warnings im Body (gestuft sichtbar).
* ``DELETE /api/analysis/rules/{rule_id}`` -- loescht eine eigene Regel ueber einen
  Composition-Root-Runner (``DeleteUserRuleRunner``).
"""

from collections.abc import Awaitable, Callable
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel

router = APIRouter(prefix="/api", tags=["analysis"])


# Composition-Root-Callable: baut den Snapshot frisch, ruft AnalyzeSnapshot und liefert die
# rohen ResolvedObservation-Objekte als ``list[Any]`` -- der api-Ring kennt keine domain/
# application-Typen, daher ``Any``. Async, weil die Projektion traffic/process (async) aufruft.
type AnalyzeRunner = Callable[[], Awaitable[list[Any]]]


# Dependency-Marker: im Composition Root (app.py) per dependency_overrides mit dem echten
# Callable verdrahtet. Ohne Verdrahtung bewusst ein lauter Fehler (Muster
# provide_list_processes).
def provide_analyze() -> AnalyzeRunner:
    raise NotImplementedError("AnalyzeRunner wird in app.py verdrahtet")


# ── Verwaltung eigener Regeln (A.2) ───────────────────────────────────────────


class UserRuleBody(BaseModel):
    """POST /api/analysis/rules -- ein schmales Request-DTO je Regel (NICHT die domain.Rule).

    Der api-Ring darf ``domain`` nicht importieren -- darum dieses api-eigene Schema mit
    genau den fachlich uebergebenen Feldern. Die Pflichtfelder (id/kind/severity/help_kind/
    title/detail_template) sind Strings; die kind-spezifischen Parameter sind optional mit
    leeren Defaults (``ports``/``path_prefixes``/``threshold``). Die Uebersetzung in eine
    ``domain.Rule`` (inkl. ``frozenset(ports)``/``tuple(path_prefixes)``) macht der
    Composition-Root-Runner, nicht dieser Rand.
    """

    id: str
    kind: str
    severity: str
    help_kind: str
    title: str
    detail_template: str
    ports: list[int] = []
    path_prefixes: list[str] = []
    threshold: int = 0


# Composition-Root-Callable: bekommt die rohen Request-DTOs (``list[UserRuleBody]``), baut
# je DTO eine ``domain.Rule``, ruft ``AddUserRules`` und liefert die rohen ``RuleIssue``-
# Objekte als ``list[Any]`` zurueck -- der api-Ring kennt weder ``domain.Rule`` noch
# ``RuleIssue``, daher ``Any``. Synchron (der Store ist lokaler SQLite-Zugriff).
type AddUserRulesRunner = Callable[[list[UserRuleBody]], list[Any]]

# Composition-Root-Callable fuer das Loeschen einer eigenen Regel (Pass-Through an den Store).
type DeleteUserRuleRunner = Callable[[str], None]

# Composition-Root-Callable: liefert die gespeicherten eigenen Regeln als rohe ``Rule``-
# Objekte (``list[Any]``); dieser Rand serialisiert sie per Attribut-Zugriff.
type ListUserRulesRunner = Callable[[], list[Any]]


def provide_add_user_rules() -> AddUserRulesRunner:
    raise NotImplementedError("AddUserRulesRunner wird in app.py verdrahtet")


def provide_list_user_rules() -> ListUserRulesRunner:
    raise NotImplementedError("ListUserRulesRunner wird in app.py verdrahtet")


def provide_delete_user_rule() -> DeleteUserRuleRunner:
    raise NotImplementedError("DeleteUserRuleRunner wird in app.py verdrahtet")


def _rule_to_dict(rule: Any) -> dict[str, Any]:
    # rule ist eine domain.analysis.Rule; per Attribut-Zugriff serialisiert (kein domain-
    # Import). ports (frozenset) wird sortiert zur Liste (deterministisch), path_prefixes
    # (tuple) zur Liste.
    return {
        "id": rule.id,
        "kind": rule.kind,
        "severity": rule.severity,
        "help_kind": rule.help_kind,
        "title": rule.title,
        "detail_template": rule.detail_template,
        "ports": sorted(rule.ports),
        "path_prefixes": list(rule.path_prefixes),
        "threshold": rule.threshold,
    }


def _issue_to_dict(issue: Any) -> dict[str, Any]:
    # issue ist ein domain.analysis.RuleIssue; per Attribut-Zugriff serialisiert.
    return {
        "rule_id": issue.rule_id,
        "severity": issue.severity,
        "code": issue.code,
        "message": issue.message,
    }


def _resolved_to_dict(r: Any) -> dict[str, Any]:
    # r ist eine application.ResolvedObservation (.observation + .help_url); per
    # Attribut-Zugriff serialisiert (kein domain/application-Import). Die eingebettete
    # Observation traegt rule_id/severity/title/detail/help_kind/subject.
    return {
        "rule_id": r.observation.rule_id,
        "severity": r.observation.severity,
        "title": r.observation.title,
        "detail": r.observation.detail,
        "help_kind": r.observation.help_kind,
        "subject": r.observation.subject,
        "help_url": r.help_url,
    }


@router.get("/analysis")
async def get_analysis(
    analyze: Annotated[AnalyzeRunner, Depends(provide_analyze)],
) -> list[dict[str, Any]]:
    """Aktuelle Beobachtungen der Lage (ZEIGEN + EINORDNEN, NIE URTEILEN).

    Der Runner baut den Snapshot frisch (Projektion aus traffic+process im Composition Root),
    wertet ihn aus und liefert die rohen Beobachtungen; dieser Rand serialisiert sie ueber
    Attribut-Zugriff. Eine leere Lage -> ``[]`` (kein Fehler).
    """
    items = await analyze()
    return [_resolved_to_dict(r) for r in items]


@router.get("/analysis/rules")
def list_user_rules(
    list_rules: Annotated[ListUserRulesRunner, Depends(provide_list_user_rules)],
) -> list[dict[str, Any]]:
    """Listet die GESPEICHERTEN eigenen Regeln (ohne die eingebauten Defaults).

    Der Nutzer verwaltet seine eigenen Regeln; die Defaults sind nicht Teil dieser Liste.
    Der Runner liefert die rohen ``Rule``-Objekte; dieser Rand serialisiert sie.
    """
    return [_rule_to_dict(rule) for rule in list_rules()]


@router.post("/analysis/rules")
def add_user_rules(
    body: list[UserRuleBody],
    add_rules: Annotated[AddUserRulesRunner, Depends(provide_add_user_rules)],
) -> JSONResponse:
    """Speichert neue eigene Regeln GESTUFT (Karl-Entscheidung).

    Der Runner baut aus den DTOs ``domain.Rule``-Objekte, validiert + speichert sie ueber
    ``AddUserRules`` und liefert die ``RuleIssue``-Befunde. Enthaelt die Liste IRGENDEINEN
    ``error`` (kaputt oder ``duplicate_id``) -> HTTP 422 mit den Issues im Body, NICHTS
    gespeichert. Nur ``warning`` (oder leer) -> HTTP 201 mit den (ggf. leeren) warnings im
    Body (gestuft sichtbar).
    """
    issues = add_rules(body)
    issue_dicts = [_issue_to_dict(issue) for issue in issues]
    if any(issue.severity == "error" for issue in issues):
        return JSONResponse(status_code=422, content={"issues": issue_dicts})
    return JSONResponse(status_code=201, content={"issues": issue_dicts})


@router.delete("/analysis/rules/{rule_id}")
def delete_user_rule(
    rule_id: str,
    delete_rule: Annotated[DeleteUserRuleRunner, Depends(provide_delete_user_rule)],
) -> dict[str, bool]:
    """Loescht eine eigene Regel. Idempotent: eine unbekannte id ist kein Fehler."""
    delete_rule(rule_id)
    return {"ok": True}
