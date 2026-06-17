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
* ``GET    /api/analysis/rules/all``       -- listet ALLE aktuell aktiven Regeln (Built-in +
  User) NACH der 5a-Injektion, aber VOR dem Deaktivierungs-Filter, je Regel mit dem Feld
  ``disabled: bool`` (ADR 0028). Quelle der UI fuer den Block "Regel-An/Aus".
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
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

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


# Composition-Root-Callable fuer den Service-Lookup: Port -> gaengiger Service-Name (oder
# None). Der api-Ring kennt das domain-Mapping (``domain.analysis.service_for_port``) NICHT
# direkt (api -> nur application); das Callable wird im Composition Root verdrahtet und
# reicht den reinen Lookup herein. Synchron (reiner In-Memory-Lookup).
type ServiceLookupRunner = Callable[[int], str | None]


def provide_service_lookup() -> ServiceLookupRunner:
    raise NotImplementedError("ServiceLookupRunner wird in app.py verdrahtet")


# Composition-Root-Callable fuer das Acknowledge-Audit (ADR 0031): schreibt eine ack/unack-
# Zeile ins append-only Log (mac, port, severity, action) -> None. Der api-Ring kennt das
# Repository (``SqliteAcknowledgementRepository.record``) NICHT direkt (api -> nur
# application); das Callable wird im Composition Root verdrahtet. Synchron (lokaler
# SQLite-Schreibzugriff).
type AcknowledgeRunner = Callable[[str, int, str, str], None]


def provide_acknowledge() -> AcknowledgeRunner:
    raise NotImplementedError("AcknowledgeRunner wird in app.py verdrahtet")


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


class AcknowledgeBody(BaseModel):
    """POST /api/analysis/acknowledge -- ein Quittier-Befehl pro (mac, port) (ADR 0031).

    ``port`` wird per ``Field``-Constraint auf 1-65535 begrenzt (wie der Service-Lookup --
    KEIN stiller Fallback, S3). ``severity`` und ``action`` sind ``Literal``-Felder: ein
    anderer Wert -> HTTP 422 (pydantic-Validierung), nicht ein leiser Durchlauf. ``severity``
    haelt die Achse-B-Stufe der quittierten Auffaelligkeit ("critical"/"notable", die zwei
    Stufen aus ``app._FLAGGED_SEVERITIES``); ``action`` ist ``ack`` (quittieren, nimmt die
    Bewertung weg) oder ``unack`` (zuruecknehmen, stellt den Befund wieder scharf).
    """

    mac: str
    port: Annotated[int, Field(ge=1, le=65535)]
    severity: Literal["critical", "notable"]
    action: Literal["ack", "unack"]


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

# Composition-Root-Callable (ADR 0028): liefert ALLE aktuell aktiven Regeln (Built-in +
# User) NACH der 5a-Injektion (Schwelle/Portlisten), aber VOR dem Deaktivierungs-Filter
# -- denn die UI muss auch abgeschaltete Regeln sehen, um sie wieder einschalten zu
# koennen. Je Regel ein ``(Rule, disabled: bool)``-Paar (Rule als ``Any``, kein domain-
# Import); ``disabled`` ergibt sich aus der Settings-Liste ``analysis_disabled_rules``.
type ListAllRulesRunner = Callable[[], list[tuple[Any, bool]]]


def provide_add_user_rules() -> AddUserRulesRunner:
    raise NotImplementedError("AddUserRulesRunner wird in app.py verdrahtet")


def provide_list_user_rules() -> ListUserRulesRunner:
    raise NotImplementedError("ListUserRulesRunner wird in app.py verdrahtet")


def provide_list_all_rules() -> ListAllRulesRunner:
    raise NotImplementedError("ListAllRulesRunner wird in app.py verdrahtet")


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
        "kind": r.observation.kind,
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


@router.get("/analysis/service")
def get_service_for_port(
    lookup: Annotated[ServiceLookupRunner, Depends(provide_service_lookup)],
    port: Annotated[int, Query(ge=1, le=65535)],
) -> dict[str, Any]:
    """Reiner Lookup: Port -> gaengiger Service-Name (KEIN Setting).

    Die Einstellungs-UI (spaeterer Schnitt) zeigt zu einem eingegebenen Port sofort den
    Service-Namen. Port-Range 1-65535 wird per FastAPI-``Query``-Constraint erzwungen --
    ein Port ausserhalb -> HTTP 422 (KEIN stiller Fallback, S3). Ein gueltiger, aber nicht
    gelisteter Port -> ``{"port": N, "service": null}`` (legitimer Leer-Zustand, kein
    Fehler). Der Runner reicht den domain-Lookup herein; dieser Rand bleibt domain-frei.
    """
    return {"port": port, "service": lookup(port)}


@router.get("/analysis/rules")
def list_user_rules(
    list_rules: Annotated[ListUserRulesRunner, Depends(provide_list_user_rules)],
) -> list[dict[str, Any]]:
    """Listet die GESPEICHERTEN eigenen Regeln (ohne die eingebauten Defaults).

    Der Nutzer verwaltet seine eigenen Regeln; die Defaults sind nicht Teil dieser Liste.
    Der Runner liefert die rohen ``Rule``-Objekte; dieser Rand serialisiert sie.
    """
    return [_rule_to_dict(rule) for rule in list_rules()]


@router.get("/analysis/rules/all")
def list_all_rules(
    list_rules: Annotated[ListAllRulesRunner, Depends(provide_list_all_rules)],
) -> list[dict[str, Any]]:
    """Listet ALLE aktuell aktiven Regeln (Built-in + User) mit Toggle-Status (ADR 0028).

    Gegenstueck zu ``GET /api/analysis/rules`` (nur eigene Regeln): die Einstellungs-UI
    (Block "Regel-An/Aus") braucht GENAU die Regeln, die die Engine auswertet -- inkl. der
    eingebauten Defaults und inkl. der per Settings DEAKTIVIERTEN Regeln, sonst koennte man
    eine abgeschaltete Regel nicht wieder einschalten. Quelle ist derselbe konfigurierte
    Provider-Stack wie die Engine NACH der 5a-Injektion (Schwelle/Portlisten), aber VOR dem
    Deaktivierungs-Filter.

    Der Runner liefert ``(Rule, disabled)``-Paare; dieser Rand serialisiert jede Regel ueber
    das vorhandene ``_rule_to_dict`` und ergaenzt das Feld ``disabled`` (KEIN zweites
    Wire-Format). Eine leere Lage -> ``[]`` (kein Fehler).
    """
    return [{**_rule_to_dict(rule), "disabled": disabled} for rule, disabled in list_rules()]


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


@router.post("/analysis/acknowledge")
def acknowledge(
    body: AcknowledgeBody,
    record: Annotated[AcknowledgeRunner, Depends(provide_acknowledge)],
) -> dict[str, bool]:
    """Quittiert (oder entquittiert) einen Achse-B-Befund PORT-GENAU (ADR 0031).

    Schreibt EINE append-only Log-Zeile (ack/unack) ueber den Composition-Root-Runner; der
    effektive Status eines (mac, port) ergibt sich aus dem jeweils JUENGSTEN Eintrag. ``ack``
    nimmt die Bewertung (Pille/Faerbung) dauerhaft weg, ``unack`` stellt den Befund wieder
    scharf -- KEIN Loeschen, die History bleibt vollstaendig. Granularitaet pro (mac, port):
    ein quittierter Port betrifft nur ihn; ein neuer auffaelliger Port am selben Host loest
    weiter aus. Port-Range/severity/action werden per Body-Constraints erzwungen (Muell ->
    422). Erfolg -> 200 ``{"ok": true}``.
    """
    record(body.mac, body.port, body.severity, body.action)
    return {"ok": True}
