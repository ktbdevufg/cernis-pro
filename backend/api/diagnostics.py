"""FastAPI-Router der diagnostics-Domaene (1a): DNS + traceroute (+ Rechte-Naht).

Aeusserer Ring: nimmt HTTP entgegen und ruft ausschliesslich die Use-Cases/Runner aus
``application/`` (import-linter: api -> nur application). Konkrete Adapter und
``domain``-Typen werden hier NICHT importiert -- die Runner kommen per FastAPI-Dependency
herein (Verdrahtung im Composition Root ``app.py``), und die Domaenen-Objekte werden ueber
Attribut-Zugriff zu JSON serialisiert (Typ ``Any``, Muster ``api/process``).

* ``GET /api/diagnostics/dns?query=<host>&types=A&types=AAAA&...`` -- ``types`` ist ein
  WIEDERHOLBARER Query-Parameter (Liste); ohne Angabe der Default ``["A","AAAA","PTR"]``.
  Liefert das ``DnsResult`` als dict (``query``, ``requested_types``, ``records[]``).
* ``GET /api/diagnostics/traceroute?target=<host>&privileged=true|false`` -- ``privileged``
  ist ein PFLICHT-Bool (bewusste Nutzerwahl, kein Default-Raten -- wie ``view`` bei
  processes). Liefert das ``TracerouteResult`` als dict.
* ``GET /api/diagnostics/traceroute/permission`` -- die ``{ok, error}``-Rechte-Naht
  (``CheckTraceroutePermission``): ``ok=true`` = privilegierte (genauere) Methode moeglich.

TOOL-FEHLT -> HTTP: Fehlt das System-Binary (``dig``/``traceroute``), wirft der Adapter
``infrastructure.diagnostics_linux.DiagnosticsToolMissing``. Diesen infrastruktur-nahen
Ausfall faengt ein GLOBALER ``exception_handler`` im Composition Root (``app.py``) und
bildet ihn auf 503 ab -- exakt wie ``SecretStoreUnavailableError`` (siehe ADR 0014 /
``application.diagnostics.errors``). Der api-Ring importiert die Exception bewusst NICHT
(api -> nur application); das Mapping bleibt am Composition Root.
"""

from collections.abc import Awaitable, Callable
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query

from application.diagnostics import CheckTraceroutePermission

router = APIRouter(prefix="/api/diagnostics", tags=["diagnostics"])

# Default-Record-Typen, wenn der Nutzer keinen ``types``-Query-Parameter angibt (A/AAAA/
# PTR -- die ueblichen Vorwaerts-/Rueckwaertsfragen). Auf Modulebene statt als Literal im
# Funktionskopf -- ein mutabler Default direkt in der Signatur waere B006; eine benannte
# Modul-Konstante ist der Default des wiederholbaren ``Query``-Parameters und wird nie
# mutiert (FastAPI kopiert pro Request).
_DEFAULT_DNS_TYPES: list[str] = ["A", "AAAA", "PTR"]


# Composition-Root-Callables: bekommen die HTTP-Parameter und liefern das rohe
# Domaenen-Objekt (``Any``, weil der api-Ring keine domain-Typen kennt). Die Wire-
# Projektion bleibt am Rand (dieser Router) -- die Runner serialisieren NICHT.
type ResolveDnsRunner = Callable[[str, list[str]], Awaitable[Any]]
type RunTracerouteRunner = Callable[[str, bool], Awaitable[Any]]


# Dependency-Marker: im Composition Root (app.py) per dependency_overrides mit den
# echten Callables/Use-Cases verdrahtet. Ohne Verdrahtung bewusst ein lauter Fehler.
def provide_resolve_dns() -> ResolveDnsRunner:
    raise NotImplementedError("ResolveDnsRunner wird in app.py verdrahtet")


def provide_run_traceroute() -> RunTracerouteRunner:
    raise NotImplementedError("RunTracerouteRunner wird in app.py verdrahtet")


def provide_check_traceroute_permission() -> CheckTraceroutePermission:
    raise NotImplementedError("CheckTraceroutePermission wird in app.py verdrahtet")


def _record_to_dict(r: Any) -> dict[str, Any]:
    # r ist ein domain.DnsRecord; per Attribut-Zugriff serialisiert (kein domain-Import).
    return {"record_type": r.record_type, "value": r.value}


def _dns_result_to_dict(result: Any) -> dict[str, Any]:
    # result ist ein domain.DnsResult; requested_types/records als Listen serialisiert.
    return {
        "query": result.query,
        "requested_types": list(result.requested_types),
        "records": [_record_to_dict(rec) for rec in result.records],
    }


def _hop_to_dict(h: Any) -> dict[str, Any]:
    # h ist ein domain.TracerouteHop; ein nicht-antwortender Hop hat address/rtt_ms null.
    return {"hop": h.hop, "address": h.address, "rtt_ms": h.rtt_ms}


def _traceroute_result_to_dict(result: Any) -> dict[str, Any]:
    # result ist ein domain.TracerouteResult; hops als Liste serialisiert.
    return {
        "target": result.target,
        "privileged": result.privileged,
        "hops": [_hop_to_dict(hop) for hop in result.hops],
    }


@router.get("/dns")
async def resolve_dns(
    query: str,
    resolve: Annotated[ResolveDnsRunner, Depends(provide_resolve_dns)],
    types: Annotated[list[str], Query()] = _DEFAULT_DNS_TYPES,
) -> dict[str, Any]:
    """DNS-Aufloesung fuer ``query`` ueber die angefragten ``types``.

    ``types`` ist ein wiederholbarer Query-Parameter (``?types=A&types=AAAA``); ohne
    Angabe gilt der Default ``["A","AAAA","PTR"]``. Der Runner liefert das ``DnsResult``;
    der Router serialisiert es (``query``, ``requested_types``, ``records[]``). Keine
    Antwort -> ``records`` leer (kein Fehler). Fehlt ``dig`` -> 503 (globaler Handler).
    """
    result = await resolve(query, types)
    return _dns_result_to_dict(result)


@router.get("/traceroute")
async def run_traceroute(
    target: str,
    privileged: bool,
    run: Annotated[RunTracerouteRunner, Depends(provide_run_traceroute)],
) -> dict[str, Any]:
    """Pfad-Messung zu ``target``; ``privileged`` ist PFLICHT (bewusste Nutzerwahl).

    ``privileged=true`` waehlt die genauere (Root-)Methode, ``false`` die unprivilegierte
    -- FastAPI lehnt fehlendes/ungueltiges ``privileged`` selbst mit 422 ab (kein Raten,
    wie ``view`` bei processes). Nicht-antwortende Hops erscheinen als ``null``-Luecke.
    Fehlt ``traceroute`` -> 503 (globaler Handler).
    """
    result = await run(target, privileged)
    return _traceroute_result_to_dict(result)


@router.get("/traceroute/permission")
def get_traceroute_permission(
    check_permission_uc: Annotated[
        CheckTraceroutePermission, Depends(provide_check_traceroute_permission)
    ],
) -> dict[str, Any]:
    """Rechte-Status fuer die genauere traceroute-Methode.

    ``{ok, error}``-Form: ``ok=true`` = die privilegierte (genauere) Methode ist moeglich
    (Root); ``ok=false`` + Begruendung = nur die unprivilegierte (ungenauere) Methode.
    """
    return check_permission_uc()
