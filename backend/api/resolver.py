"""FastAPI-Router der resolver-Domaene: "wer ist die Gegenstelle?".

Aeusserer Ring: nimmt HTTP entgegen und ruft ausschliesslich den Use-Case aus
``application/`` (import-linter: api -> nur application). Konkrete Adapter und
``domain``-Typen werden hier NICHT importiert -- der Use-Case kommt per FastAPI-Dependency
herein (Verdrahtung im Composition Root ``app.py``), und das ``RemoteEndpointFacts``-
Aggregat wird ueber Attribut-Zugriff zu JSON serialisiert (Typ ``Any``, Muster
``api/diagnostics``).

* ``GET /api/resolve?ip=<ip>&port=<n optional>`` -- ``ip`` Pflicht (str), ``port`` optional
  (int, FastAPI validiert 1..65535). Liefert die Fakten ueber die Gegenstelle: jedes Feld
  als ``{value, source}`` (``source`` = der ``SourceTag``-String der liefernden Quelle),
  ``tls_cert.value`` als verschachteltes Objekt (oder ``null``), ``country_conflict`` als
  ``bool``. Jede fehlende Quelle liefert ehrlich ``value: null`` -- KEIN Fehler.

TOOL-/DATEN-FEHLT -> HTTP: Fehlt das System-Binary (``dig``) oder die Geo/ASN-CSV, wirft
der jeweilige Adapter ``infrastructure.resolver.errors.ResolverToolMissing`` bzw.
``ResolverDataMissing``. Diese infra-nahen Ausfaelle faengt ein GLOBALER
``exception_handler`` im Composition Root (``app.py``) und bildet sie auf 503 ab -- exakt
wie ``DiagnosticsToolMissing``. Der api-Ring importiert diese Exceptions bewusst NICHT
(api -> nur application); das Mapping bleibt am Composition Root.
"""

from collections.abc import Awaitable, Callable
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query

router = APIRouter(prefix="/api", tags=["resolver"])


# Composition-Root-Callable: bekommt die HTTP-Parameter (ip + optionaler port) und liefert
# das rohe ``RemoteEndpointFacts``-Aggregat (``Any``, weil der api-Ring keine domain-Typen
# kennt). Die Wire-Projektion bleibt am Rand (dieser Router) -- der Runner serialisiert NICHT.
type ResolveEndpointRunner = Callable[[str, int | None], Awaitable[Any]]


# Dependency-Marker: im Composition Root (app.py) per dependency_overrides mit dem echten
# Use-Case-Runner verdrahtet. Ohne Verdrahtung bewusst ein lauter Fehler.
def provide_resolve_endpoint() -> ResolveEndpointRunner:
    raise NotImplementedError("ResolveEndpointRunner wird in app.py verdrahtet")


def _fact_to_dict(fact: Any) -> dict[str, Any]:
    # fact ist ein domain.ResolverFact[T]; das Frontend-Paar {value, source}. ``source`` ist
    # ein domain.SourceTag (Enum) -> dessen ``.value``-String (kein domain-Import noetig).
    return {"value": fact.value, "source": fact.source.value}


def _tls_cert_to_dict(fact: Any) -> dict[str, Any]:
    # fact ist ein domain.ResolverFact[TlsCertDetails]; ``value`` ist ein TlsCertDetails
    # ODER None (kein Port / Fehlschlag). Bei None bleibt der value null; sonst die
    # anzeigbaren Cert-Felder als verschachteltes Objekt (Attribut-Zugriff, kein domain-Import).
    details = fact.value
    value: dict[str, Any] | None = None
    if details is not None:
        value = {
            "subject_cn": details.subject_cn,
            "san": list(details.san),
            "issuer": details.issuer,
            "valid_from": details.valid_from,
            "valid_until": details.valid_until,
            "serial": details.serial,
            "fingerprint_sha256": details.fingerprint_sha256,
            "self_signed": details.self_signed,
        }
    return {"value": value, "source": fact.source.value}


def _facts_to_dict(facts: Any) -> dict[str, Any]:
    # facts ist ein domain.RemoteEndpointFacts; jedes Feld als {value, source}, tls_cert
    # verschachtelt, country_conflict als reines bool (kein Fact -> kein {value, source}).
    return {
        "ptr": _fact_to_dict(facts.ptr),
        "forward_confirmed": _fact_to_dict(facts.forward_confirmed),
        "tls_cert": _tls_cert_to_dict(facts.tls_cert),
        "dyndns": _fact_to_dict(facts.dyndns),
        "org": _fact_to_dict(facts.org),
        "netname": _fact_to_dict(facts.netname),
        "net_range": _fact_to_dict(facts.net_range),
        "asn": _fact_to_dict(facts.asn),
        "asn_org": _fact_to_dict(facts.asn_org),
        "abuse_contact": _fact_to_dict(facts.abuse_contact),
        "country_rdap_net": _fact_to_dict(facts.country_rdap_net),
        "country_org_address": _fact_to_dict(facts.country_org_address),
        "country_geodb": _fact_to_dict(facts.country_geodb),
        "service_hint": _fact_to_dict(facts.service_hint),
        "banner": _fact_to_dict(facts.banner),
        "country_conflict": facts.country_conflict,
    }


@router.get("/resolve")
async def resolve_endpoint(
    ip: str,
    resolve: Annotated[ResolveEndpointRunner, Depends(provide_resolve_endpoint)],
    port: Annotated[int | None, Query(ge=1, le=65535)] = None,
) -> dict[str, Any]:
    """Faktensicht auf die Gegenstelle ``ip`` (optional fuer ``port`` mit TLS-Abruf).

    ``ip`` ist Pflicht (str); ``port`` ist optional (int, 1..65535 -- FastAPI lehnt einen
    ungueltigen Port mit 422 ab). Der Runner liefert das ``RemoteEndpointFacts``-Aggregat;
    der Router serialisiert es: jedes Feld als ``{value, source}``, ``tls_cert.value`` als
    verschachteltes Objekt (oder ``null`` ohne Port/bei Fehlschlag), ``country_conflict``
    als ``bool``. Fehlende Quellen -> ``value: null`` (kein Fehler). Fehlt ``dig`` oder die
    Geo/ASN-CSV -> 503 (globaler Handler im Composition Root).
    """
    facts = await resolve(ip, port)
    return _facts_to_dict(facts)
