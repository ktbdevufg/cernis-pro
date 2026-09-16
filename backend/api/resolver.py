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

import ipaddress
from collections.abc import Awaitable, Callable
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field, field_validator

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


# ── Batch-PTR (Paket 5): nur der reverse-DNS-Name zu MEHREREN IPs ──────────────
# Eine schlanke, lokale Sicht fuer die Verkehrsliste -- NUR der PTR-Name pro IP, ohne die
# teure Mehrfach-Aufloesung (RDAP/TLS/Geo) von GET /api/resolve. Eigener Runner, eigener
# Marker (Muster oben): der Use-Case kommt per FastAPI-Dependency herein, im Composition
# Root verdrahtet. KEIN domain-/infrastructure-Import im api-Ring.

# Obergrenze IPs pro Batch-Call: die teure Mehrfach-Aufloesung entfaellt zwar, aber ein
# Batch loest je IP einen DNS-Lookup aus -- 256 deckt eine /24-Verkehrsliste ab und
# deckelt die Nebenlaeufigkeit. Mehr -> 422 (Validierung unten).
_MAX_BATCH_IPS = 256

# Runner: nimmt das Tuple der angefragten IPs und liefert die {ip: name_or_none}-Map
# (``Any``-Werte sind hier ``str | None``; der api-Ring kennt keine domain-Typen, aber die
# Map ist ein reiner dict -> direkt JSON-serialisierbar, keine Projektion noetig).
type ResolvePtrBatchRunner = Callable[[tuple[str, ...]], Awaitable[dict[str, str | None]]]


# Dependency-Marker: im Composition Root (app.py) per dependency_overrides mit dem echten
# Use-Case verdrahtet. Ohne Verdrahtung bewusst ein lauter Fehler (Muster oben).
def provide_resolve_ptr_batch() -> ResolvePtrBatchRunner:
    raise NotImplementedError("ResolvePtrBatchRunner wird in app.py verdrahtet")


class ResolvePtrBatchBody(BaseModel):
    """POST /api/resolve/ptr -- die angefragten IPs als schmales Request-DTO.

    Validierung (Auftrag, ungueltige Eingabe -> 422 ueber pydantic):

    * ``ips``: mindestens 1, hoechstens ``_MAX_BATCH_IPS`` Eintraege
      (``Field(min_length/max_length)``, Muster ``Field`` im api-Ring wie diagnostics).
    * jeder Eintrag muss eine gueltige IP-Adresse sein -- ueber stdlib ``ipaddress`` im
      ``field_validator`` geprueft (reine Eingabevalidierung im api-Ring, KEIN
      domain-Import). Ein ungueltiges Literal loest einen ValueError -> 422 aus.
    """

    ips: list[str] = Field(min_length=1, max_length=_MAX_BATCH_IPS)

    @field_validator("ips")
    @classmethod
    def _alle_ips_gueltig(cls, ips: list[str]) -> list[str]:
        for candidate in ips:
            try:
                ipaddress.ip_address(candidate)
            except ValueError as exc:
                raise ValueError(f"ungueltige IP-Adresse: {candidate!r}") from exc
        return ips


@router.post("/resolve/ptr")
async def resolve_ptr_batch(
    body: ResolvePtrBatchBody,
    resolve_ptr: Annotated[ResolvePtrBatchRunner, Depends(provide_resolve_ptr_batch)],
) -> dict[str, str | None]:
    """Batch-Reverse-DNS: liefert ``{ip: ptr_name_or_null}`` fuer die angefragten IPs.

    Schlanke, lokale Sicht fuer die Verkehrsliste -- NUR der PTR-Name, nicht die reiche
    Faktensicht von ``GET /api/resolve``. Der Body validiert die IPs (1..``_MAX_BATCH_IPS``,
    jede ein gueltiges IP-Literal -> sonst 422). Jede angefragte IP erscheint als
    Schluessel; ein leerer PTR (kein Name) ist ehrlich ``null``. Der Use-Case dedupliziert,
    cacht (TTL) und loest nebenlaeufig auf. Fehlt ``dig`` -> 503 (globaler Handler im
    Composition Root, derselbe wie bei ``GET /api/resolve``).
    """
    return await resolve_ptr(tuple(body.ips))
