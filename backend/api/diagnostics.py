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
* ``GET /api/diagnostics/tools?tools=dig&tools=traceroute`` (1b) -- ``tools`` ist ein
  WIEDERHOLBARER Query-Parameter. OHNE ``tools`` werden ALLE registrierten Tools geprueft
  (Erstinstallation); MIT ``tools`` nur die genannten (Laufzeit). Liefert den ``ToolReport``
  als dict (``manager`` str|null, ``statuses[]`` {name, available}, ``install_command``
  str|null). KEINE Selbst-Installation -- nur der Befehls-TEXT (Sicherheits-Prinzip).
* ``GET /api/diagnostics/banner?target=<host>&port=<n>`` (2a) -- klopft EINMAL an den Port
  und liest die Begruessung. ``target`` Pflicht (str), ``port`` Pflicht (int, FastAPI
  validiert 1..65535). Liefert das ``BannerResult`` als dict (``target``, ``port``,
  ``probe``, ``banner`` str|null, ``state``). ``banner`` ist ehrlich ``null``, wenn nichts
  kam (kein erfundener Wert). KEINE konfigurierbaren Payloads -- nur eine minimale
  Standard-Anfrage (Sicherheits-Grenze: Diagnose, kein Byte-Sender).

* ``GET /api/diagnostics/external/ip`` (2b) -- externer IP-Check ueber einen cpnetcheck-
  konformen Dienst (Modell D). Liefert ``{configured, ip, family, error}``;
  ``configured=false`` = nicht konfiguriert (URL/Token fehlt, neutraler Hinweis, KEIN
  Aussen-Aufruf). KEINE Speicherung. Der Token wird NIE im Body ausgegeben.
* ``GET /api/diagnostics/external/ports?ports=80&ports=443`` (2b) -- externer Port-Check.
  ``ports`` ist ein wiederholbarer Pflicht-Query-Param (int, FastAPI validiert 1..65535).
  Liefert ``{configured, checked_ip, family, results:[{port,reachable,state}], error}``.
  ``configured=false`` = nicht konfiguriert (Modell D). Der Token wird NIE im Body
  ausgegeben.

* ``GET /api/diagnostics/dhcp`` (3) -- Rogue-DHCP-Erkennung: sendet EIN DHCP DISCOVER und
  sammelt die antwortenden DHCP-Server, klassifiziert gegen die erwartete Menge (Setting
  ``expected_dhcp_servers`` ODER Gateway-Fallback). Liefert ``{servers:[{ip, mac, is_
  expected}], expected:[...], has_unexpected}``. ``mac`` ist ehrlich ``null``, wenn nmap sie
  nicht ausweist. ZEIGEN+EINORDNEN ohne Urteil (``is_expected``/``has_unexpected`` sind
  Fakten). ROOT-PFLICHTIG: ohne Root wirft der Use-Case ``RogueDhcpPermissionError`` -> 403
  (globaler Handler, Muster der Tool-fehlt-/Dienst-Naht); der Probe laeuft NIE blind.
* ``GET /api/diagnostics/dhcp/permission`` (3) -- die ``{ok, error}``-Rechte-Naht
  (``CheckDhcpPermission``): ``ok=true`` = Root vorhanden, Discovery moeglich; ``ok=false`` +
  Begruendung = gesperrt (nmap fehlt ODER kein Root, KEINE rootless Alternative).

TOOL-FEHLT -> HTTP: Fehlt das System-Binary (``dig``/``traceroute``), wirft der Adapter
``infrastructure.diagnostics_linux.DiagnosticsToolMissing``. Diesen infrastruktur-nahen
Ausfall faengt ein GLOBALER ``exception_handler`` im Composition Root (``app.py``) und
bildet ihn auf 503 ab -- exakt wie ``SecretStoreUnavailableError`` (siehe ADR 0014 /
``application.diagnostics.errors``). Der api-Ring importiert die Exception bewusst NICHT
(api -> nur application); das Mapping bleibt am Composition Root.

EXTERNER-DIENST-FEHLER -> HTTP (2b): Scheitert der externe cpnetcheck-Dienst (HTTP >=400,
Netzfehler, Timeout, kaputtes JSON), wirft der Adapter
``infrastructure.diagnostics_linux.ExternalCheckFailed``. Dieser infra-nahe Ausfall wird
GENAUSO ueber einen globalen ``exception_handler`` im Composition Root auf **502** (Bad
Gateway -- externer Dienst) abgebildet (siehe ADR 0014 Block 2b /
``application.diagnostics.errors.ExternalCheckError``). Der api-Ring importiert die
Exception bewusst NICHT (api -> nur application); das Mapping bleibt am Composition Root.
NIE Token/interne Details im Fehler-Body.

ROGUE-DHCP-RECHTE -> HTTP (3): Wird ``GET /api/diagnostics/dhcp`` ohne Root angefragt
(oder fehlt ``nmap``), wirft der Use-Case ``application.diagnostics.RogueDhcpPermissionError``
-- der Probe laeuft NIE blind gegen fehlendes Root. Diesen application-Zustand bildet ein
GLOBALER ``exception_handler`` im Composition Root (``app.py``) auf **403** ab (die Discovery
ist nicht erlaubt, nicht der Dienst kaputt) -- konsistent zur Tool-fehlt-/Dienst-Naht (die
das Mapping ebenfalls am Composition Root halten). Anders als bei DNS/traceroute importiert
der api-Ring DIESE application-Exception bewusst NICHT zum Werfen; das Mapping sitzt am
Composition Root. ``CheckDhcpPermission`` (``GET /api/diagnostics/dhcp/permission``) liefert
den Rechte-Status separat als ``{ok, error}`` (kein 403, sondern ein Auskunfts-Endpunkt).
"""

from collections.abc import Awaitable, Callable
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from pydantic import Field

from application.diagnostics import CheckDhcpPermission, CheckTraceroutePermission

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
# 1b: prueft die angefragten (oder bei None alle) Tools und liefert den rohen ToolReport
# (``Any`` -- der api-Ring kennt keine domain-Typen). Synchron: reine lokale which-Checks.
type CheckToolsRunner = Callable[[list[str] | None], Any]
# 2a: klopft an target:port und liefert das rohe BannerResult (``Any`` -- der api-Ring kennt
# keine domain-Typen). Async: blockierendes Socket-I/O im Adapter ueber asyncio gekapselt.
type GrabBannerRunner = Callable[[str, int], Awaitable[Any]]
# 2b: externer Check ueber cpnetcheck. EINE Runner-Signatur mit optionaler Portliste
# (``None`` -> reiner IP-Check; Liste -> IP + Port-Check) bedient BEIDE Routen unten.
# Liefert das rohe ExternalCheckResult (``Any`` -- der api-Ring kennt keine domain-Typen).
# Async: HTTP-I/O im Adapter ueber httpx gekapselt.
type CheckExternalRunner = Callable[[list[int] | None], Awaitable[Any]]
# 3: sendet EIN DHCP DISCOVER, klassifiziert und liefert das rohe RogueDhcpResult (``Any`` --
# der api-Ring kennt keine domain-Typen). Async: blockierendes nmap im Adapter ueber
# run_in_executor gekapselt. KEINE Parameter -- die erwartete Menge zieht der Use-Case selbst.
type DetectRogueDhcpRunner = Callable[[], Awaitable[Any]]


# Dependency-Marker: im Composition Root (app.py) per dependency_overrides mit den
# echten Callables/Use-Cases verdrahtet. Ohne Verdrahtung bewusst ein lauter Fehler.
def provide_resolve_dns() -> ResolveDnsRunner:
    raise NotImplementedError("ResolveDnsRunner wird in app.py verdrahtet")


def provide_run_traceroute() -> RunTracerouteRunner:
    raise NotImplementedError("RunTracerouteRunner wird in app.py verdrahtet")


def provide_check_traceroute_permission() -> CheckTraceroutePermission:
    raise NotImplementedError("CheckTraceroutePermission wird in app.py verdrahtet")


def provide_check_tools() -> CheckToolsRunner:
    raise NotImplementedError("CheckToolsRunner wird in app.py verdrahtet")


def provide_grab_banner() -> GrabBannerRunner:
    raise NotImplementedError("GrabBannerRunner wird in app.py verdrahtet")


def provide_check_external() -> CheckExternalRunner:
    raise NotImplementedError("CheckExternalRunner wird in app.py verdrahtet")


def provide_detect_rogue_dhcp() -> DetectRogueDhcpRunner:
    raise NotImplementedError("DetectRogueDhcpRunner wird in app.py verdrahtet")


def provide_check_dhcp_permission() -> CheckDhcpPermission:
    raise NotImplementedError("CheckDhcpPermission wird in app.py verdrahtet")


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


def _tool_status_to_dict(s: Any) -> dict[str, Any]:
    # s ist ein domain.ToolStatus; per Attribut-Zugriff serialisiert (kein domain-Import).
    return {"name": s.name, "available": s.available}


def _tool_report_to_dict(report: Any) -> dict[str, Any]:
    # report ist ein domain.ToolReport; manager/install_command sind ehrlich str|None.
    return {
        "manager": report.manager,
        "statuses": [_tool_status_to_dict(status) for status in report.statuses],
        "install_command": report.install_command,
    }


def _banner_result_to_dict(result: Any) -> dict[str, Any]:
    # result ist ein domain.BannerResult; banner ist ehrlich str|None (kein erfundener Wert).
    return {
        "target": result.target,
        "port": result.port,
        "probe": result.probe,
        "banner": result.banner,
        "state": result.state,
    }


def _external_port_to_dict(p: Any) -> dict[str, Any]:
    # p ist ein domain.ExternalPortResult; per Attribut-Zugriff serialisiert.
    return {"port": p.port, "reachable": p.reachable, "state": p.state}


def _external_ip_to_dict(result: Any) -> dict[str, Any]:
    # result ist ein domain.ExternalCheckResult; IP-Sicht (2b). ``ip`` aus checked_ip --
    # ehrlich null, wenn nicht konfiguriert. ``configured``/``error`` benennen den Zustand.
    return {
        "configured": result.configured,
        "ip": result.checked_ip,
        "family": result.family,
        "error": result.error,
    }


def _external_ports_to_dict(result: Any) -> dict[str, Any]:
    # result ist ein domain.ExternalCheckResult; Port-Sicht (2b). ``results`` ist je Port
    # ein {port,reachable,state}; leer, wenn nicht konfiguriert oder reiner IP-Check.
    return {
        "configured": result.configured,
        "checked_ip": result.checked_ip,
        "family": result.family,
        "results": [_external_port_to_dict(p) for p in result.ports],
        "error": result.error,
    }


def _dhcp_server_to_dict(s: Any) -> dict[str, Any]:
    # s ist ein domain.DhcpServer; ``mac`` ist ehrlich str|None (kein erfundener Wert).
    return {"ip": s.ip, "mac": s.mac, "is_expected": s.is_expected}


def _rogue_dhcp_to_dict(result: Any) -> dict[str, Any]:
    # result ist ein domain.RogueDhcpResult; ``expected`` die zugrunde gelegte Menge (leer =
    # keine Erwartung konfiguriert), ``has_unexpected`` ein Fakt (kein Urteil).
    return {
        "servers": [_dhcp_server_to_dict(s) for s in result.servers],
        "expected": list(result.expected),
        "has_unexpected": result.has_unexpected,
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


@router.get("/tools")
def check_tools(
    check: Annotated[CheckToolsRunner, Depends(provide_check_tools)],
    tools: Annotated[list[str] | None, Query()] = None,
) -> dict[str, Any]:
    """Tool-/Paketmanager-Bericht (1b); ``tools`` ist ein optionaler wiederholbarer Param.

    OHNE ``tools`` (``None``) -> ALLE registrierten Tools pruefen (Erstinstallation); MIT
    ``tools=dig&tools=traceroute`` -> nur die genannten (Laufzeit). Der Runner liefert den
    ``ToolReport``; der Router serialisiert ihn (``manager`` str|null, ``statuses[]``,
    ``install_command`` str|null -- ehrlich ``null``, wenn nichts fehlt oder kein Manager
    bekannt ist). KEINE Selbst-Installation -- nur der Befehls-TEXT (Sicherheits-Prinzip).
    """
    report = check(tools)
    return _tool_report_to_dict(report)


@router.get("/banner")
async def grab_banner(
    target: str,
    grab: Annotated[GrabBannerRunner, Depends(provide_grab_banner)],
    port: Annotated[int, Query(ge=1, le=65535)],
) -> dict[str, Any]:
    """Banner-Grabbing (2a): klopft EINMAL an ``target:port`` und liest die Begruessung.

    ``target`` (str) und ``port`` (int, 1..65535) sind Pflicht -- FastAPI lehnt fehlendes/
    ungueltiges ``port`` selbst mit 422 ab (kein Raten). Der Runner liefert das
    ``BannerResult``; der Router serialisiert es (``target``, ``port``, ``probe``,
    ``banner`` str|null, ``state``). ``banner`` ist ehrlich ``null``, wenn nichts kam (kein
    erfundener Wert). KEINE konfigurierbaren Payloads -- nur eine minimale Standard-Anfrage.
    """
    result = await grab(target, port)
    return _banner_result_to_dict(result)


@router.get("/external/ip")
async def external_ip(
    check: Annotated[CheckExternalRunner, Depends(provide_check_external)],
) -> dict[str, Any]:
    """Externer IP-Check (2b): die aus Sicht des cpnetcheck-Diensts oeffentliche IP.

    Ruft den Runner OHNE Ports (reiner IP-Check). Liefert ``{configured, ip, family,
    error}``: ``configured=false`` heisst "nicht konfiguriert" (URL/Token fehlt) -> ``ip``/
    ``family`` ``null``, ``error`` traegt den neutralen Hinweis (KEIN Aufruf nach aussen,
    Modell D). Bei einem Dienstfehler wirft der Adapter -> 502 (globaler Handler). Der Token
    wird NIE im Body ausgegeben.
    """
    result = await check(None)
    return _external_ip_to_dict(result)


@router.get("/external/ports")
async def external_ports(
    check: Annotated[CheckExternalRunner, Depends(provide_check_external)],
    ports: Annotated[list[Annotated[int, Field(ge=1, le=65535)]], Query()],
) -> dict[str, Any]:
    """Externer Port-Check (2b): sind die Ports von aussen erreichbar?

    ``ports`` ist ein wiederholbarer Pflicht-Query-Param (``?ports=80&ports=443``); FastAPI
    validiert JEDEN Wert als int im Bereich 1..65535 (Item-level ``Field(ge/le)`` -- ein
    Constraint direkt auf ``list[int]`` wuerde gegen die ganze Liste pruefen; ungueltig ->
    422). Der Runner reicht die Ports an den Use-Case (der dedupt/begrenzt client-seitig).
    Liefert ``{configured,
    checked_ip, family, results:[{port,reachable,state}], error}``: ``configured=false`` ->
    nicht konfiguriert (neutraler Hinweis, kein Aussen-Aufruf). Dienstfehler -> 502
    (globaler Handler). Der Token wird NIE im Body ausgegeben.
    """
    result = await check(ports)
    return _external_ports_to_dict(result)


@router.get("/dhcp")
async def detect_rogue_dhcp(
    detect: Annotated[DetectRogueDhcpRunner, Depends(provide_detect_rogue_dhcp)],
) -> dict[str, Any]:
    """Rogue-DHCP-Erkennung (3): EIN DHCP DISCOVER, antwortende Server klassifizieren.

    Keine Parameter -- die erwartete Menge zieht der Use-Case selbst (Setting
    ``expected_dhcp_servers`` ODER Gateway-Fallback). Der Runner liefert das
    ``RogueDhcpResult``; der Router serialisiert es (``servers[]`` {ip, mac str|null,
    is_expected}, ``expected[]``, ``has_unexpected``). ``mac`` ist ehrlich ``null``, wenn
    nmap sie nicht ausweist. ZEIGEN+EINORDNEN ohne Urteil. ROOT-PFLICHTIG: ohne Root (oder
    fehlt nmap) -> 403 (globaler Handler ``RogueDhcpPermissionError``); der Probe laeuft NIE
    blind gegen fehlendes Root.
    """
    result = await detect()
    return _rogue_dhcp_to_dict(result)


@router.get("/dhcp/permission")
def get_dhcp_permission(
    check_permission_uc: Annotated[CheckDhcpPermission, Depends(provide_check_dhcp_permission)],
) -> dict[str, Any]:
    """Rechte-Status fuer die Rogue-DHCP-Erkennung (3).

    ``{ok, error}``-Form: ``ok=true`` = Root vorhanden, Discovery moeglich; ``ok=false`` +
    Begruendung = gesperrt (``nmap`` fehlt ODER kein Root -- Rogue-DHCP braucht Root, KEINE
    rootless Alternative). Auskunfts-Endpunkt (kein 403 -- das ist die Daten-Route ``/dhcp``).
    """
    return check_permission_uc()
