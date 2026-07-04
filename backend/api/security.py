"""FastAPI-Router der security-Domaene (v2) -- ARP-Guard + drei Inspektoren.

Aeusserer Ring: nimmt HTTP entgegen, ruft NUR Use-Cases aus ``application/`` (import-
linter: api -> application). Konkrete Adapter/Ports/domain-Typen werden NICHT importiert
(Verdrahtung im Composition Root ``app.py``); die SEC.3-Result-/Record-Typen werden ueber
Attribut-Zugriff (Typ ``Any``) zu JSON serialisiert -- Muster scanning ``_host_to_dict`` /
alerting ``_rule_to_dict``.

Endpunkte = die vom Frontend WIRKLICH genutzten (F der Lesung):
* ``POST   /api/security/arp-scan``      -> {alerts:[...], count}  (SecurityView)
* ``GET    /api/security/arp-alerts``    -> list[alert-dict]       (SecurityView)
* ``GET    /api/security/arp-baseline``  -> list[baseline-dict]    (SecurityView)
* ``DELETE /api/security/arp-baseline``  -> {ok:true}              (SecurityView)
* ``POST   /api/cve/lookup-v2``          -> CVE-Liste, severity-sortiert (ReportView)
* ``POST   /api/tls/inspect-host``       -> list[tls-dict]         (HostDetail)
* ``POST   /api/security/default-creds`` -> list[cred-dict]        (HostDetail)

BEWUSST WEGGELASSEN (tote Endpunkte, vom Frontend NIE gerufen -- F der Lesung):
* ``POST /api/cve/lookup`` (v1) -- ReportView nutzt nur ``lookup-v2``.
* ``POST /api/tls/inspect`` (single) -- HostDetail nutzt nur ``inspect-host``.
Sie fehlen bewusst (404). API-Vertrag darf in v2 brechen (CLAUDE.md); kein Konsument.

Wire-Form altcode-treu (das Frontend liest sie ungeaendert):
* arp-alerts: ArpAlertRecord -> dict MIT ``datetime`` (SecurityView rendert es), OHNE
  ``id`` (bewusste Streichung, Frontend liest es nie -- s. ArpAlertRecord).
* arp-baseline: ArpBaselineRecord -> dict mit ``first_seen``/``last_seen`` (epoch-float,
  SecurityView rendert sie als Datum).
* cve/lookup-v2: CVE-Liste OHNE ``is_public``/``risk_level`` (DF3/E.6 -- toter Risk-Pfad).
  Request nimmt NUR ``ports``; ``external_ip``/``port_forwards`` werden IGNORIERT (das
  Frontend schickt ``external_ip`` mit, braucht es aber nicht -> nicht crashen).
* tls/inspect-host: ``san``/``warnings`` als JSON-LIST (tuple->list am Rand; Wire-treu).

KEINE alerting-Naht: ARP-Alerts feuern KEINE alerting-Regeln (DF1, latente Naht als
Notiz dokumentiert -- arp_guard ``new_device`` / alerting ``RULE_TYPE_NEW_DEVICE``).
"""

from collections.abc import Callable
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from application.security import (
    CheckDefaultCreds,
    ClearArpBaseline,
    GetArpAlerts,
    GetArpBaseline,
    InspectTls,
    LookupCves,
    RunArpScan,
)

router = APIRouter(tags=["security"])


# ── Dependency-Marker (im Composition Root per dependency_overrides verdrahtet) ──


def provide_run_arp_scan() -> RunArpScan:
    raise NotImplementedError("provide_run_arp_scan nicht verdrahtet (app.py)")


def provide_get_arp_alerts() -> GetArpAlerts:
    raise NotImplementedError("provide_get_arp_alerts nicht verdrahtet (app.py)")


def provide_get_arp_baseline() -> GetArpBaseline:
    raise NotImplementedError("provide_get_arp_baseline nicht verdrahtet (app.py)")


def provide_clear_arp_baseline() -> ClearArpBaseline:
    raise NotImplementedError("provide_clear_arp_baseline nicht verdrahtet (app.py)")


def provide_lookup_cves() -> LookupCves:
    raise NotImplementedError("provide_lookup_cves nicht verdrahtet (app.py)")


def provide_inspect_tls() -> InspectTls:
    raise NotImplementedError("provide_inspect_tls nicht verdrahtet (app.py)")


def provide_check_default_creds() -> CheckDefaultCreds:
    raise NotImplementedError("provide_check_default_creds nicht verdrahtet (app.py)")


# Ziel-Bereichs-Pruefung (default-creds): Callable[[str], bool] -- ``True`` = privates
# Netz. Liegt im infrastructure-Ring (net_scope.is_private_target); der api-Ring darf
# infrastructure NICHT importieren, darum als dependency-Marker injiziert (Verdrahtung
# im Composition Root app.py, Regel 5). Muster: reines Pruef-Callable am api-Rand.
def provide_target_scope_guard() -> Callable[[str], bool]:
    raise NotImplementedError("provide_target_scope_guard nicht verdrahtet (app.py)")


# ── Body-Modelle (kein rohes Body(dict) -- B008; Hausmuster api/alerting) ──────


class CveLookupBody(BaseModel):
    """CVE-Lookup-Request. NUR ``ports`` wird verarbeitet; ``external_ip``/
    ``port_forwards`` sind toter Risk-Pfad (DF3/E.6) -- als optionale Felder akzeptiert
    (das Frontend schickt ``external_ip`` mit), aber IGNORIERT."""

    ports: list[dict[str, Any]] = []
    external_ip: str = ""  # ignoriert (toter Pfad)
    port_forwards: list[int] = []  # ignoriert (toter Pfad)


class TlsInspectBody(BaseModel):
    host: str = ""
    ports: list[dict[str, Any]] = []


class DefaultCredsBody(BaseModel):
    host: str = ""
    ports: list[dict[str, Any]] = []
    vendor: str = ""


class ArmBody(BaseModel):
    """POST /api/security/default-creds/arm -- schaltet die Sonderfunktion sitzungsweit."""

    armed: bool = False


# ── Rand-Serializer (dataclass -> dict via Attribut-Zugriff, Typ Any) ──────────


def _alert_to_dict(a: Any) -> dict[str, Any]:
    # ArpAlertRecord -> Altcode-get_arp_alerts-dict OHNE id, MIT ts/datetime.
    return {
        "alert_type": a.alert_type,
        "ip": a.ip,
        "old_mac": a.old_mac,
        "new_mac": a.new_mac,
        "old_vendor": a.old_vendor,
        "new_vendor": a.new_vendor,
        "severity": a.severity,
        "message": a.message,
        "ts": a.ts,
        "datetime": a.datetime,
    }


def _baseline_to_dict(b: Any) -> dict[str, Any]:
    # ArpBaselineRecord -> Altcode-get_arp_baseline-dict.
    return {
        "ip": b.ip,
        "mac": b.mac,
        "vendor": b.vendor,
        "first_seen": b.first_seen,
        "last_seen": b.last_seen,
    }


def _cve_to_dict(c: Any) -> dict[str, Any]:
    # CveFinding -> dict. OHNE is_public/risk_level (DF3/E.6 -- toter Risk-Pfad).
    return {
        "cve_id": c.cve_id,
        "description": c.description,
        "severity": c.severity,
        "cvss_score": c.cvss_score,
        "published": c.published,
        "port": c.port,
        "service": c.service,
        "url": c.url,
    }


def _cert_to_dict(cert: Any) -> dict[str, Any] | None:
    if cert is None:
        return None
    return {
        "subject": cert.subject,
        "issuer": cert.issuer,
        "san": list(cert.san),  # tuple -> JSON-list (Wire-treu)
        "not_before": cert.not_before,
        "not_after": cert.not_after,
        "days_remaining": cert.days_remaining,
        "is_expired": cert.is_expired,
        "is_self_signed": cert.is_self_signed,
        "serial": cert.serial,
    }


def _tls_to_dict(t: Any) -> dict[str, Any]:
    return {
        "host": t.host,
        "port": t.port,
        "reachable": t.reachable,
        "tls_version": t.tls_version,
        "cipher_name": t.cipher_name,
        "cipher_bits": t.cipher_bits,
        "cert": _cert_to_dict(t.cert),
        "grade": t.grade,
        "warnings": list(t.warnings),  # tuple -> JSON-list (Wire-treu)
        "error": t.error,
    }


def _cred_to_dict(c: Any) -> dict[str, Any]:
    return {
        "host": c.host,
        "port": c.port,
        "service": c.service,
        "username": c.username,
        "password": c.password,
        "success": c.success,
        "method": c.method,
        "note": c.note,
    }


# Hinweis zur ports-Eingabe: die Inspektor-Use-Cases (LookupCves/InspectTls/
# CheckDefaultCreds) nehmen die ROHEN ``list[dict]`` ({port, service}) und wandeln
# intern in ``PortQuery`` -- so muss der api-Ring den ports-Typ ``PortQuery`` NICHT
# importieren (Muster: typisierte Eingabe wird unterhalb von api gebaut, wie
# ``ws_scan._build_config`` ``ScanConfig`` aus dict baut, nur hier im Use-Case statt
# Composition Root, weil es eine reine Datenwandlung ohne I/O ist).


# ── ARP-Routen ─────────────────────────────────────────────────────────────


@router.post("/api/security/arp-scan")
async def api_arp_scan(
    run_arp_scan: Annotated[RunArpScan, Depends(provide_run_arp_scan)],
) -> dict[str, Any]:
    alerts = await run_arp_scan()
    # RunArpScan gibt ArpAlert (Domaenentyp, ohne Zeit) -- die Scan-Response zeigt die
    # frisch erkannten Alerts. SecurityView verwirft die Response und pollt arp-alerts
    # neu; die Form bleibt trotzdem treu ({alerts, count}). Die ts/datetime fehlen hier
    # (Domaenentyp), das ist altcode-abweichend -> wir bauen die Form aus dem, was da ist.
    return {
        "alerts": [_scan_alert_to_dict(a) for a in alerts],
        "count": len(alerts),
    }


def _scan_alert_to_dict(a: Any) -> dict[str, Any]:
    # ArpAlert (Domaenentyp, OHNE Zeit) -> dict fuer die arp-scan-Response. Da der frisch
    # erkannte Alert noch keine persistierte Zeit hat, traegt die Scan-Response keine
    # ts/datetime (SecurityView nutzt die Scan-Response ohnehin nicht -- es pollt
    # arp-alerts, das die Zeit aus der DB hat).
    return {
        "alert_type": a.alert_type,
        "ip": a.ip,
        "old_mac": a.old_mac,
        "new_mac": a.new_mac,
        "old_vendor": a.old_vendor,
        "new_vendor": a.new_vendor,
        "severity": a.severity,
        "message": a.message,
    }


@router.get("/api/security/arp-alerts")
def api_arp_alerts(
    get_arp_alerts: Annotated[GetArpAlerts, Depends(provide_get_arp_alerts)],
    limit: int = Query(default=50, ge=1, le=500),
) -> list[dict[str, Any]]:
    return [_alert_to_dict(a) for a in get_arp_alerts(limit)]


@router.get("/api/security/arp-baseline")
def api_arp_baseline(
    get_arp_baseline: Annotated[GetArpBaseline, Depends(provide_get_arp_baseline)],
) -> list[dict[str, Any]]:
    return [_baseline_to_dict(b) for b in get_arp_baseline()]


@router.delete("/api/security/arp-baseline")
def api_clear_arp_baseline(
    clear_arp_baseline: Annotated[ClearArpBaseline, Depends(provide_clear_arp_baseline)],
) -> dict[str, bool]:
    clear_arp_baseline()
    return {"ok": True}


# ── Inspektor-Routen ───────────────────────────────────────────────────────


@router.post("/api/cve/lookup-v2")
async def api_cve_lookup_v2(
    body: CveLookupBody,
    lookup_cves: Annotated[LookupCves, Depends(provide_lookup_cves)],
) -> list[dict[str, Any]]:
    # external_ip/port_forwards aus dem Body werden IGNORIERT (toter Risk-Pfad DF3/E.6).
    findings = await lookup_cves(body.ports)
    return [_cve_to_dict(c) for c in findings]


@router.post("/api/tls/inspect-host")
async def api_tls_inspect_host(
    body: TlsInspectBody,
    inspect_tls: Annotated[InspectTls, Depends(provide_inspect_tls)],
) -> list[dict[str, Any]]:
    findings = await inspect_tls(body.host, body.ports)
    return [_tls_to_dict(t) for t in findings]


@router.post("/api/security/default-creds")
async def api_default_creds(
    request: Request,
    body: DefaultCredsBody,
    check_default_creds: Annotated[CheckDefaultCreds, Depends(provide_check_default_creds)],
    is_private_target: Annotated[Callable[[str], bool], Depends(provide_target_scope_guard)],
) -> Any:
    # Arm-Guard: die intrusive Sonderfunktion laeuft NUR, wenn sie fuer diese Sitzung
    # freigeschaltet ist (Laufzeit-Flag am app.state, Muster capture/traffic; kein
    # Use-Case). Nicht freigeschaltet -> 403 (Muster capture.py JSONResponse 403).
    if getattr(request.app.state, "default_creds_armed", False) is not True:
        return JSONResponse(
            status_code=403,
            content={
                "ok": False,
                "error": "Standardpasswort-Pruefung ist fuer diese Sitzung nicht freigeschaltet.",
            },
        )
    # Private-Netz-Guard: nur Ziele im eigenen, privaten Netz. Die Pruefung liegt im
    # infrastructure-Ring (net_scope) und kommt per dependency herein -- der api-Ring
    # importiert infrastructure NICHT direkt (Verdrahtung app.py, Regel 5).
    if is_private_target(body.host) is False:
        return JSONResponse(
            status_code=403,
            content={
                "ok": False,
                "error": "Nur Ziele im eigenen, privaten Netz sind zulaessig.",
            },
        )
    findings = await check_default_creds(body.host, body.ports, body.vendor)
    return [_cred_to_dict(c) for c in findings]


# ── default-creds Arm/State (Laufzeit-Flag am api-Rand, KEINE Domaenenlogik) ──
# Reines sitzungsweites Opt-in-Flag am ``app.state`` (Muster capture/traffic). Nicht
# persistent (Startwert False im Composition Root), kein Use-Case, kein Port.


@router.get("/api/security/default-creds/state")
def api_default_creds_state(request: Request) -> dict[str, bool]:
    return {"armed": bool(getattr(request.app.state, "default_creds_armed", False))}


@router.post("/api/security/default-creds/arm")
def api_default_creds_arm(request: Request, body: ArmBody) -> dict[str, bool]:
    request.app.state.default_creds_armed = body.armed
    return {"armed": body.armed}
