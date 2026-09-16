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

from collections.abc import Awaitable, Callable
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


# ── Standardzugangs-Redesign Etappe C: Composition-Root-Callable-Runner ──────
#
# Muster analysis.py (``AddUserRulesRunner``/``AnalyzeRunner``): der api-Ring bleibt
# domain-frei -- das Bauen der ``domain.DefaultCredsEintrag`` aus dem Body-DTO und der
# Aufruf der Use-Cases (mit Repos/Adaptern) passiert im Composition-Root-Runner, nicht
# hier. Die Ergebnis-Objekte (DefaultCredsEintrag/PruefPlan/PruefHistorie*/CredFinding)
# werden ueber Attribut-Zugriff (Typ ``Any``) zu JSON serialisiert. Jeder Marker wirft
# bis zur Verdrahtung bewusst laut (Muster ``provide_analyze``).


# Liefert alle Standardzugangs-Eintraege als rohe ``DefaultCredsEintrag`` (``list[Any]``);
# dieser Rand serialisiert sie per Attribut-Zugriff (Muster ``ListUserRulesRunner``).
type ListDefaultCredsRunner = Callable[[], list[Any]]

# Legt einen neuen Eintrag an: baut die ``domain.DefaultCredsEintrag`` aus dem DTO und ruft
# ``AddDefaultCredsEintrag``. Ein Validierungsfehler aus dem Store ist ein ``ValueError``
# -- der Endpunkt faengt ihn und macht daraus HTTP 422 (KEIN stiller Durchlauf, S3).
type AddDefaultCredsRunner = Callable[["EintragBody"], None]

# Aktualisiert einen Eintrag ueber die ``eintrag_id``. Liefert ``True``, wenn ein Eintrag
# mit dieser id existierte (und aktualisiert wurde), sonst ``False`` -- der Store macht bei
# unbekannter id einen stillen No-op, darum meldet der Runner die Existenz zurueck, damit
# der Endpunkt eine unbekannte id sauber als 404 melden kann. Ein Validierungsfehler ist
# wieder ein ``ValueError`` -> 422.
type UpdateDefaultCredsRunner = Callable[[str, "EintragBody"], bool]

# Loescht einen Eintrag ueber seine ``eintrag_id`` (Pass-Through, idempotent).
type DeleteDefaultCredsRunner = Callable[[str], None]

# Schaltet einen Eintrag aktiv/inaktiv (Pass-Through an ``SetDefaultCredsAktiv``).
type SetDefaultCredsAktivRunner = Callable[[str, bool], None]

# Stellt die mitgelieferten Eintraege wieder her (Pass-Through an ``ResetDefaultCredsListe``).
type ResetDefaultCredsRunner = Callable[[], None]

# Ermittelt den ``PruefPlan`` fuer Hersteller/Modell (rein lesend). Liefert das rohe
# ``PruefPlan``-Objekt (``Any``); dieser Rand serialisiert es per Attribut-Zugriff.
type ErmittlePruefplanRunner = Callable[[str, str], Any]

# Fuehrt die AKTIVE, gezielte Pruefung aus: prueft die uebergebenen Kandidaten gegen die
# offenen Ports (``PruefeGewaehlteKandidaten``), protokolliert das Ergebnis in der Historie
# (``SpeicherePruefung`` mit ``fall="kandidaten"``) und liefert die rohen ``CredFinding``
# (``list[Any]``). Async (aktive Logins im Adapter). Die Guards (Arm + Privatnetz) sitzen
# am api-Rand VOR diesem Runner (der Runner selbst kennt keine Guards).
type PruefenRunner = Callable[["PruefenBody"], Awaitable[list[Any]]]

# Liefert die neuesten Historien-Zusammenfassungen (ohne Findings-Blob) als ``list[Any]``.
type GetPruefHistorieRunner = Callable[[], list[Any]]

# Liefert einen Historien-Datensatz MIT Findings (``Any``) oder ``None`` (unbekannte id).
type GetPruefHistorieDetailRunner = Callable[[int], Any | None]


def provide_list_default_creds() -> ListDefaultCredsRunner:
    raise NotImplementedError("provide_list_default_creds nicht verdrahtet (app.py)")


def provide_add_default_creds() -> AddDefaultCredsRunner:
    raise NotImplementedError("provide_add_default_creds nicht verdrahtet (app.py)")


def provide_update_default_creds() -> UpdateDefaultCredsRunner:
    raise NotImplementedError("provide_update_default_creds nicht verdrahtet (app.py)")


def provide_delete_default_creds() -> DeleteDefaultCredsRunner:
    raise NotImplementedError("provide_delete_default_creds nicht verdrahtet (app.py)")


def provide_set_default_creds_aktiv() -> SetDefaultCredsAktivRunner:
    raise NotImplementedError("provide_set_default_creds_aktiv nicht verdrahtet (app.py)")


def provide_reset_default_creds() -> ResetDefaultCredsRunner:
    raise NotImplementedError("provide_reset_default_creds nicht verdrahtet (app.py)")


def provide_ermittle_pruefplan() -> ErmittlePruefplanRunner:
    raise NotImplementedError("provide_ermittle_pruefplan nicht verdrahtet (app.py)")


def provide_pruefen_kandidaten() -> PruefenRunner:
    raise NotImplementedError("provide_pruefen_kandidaten nicht verdrahtet (app.py)")


def provide_get_pruef_historie() -> GetPruefHistorieRunner:
    raise NotImplementedError("provide_get_pruef_historie nicht verdrahtet (app.py)")


def provide_get_pruef_historie_detail() -> GetPruefHistorieDetailRunner:
    raise NotImplementedError("provide_get_pruef_historie_detail nicht verdrahtet (app.py)")


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


# ── Body-Modelle der Etappe-C-Endpunkte (api-eigen, NICHT die domain-Typen) ───
#
# Muster analysis.py ``UserRuleBody``: der api-Ring darf ``domain`` nicht importieren --
# darum diese api-eigenen Schemas mit genau den fachlich uebergebenen Feldern. Die
# Uebersetzung in eine ``domain.DefaultCredsEintrag``/``CredentialKandidat`` macht der
# Composition-Root-Runner, nicht dieser Rand.


class KandidatBody(BaseModel):
    """Ein Kandidat innerhalb eines Listen-Eintrags (username/password/konfidenz).

    ``password`` darf leer sein (blank-Login, legitimer Werkszustand). ``konfidenz`` ist
    ein String -- die erlaubten Werte pruefen Domaene/Adapter (validierender Schreibpfad).
    """

    username: str = ""
    password: str = ""
    konfidenz: str = "benutzer"


class EintragBody(BaseModel):
    """POST/PUT /api/security/default-creds-list -- ein Standardzugangs-Eintrag.

    Schmales Request-DTO (NICHT die ``domain.DefaultCredsEintrag``). ``kandidaten`` sind
    ``KandidatBody`` (kein domain-Import). Die strukturelle Validierung (Zustand<->Kandidaten,
    leere id/Hersteller) macht der Store ueber die reine Domaenen-Validierung -> ``ValueError``
    -> HTTP 422 am Endpunkt-Rand.
    """

    eintrag_id: str = ""
    hersteller: str = ""
    modell: str = ""
    zustand: str = "hat_defaults"
    kandidaten: list[KandidatBody] = []
    quelle_url: str = ""
    aktiv: bool = True
    herkunft: str = "benutzer"


class AktivBody(BaseModel):
    """POST /api/security/default-creds-list/{eintrag_id}/aktiv -- aktiv/inaktiv schalten."""

    aktiv: bool = False


class ErmittelBody(BaseModel):
    """POST /api/security/default-creds/ermitteln -- Hersteller/Modell fuer den Pruefplan."""

    hersteller: str = ""
    modell: str = ""


class PruefKandidatBody(BaseModel):
    """Ein zu pruefendes Credential-Paar (username/password) fuer die aktive Pruefung."""

    username: str = ""
    password: str = ""


class PruefenBody(BaseModel):
    """POST /api/security/default-creds/pruefen -- die AKTIVE, gezielte Pruefung.

    ``host`` + offene ``ports`` ({port, service}) + die vom Aufrufer GEWAEHLTEN
    ``kandidaten`` ((username, password)-Paare) + ``hersteller``/``modell`` (fuer die
    Historie). INTRUSIV -- der Endpunkt traegt Arm- UND Privatnetz-Guard.
    """

    host: str = ""
    ports: list[dict[str, Any]] = []
    kandidaten: list[PruefKandidatBody] = []
    hersteller: str = ""
    modell: str = ""


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


def _kandidat_to_dict(k: Any) -> dict[str, Any]:
    # CredentialKandidat -> dict (per Attribut-Zugriff, kein domain-Import).
    return {
        "username": k.username,
        "password": k.password,
        "konfidenz": k.konfidenz,
    }


def _eintrag_to_dict(e: Any) -> dict[str, Any]:
    # DefaultCredsEintrag -> dict; kandidaten (tuple) -> Liste von Kandidaten-dicts
    # (Muster _rule_to_dict: tuple->list am Rand, Attribut-Zugriff).
    return {
        "eintrag_id": e.eintrag_id,
        "hersteller": e.hersteller,
        "modell": e.modell,
        "zustand": e.zustand,
        "kandidaten": [_kandidat_to_dict(k) for k in e.kandidaten],
        "quelle_url": e.quelle_url,
        "aktiv": e.aktiv,
        "herkunft": e.herkunft,
    }


def _pruefplan_to_dict(p: Any) -> dict[str, Any]:
    # PruefPlan -> dict {fall, eintraege:[...], quelle_urls:[...]}; eintraege ueber
    # _eintrag_to_dict, quelle_urls (tuple) -> Liste (Wire-treu).
    return {
        "fall": p.fall,
        "eintraege": [_eintrag_to_dict(e) for e in p.eintraege],
        "quelle_urls": list(p.quelle_urls),
    }


def _historie_summary_to_dict(s: Any) -> dict[str, Any]:
    # PruefHistorieSummary -> dict OHNE Findings-Blob (Muster ScanSummary).
    return {
        "eintrag_id": s.eintrag_id,
        "geprueft_at": s.geprueft_at,
        "host": s.host,
        "hersteller": s.hersteller,
        "modell": s.modell,
        "fall": s.fall,
        "treffer_count": s.treffer_count,
    }


def _historie_detail_to_dict(d: Any) -> dict[str, Any]:
    # PruefHistorieDetail -> dict MIT Findings; findings (tuple) ueber _cred_to_dict.
    return {
        "eintrag_id": d.eintrag_id,
        "geprueft_at": d.geprueft_at,
        "host": d.host,
        "hersteller": d.hersteller,
        "modell": d.modell,
        "fall": d.fall,
        "treffer_count": d.treffer_count,
        "findings": [_cred_to_dict(f) for f in d.findings],
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


# ── Standardzugangs-Liste: Verwaltung (CRUD/Reset -- KEIN Arm/Netz-Guard) ─────
#
# Die Listen-Pflege ist harmlos (kein aktiver Login, nur lokale SQLite-Verwaltung) --
# darum kein Arm-/Privatnetz-Guard. Muster analysis.py ``/api/analysis/rules`` (duenne
# Endpunkte, Runner im Composition Root).


@router.get("/api/security/default-creds-list")
def api_default_creds_list(
    list_eintraege: Annotated[ListDefaultCredsRunner, Depends(provide_list_default_creds)],
) -> list[dict[str, Any]]:
    """Alle Standardzugangs-Eintraege (Verwaltungs-/Anzeige-Sicht). Leer -> ``[]``."""
    return [_eintrag_to_dict(e) for e in list_eintraege()]


@router.post("/api/security/default-creds-list")
def api_default_creds_add(
    body: EintragBody,
    add_eintrag: Annotated[AddDefaultCredsRunner, Depends(provide_add_default_creds)],
) -> Any:
    """Legt einen neuen Eintrag an. Validierungsfehler (``ValueError`` aus dem Store) -> 422.

    Der Runner baut die ``domain.DefaultCredsEintrag`` aus dem DTO und ruft
    ``AddDefaultCredsEintrag``. Ein struktureller Mangel (leere id/Hersteller,
    Zustand<->Kandidaten-Widerspruch, Duplikat-id) ist ein ``ValueError`` -> HTTP 422 mit
    Meldung (KEIN stiller Durchlauf, S3). Erfolg -> 201 ``{"ok": true}``.
    """
    try:
        add_eintrag(body)
    except ValueError as exc:
        return JSONResponse(status_code=422, content={"ok": False, "error": str(exc)})
    return JSONResponse(status_code=201, content={"ok": True})


@router.put("/api/security/default-creds-list/{eintrag_id}")
def api_default_creds_update(
    eintrag_id: str,
    body: EintragBody,
    update_eintrag: Annotated[UpdateDefaultCredsRunner, Depends(provide_update_default_creds)],
) -> Any:
    """Aktualisiert einen bestehenden Eintrag. Unbekannte id -> 404, Validierungsfehler -> 422.

    Der Runner meldet ueber ``bool`` zurueck, ob ein Eintrag mit dieser id existierte (der
    Store macht bei unbekannter id sonst einen stillen No-op) -- ``False`` -> HTTP 404
    (kein stilles Erfolgs-OK auf eine nicht existierende Ressource). Ein struktureller
    Mangel ist ein ``ValueError`` -> HTTP 422.
    """
    try:
        existierte = update_eintrag(eintrag_id, body)
    except ValueError as exc:
        return JSONResponse(status_code=422, content={"ok": False, "error": str(exc)})
    if existierte is False:
        return JSONResponse(
            status_code=404,
            content={"ok": False, "error": f"Kein Eintrag mit eintrag_id {eintrag_id!r}."},
        )
    return {"ok": True}


@router.delete("/api/security/default-creds-list/{eintrag_id}")
def api_default_creds_delete(
    eintrag_id: str,
    delete_eintrag: Annotated[DeleteDefaultCredsRunner, Depends(provide_delete_default_creds)],
) -> dict[str, bool]:
    """Loescht einen Eintrag. Idempotent: unbekannte id ist kein Fehler (Muster delete_rule)."""
    delete_eintrag(eintrag_id)
    return {"ok": True}


@router.post("/api/security/default-creds-list/{eintrag_id}/aktiv")
def api_default_creds_set_aktiv(
    eintrag_id: str,
    body: AktivBody,
    set_aktiv: Annotated[SetDefaultCredsAktivRunner, Depends(provide_set_default_creds_aktiv)],
) -> dict[str, bool]:
    """Schaltet einen Eintrag aktiv/inaktiv, ohne ihn zu loeschen."""
    set_aktiv(eintrag_id, body.aktiv)
    return {"ok": True}


@router.post("/api/security/default-creds-list/reset")
def api_default_creds_reset(
    reset: Annotated[ResetDefaultCredsRunner, Depends(provide_reset_default_creds)],
) -> dict[str, bool]:
    """Stellt die mitgelieferten Eintraege wieder her (benutzer-eigene bleiben)."""
    reset()
    return {"ok": True}


# ── Standardzugangs-Workflow: Ermittlung (lesend) + aktive Pruefung + Historie ─


@router.post("/api/security/default-creds/ermitteln")
def api_default_creds_ermitteln(
    body: ErmittelBody,
    ermittle: Annotated[ErmittlePruefplanRunner, Depends(provide_ermittle_pruefplan)],
) -> dict[str, Any]:
    """Ermittelt den Pruefplan fuer Hersteller/Modell (rein lesend -> kein Guard).

    Nur ein Listen-Lookup (kein aktiver Login) -> weder Arm- noch Privatnetz-Guard. Liefert
    ``{fall, eintraege:[...], quelle_urls:[...]}`` (einer der drei Faelle).
    """
    return _pruefplan_to_dict(ermittle(body.hersteller, body.modell))


@router.post("/api/security/default-creds/pruefen")
async def api_default_creds_pruefen(
    request: Request,
    body: PruefenBody,
    pruefen: Annotated[PruefenRunner, Depends(provide_pruefen_kandidaten)],
    is_private_target: Annotated[Callable[[str], bool], Depends(provide_target_scope_guard)],
) -> Any:
    """AKTIVE, gezielte Pruefung -- INTRUSIV, traegt Arm- UND Privatnetz-Guard.

    Exakt wie der bestehende ``POST /api/security/default-creds``: erst Arm-Guard (nicht
    freigeschaltet -> 403), dann Privatnetz-Guard (host nicht privat -> 403), dann pruefen,
    dann Historie speichern, dann Findings zurueck. Der Composition-Root-Runner fuehrt
    ``PruefeGewaehlteKandidaten`` aus, protokolliert das Ergebnis via ``SpeicherePruefung``
    (fall="kandidaten") und liefert die rohen Findings; dieser Rand serialisiert sie.
    """
    # 1. Arm-Guard: die intrusive Sonderfunktion laeuft NUR, wenn sie fuer diese Sitzung
    # freigeschaltet ist (Laufzeit-Flag am app.state, Muster api_default_creds).
    if getattr(request.app.state, "default_creds_armed", False) is not True:
        return JSONResponse(
            status_code=403,
            content={
                "ok": False,
                "error": "Standardpasswort-Pruefung ist fuer diese Sitzung nicht freigeschaltet.",
            },
        )
    # 2. Privatnetz-Guard: nur Ziele im eigenen, privaten Netz (Pruefung kommt per
    # dependency aus dem infrastructure-Ring, Muster api_default_creds).
    if is_private_target(body.host) is False:
        return JSONResponse(
            status_code=403,
            content={
                "ok": False,
                "error": "Nur Ziele im eigenen, privaten Netz sind zulaessig.",
            },
        )
    # 3./4. Pruefen + Historie speichern uebernimmt der Runner (composed use-case).
    findings = await pruefen(body)
    return [_cred_to_dict(c) for c in findings]


@router.get("/api/security/default-creds/historie")
def api_default_creds_historie(
    get_historie: Annotated[GetPruefHistorieRunner, Depends(provide_get_pruef_historie)],
) -> list[dict[str, Any]]:
    """Die neuesten Pruef-Datensaetze als Zusammenfassungen (neueste zuerst, ohne Findings)."""
    return [_historie_summary_to_dict(s) for s in get_historie()]


@router.get("/api/security/default-creds/historie/{eintrag_id}")
def api_default_creds_historie_detail(
    eintrag_id: int,
    get_detail: Annotated[GetPruefHistorieDetailRunner, Depends(provide_get_pruef_historie_detail)],
) -> Any:
    """Ein Pruef-Datensatz MIT Findings. Unbekannte id -> 404."""
    detail = get_detail(eintrag_id)
    if detail is None:
        return JSONResponse(
            status_code=404,
            content={"ok": False, "error": f"Kein Historien-Eintrag mit id {eintrag_id}."},
        )
    return _historie_detail_to_dict(detail)
