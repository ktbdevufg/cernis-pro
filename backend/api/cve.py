"""FastAPI-Router der cve-Domaene (Etappe 1, ADR 0037).

Aeusserer Ring: nimmt HTTP entgegen und ruft ausschliesslich ``application/`` (import-
linter: api -> nur application). Die Lese-Use-Cases (``GetActiveFindings``,
``GetCveMonitorStatus``) werden per FastAPI-Dependency hereingereicht (Verdrahtung in
``app.py``); der Acknowledge-SCHREIBpfad kommt als Composition-Root-Callable herein
(Muster ``api/analysis._acknowledge`` -- der api-Ring bleibt repo-frei).

Routen:
* ``GET  /api/cve``                 -- alle AKTIVEN (nicht quittierten) Befunde + is_new.
* ``GET  /api/cve/host/{mac}``      -- aktive Befunde eines Hosts.
* ``POST /api/cve/acknowledge``     -- ack/unack eines (mac, cve_id, port)-Befunds.
* ``GET  /api/cve/status``          -- schlanker Worker-/Pruef-Status.

Wire-Form wird HIER am Rand gebaut (kein ``.to_dict()`` in domain/application): die rohen
``ActiveFinding``/``MonitorStatus``-dataclasses werden per Attribut-Zugriff serialisiert.
severity + cvss_score werden mitgeliefert (fuers spaetere farbliche Hervorheben).
"""

from collections.abc import Callable
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Path
from pydantic import BaseModel

from application.cve import ActiveFinding, GetActiveFindings, GetCveMonitorStatus, MonitorStatus

router = APIRouter(prefix="/api/cve", tags=["cve"])


# ── Dependency-Marker (im Composition Root per dependency_overrides verdrahtet) ──


def provide_get_active_findings() -> GetActiveFindings:
    raise NotImplementedError("provide_get_active_findings nicht verdrahtet (app.py)")


def provide_get_cve_status() -> GetCveMonitorStatus:
    raise NotImplementedError("provide_get_cve_status nicht verdrahtet (app.py)")


# Composition-Root-Callable fuer das Acknowledge-Audit (ADR 0037): schreibt eine
# ack/unack-Zeile (mac, cve_id, port, action) -> None. Der api-Ring kennt das Repository
# NICHT direkt; das Callable wird in app.py verdrahtet. Synchron (lokaler SQLite-Zugriff).
type CveAcknowledgeRunner = Callable[[str, str, int, str], None]


def provide_cve_acknowledge() -> CveAcknowledgeRunner:
    raise NotImplementedError("provide_cve_acknowledge nicht verdrahtet (app.py)")


# ── Body-Modelle ────────────────────────────────────────────────────────────


class CveAcknowledgeBody(BaseModel):
    """POST /api/cve/acknowledge -- ein Quittier-Befehl pro (mac, cve_id, port) (ADR 0037).

    ``action`` ist ein ``Literal``: ein anderer Wert -> HTTP 422 (kein stiller Durchlauf,
    S3). ``ack`` nimmt den Befund aus dem aktiven Warnstand, ``unack`` reaktiviert ihn.
    """

    mac: str
    cve_id: str
    port: int
    action: Literal["ack", "unack"]


# ── Rand-Serializer (dataclass -> dict via Attribut-Zugriff) ───────────────────


def _finding_to_dict(f: ActiveFinding) -> dict[str, object]:
    return {
        "mac": f.mac,
        "ip": f.ip,
        "cve_id": f.cve_id,
        "port": f.port,
        "service": f.service,
        "severity": f.severity,
        "cvss_score": f.cvss_score,
        "description": f.description,
        "url": f.url,
        "published": f.published,
        "first_seen_ts": f.first_seen_ts,
        "last_seen_ts": f.last_seen_ts,
        "is_new": f.is_new,
    }


def _status_to_dict(s: MonitorStatus) -> dict[str, object]:
    # sleeping: der Worker schlaeft (kein NVD-Aufruf), wenn aktuell KEIN Host faellig ist.
    return {
        "hosts_total": s.hosts_total,
        "hosts_due": s.hosts_due,
        "hosts_checked": s.hosts_checked,
        "findings_total": s.findings_total,
        "findings_active": s.findings_active,
        "sleeping": s.hosts_due == 0,
    }


# ── Routen ───────────────────────────────────────────────────────────────────


@router.get("")
def list_active_findings(
    get_findings: Annotated[GetActiveFindings, Depends(provide_get_active_findings)],
) -> list[dict[str, object]]:
    """Alle aktiven (nicht quittierten) CVE-Befunde, mit is_new-Flag. Leer -> ``[]``."""
    return [_finding_to_dict(f) for f in get_findings()]


@router.get("/host/{mac}")
def list_active_findings_for_host(
    mac: Annotated[str, Path()],
    get_findings: Annotated[GetActiveFindings, Depends(provide_get_active_findings)],
) -> list[dict[str, object]]:
    """Aktive Befunde EINES Hosts. Unbekannte/leere MAC -> ``[]``."""
    return [_finding_to_dict(f) for f in get_findings(mac)]


@router.post("/acknowledge")
def acknowledge(
    body: CveAcknowledgeBody,
    record: Annotated[CveAcknowledgeRunner, Depends(provide_cve_acknowledge)],
) -> dict[str, bool]:
    """Quittiert (``ack``) oder reaktiviert (``unack``) einen Befund pro (mac, cve_id, port).

    Schreibt EINE append-only Log-Zeile ueber den Composition-Root-Runner; der effektive
    Status ergibt sich aus dem juengsten Eintrag. KEIN Loeschen. Erfolg -> ``{"ok": true}``.
    """
    record(body.mac, body.cve_id, body.port, body.action)
    return {"ok": True}


@router.get("/status")
def get_status(
    get_status: Annotated[GetCveMonitorStatus, Depends(provide_get_cve_status)],
) -> dict[str, object]:
    """Schlanker Worker-/Pruef-Status (Hosts gesamt/faellig/geprueft, Befunde, sleeping)."""
    return _status_to_dict(get_status())
