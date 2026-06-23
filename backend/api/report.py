"""FastAPI-Router des Sicherheitsberichts (Etappe 2c), prefix ``/api/report``.

Aeusserer Ring: nimmt HTTP entgegen. Wie ``api/dns_watch.py`` (das Vorbild) kennt
dieser Router WEDER ``application`` NOCH ``domain`` NOCH ``infrastructure`` (Regel 4):
der injizierte Lese-Runner kommt als schmaler lokaler Vertrag per Dependency herein,
verdrahtet im Composition Root (``app.py``).

Damit der api-Ring application-frei bleibt UND der Aufruf trotzdem typsicher ist (mypy
strict), beschreibt ein schmales lokales ``Protocol`` den Vertrag des injizierten
Lese-Runners (eine ``async``-Methode, die die FERTIG projizierte Wire-Sicht liefert).
Der api-Ring definiert eigene schmale pydantic-``*Out``-Response-Modelle; die Projektion
vom application-Typ ``SecurityReport`` auf diese Wire-Form macht der Composition-Root-
Runner in ``app.py``, NICHT der Router -- so nennt der api-Ring den application-Typ nie.

Endpunkt:

* ``GET /api/report/security`` -> der aggregierte Sicherheitsbericht (Score + offene/
  quittierte Befunde + ehrliche Statusfelder). KEIN 404-Fall: liegt kein juengster Scan
  als Basis vor, ist das ein DATUM (``has_scan`` False + leere Listen + Score 100), kein
  HTTP-Fehler.
"""

from typing import Annotated, Protocol

from fastapi import APIRouter, Depends
from pydantic import BaseModel

router = APIRouter(prefix="/api/report", tags=["report"])


# ── schmale api-Response-Modelle (eigene Wire-Form, KEIN application-Typ) ──────
# Die Felder spiegeln ``application.reporting.SecurityScore``/``SecurityReport`` samt der
# drei Finding-Typen, ohne diese Typen zu importieren. Der Composition-Root-Runner
# projiziert die application-Sicht auf genau diese Form (Regel 4: api kennt application
# nicht).


class ScoreOut(BaseModel):
    """Der Netz-Gesundheit-Score samt Einstufung und Zaehlern (Wire-Form)."""

    score: int
    level: str
    device_count: int
    total_burden: float
    critical_devices: int
    notable_devices: int
    clean_devices: int


class PortFindingOut(BaseModel):
    """Ein offener-/riskanter-Port-Befund EINES Geraets (Wire-Form)."""

    device_label: str
    ports: str
    severity: str
    reason: str


class CveFindingOut(BaseModel):
    """Ein CVE-Befund EINES Geraets (Wire-Form)."""

    device_label: str
    cve_id: str
    cvss_score: float
    severity: str
    service: str


class NetFindingOut(BaseModel):
    """Ein netzweiter Befund (IP-Konflikt / DNS-Umgehung / Rogue-DHCP, Wire-Form)."""

    kind: str
    device_label: str
    description: str
    severity: str


class SecurityReportOut(BaseModel):
    """Die Gesamtsicht des Sicherheitsberichts: Score + offene/quittierte Befunde + Status.

    ``has_scan`` und ``rogue_dhcp_checked_ts`` sind die zwei EHRLICHEN Statusfelder, die
    der Composition-Root-Runner setzt (der api-Ring rechnet nichts):

    * ``has_scan`` ist ``False``, wenn KEIN juengster Scan als Basis vorlag (Bericht-Basis
      leer). Dann sind die Listen leer und der Score steht ehrlich auf 100 -- das ist ein
      Datum, KEIN HTTP-Fehler (Frontend zeigt den Hinweis, kein Logik-Bedarf).
    * ``rogue_dhcp_checked_ts`` ist der ``checked_ts`` des letzten gespeicherten
      Rogue-DHCP-Stands (Unix-ts), oder ``None`` = noch nie geprueft. So kann das Frontend
      das Pruefdatum bzw. den "noch nie geprueft / Root noetig"-Hinweis zeigen, OHNE Logik.
    """

    score: ScoreOut
    port_findings: list[PortFindingOut]
    cve_findings: list[CveFindingOut]
    net_findings: list[NetFindingOut]
    acknowledged_port_findings: list[PortFindingOut]
    acknowledged_cve_findings: list[CveFindingOut]
    acknowledged_net_findings: list[NetFindingOut]
    device_count: int
    has_scan: bool
    rogue_dhcp_checked_ts: float | None


# ── injizierter Composition-Root-Runner ────────────────────────────────────────
# Provider-Marker: in app.py per dependency_overrides mit dem echten Root-Runner
# verdrahtet. Ohne Verdrahtung bewusst ein lauter Fehler (kein stiller Fallback, S3).


class SecurityReportRunner(Protocol):
    """Schmaler Vertrag des injizierten Lese-Runners (liefert die fertige Sicht)."""

    async def __call__(self) -> SecurityReportOut:
        """Baut den Sicherheitsbericht und liefert ihn api-fertig (Wire-Form)."""
        ...


def provide_security_report() -> SecurityReportRunner:
    raise NotImplementedError("SecurityReportRunner wird in app.py verdrahtet")


# ── Routen ───────────────────────────────────────────────────────────────────


@router.get("/security")
async def get_security_report(
    runner: Annotated[SecurityReportRunner, Depends(provide_security_report)],
) -> SecurityReportOut:
    """Liefert den aggregierten Sicherheitsbericht (Score + Befunde + Statusfelder).

    KEIN 404-Fall: liegt kein juengster Scan als Basis vor, ist das ein DATUM
    (``has_scan`` False + leere Listen + Score 100), kein HTTP-Fehler. Die ganze
    Projektion (inkl. der Statusfelder) macht der injizierte Composition-Root-Runner.
    """
    return await runner()
