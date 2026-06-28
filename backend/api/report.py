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

from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel

router = APIRouter(prefix="/api/report", tags=["report"])


# ── schmale api-Response-Modelle (eigene Wire-Form, KEIN application-Typ) ──────
# Die Felder spiegeln ``application.reporting.SecurityScore``/``SecurityReport`` samt der
# drei Finding-Typen, ohne diese Typen zu importieren. Der Composition-Root-Runner
# projiziert die application-Sicht auf genau diese Form (Regel 4: api kennt application
# nicht).


class ScoreContributionOut(BaseModel):
    """Der Last-Beitrag EINES belasteten Geraets zum Score (Wire-Form).

    ``device_label`` der Anzeigename, ``worst_severity`` "critical"/"notable",
    ``burden_value`` der tatsaechliche Lastwert. Nur belastete Geraete; saubere
    stehen in ``ScoreOut.clean_devices``. Single Source -- das Frontend zeigt nur an.
    """

    device_label: str
    worst_severity: str
    burden_value: float


class ScoreOut(BaseModel):
    """Der Netz-Gesundheit-Score samt Einstufung und Zaehlern (Wire-Form)."""

    score: int
    level: str
    device_count: int
    total_burden: float
    critical_devices: int
    notable_devices: int
    clean_devices: int
    contributions: list[ScoreContributionOut]


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
    description: str


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


# ── PDF-Download: injizierter Composition-Root-Runner ──────────────────────────
# Muster ``SecurityReportRunner`` / ``api/export.py``: der Runner liefert ein Objekt mit den
# drei Attributen ``content`` (bytes), ``media_type`` (str), ``filename`` (str). Der api-Ring
# kennt diesen Ergebnis-Typ NICHT (er lebt im Composition Root) -- der Router liest nur die
# drei Attribute per Attribut-Zugriff (``type: ignore[attr-defined]``, analog ``api/export.py``).
# Provider-Marker: in app.py per dependency_overrides verdrahtet; ohne Verdrahtung bewusst ein
# lauter Fehler (kein stiller Fallback, S3).


class SecurityReportPdfRunner(Protocol):
    """Schmaler Vertrag des injizierten PDF-Runners (liefert das fertige Download-Ergebnis)."""

    async def __call__(self) -> object:
        """Baut den Sicherheitsbericht als PDF und liefert content/media_type/filename."""
        ...


def provide_security_report_pdf() -> SecurityReportPdfRunner:
    raise NotImplementedError("SecurityReportPdfRunner wird in app.py verdrahtet")


@router.get("/security/pdf")
async def get_security_report_pdf(
    runner: Annotated[SecurityReportPdfRunner, Depends(provide_security_report_pdf)],
) -> Response:
    """Liefert den Sicherheitsbericht als PDF-Download (Bytes, ``attachment``).

    Der injizierte Composition-Root-Runner baut den Bericht, projiziert ihn auf das
    render-fertige PDF-Modell und rendert das PDF; er liefert ein Objekt mit ``content``
    (PDF-Bytes), ``media_type`` (``application/pdf``) und ``filename``. Der Router verpackt
    es in eine ``Response`` mit ``Content-Disposition: attachment; filename="..."`` -- so
    laedt der Browser die Datei als Download statt sie inline anzuzeigen.

    KEIN 404-Fall: liegt kein juengster Scan als Basis vor, ist das ein gueltiges PDF mit
    Score 100 (leere Basis), kein HTTP-Fehler -- analog ``GET /api/report/security``.
    """
    result = await runner()
    # result kommt aus dem Composition Root; per Attribut-Zugriff gelesen (kein Typ-Import im
    # Router -- der api-Ring kennt nur die drei Attribute, Muster ``api/export.py``).
    return Response(
        content=result.content,  # type: ignore[attr-defined]
        media_type=result.media_type,  # type: ignore[attr-defined]
        headers={
            "Content-Disposition": f'attachment; filename="{result.filename}"'  # type: ignore[attr-defined]
        },
    )


# ── Handbuch-Download: injizierter Composition-Root-Runner ──────────────────────
# Analog ``SecurityReportPdfRunner``: der Runner liefert ein Objekt mit den drei Attributen
# ``content`` (bytes), ``media_type`` (str), ``filename`` (str). Der api-Ring kennt diesen
# Ergebnis-Typ NICHT -- der Router liest nur die drei Attribute (``type: ignore[attr-defined]``).
# Provider-Marker: in app.py per dependency_overrides verdrahtet; ohne Verdrahtung bewusst ein
# lauter Fehler (kein stiller Fallback, S3).


class ManualPdfRunner(Protocol):
    """Schmaler Vertrag des injizierten Handbuch-PDF-Runners (liefert das Download-Ergebnis)."""

    async def __call__(self, lang: str) -> object:
        """Baut das Benutzerhandbuch als PDF und liefert content/media_type/filename."""
        ...


def provide_manual_pdf() -> ManualPdfRunner:
    raise NotImplementedError("ManualPdfRunner wird in app.py verdrahtet")


@router.get("/manual/pdf")
async def get_manual_pdf(
    runner: Annotated[ManualPdfRunner, Depends(provide_manual_pdf)],
    lang: str = "de",
) -> Response:
    """Liefert das Benutzerhandbuch als PDF-Download (Bytes, ``attachment``).

    ``lang`` ist ein einfacher Query-Parameter ("de"/"en"); jeder andere Wert faellt im
    Composition Root auf "de" zurueck (dort behandelt, nicht im Router). Der injizierte
    Composition-Root-Runner laedt die Hilfe-Inhalte, projiziert sie auf das render-fertige
    Handbuch-PDF-Modell und rendert das PDF; er liefert ein Objekt mit ``content`` (PDF-Bytes),
    ``media_type`` (``application/pdf``) und ``filename``. Der Router verpackt es in eine
    ``Response`` mit ``Content-Disposition: attachment; filename="..."``.
    """
    result = await runner(lang)
    return Response(
        content=result.content,  # type: ignore[attr-defined]
        media_type=result.media_type,  # type: ignore[attr-defined]
        headers={
            "Content-Disposition": f'attachment; filename="{result.filename}"'  # type: ignore[attr-defined]
        },
    )


# ── Bestandsbericht: schmale api-Response-Modelle (eigene Wire-Form) ────────────
# Analog zum Sicherheitsbericht oben: eigene schmale pydantic-``*Out``-Modelle, die die
# application-Sicht ``InventoryReport`` (samt ``DistributionEntry``/``InventoryDeviceRow``)
# spiegeln, OHNE diese Typen zu importieren (Regel 4: api kennt application nicht). Der
# Composition-Root-Runner in ``app.py`` projiziert die application-Sicht auf genau diese Form.


class InventoryDistributionOut(BaseModel):
    """Ein Eintrag einer Verteilungs-Tabelle (Hersteller bzw. Kategorie, Wire-Form).

    ``label`` der Hersteller- bzw. Kategorie-Name (ein leerer wird vom Root als "(ohne)"
    gefuehrt), ``count`` die Anzahl der Geraete dazu.
    """

    label: str
    count: int


class InventoryDeviceRowOut(BaseModel):
    """Eine Geraete-Zeile des Bestandsberichts (Wire-Form).

    Alle Anzeige-Texte (``device_label``, die beiden Datums-Texte, der ``last_ip``-Leerstring
    statt None) sind schon vom Composition-Root-Runner fertig gesetzt; ``last_seen_ts`` ist die
    letzte Sichtung als Unix-Sekunden (Sortierschluessel fuers Frontend). ``trust_state`` und
    ``source`` sind die ROHEN StrEnum-Werte ("neutral"/"trusted"/"watch" bzw. "scan"/"manual"),
    ``archived`` trennt aktive von archivierten Zeilen.
    """

    device_label: str
    vendor: str
    last_ip: str
    first_seen_text: str
    last_seen_text: str
    last_seen_ts: float
    times_seen: int
    category: str
    is_known: bool
    trust_state: str
    source: str
    archived: bool


class InventoryReportOut(BaseModel):
    """Die Gesamtsicht des Bestandsberichts: Kennzahlen + Verteilungen + Geraete-Listen.

    ``total``/``known``/``unknown``/``active_24h`` sind die Bestands-Grundzahlen,
    ``trusted``/``watch``/``neutral`` die ueber ALLE Zeilen gezaehlten Vertrauens-Stufen.
    ``vendor_distribution``/``category_distribution`` die beiden Verteilungs-Tabellen,
    ``device_rows`` die aktiven, ``archived_rows`` die archivierten Geraete. KEIN 404-Fall:
    leerer Bestand ist ein DATUM (alle Zaehler 0, leere Listen), kein HTTP-Fehler.
    """

    total: int
    known: int
    unknown: int
    active_24h: int
    trusted: int
    watch: int
    neutral: int
    vendor_distribution: list[InventoryDistributionOut]
    category_distribution: list[InventoryDistributionOut]
    device_rows: list[InventoryDeviceRowOut]
    archived_rows: list[InventoryDeviceRowOut]


# ── Bestandsbericht: injizierter Composition-Root-Runner ───────────────────────
# Provider-Marker (Muster ``SecurityReportRunner``): in app.py per dependency_overrides mit dem
# echten Root-Runner verdrahtet. Ohne Verdrahtung bewusst ein lauter Fehler (kein stiller
# Fallback, S3).


class InventoryReportRunner(Protocol):
    """Schmaler Vertrag des injizierten Lese-Runners (liefert die fertige Bestands-Sicht)."""

    async def __call__(self) -> InventoryReportOut:
        """Baut den Bestandsbericht und liefert ihn api-fertig (Wire-Form)."""
        ...


def provide_inventory_report() -> InventoryReportRunner:
    raise NotImplementedError("InventoryReportRunner wird in app.py verdrahtet")


@router.get("/inventory")
async def get_inventory_report(
    runner: Annotated[InventoryReportRunner, Depends(provide_inventory_report)],
) -> InventoryReportOut:
    """Liefert den aggregierten Bestandsbericht (Kennzahlen + Verteilungen + Geraete-Listen).

    KEIN 404-Fall: leerer Bestand ist ein DATUM (alle Zaehler 0, leere Listen), kein
    HTTP-Fehler. Die ganze Projektion macht der injizierte Composition-Root-Runner (Regel 4:
    der api-Ring kennt application nicht).
    """
    return await runner()


# ── Bestandsbericht-PDF: injizierter Composition-Root-Runner ───────────────────
# Muster ``SecurityReportPdfRunner``: der Runner liefert ein Objekt mit den drei Attributen
# ``content`` (bytes), ``media_type`` (str), ``filename`` (str). Der api-Ring kennt diesen
# Ergebnis-Typ NICHT -- der Router liest nur die drei Attribute (``type: ignore[attr-defined]``).
# Provider-Marker: in app.py verdrahtet; ohne Verdrahtung bewusst ein lauter Fehler (S3).


class InventoryReportPdfRunner(Protocol):
    """Schmaler Vertrag des injizierten PDF-Runners (liefert das fertige Download-Ergebnis)."""

    async def __call__(self) -> object:
        """Baut den Bestandsbericht als PDF und liefert content/media_type/filename."""
        ...


def provide_inventory_report_pdf() -> InventoryReportPdfRunner:
    raise NotImplementedError("InventoryReportPdfRunner wird in app.py verdrahtet")


@router.get("/inventory/pdf")
async def get_inventory_report_pdf(
    runner: Annotated[InventoryReportPdfRunner, Depends(provide_inventory_report_pdf)],
) -> Response:
    """Liefert den Bestandsbericht als PDF-Download (Bytes, ``attachment``).

    Der injizierte Composition-Root-Runner baut den Bericht, projiziert ihn auf das
    render-fertige PDF-Modell und rendert das PDF; er liefert ein Objekt mit ``content``
    (PDF-Bytes), ``media_type`` (``application/pdf``) und ``filename``. Der Router verpackt es
    in eine ``Response`` mit ``Content-Disposition: attachment; filename="..."``.

    KEIN 404-Fall: leerer Bestand ist ein gueltiges PDF (alle Zaehler 0, leere Listen), kein
    HTTP-Fehler -- analog ``GET /api/report/inventory``.
    """
    result = await runner()
    # result kommt aus dem Composition Root; per Attribut-Zugriff gelesen (kein Typ-Import im
    # Router -- der api-Ring kennt nur die drei Attribute, Muster ``get_security_report_pdf``).
    return Response(
        content=result.content,  # type: ignore[attr-defined]
        media_type=result.media_type,  # type: ignore[attr-defined]
        headers={
            "Content-Disposition": f'attachment; filename="{result.filename}"'  # type: ignore[attr-defined]
        },
    )
