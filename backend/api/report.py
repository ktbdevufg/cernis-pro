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


# ── CVE-Bericht: schmale api-Response-Modelle (eigene Wire-Form) ────────────────
# Analog zum Sicherheits-/Bestandsbericht oben: eigene schmale pydantic-``*Out``-Modelle, die
# die application-Sicht ``CveReport`` (samt ``SeverityCount``/``DeviceCveRow``/``ServiceCveRow``/
# ``CveFindingRow``) spiegeln, OHNE diese Typen zu importieren (Regel 4: api kennt application
# nicht). Der Composition-Root-Runner in ``app.py`` projiziert die application-Sicht auf genau
# diese Form.


class CveSeverityCountOut(BaseModel):
    """Ein Eintrag der Severity-Verteilung (Stufe + Anzahl, Wire-Form).

    ``severity`` die Stufe (CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN), ``count`` die Anzahl aktiver
    Befunde dieser Stufe (auch 0 -- es werden immer alle fuenf Stufen geliefert). Reine
    Anzeige; der Composition-Root-Runner projiziert die application-Sicht hierher.
    """

    severity: str
    count: int


class CveDeviceRowOut(BaseModel):
    """Eine Zeile je betroffenem Geraet (Sektion 2, Wire-Form).

    ``device_label`` der Anzeigename, ``mac`` die MAC, ``finding_count`` die Anzahl aktiver
    Befunde, ``highest_severity`` die hoechste Stufe, ``highest_cvss`` der hoechste CVSS,
    ``services`` die kommaseparierte Dienste-Liste. Alle Werte kommen vom Composition-Root-
    Runner fertig herein (api rechnet nicht).
    """

    device_label: str
    mac: str
    finding_count: int
    highest_severity: str
    highest_cvss: float
    services: str


class CveServiceRowOut(BaseModel):
    """Eine Zeile je Dienst (Sektion 3, Muster nach Dienst, Wire-Form).

    ``service`` der Dienst-Name, ``finding_count`` die Anzahl aktiver Befunde, ``device_count``
    die Anzahl betroffener Geraete, ``highest_severity`` die hoechste Stufe, ``highest_cvss``
    der hoechste CVSS, ``oldest_published`` die aelteste Veroeffentlichung als Text ("" moeglich).
    """

    service: str
    finding_count: int
    device_count: int
    highest_severity: str
    highest_cvss: float
    oldest_published: str


class CveFindingRowOut(BaseModel):
    """Eine vollstaendige Befund-Zeile (Sektion 4, aktiv ODER quittiert, Wire-Form).

    Alle Anzeige-Texte (``device_label``, ``first_seen_text``) sind schon vom Composition-Root-
    Runner fertig gesetzt; ``first_seen_ts`` ist der Sortier-/Alters-Schluessel als Unix-Sekunden
    (fuers Frontend). ``acknowledged`` trennt aktive von quittierten Zeilen, ``is_new`` ist die
    durchgereichte Domaenen-Ableitung.
    """

    device_label: str
    mac: str
    cve_id: str
    severity: str
    cvss_score: float
    service: str
    port: int
    first_seen_text: str
    first_seen_ts: float
    published: str
    acknowledged: bool
    is_new: bool


class CveReportOut(BaseModel):
    """Die Gesamtsicht des CVE-Berichts: Kennzahlen + Verteilung + drei Sektions-Listen.

    ``generated_findings_total`` alle persistierten Befunde, ``active_total`` die aktiven,
    ``acknowledged_total`` die quittierten, ``new_total`` die neuen, ``affected_devices`` die
    betroffenen Geraete. ``hosts_total``/``hosts_checked`` die Host-Zaehler, ``coverage_text``
    die fertige Prozent-Darstellung der Abdeckung (vom Composition-Root-Runner),
    ``highest_severity`` die hoechste Stufe, ``oldest_published`` die aelteste Veroeffentlichung.
    ``severity_counts`` die Verteilung, ``device_rows``/``service_rows``/``all_rows`` die drei
    Sektions-Listen. KEIN 404-Fall: leerer Stand ist ein DATUM, kein HTTP-Fehler.
    """

    generated_findings_total: int
    active_total: int
    acknowledged_total: int
    new_total: int
    affected_devices: int
    hosts_total: int
    hosts_checked: int
    coverage_text: str
    highest_severity: str
    oldest_published: str
    severity_counts: list[CveSeverityCountOut]
    device_rows: list[CveDeviceRowOut]
    service_rows: list[CveServiceRowOut]
    all_rows: list[CveFindingRowOut]


# ── CVE-Bericht: injizierter Composition-Root-Runner ───────────────────────────
# Provider-Marker (Muster ``InventoryReportRunner``): in app.py per dependency_overrides mit dem
# echten Root-Runner verdrahtet. Ohne Verdrahtung bewusst ein lauter Fehler (kein stiller
# Fallback, S3).


class CveReportRunner(Protocol):
    """Schmaler Vertrag des injizierten Lese-Runners (liefert die fertige CVE-Sicht)."""

    async def __call__(self) -> CveReportOut:
        """Baut den CVE-Bericht und liefert ihn api-fertig (Wire-Form)."""
        ...


def provide_cve_report() -> CveReportRunner:
    raise NotImplementedError("CveReportRunner wird in app.py verdrahtet")


@router.get("/cve")
async def get_cve_report(
    runner: Annotated[CveReportRunner, Depends(provide_cve_report)],
) -> CveReportOut:
    """Liefert den aggregierten CVE-Bericht (Kennzahlen + Verteilung + Sektions-Listen).

    KEIN 404-Fall: leerer Stand ist ein DATUM (alle Zaehler 0, leere Listen), kein HTTP-Fehler.
    Die ganze Projektion macht der injizierte Composition-Root-Runner (Regel 4: der api-Ring
    kennt application nicht).
    """
    return await runner()


# ── CVE-Bericht-PDF: injizierter Composition-Root-Runner ───────────────────────
# Muster ``InventoryReportPdfRunner``: der Runner liefert ein Objekt mit den drei Attributen
# ``content`` (bytes), ``media_type`` (str), ``filename`` (str). Der api-Ring kennt diesen
# Ergebnis-Typ NICHT -- der Router liest nur die drei Attribute (``type: ignore[attr-defined]``).
# Provider-Marker: in app.py verdrahtet; ohne Verdrahtung bewusst ein lauter Fehler (S3).


class CveReportPdfRunner(Protocol):
    """Schmaler Vertrag des injizierten PDF-Runners (liefert das fertige Download-Ergebnis)."""

    async def __call__(self) -> object:
        """Baut den CVE-Bericht als PDF und liefert content/media_type/filename."""
        ...


def provide_cve_report_pdf() -> CveReportPdfRunner:
    raise NotImplementedError("CveReportPdfRunner wird in app.py verdrahtet")


@router.get("/cve/pdf")
async def get_cve_report_pdf(
    runner: Annotated[CveReportPdfRunner, Depends(provide_cve_report_pdf)],
) -> Response:
    """Liefert den CVE-Bericht als PDF-Download (Bytes, ``attachment``).

    Der injizierte Composition-Root-Runner baut den Bericht, projiziert ihn auf das
    render-fertige PDF-Modell und rendert das PDF; er liefert ein Objekt mit ``content``
    (PDF-Bytes), ``media_type`` (``application/pdf``) und ``filename``. Der Router verpackt es
    in eine ``Response`` mit ``Content-Disposition: attachment; filename="..."``.

    KEIN 404-Fall: leerer Stand ist ein gueltiges PDF (alle Zaehler 0, leere Listen), kein
    HTTP-Fehler -- analog ``GET /api/report/cve``.
    """
    result = await runner()
    # result kommt aus dem Composition Root; per Attribut-Zugriff gelesen (kein Typ-Import im
    # Router -- der api-Ring kennt nur die drei Attribute, Muster ``get_inventory_report_pdf``).
    return Response(
        content=result.content,  # type: ignore[attr-defined]
        media_type=result.media_type,  # type: ignore[attr-defined]
        headers={
            "Content-Disposition": f'attachment; filename="{result.filename}"'  # type: ignore[attr-defined]
        },
    )


# ── Aussenkontakte-Bericht: schmale api-Response-Modelle (eigene Wire-Form) ─────
# Analog zum Sicherheits-/Bestands-/CVE-Bericht oben: eigene schmale pydantic-``*Out``-Modelle,
# die die application-Sicht ``OutboundReport`` (samt ``CountryCount``/``OperatorCount``/
# ``OutboundContactRow``) spiegeln, OHNE diese Typen zu importieren (Regel 4: api kennt
# application nicht). Der Composition-Root-Runner in ``app.py`` projiziert die application-Sicht
# auf genau diese Form.


class OutboundCountryOut(BaseModel):
    """Ein Eintrag der Land-Verteilung (Land + Anzahl Gegenstellen, Wire-Form).

    ``country`` das Land (ein leeres wird vom Root als "(unbekannt)" gefuehrt), ``count`` die
    Anzahl der nicht-lokalen Gegenstellen mit diesem Land. Reine Anzeige.
    """

    country: str
    count: int


class OutboundOperatorOut(BaseModel):
    """Ein Eintrag der Betreiber-Verteilung (Betreiber + Anzahl Gegenstellen, Wire-Form).

    ``operator`` der Betreiber (ein leerer wird vom Root als "(unbekannt)" gefuehrt), ``count``
    die Anzahl der nicht-lokalen Gegenstellen mit diesem Betreiber. Reine Anzeige.
    """

    operator: str
    count: int


class OutboundContactRowOut(BaseModel):
    """Eine Aussenkontakt-Zeile des Berichts (Wire-Form).

    Alle Anzeige-Texte (``hostname``/``country``/``operator``/``asn``/``app_name`` als
    Leerstring statt None, die beiden Datums-Texte) sind schon vom Composition-Root-Runner
    fertig gesetzt; ``first_seen_ts``/``last_seen_ts`` sind die rohen Sortier-/Alters-Schluessel
    als Unix-Sekunden (fuers Frontend). ``is_local`` markiert eine lokale/Infrastruktur-
    Gegenstelle, ``tracker_lists``/``threat_lists`` die Namen der treffenden Blocklisten (leer =
    kein Treffer) -- beide vom Root gesetzt.
    """

    remote_ip: str
    hostname: str
    country: str
    operator: str
    asn: str
    app_name: str
    first_seen_text: str
    last_seen_text: str
    first_seen_ts: float
    last_seen_ts: float
    total_count: int
    peak_count: int
    is_local: bool
    tracker_lists: list[str]
    threat_lists: list[str]


class OutboundReportOut(BaseModel):
    """Die Gesamtsicht des Aussenkontakte-Berichts: Bezugsrahmen, Kennzahlen, Verteilungen, Liste.

    ``recording_label`` der Anzeigename der Aufzeichnung (oder die fertige "Alle
    Aufzeichnungen"-Bezeichnung), ``recording_scope`` der rohe Bezugsrahmen-Schluessel
    ("single"/"all"). Die neun int-Kennzahlen sind die schon ermittelten Zaehler
    (``contacts_total``/``remote_total``/``local_total``/``connection_total``/
    ``countries_total``/``operators_total``/``tracker_contacts``/``threat_contacts``/
    ``flagged_contacts``). ``country_distribution``/``operator_distribution`` die beiden
    Verteilungs-Tabellen, ``contact_rows`` die sortierte Gesamt-Kontaktliste. KEIN 404-Fall:
    leerer Stand ist ein DATUM (alle Zaehler 0, leere Listen), kein HTTP-Fehler.
    """

    recording_label: str
    recording_scope: str
    contacts_total: int
    remote_total: int
    local_total: int
    connection_total: int
    countries_total: int
    operators_total: int
    tracker_contacts: int
    threat_contacts: int
    flagged_contacts: int
    country_distribution: list[OutboundCountryOut]
    operator_distribution: list[OutboundOperatorOut]
    contact_rows: list[OutboundContactRowOut]


class OutboundReportRecordingOut(BaseModel):
    """Eine waehlbare Aufzeichnung fuers Berichts-Dropdown (schlanke Wire-Form).

    ``id`` der technische Schluessel der Aufzeichnung (Query-Wert fuer ``recording_id``),
    ``label`` der Anzeigename (vom Root auf die id zurueckgefallen, falls leer). Bewusst ein
    EIGENER, report-spezifischer schlanker Pfad -- das Frontend fuellt damit das Dropdown, OHNE
    den vollen ``outbound_log``-Router zu nutzen.
    """

    id: str
    label: str


# ── Aussenkontakte-Bericht: injizierte Composition-Root-Runner ─────────────────
# Provider-Marker (Muster ``CveReportRunner``): in app.py per dependency_overrides mit den echten
# Root-Runnern verdrahtet. Ohne Verdrahtung bewusst ein lauter Fehler (kein stiller Fallback, S3).
#
# Der Bericht laeuft ueber EINE Aufzeichnung ODER alle: ``recording_id`` ist ein optionaler
# Query-Parameter (None bzw. leer = "alle Aufzeichnungen zusammengefasst"; ein konkreter Wert =
# nur diese Aufzeichnung). Der dritte Runner liefert die waehlbaren Aufzeichnungen fuers Dropdown.


class OutboundReportRunner(Protocol):
    """Schmaler Vertrag des injizierten Lese-Runners (liefert die fertige Aussenkontakte-Sicht)."""

    async def __call__(self, recording_id: str | None) -> OutboundReportOut:
        """Baut den Aussenkontakte-Bericht (eine Aufzeichnung oder alle) Wire-fertig."""
        ...


def provide_outbound_report() -> OutboundReportRunner:
    raise NotImplementedError("OutboundReportRunner wird in app.py verdrahtet")


class OutboundReportPdfRunner(Protocol):
    """Schmaler Vertrag des injizierten PDF-Runners (liefert das fertige Download-Ergebnis)."""

    async def __call__(self, recording_id: str | None) -> object:
        """Baut den Aussenkontakte-Bericht als PDF und liefert content/media_type/filename."""
        ...


def provide_outbound_report_pdf() -> OutboundReportPdfRunner:
    raise NotImplementedError("OutboundReportPdfRunner wird in app.py verdrahtet")


class OutboundReportRecordingsRunner(Protocol):
    """Schmaler Vertrag des injizierten Recordings-Runners (liefert das Dropdown-Datum)."""

    async def __call__(self) -> list[OutboundReportRecordingOut]:
        """Liefert die waehlbaren Aufzeichnungen als schlanke Wire-Form (leere Liste = Datum)."""
        ...


def provide_outbound_report_recordings() -> OutboundReportRecordingsRunner:
    raise NotImplementedError("OutboundReportRecordingsRunner wird in app.py verdrahtet")


# ── Aussenkontakte-Bericht: Routen ─────────────────────────────────────────────
# Reihenfolge (Auftrag): recordings, dann outbound, dann pdf. Alle drei haben feste, eindeutige
# Suffixe (kein Pfad-Parameter-Konflikt), die Reihenfolge ist daher unkritisch -- aber so definiert.


@router.get("/outbound/recordings")
async def get_outbound_report_recordings(
    runner: Annotated[OutboundReportRecordingsRunner, Depends(provide_outbound_report_recordings)],
) -> list[OutboundReportRecordingOut]:
    """Liefert die waehlbaren Aufzeichnungen fuers Berichts-Dropdown (schlanke Wire-Form).

    KEIN 404-Fall: eine leere Liste ist ein DATUM (noch keine Aufzeichnungen), kein HTTP-Fehler.
    Die Projektion macht der injizierte Composition-Root-Runner (Regel 4: api kennt application
    nicht).
    """
    return await runner()


@router.get("/outbound")
async def get_outbound_report(
    runner: Annotated[OutboundReportRunner, Depends(provide_outbound_report)],
    recording_id: str | None = None,
) -> OutboundReportOut:
    """Liefert den aggregierten Aussenkontakte-Bericht (EINE Aufzeichnung oder alle).

    ``recording_id`` ist optional: None bzw. leer = alle Aufzeichnungen zusammengefasst, ein
    konkreter Wert = nur diese Aufzeichnung. KEIN 404-Fall: leerer Stand ist ein DATUM (alle
    Zaehler 0, leere Listen), kein HTTP-Fehler. Die ganze Projektion macht der injizierte
    Composition-Root-Runner (Regel 4: der api-Ring kennt application nicht).
    """
    return await runner(recording_id)


@router.get("/outbound/pdf")
async def get_outbound_report_pdf(
    runner: Annotated[OutboundReportPdfRunner, Depends(provide_outbound_report_pdf)],
    recording_id: str | None = None,
) -> Response:
    """Liefert den Aussenkontakte-Bericht als PDF-Download (Bytes, ``attachment``).

    ``recording_id`` ist optional (None/leer = alle Aufzeichnungen, ein Wert = nur diese). Der
    injizierte Composition-Root-Runner baut den Bericht, projiziert ihn auf das render-fertige
    PDF-Modell und rendert das PDF; er liefert ein Objekt mit ``content`` (PDF-Bytes),
    ``media_type`` (``application/pdf``) und ``filename``. Der Router verpackt es in eine
    ``Response`` mit ``Content-Disposition: attachment; filename="..."``.

    KEIN 404-Fall: leerer Stand ist ein gueltiges PDF (alle Zaehler 0, leere Listen), kein
    HTTP-Fehler -- analog ``GET /api/report/outbound``.
    """
    result = await runner(recording_id)
    # result kommt aus dem Composition Root; per Attribut-Zugriff gelesen (kein Typ-Import im
    # Router -- der api-Ring kennt nur die drei Attribute, Muster ``get_cve_report_pdf``).
    return Response(
        content=result.content,  # type: ignore[attr-defined]
        media_type=result.media_type,  # type: ignore[attr-defined]
        headers={
            "Content-Disposition": f'attachment; filename="{result.filename}"'  # type: ignore[attr-defined]
        },
    )


# ── DNS-Waechter-Bericht: schmale api-Response-Modelle (eigene Wire-Form) ───────
# Analog zum Bestands-/Aussenkontakte-Bericht oben: eigene schmale pydantic-``*Out``-Modelle, die
# die application-Sicht ``DnsWatchReport`` (samt ``CategoryCount``/``AppCount``/
# ``DnsWatchContactRow``) spiegeln, OHNE diese Typen zu importieren (Regel 4: api kennt
# application nicht). Der Composition-Root-Runner in ``app.py`` projiziert die application-Sicht
# auf genau diese Form. EINFACHER als der Aussenkontakte-Bericht: KEIN Dropdown, KEIN
# ``recording_id`` -- genau zwei Routen wie beim Bestandsbericht.


class DnsCategoryCountOut(BaseModel):
    """Ein Eintrag der Kategorie-Verteilung (Kategorie + Anzahl aktiver Kontakte, Wire-Form).

    ``category`` der ROHE Kategorie-Schluessel ("offen"/"moegliche_doh"/"erwartungsgemaess"),
    ``count`` die Anzahl aktiver Kontakte dieser Kategorie (auch 0 -- es kommen immer alle drei).
    Reine Anzeige.
    """

    category: str
    count: int


class DnsAppCountOut(BaseModel):
    """Ein Eintrag der Programm-Verteilung (Programm + Anzahl aktiver Kontakte, Wire-Form).

    ``app_name`` der Programmname (ein leerer wird vom Root als "(ohne)" gefuehrt), ``count`` die
    Anzahl aktiver Zeilen mit diesem Programm. Reine Anzeige.
    """

    app_name: str
    count: int


class DnsWatchContactRowOut(BaseModel):
    """Eine DNS-relevante Kontakt-Zeile des Berichts (Wire-Form).

    Alle Anzeige-Texte (``hostname``/``app_name`` als Leerstring statt None) sind schon vom
    Composition-Root-Runner fertig gesetzt; ``category`` der ROHE Kategorie-Schluessel, ``port``
    der ``remote_port`` (0 = unbekannt), ``connection_count`` die Anzahl der Verbindungen dieser
    Gegenstelle, ``acknowledged`` der Quittiert-Marker (False = aktiv, True = quittiert).
    """

    remote_ip: str
    hostname: str
    category: str
    app_name: str
    port: int
    connection_count: int
    acknowledged: bool


class DnsWatchReportOut(BaseModel):
    """Die Gesamtsicht des DNS-Waechter-Berichts: Bezugsrahmen, Kennzahlen, Verteilungen, Liste.

    ``host_scope`` der rohe Bezugsrahmen-Schluessel ("local_host"), ``expected_servers`` die
    erwarteten DNS-Server, ``doh_providers`` die bekannten DoH-Anbieter -- alle drei unveraendert
    durchgereicht. Die sieben int-Kennzahlen sind die schon ermittelten Zaehler
    (``contacts_total``/``active_total``/``acknowledged_total``/``expected_active``/
    ``open_active``/``doh_active``/``flagged_active``). ``category_distribution``/
    ``app_distribution`` die beiden Verteilungs-Tabellen, ``contact_rows`` die sortierte
    Gesamt-Kontaktliste. KEIN 404-Fall: leerer Stand ist ein DATUM (alle Zaehler 0, leere
    Listen), kein HTTP-Fehler.
    """

    host_scope: str
    expected_servers: list[str]
    doh_providers: list[str]
    contacts_total: int
    active_total: int
    acknowledged_total: int
    expected_active: int
    open_active: int
    doh_active: int
    flagged_active: int
    category_distribution: list[DnsCategoryCountOut]
    app_distribution: list[DnsAppCountOut]
    contact_rows: list[DnsWatchContactRowOut]


# ── DNS-Waechter-Bericht: injizierter Composition-Root-Runner ──────────────────
# Provider-Marker (Muster ``InventoryReportRunner``): in app.py per dependency_overrides mit dem
# echten Root-Runner verdrahtet. Ohne Verdrahtung bewusst ein lauter Fehler (kein stiller
# Fallback, S3).


class DnsWatchReportRunner(Protocol):
    """Schmaler Vertrag des injizierten Lese-Runners (liefert die fertige DNS-Waechter-Sicht)."""

    async def __call__(self) -> DnsWatchReportOut:
        """Baut den DNS-Waechter-Bericht und liefert ihn api-fertig (Wire-Form)."""
        ...


def provide_dns_watch_report() -> DnsWatchReportRunner:
    raise NotImplementedError("DnsWatchReportRunner wird in app.py verdrahtet")


@router.get("/dns-watch")
async def get_dns_watch_report(
    runner: Annotated[DnsWatchReportRunner, Depends(provide_dns_watch_report)],
) -> DnsWatchReportOut:
    """Liefert den aggregierten DNS-Waechter-Bericht (Kennzahlen + Verteilungen + Kontaktliste).

    KEIN 404-Fall: leerer Stand ist ein DATUM (alle Zaehler 0, leere Listen), kein HTTP-Fehler.
    Die ganze Projektion macht der injizierte Composition-Root-Runner (Regel 4: der api-Ring
    kennt application nicht). Der Router-prefix ``/api/report`` ergibt ``/api/report/dns-watch``
    -- keine Kollision mit dem Live-Router ``/api/dns-watch``.
    """
    return await runner()


# ── DNS-Waechter-Bericht-PDF: injizierter Composition-Root-Runner ──────────────
# Muster ``InventoryReportPdfRunner``: der Runner liefert ein Objekt mit den drei Attributen
# ``content`` (bytes), ``media_type`` (str), ``filename`` (str). Der api-Ring kennt diesen
# Ergebnis-Typ NICHT -- der Router liest nur die drei Attribute (``type: ignore[attr-defined]``).
# Provider-Marker: in app.py verdrahtet; ohne Verdrahtung bewusst ein lauter Fehler (S3).


class DnsWatchReportPdfRunner(Protocol):
    """Schmaler Vertrag des injizierten PDF-Runners (liefert das fertige Download-Ergebnis)."""

    async def __call__(self) -> object:
        """Baut den DNS-Waechter-Bericht als PDF und liefert content/media_type/filename."""
        ...


def provide_dns_watch_report_pdf() -> DnsWatchReportPdfRunner:
    raise NotImplementedError("DnsWatchReportPdfRunner wird in app.py verdrahtet")


@router.get("/dns-watch/pdf")
async def get_dns_watch_report_pdf(
    runner: Annotated[DnsWatchReportPdfRunner, Depends(provide_dns_watch_report_pdf)],
) -> Response:
    """Liefert den DNS-Waechter-Bericht als PDF-Download (Bytes, ``attachment``).

    Der injizierte Composition-Root-Runner baut den Bericht, projiziert ihn auf das
    render-fertige PDF-Modell und rendert das PDF; er liefert ein Objekt mit ``content``
    (PDF-Bytes), ``media_type`` (``application/pdf``) und ``filename``. Der Router verpackt es
    in eine ``Response`` mit ``Content-Disposition: attachment; filename="..."``.

    KEIN 404-Fall: leerer Stand ist ein gueltiges PDF (alle Zaehler 0, leere Listen), kein
    HTTP-Fehler -- analog ``GET /api/report/dns-watch``.
    """
    result = await runner()
    # result kommt aus dem Composition Root; per Attribut-Zugriff gelesen (kein Typ-Import im
    # Router -- der api-Ring kennt nur die drei Attribute, Muster ``get_inventory_report_pdf``).
    return Response(
        content=result.content,  # type: ignore[attr-defined]
        media_type=result.media_type,  # type: ignore[attr-defined]
        headers={
            "Content-Disposition": f'attachment; filename="{result.filename}"'  # type: ignore[attr-defined]
        },
    )


# ── DNS-Umgehungs-Bericht: schmale api-Response-Modelle (eigene Wire-Form) ──────
# NEUER, EIGENER Bericht NEBEN dem host-lokalen DNS-Waechter-Bericht (der bleibt
# UNANGETASTET): dieser liest die PERSISTIERTEN netzweiten Umgehungs-Laeufe (Etappe 3) mit
# BEZUGSRAHMEN-Wahl (eine Aufzeichnung ODER alle zusammengefasst) -- Muster des
# Aussenkontakte-Berichts (recording_id als optionaler Query-Parameter + Recordings-Liste).
# Eigene schmale pydantic-``*Out``-Modelle, die die application-Sicht ``DnsBypassReport``
# (samt ``ResolverCount``/``DnsBypassReportRow``) spiegeln, OHNE diese Typen zu importieren
# (Regel 4: api kennt application nicht). Der Composition-Root-Runner in ``app.py`` projiziert
# die application-Sicht auf genau diese Form. Der Router-prefix ``/api/report`` ergibt
# ``/api/report/dns-bypass`` -- keine Kollision mit dem Live-Router ``/api/dns-bypass``.


class DnsBypassResolverOut(BaseModel):
    """Ein Eintrag der Ziel-Resolver-Verteilung (Ziel-IP + Anzahl Umgehungen, Wire-Form).

    ``dst_ip`` der Ziel-Resolver, ``count`` die Summe der Umgehungs-Anfragen an dieses Ziel
    (ueber alle fragenden Geraete). Reine Anzeige.
    """

    dst_ip: str
    count: int


class DnsBypassReportRowOut(BaseModel):
    """Eine Umgehungs-Zeile des Berichts (Wire-Form, spiegelt die Live-View-Felder).

    Alle Anzeige-/Bewertungs-Felder sind schon vom Composition-Root-Runner fertig gesetzt:
    ``device_name`` der best-effort im Bestand aufgeloeste Anzeigename ("" statt None, wenn
    keine IP passt), ``is_doh``/``doh_source_name`` die DoH-Bewertung des Ziels (Name der
    treffenden aktiven DOH-Quelle, "" wenn keine). ``src_ip`` das fragende Geraet, ``dst_ip``
    der nicht-erwartete Resolver, ``query_count`` die Anzahl Umgehungs-Anfragen dieser Gruppe,
    ``sample_qnames`` bis zu fuenf distinct qnames als Beleg.
    """

    src_ip: str
    device_name: str
    dst_ip: str
    is_doh: bool
    doh_source_name: str
    query_count: int
    sample_qnames: list[str]


class DnsBypassReportOut(BaseModel):
    """Die Gesamtsicht des DNS-Umgehungs-Berichts: Bezugsrahmen, Kennzahlen, Verteilung, Liste.

    ``recording_label`` der Anzeigename der Aufzeichnung (oder die fertige "Alle
    Aufzeichnungen"-Bezeichnung), ``recording_scope`` der rohe Bezugsrahmen-Schluessel
    ("single"/"all"), ``expected_servers`` die erwartete Resolver-Menge als ehrlicher Beleg.
    Die vier int-Kennzahlen sind die schon ermittelten Zaehler (``queries_total``/
    ``bypass_total``/``expected_total``/``bypass_devices``). ``resolver_distribution`` die
    Ziel-Resolver-Verteilung, ``bypass_rows`` die sortierte Umgehungs-Liste. KEIN 404-Fall:
    leerer Stand ist ein DATUM (alle Zaehler 0, leere Listen), kein HTTP-Fehler.
    """

    recording_label: str
    recording_scope: str
    expected_servers: list[str]
    queries_total: int
    bypass_total: int
    expected_total: int
    bypass_devices: int
    resolver_distribution: list[DnsBypassResolverOut]
    bypass_rows: list[DnsBypassReportRowOut]


class DnsBypassReportRecordingOut(BaseModel):
    """Eine waehlbare Aufzeichnung fuers Berichts-Dropdown (schlanke Wire-Form).

    ``id`` der technische Schluessel der Aufzeichnung (Query-Wert fuer ``recording_id``),
    ``label`` der Anzeigename (vom Root auf die id zurueckgefallen, falls leer). Bewusst ein
    EIGENER, report-spezifischer schlanker Pfad (Muster ``OutboundReportRecordingOut``) -- das
    Frontend fuellt damit das Dropdown, OHNE den vollen ``dns_bypass``-Router zu nutzen.
    """

    id: str
    label: str


# ── DNS-Umgehungs-Bericht: injizierte Composition-Root-Runner ──────────────────
# Provider-Marker (Muster ``OutboundReportRunner``): in app.py per dependency_overrides mit den
# echten Root-Runnern verdrahtet. Ohne Verdrahtung bewusst ein lauter Fehler (kein stiller
# Fallback, S3).
#
# Der Bericht laeuft ueber EINE Aufzeichnung ODER alle: ``recording_id`` ist ein optionaler
# Query-Parameter (None bzw. leer = "alle Aufzeichnungen zusammengefasst"; ein konkreter Wert =
# nur diese Aufzeichnung). Der dritte Runner liefert die waehlbaren Aufzeichnungen fuers Dropdown.


class DnsBypassReportRunner(Protocol):
    """Schmaler Vertrag des injizierten Lese-Runners (liefert die fertige Umgehungs-Sicht)."""

    async def __call__(self, recording_id: str | None) -> DnsBypassReportOut:
        """Baut den DNS-Umgehungs-Bericht (eine Aufzeichnung oder alle) Wire-fertig."""
        ...


def provide_dns_bypass_report() -> DnsBypassReportRunner:
    raise NotImplementedError("DnsBypassReportRunner wird in app.py verdrahtet")


class DnsBypassReportPdfRunner(Protocol):
    """Schmaler Vertrag des injizierten PDF-Runners (liefert das fertige Download-Ergebnis)."""

    async def __call__(self, recording_id: str | None) -> object:
        """Baut den DNS-Umgehungs-Bericht als PDF und liefert content/media_type/filename."""
        ...


def provide_dns_bypass_report_pdf() -> DnsBypassReportPdfRunner:
    raise NotImplementedError("DnsBypassReportPdfRunner wird in app.py verdrahtet")


class DnsBypassReportRecordingsRunner(Protocol):
    """Schmaler Vertrag des injizierten Recordings-Runners (liefert das Dropdown-Datum)."""

    async def __call__(self) -> list[DnsBypassReportRecordingOut]:
        """Liefert die waehlbaren Aufzeichnungen als schlanke Wire-Form (leere Liste = Datum)."""
        ...


def provide_dns_bypass_report_recordings() -> DnsBypassReportRecordingsRunner:
    raise NotImplementedError("DnsBypassReportRecordingsRunner wird in app.py verdrahtet")


# ── DNS-Umgehungs-Bericht: Routen ──────────────────────────────────────────────
# Reihenfolge (Muster Aussenkontakte): recordings, dann dns-bypass, dann pdf. Alle drei haben
# feste, eindeutige Suffixe (kein Pfad-Parameter-Konflikt), die Reihenfolge ist daher unkritisch.


@router.get("/dns-bypass/recordings")
async def get_dns_bypass_report_recordings(
    runner: Annotated[
        DnsBypassReportRecordingsRunner, Depends(provide_dns_bypass_report_recordings)
    ],
) -> list[DnsBypassReportRecordingOut]:
    """Liefert die waehlbaren Aufzeichnungen fuers Berichts-Dropdown (schlanke Wire-Form).

    KEIN 404-Fall: eine leere Liste ist ein DATUM (noch keine Aufzeichnungen), kein HTTP-Fehler.
    Die Projektion macht der injizierte Composition-Root-Runner (Regel 4: api kennt application
    nicht).
    """
    return await runner()


@router.get("/dns-bypass")
async def get_dns_bypass_report(
    runner: Annotated[DnsBypassReportRunner, Depends(provide_dns_bypass_report)],
    recording_id: str | None = None,
) -> DnsBypassReportOut:
    """Liefert den aggregierten DNS-Umgehungs-Bericht (EINE Aufzeichnung oder alle).

    ``recording_id`` ist optional: None bzw. leer = alle Aufzeichnungen zusammengefasst, ein
    konkreter Wert = nur diese Aufzeichnung. KEIN 404-Fall: leerer Stand ist ein DATUM (alle
    Zaehler 0, leere Listen), kein HTTP-Fehler. Die ganze Projektion macht der injizierte
    Composition-Root-Runner (Regel 4: der api-Ring kennt application nicht). Der Router-prefix
    ``/api/report`` ergibt ``/api/report/dns-bypass`` -- keine Kollision mit dem Live-Router
    ``/api/dns-bypass``.
    """
    return await runner(recording_id)


@router.get("/dns-bypass/pdf")
async def get_dns_bypass_report_pdf(
    runner: Annotated[DnsBypassReportPdfRunner, Depends(provide_dns_bypass_report_pdf)],
    recording_id: str | None = None,
) -> Response:
    """Liefert den DNS-Umgehungs-Bericht als PDF-Download (Bytes, ``attachment``).

    ``recording_id`` ist optional (None/leer = alle Aufzeichnungen, ein Wert = nur diese). Der
    injizierte Composition-Root-Runner baut den Bericht, projiziert ihn auf das render-fertige
    PDF-Modell und rendert das PDF; er liefert ein Objekt mit ``content`` (PDF-Bytes),
    ``media_type`` (``application/pdf``) und ``filename``. Der Router verpackt es in eine
    ``Response`` mit ``Content-Disposition: attachment; filename="..."``.

    KEIN 404-Fall: leerer Stand ist ein gueltiges PDF (alle Zaehler 0, leere Listen), kein
    HTTP-Fehler -- analog ``GET /api/report/dns-bypass``.
    """
    result = await runner(recording_id)
    # result kommt aus dem Composition Root; per Attribut-Zugriff gelesen (kein Typ-Import im
    # Router -- der api-Ring kennt nur die drei Attribute, Muster ``get_outbound_report_pdf``).
    return Response(
        content=result.content,  # type: ignore[attr-defined]
        media_type=result.media_type,  # type: ignore[attr-defined]
        headers={
            "Content-Disposition": f'attachment; filename="{result.filename}"'  # type: ignore[attr-defined]
        },
    )
