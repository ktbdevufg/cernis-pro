"""FastAPI-Router der export-Domaene (Block 1): gespeicherter Scan als CSV/JSON/PDF.

Aeusserer Ring: nimmt HTTP entgegen und ruft ausschliesslich den Use-Case/Runner aus
``application/`` (import-linter: api -> nur application). Konkrete Adapter und ``domain``-
Typen werden hier NICHT importiert -- der Runner kommt per FastAPI-Dependency herein
(Verdrahtung im Composition Root ``app.py``, Muster ``api/diagnostics``). Der Runner liefert
das ``ExportResult`` (Bytes + ``media_type`` + Dateiname); der Router macht daraus eine
``Response`` mit ``Content-Disposition: attachment`` (der Browser laedt die Datei herunter).

* ``GET /api/export/scan/{scan_id}?format=csv|json|pdf`` (Block 1) -- exportiert den
  gespeicherten Scan ``scan_id`` im gewuenschten Format. ``format`` ist ein PFLICHT-Literal-
  Query-Param (FastAPI lehnt ein ungueltiges ``format`` selbst mit 422 ab -- kein Raten).
  Liefert die Datei als Download (``media_type`` + ``Content-Disposition: attachment; ...``).
  SYNCHRON.
* ``GET /api/export/analysis?format=csv|json|pdf`` (Block 2) -- exportiert die AKTUELLEN
  Analyse-Befunde im gewuenschten Format. KEIN ``scan_id``/``analysis_id``-Pfadparameter: die
  Analyse hat keinen gespeicherten Stand, der Runner baut den Snapshot bei jedem Aufruf frisch
  (genau wie GET /api/analysis -- "die Analyse von jetzt", ADR 0015). ASYNC -- der Runner
  awaitet den frischen Snapshot-Bau (traffic/process). Kein NotFound (die Analyse kann nicht
  fehlen). ``format`` ist wieder ein PFLICHT-Literal-Query-Param (422 bei ungueltig).
* ``GET /api/export/logging/{task_id}?format=csv|json|pdf&since=<ts>&until=<ts>`` (Block 3) --
  exportiert den Logging-Report einer Aufgabe ueber einen Zeitraum. ``format`` wieder
  PFLICHT-Literal (422). ``since``/``until`` sind OPTIONALE Query-Floats (Unix-ts), Default
  ``None`` (offener Zeitraum = der ganze Task). SYNCHRON wie der Scan-Export (sync Lese-Repos +
  CPU-Rendern). Existiert die ``task_id`` nicht, wirft der Use-Case ``LoggingReportNotFound``
  -> 404 (eigener globaler Handler, s.u.).

SCAN-/LOGGING-NICHT-GEFUNDEN -> HTTP: Existiert die ``scan_id`` bzw. ``task_id`` nicht, wirft
der Use-Case ``application.export.ScanNotFoundError`` bzw. ``LoggingReportNotFound``. Diese
application-Zustaende bildet je ein GLOBALER ``exception_handler`` im Composition Root
(``app.py``) auf **404** ab (Muster der diagnostics-Rechte-/Dienst-Naht: das Mapping sitzt am
Composition Root, der api-Ring bleibt domain-/infra-frei). Der api-Ring importiert die
Exceptions bewusst NICHT zum Werfen. Der Analyse-Export hat keinen solchen Fall (immer frisch
erzeugt).
"""

from collections.abc import Awaitable, Callable
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query, Response

router = APIRouter(prefix="/api/export", tags=["export"])

# Composition-Root-Callable: bekommt ``scan_id`` + das validierte Format-Literal und liefert
# das ``ExportResult`` (Bytes + media_type + Dateiname). Der api-Ring kennt den
# ``ExportResult``-Typ NICHT als domain/infrastructure -- er ist eine application-Struktur;
# der Router liest nur die drei Attribute (``content``/``media_type``/``filename``) per
# Attribut-Zugriff. Synchron: CSV/JSON sind reine Funktionen, das PDF-Rendern ist CPU-Arbeit
# ohne Netz-I/O (der Use-Case ist ehrlich synchron) -- kein ``Awaitable``.
type ExportScanRunner = Callable[[int, Literal["csv", "json", "pdf"]], object]


# Dependency-Marker: im Composition Root (app.py) per dependency_overrides mit dem echten
# ExportScan-Use-Case (ueber die scanning->export-Projektion) verdrahtet. Ohne Verdrahtung
# bewusst ein lauter Fehler (Muster ``api/diagnostics``).
def provide_export_scan() -> ExportScanRunner:
    raise NotImplementedError("ExportScanRunner wird in app.py verdrahtet")


@router.get("/scan/{scan_id}")
def export_scan(
    scan_id: int,
    export: Annotated[ExportScanRunner, Depends(provide_export_scan)],
    format: Literal["csv", "json", "pdf"],
) -> Response:
    """Exportiert den gespeicherten Scan ``scan_id`` als Download im gewuenschten Format.

    ``format`` ist ein PFLICHT-Literal-Query-Param (``?format=csv|json|pdf``); FastAPI lehnt
    ein fehlendes/ungueltiges ``format`` selbst mit 422 ab (kein Raten). Der Runner liefert
    das ``ExportResult`` (Bytes + ``media_type`` + Dateiname); der Router verpackt es in eine
    ``Response`` mit ``Content-Disposition: attachment; filename="..."`` -- so laedt der
    Browser die Datei als Download statt sie inline anzuzeigen. Existiert die ``scan_id``
    nicht, wirft der Use-Case ``ScanNotFoundError`` -> 404 (globaler Handler).
    """
    result = export(scan_id, format)
    # result ist ein application.ExportResult; per Attribut-Zugriff gelesen (kein
    # application-Typ-Import im Router -- der api-Ring kennt nur die drei Attribute).
    return Response(
        content=result.content,  # type: ignore[attr-defined]
        media_type=result.media_type,  # type: ignore[attr-defined]
        headers={
            "Content-Disposition": f'attachment; filename="{result.filename}"'  # type: ignore[attr-defined]
        },
    )


# Composition-Root-Callable (Block 2): bekommt das validierte Format-Literal und liefert das
# ``ExportResult`` (Bytes + media_type + Dateiname). ASYNC (``Awaitable``), anders als der
# synchrone Scan-Runner: der ExportAnalysis-Use-Case awaitet den frischen Snapshot-Bau
# (traffic/process). KEIN ``scan_id``-Parameter -- die Analyse hat keine id. Der api-Ring
# kennt den ``ExportResult``-Typ NICHT als domain/infrastructure (application-Struktur, ueber
# die drei Attribute gelesen).
type ExportAnalysisRunner = Callable[[Literal["csv", "json", "pdf"]], Awaitable[object]]


# Dependency-Marker: im Composition Root (app.py) per dependency_overrides mit dem echten
# ExportAnalysis-Use-Case (ueber die analysis->export-Projektion) verdrahtet. Ohne
# Verdrahtung bewusst ein lauter Fehler (Muster ``provide_export_scan``).
def provide_export_analysis() -> ExportAnalysisRunner:
    raise NotImplementedError("ExportAnalysisRunner wird in app.py verdrahtet")


@router.get("/analysis")
async def export_analysis(
    export: Annotated[ExportAnalysisRunner, Depends(provide_export_analysis)],
    format: Literal["csv", "json", "pdf"],
) -> Response:
    """Exportiert die AKTUELLEN Analyse-Befunde als Download im gewuenschten Format.

    KEIN ``scan_id``/``analysis_id``: die Analyse hat keinen gespeicherten Stand, der Runner
    baut den Snapshot bei jedem Aufruf frisch (genau wie GET /api/analysis -- "die Analyse von
    jetzt", ADR 0015). ASYNC: der Runner awaitet den frischen Snapshot-Bau (traffic/process).
    ``format`` ist ein PFLICHT-Literal-Query-Param (``?format=csv|json|pdf``); FastAPI lehnt
    ein fehlendes/ungueltiges ``format`` selbst mit 422 ab. Der Runner liefert das
    ``ExportResult`` (Bytes + ``media_type`` + Dateiname); der Router verpackt es in eine
    ``Response`` mit ``Content-Disposition: attachment; filename="..."`` -- so laedt der
    Browser die Datei als Download. Kein NotFound (die Analyse kann nicht fehlen).
    """
    result = await export(format)
    # result ist ein application.ExportResult; per Attribut-Zugriff gelesen (kein
    # application-Typ-Import im Router -- der api-Ring kennt nur die drei Attribute).
    return Response(
        content=result.content,  # type: ignore[attr-defined]
        media_type=result.media_type,  # type: ignore[attr-defined]
        headers={
            "Content-Disposition": f'attachment; filename="{result.filename}"'  # type: ignore[attr-defined]
        },
    )


# Composition-Root-Callable (Block 3): bekommt ``task_id`` + das validierte Format-Literal +
# den optionalen Zeitraum (``since``/``until`` als Unix-ts oder ``None``) und liefert das
# ``ExportResult`` (Bytes + media_type + Dateiname). SYNCHRON wie der Scan-Runner (sync
# Lese-Repos + CPU-Rendern, kein Netz-I/O) -- kein ``Awaitable``. Der api-Ring kennt den
# ``ExportResult``-Typ NICHT als domain/infrastructure (application-Struktur, ueber die drei
# Attribute gelesen).
type ExportLoggingRunner = Callable[
    [str, Literal["csv", "json", "pdf"], float | None, float | None], object
]


# Dependency-Marker: im Composition Root (app.py) per dependency_overrides mit dem echten
# ExportLoggingReport-Use-Case (ueber die monitoring->export-Projektion) verdrahtet. Ohne
# Verdrahtung bewusst ein lauter Fehler (Muster ``provide_export_scan``).
def provide_export_logging() -> ExportLoggingRunner:
    raise NotImplementedError("ExportLoggingRunner wird in app.py verdrahtet")


@router.get("/logging/{task_id}")
def export_logging(
    task_id: str,
    export: Annotated[ExportLoggingRunner, Depends(provide_export_logging)],
    format: Literal["csv", "json", "pdf"],
    since: Annotated[float | None, Query()] = None,
    until: Annotated[float | None, Query()] = None,
) -> Response:
    """Exportiert den Logging-Report ``task_id`` ueber einen Zeitraum als Download.

    ``format`` ist ein PFLICHT-Literal-Query-Param (``?format=csv|json|pdf``); FastAPI lehnt
    ein fehlendes/ungueltiges ``format`` selbst mit 422 ab. ``since``/``until`` sind OPTIONALE
    Query-Floats (Unix-ts), Default ``None`` (offener Zeitraum = der ganze Task) -- sie werden
    unveraendert an den Runner durchgereicht (die Repos-Grenzen/SLA-Rechnung macht der
    Composition Root). Der Runner liefert das ``ExportResult`` (Bytes + ``media_type`` +
    Dateiname); der Router verpackt es in eine ``Response`` mit ``Content-Disposition:
    attachment; filename="..."`` -- so laedt der Browser die Datei als Download. Existiert die
    ``task_id`` nicht, wirft der Use-Case ``LoggingReportNotFound`` -> 404 (globaler Handler).
    """
    result = export(task_id, format, since, until)
    # result ist ein application.ExportResult; per Attribut-Zugriff gelesen (kein
    # application-Typ-Import im Router -- der api-Ring kennt nur die drei Attribute).
    return Response(
        content=result.content,  # type: ignore[attr-defined]
        media_type=result.media_type,  # type: ignore[attr-defined]
        headers={
            "Content-Disposition": f'attachment; filename="{result.filename}"'  # type: ignore[attr-defined]
        },
    )
