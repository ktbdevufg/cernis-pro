"""FastAPI-Router der export-Domaene (Block 1): gespeicherter Scan als CSV/JSON/PDF.

Aeusserer Ring: nimmt HTTP entgegen und ruft ausschliesslich den Use-Case/Runner aus
``application/`` (import-linter: api -> nur application). Konkrete Adapter und ``domain``-
Typen werden hier NICHT importiert -- der Runner kommt per FastAPI-Dependency herein
(Verdrahtung im Composition Root ``app.py``, Muster ``api/diagnostics``). Der Runner liefert
das ``ExportResult`` (Bytes + ``media_type`` + Dateiname); der Router macht daraus eine
``Response`` mit ``Content-Disposition: attachment`` (der Browser laedt die Datei herunter).

* ``GET /api/export/scan/{scan_id}?format=csv|json|pdf`` -- exportiert den gespeicherten
  Scan ``scan_id`` im gewuenschten Format. ``format`` ist ein PFLICHT-Literal-Query-Param
  (FastAPI lehnt ein ungueltiges ``format`` selbst mit 422 ab -- kein Raten). Liefert die
  Datei als Download (``media_type`` + ``Content-Disposition: attachment; filename="..."``).

SCAN-NICHT-GEFUNDEN -> HTTP: Existiert die ``scan_id`` nicht, wirft der Use-Case
``application.export.ScanNotFoundError``. Diesen application-Zustand bildet ein GLOBALER
``exception_handler`` im Composition Root (``app.py``) auf **404** ab (Muster der
diagnostics-Rechte-/Dienst-Naht: das Mapping sitzt am Composition Root, der api-Ring bleibt
domain-/infra-frei). Der api-Ring importiert die Exception bewusst NICHT zum Werfen.
"""

from collections.abc import Callable
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Response

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
