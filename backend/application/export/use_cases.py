"""Use-Case der export-Domaene (Block 1) -- gespeicherten Scan als CSV/JSON/PDF exportieren.

Orchestriert die reine Domaene (``to_json``/``to_csv``/``build_pdf_model``) + den einen Port
(``ReportRenderer`` fuer das PDF). Kennt ``domain/`` und ``ports/``, NIEMALS
``infrastructure/`` (maschinell per import-linter erzwungen). Der Port kommt per
Constructor-Injection als Protocol-Typ herein -- nie ein konkreter Adapter.

Der Use-Case bleibt duenn und frei von Fremd-Domaenen-Kopplung: er bekommt den Scan NICHT
direkt aus scanning, sondern ueber ein schlankes ``scan_provider``-Callable
(``Callable[[int], ExportableScan | None]``), das im Composition Root die scanning-Daten
holt UND auf ``domain.export.ExportableScan`` projiziert (genau das analysis-Muster mit
seiner ``Observed*``-Projektion im Composition Root, ADR 0015). So importiert der Use-Case
KEINE scanning-Use-Cases und KEINE scanning-Domaene -- nur das Callable + den Renderer +
``domain.export``.

* ``ExportScan`` -- holt den (projizierten) Scan zur ``scan_id`` (``None`` ->
  ``ScanNotFoundError``) und serialisiert ihn je nach Format: CSV/JSON ueber die reinen
  domain-Funktionen (Ergebnis als UTF-8-Bytes), PDF ueber ``build_pdf_model`` +
  ``renderer.render_pdf``. Liefert ein ``ExportResult`` (Bytes + ``media_type`` + Dateiname).
"""

from collections.abc import Callable
from dataclasses import dataclass

from application.export.errors import ScanNotFoundError
from domain.export import (
    ExportableScan,
    ExportFormat,
    build_pdf_model,
    to_csv,
    to_json,
)
from ports.export import ReportRenderer

# Liefert den projizierten ``ExportableScan`` zu einer ``scan_id`` oder ``None`` (Scan
# existiert nicht). Ein schlankes Callable statt des konkreten ScanHistoryRepository/der
# scanning-Use-Cases: so bleibt der Use-Case frei von Fremd-Domaenen-Kopplung (die
# Projektion scanning -> export lebt im Composition Root). ``None`` ist ein legitimer
# Zustand ("Scan-ID gibt es nicht"), kein Fehler -- der Use-Case uebersetzt es in
# ``ScanNotFoundError`` (ADR 0001: kein stiller leerer Export).
ScanProvider = Callable[[int], ExportableScan | None]

# Format -> (media_type, Datei-Endung). Die EINZIGE Quelle der Wahrheit, wie ein Format auf
# seinen MIME-Typ + die Dateiendung abbildet. Reine Daten -- der Use-Case waehlt darueber,
# kein verstreutes Raten. ``text/csv``/``application/json``/``application/pdf`` sind die
# kanonischen MIME-Typen der drei Formate.
_FORMAT_MEDIA_TYPES: dict[ExportFormat, tuple[str, str]] = {
    "csv": ("text/csv", "csv"),
    "json": ("application/json", "json"),
    "pdf": ("application/pdf", "pdf"),
}


@dataclass(frozen=True)
class ExportResult:
    """Das Ergebnis eines Exports als schlanke application-Struktur (frozen).

    ``content`` die fertigen Bytes (UTF-8-kodierter CSV/JSON-String ODER die PDF-Bytes),
    ``media_type`` der MIME-Typ (``text/csv``/``application/json``/``application/pdf``),
    ``filename`` der vorgeschlagene Download-Name (``cernis-scan-<scan_id>.<ext>``).

    BEWUSST in application (NICHT domain, ADR 0015): ``media_type``/``filename`` sind
    Transport-nahe Begriffe (HTTP-Download), keine reine Domaenen-Bedeutung -- sie gehoeren
    in den Use-Case-Vertrag, nicht in die framework-freie Domaene.
    """

    content: bytes
    media_type: str
    filename: str


class ExportScan:
    """Exportiert einen gespeicherten Scan als CSV/JSON/PDF (Block 1).

    Duenn (Muster der diagnostics-/analysis-Use-Cases): orchestriert die reine Domaene +
    den ``ReportRenderer``, keine Eigenlogik ausser dem Format-Switch. Der ``scan_provider``
    + der Renderer kommen per Constructor-Injection herein (Callable bzw. Protocol-Typ) --
    nie ein konkreter Adapter, nie ein scanning-Import (die Projektion lebt im Composition
    Root). Synchron: CSV/JSON sind reine domain-Funktionen, das PDF-Rendern ist CPU-Arbeit
    ohne Netz-I/O (der Port ist ehrlich synchron) -- es gibt kein I/O, also kein ``async``.
    """

    def __init__(self, scan_provider: ScanProvider, renderer: ReportRenderer) -> None:
        self._scan_provider = scan_provider
        self._renderer = renderer

    def __call__(self, scan_id: int, fmt: ExportFormat) -> ExportResult:
        """Exportiert den Scan ``scan_id`` im Format ``fmt`` -> ``ExportResult``.

        Holt den projizierten Scan ueber den ``scan_provider``; ``None`` ->
        ``ScanNotFoundError`` (ADR 0001: kein stiller leerer Export). Je nach ``fmt``:

        * ``json`` -> ``to_json`` (verlustfrei strukturiert), als UTF-8-Bytes.
        * ``csv`` -> ``to_csv`` (flache Kernfelder), als UTF-8-Bytes.
        * ``pdf`` -> ``build_pdf_model`` (reines Modell) + ``renderer.render_pdf`` (Bytes).

        Der ``media_type`` + die Datei-Endung kommen aus ``_FORMAT_MEDIA_TYPES``; der
        ``filename`` ist ``cernis-scan-<scan_id>.<ext>``. ``fmt`` ist bereits ein gueltiges
        ``ExportFormat``-Literal (der api-Rand validiert via FastAPI 422).
        """
        scan = self._scan_provider(scan_id)
        if scan is None:
            raise ScanNotFoundError(scan_id)
        content = self._render(scan, fmt)
        media_type, ext = _FORMAT_MEDIA_TYPES[fmt]
        filename = f"cernis-scan-{scan_id}.{ext}"
        return ExportResult(content=content, media_type=media_type, filename=filename)

    def _render(self, scan: ExportableScan, fmt: ExportFormat) -> bytes:
        """Serialisiert den projizierten Scan in das Zielformat -> Bytes (Format-Switch).

        CSV/JSON: die reine domain-Funktion liefert einen String, der hier UTF-8-kodiert
        wird (deterministisch, ``ensure_ascii=False`` haelt Sonderzeichen lesbar -- die
        Kodierung ist der einzige Schritt nach der reinen Serialisierung). PDF: das reine
        ``build_pdf_model`` + der ``ReportRenderer`` (das Rendern ist Infrastruktur, hier
        nur der Aufruf).
        """
        if fmt == "json":
            return to_json(scan).encode("utf-8")
        if fmt == "csv":
            return to_csv(scan).encode("utf-8")
        return self._renderer.render_pdf(build_pdf_model(scan))
