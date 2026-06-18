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

* ``ExportScan`` (Block 1) -- holt den (projizierten) Scan zur ``scan_id`` (``None`` ->
  ``ScanNotFoundError``) und serialisiert ihn je nach Format: CSV/JSON ueber die reinen
  domain-Funktionen (Ergebnis als UTF-8-Bytes), PDF ueber ``build_pdf_model`` +
  ``renderer.render_pdf``. Liefert ein ``ExportResult`` (Bytes + ``media_type`` + Dateiname).
  Synchron.
* ``ExportAnalysis`` (Block 2) -- holt die AKTUELLEN Analyse-Befunde ueber ein async
  ``analysis_provider``-Callable (frisch analysiert + projiziert im Composition Root, wie
  GET /api/analysis) und serialisiert sie je Format (``analysis_to_json``/``analysis_to_csv``/
  ``build_analysis_pdf_model`` + ``renderer.render_pdf``). ASYNC -- der Snapshot-Bau ist
  async. Kein NotFound: die Analyse wird immer frisch erzeugt (kein ``analysis_id``).
* ``ExportLoggingReport`` (Block 3) -- holt den Logging-Report einer Aufgabe ueber einen
  Zeitraum ueber ein ``logging_report_provider``-Callable (``task_id`` + ``since``/``until``;
  None -> ``LoggingReportNotFound``) und serialisiert ihn je Format
  (``logging_report_to_json``/``logging_report_to_csv``/``build_logging_report_pdf_model`` +
  ``renderer.render_pdf``). SYNCHRON wie ``ExportScan`` (die Lese-Repos sind sync, das Rendern
  CPU-Arbeit). Eigener ``LoggingReportNotFound`` (keine ``application.monitoring``-Kopplung,
  symmetrisch zu ``ScanNotFoundError``).
"""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from application.export.errors import LoggingReportNotFound, ScanNotFoundError
from domain.export import (
    ExportableAnalysis,
    ExportableLoggingReport,
    ExportableScan,
    ExportFormat,
    analysis_to_csv,
    analysis_to_json,
    build_analysis_pdf_model,
    build_logging_report_filename,
    build_logging_report_pdf_model,
    build_pdf_model,
    logging_report_to_csv,
    logging_report_to_json,
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


# ── Block 2: Analyse-Befunde exportieren (ADR 0015, Block 2) ──────────────────────────────
#
# Liefert die AKTUELLE ``ExportableAnalysis`` (frisch analysiert + projiziert im Composition
# Root -- Muster ``ScanProvider``). ASYNC, weil der Snapshot-Bau (traffic/process) async ist:
# der Composition-Root-Provider awaitet ``_analyze_snapshot`` und projiziert das Ergebnis.
# Anders als ``ScanProvider`` gibt es KEIN ``None``/NotFound: die Analyse wird immer frisch
# erzeugt, sie kann nicht "fehlen" (kein ``analysis_id``, ADR 0015). ``generated_at`` setzt
# der Composition Root ueber die ``Clock`` direkt in die projizierte ``ExportableAnalysis``
# (Fremd-Domaenen-/Uhr-Kopplung gehoert in die Verdrahtung) -- der Use-Case braucht darum
# KEINE eigene Uhr (symmetrisch zu ``ExportScan``, der auch nur einen Provider kennt).
AnalysisProvider = Callable[[], Awaitable[ExportableAnalysis]]


class ExportAnalysis:
    """Exportiert die aktuellen Analyse-Befunde als CSV/JSON/PDF (Block 2).

    Duenn (Muster ``ExportScan``): orchestriert die reine Domaene (``analysis_to_json``/
    ``analysis_to_csv``/``build_analysis_pdf_model``) + den ``ReportRenderer``, keine
    Eigenlogik ausser dem Format-Switch. Der ``analysis_provider`` + der Renderer kommen per
    Constructor-Injection herein (Callable bzw. Protocol-Typ) -- nie ein konkreter Adapter,
    nie ein analysis-Import (die frische Analyse + Projektion auf ``ExportableAnalysis`` lebt
    im Composition Root, independence-Contract).

    ASYNC -- anders als ``ExportScan`` (synchron): der ``analysis_provider`` baut den Snapshot
    frisch aus traffic/process (async, wie GET /api/analysis). Der Use-Case awaitet ihn; das
    eigentliche Serialisieren/Rendern bleibt synchron (reine Funktionen bzw. CPU-Rendern).
    """

    def __init__(self, analysis_provider: AnalysisProvider, renderer: ReportRenderer) -> None:
        self._analysis_provider = analysis_provider
        self._renderer = renderer

    async def __call__(self, fmt: ExportFormat) -> ExportResult:
        """Exportiert die aktuellen Befunde im Format ``fmt`` -> ``ExportResult``.

        Holt die aktuelle ``ExportableAnalysis`` ueber den ``analysis_provider`` (await --
        frischer Snapshot-Bau). Je nach ``fmt``:

        * ``json`` -> ``analysis_to_json`` (verlustfrei strukturiert), als UTF-8-Bytes.
        * ``csv`` -> ``analysis_to_csv`` (flache Befund-Tabelle), als UTF-8-Bytes.
        * ``pdf`` -> ``build_analysis_pdf_model`` (reines Modell) + ``renderer.render_pdf``.

        Der ``media_type`` + die Datei-Endung kommen aus ``_FORMAT_MEDIA_TYPES``; der
        ``filename`` ist ``cernis-analysis-<generated_at-kompakt>.<ext>`` -- ein Zeitstempel
        im Namen ist nuetzlich, da es (anders als beim Scan) keine ``analysis_id`` gibt
        (mehrere Exporte bleiben unterscheidbar). ``fmt`` ist bereits ein gueltiges
        ``ExportFormat``-Literal (der api-Rand validiert via FastAPI 422).
        """
        analysis = await self._analysis_provider()
        content = self._render(analysis, fmt)
        media_type, ext = _FORMAT_MEDIA_TYPES[fmt]
        filename = f"cernis-analysis-{_filename_stamp(analysis.generated_at)}.{ext}"
        return ExportResult(content=content, media_type=media_type, filename=filename)

    def _render(self, analysis: ExportableAnalysis, fmt: ExportFormat) -> bytes:
        """Serialisiert die projizierte Analyse in das Zielformat -> Bytes (Format-Switch).

        CSV/JSON: die reine domain-Funktion liefert einen String, der hier UTF-8-kodiert wird
        (deterministisch, ``ensure_ascii=False`` haelt Sonderzeichen lesbar). PDF: das reine
        ``build_analysis_pdf_model`` + der ``ReportRenderer`` (das Rendern ist Infrastruktur,
        hier nur der Aufruf).
        """
        if fmt == "json":
            return analysis_to_json(analysis).encode("utf-8")
        if fmt == "csv":
            return analysis_to_csv(analysis).encode("utf-8")
        return self._renderer.render_pdf(build_analysis_pdf_model(analysis))


# ── Block 3: Logging-Report exportieren (Reporting Schnitt 1a) ────────────────────────────
#
# Liefert den projizierten ``ExportableLoggingReport`` zu ``task_id`` + Zeitraum
# (``since``/``until`` als absolute Unix-ts oder ``None`` fuer offen) -- oder ``None`` (Task
# unbekannt). Ein schlankes Callable statt der drei Logging-Repos + ``compute_sla_stats``: so
# bleibt der Use-Case frei von monitoring-Kopplung (die Projektion + die SLA-Rechnung leben im
# Composition Root, Muster ``ScanProvider``). ``None`` ist ein legitimer Zustand ("Task gibt es
# nicht"), kein Fehler -- der Use-Case uebersetzt es in ``LoggingReportNotFound`` (ADR 0001:
# kein stiller leerer Export). SYNCHRON: die Lese-Repos sind sync (sqlite), die Projektion ist
# reine Werte-Arbeit -- symmetrisch zu ``ScanProvider``.
LoggingReportProvider = Callable[[str, float | None, float | None], ExportableLoggingReport | None]


class ExportLoggingReport:
    """Exportiert den Logging-Report einer Aufgabe ueber einen Zeitraum als CSV/JSON/PDF (Block 3).

    Duenn (Muster ``ExportScan``): orchestriert die reine Domaene (``logging_report_to_json``/
    ``logging_report_to_csv``/``build_logging_report_pdf_model``) + den ``ReportRenderer``,
    keine Eigenlogik ausser dem Format-Switch. Der ``logging_report_provider`` + der Renderer
    kommen per Constructor-Injection herein (Callable bzw. Protocol-Typ) -- nie ein konkreter
    Adapter, nie ein monitoring-Import (die Projektion + SLA-Rechnung lebt im Composition
    Root). SYNCHRON wie ``ExportScan``: die Logging-Lese-Repos sind sync, das PDF-Rendern ist
    CPU-Arbeit ohne Netz-I/O -- es gibt kein I/O, also kein ``async``.
    """

    def __init__(self, report_provider: LoggingReportProvider, renderer: ReportRenderer) -> None:
        self._report_provider = report_provider
        self._renderer = renderer

    def __call__(
        self,
        task_id: str,
        fmt: ExportFormat,
        since: float | None,
        until: float | None,
    ) -> ExportResult:
        """Exportiert den Logging-Report ``task_id`` im Zeitraum ``[since, until)`` als ``fmt``.

        Holt den projizierten Report ueber den ``logging_report_provider`` (mit ``task_id`` +
        Zeitraum); ``None`` -> ``LoggingReportNotFound`` (ADR 0001: kein stiller leerer Export).
        ``since``/``until`` sind absolute Unix-ts oder ``None`` (offener Zeitraum = ganzer
        Task). Je nach ``fmt``:

        * ``json`` -> ``logging_report_to_json`` (verlustfrei: Kopf + alle Punkte + Events).
        * ``csv`` -> ``logging_report_to_csv`` (die dichte RTT-Messreihe), als UTF-8-Bytes.
        * ``pdf`` -> ``build_logging_report_pdf_model`` + ``renderer.render_pdf`` (Bytes).

        Der ``media_type`` + die Datei-Endung kommen aus ``_FORMAT_MEDIA_TYPES``; der
        ``filename`` ist der SPRECHENDE ``CERNISPRO_<bereinigtes-Label>_<YYYY-MM-DD_HHMM>.<ext>``
        aus dem reinen Domaenen-Helfer ``build_logging_report_filename`` (gebaut aus dem
        projizierten Report -- nach dem Provider-Aufruf verfuegbar -- statt der alten
        kryptischen ``cernis-monitoring-<task_id>``-Form). ``task_id`` dient nur noch dem
        ``LoggingReportNotFound``. ``fmt`` ist bereits ein gueltiges ``ExportFormat``-Literal
        (der api-Rand validiert via FastAPI 422).
        """
        report = self._report_provider(task_id, since, until)
        if report is None:
            raise LoggingReportNotFound(task_id)
        content = self._render(report, fmt)
        media_type, ext = _FORMAT_MEDIA_TYPES[fmt]
        filename = build_logging_report_filename(report, ext)
        return ExportResult(content=content, media_type=media_type, filename=filename)

    def _render(self, report: ExportableLoggingReport, fmt: ExportFormat) -> bytes:
        """Serialisiert den projizierten Report in das Zielformat -> Bytes (Format-Switch).

        CSV/JSON: die reine domain-Funktion liefert einen String, der hier UTF-8-kodiert wird
        (deterministisch, ``ensure_ascii=False`` haelt Sonderzeichen lesbar). PDF: das reine
        ``build_logging_report_pdf_model`` + der ``ReportRenderer`` (das Rendern ist
        Infrastruktur, hier nur der Aufruf).
        """
        if fmt == "json":
            return logging_report_to_json(report).encode("utf-8")
        if fmt == "csv":
            return logging_report_to_csv(report).encode("utf-8")
        return self._renderer.render_pdf(build_logging_report_pdf_model(report))


def _filename_stamp(generated_at: str) -> str:
    """Macht aus dem ISO-``generated_at`` einen dateinamen-tauglichen kompakten Stempel.

    Reduziert ``"2026-06-11T12:00:00+00:00"`` auf ``"20260611-120000"`` -- nur Ziffern +
    ein Bindestrich, sodass der Stempel ohne Quoting in einen Dateinamen passt. Robust gegen
    Varianten des ISO-Strings (Bruchsekunden, Zeitzonen-Offset): es werden schlicht alle
    Ziffern der ersten beiden ISO-Bestandteile (Datum + Zeit) genommen. Faellt der Wert
    voellig unerwartet aus (keine Ziffern), bleibt ``"unknown"`` (kein leerer Stempel) --
    KEIN Fehler, da der Dateiname nur kosmetisch ist (ADR 0015, Block 2).
    """
    head = generated_at.replace("T", " ").split(" ")
    date_part = "".join(ch for ch in head[0] if ch.isdigit())
    time_part = ""
    if len(head) > 1:
        # Zeit-Teil bis zum Zeitzonen-/Bruchsekunden-Trenner; nur die Ziffern (HHMMSS).
        time_raw = head[1].split("+")[0].split("-")[0].split(".")[0]
        time_part = "".join(ch for ch in time_raw if ch.isdigit())
    stamp = f"{date_part}-{time_part}" if time_part else date_part
    return stamp if date_part else "unknown"
