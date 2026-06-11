"""Tests des ReportlabRenderer-Adapters (Block 1) -- valides PDF, kein Layout-Assert.

Kein echtes Netz, kein Datei-I/O ausser dem in-memory ``BytesIO``: der Adapter rendert ein
reines ``PdfReportModel`` zu Bytes; wir pruefen NUR, dass valides PDF rauskommt (nicht-leere
Bytes, die mit dem Magic-Header ``%PDF`` beginnen) -- kein Layout-/Pixel-Assert (das fuehrt
reportlab). Auch der leere Scan (0 Hosts) muss ein valides PDF ergeben (nur Kopfzeile).
"""

from domain.export import (
    ExportableAnalysis,
    ExportableFinding,
    PdfReportModel,
    build_analysis_pdf_model,
)
from infrastructure.export_pdf import ReportlabRenderer


def _model(*rows: tuple[str, ...]) -> PdfReportModel:
    return PdfReportModel(
        title="CERNIS PRO — Scan-Bericht",
        meta=(
            ("Scan-Zeitpunkt", "2026-06-11T12:00:00"),
            ("Gescanntes Netz", "192.168.1.0/24"),
            ("Geräteanzahl", str(len(rows))),
        ),
        columns=("ip", "mac", "vendor", "hostname", "os_guess", "category", "open_ports"),
        rows=rows,
    )


def test_render_pdf_returns_valid_pdf_bytes() -> None:
    model = _model(
        ("192.168.1.10", "aa:bb:cc:dd:ee:ff", "Acme", "box.local", "Linux", "server", "22/tcp")
    )
    data = ReportlabRenderer().render_pdf(model)
    assert isinstance(data, bytes)
    assert len(data) > 0
    assert data.startswith(b"%PDF")


def test_render_pdf_empty_scan_is_valid_pdf() -> None:
    """Ein Bericht ohne Hosts (leere rows) ergibt ein valides PDF (nur Kopfzeile)."""
    data = ReportlabRenderer().render_pdf(_model())
    assert data.startswith(b"%PDF")


def test_render_pdf_handles_special_characters() -> None:
    """Sonderzeichen in den Zeilen brechen das Rendern nicht (valides PDF)."""
    model = _model(("10.0.0.5", "", "A & B Inc", "büro-drucker", "", "printer", "9100/tcp"))
    data = ReportlabRenderer().render_pdf(model)
    assert data.startswith(b"%PDF")


def test_render_pdf_analysis_model_is_valid_pdf() -> None:
    """Smoke (ADR 0015, Block 2): das generalisierte Analyse-Modell liefert ebenfalls %PDF.

    Derselbe Adapter rendert Scan- UND Analyse-Bericht (generisches PdfReportModel) -- ein
    Modell aus ``build_analysis_pdf_model`` (anderer Kopf, andere Spalten) muss valides PDF
    ergeben. Auch die leere Analyse (0 findings) -> nur Kopfzeile, gueltig.
    """
    analysis = ExportableAnalysis(
        generated_at="2026-06-11T12:00:00+00:00",
        findings=(
            ExportableFinding(
                rule_id="remote_access_port",
                severity="notable",
                title="Verbindung zu einem Fernzugriffs-Port",
                detail="Verbindung zu 1.2.3.4:5900 (5900).",
                subject="1.2.3.4:5900",
                help_kind="remote_access_port",
                help_url="https://help.example/remote",
            ),
        ),
        finding_count=1,
    )
    data = ReportlabRenderer().render_pdf(build_analysis_pdf_model(analysis))
    assert data.startswith(b"%PDF")

    empty = ExportableAnalysis(generated_at="2026-06-11T00:00:00+00:00")
    assert ReportlabRenderer().render_pdf(build_analysis_pdf_model(empty)).startswith(b"%PDF")
