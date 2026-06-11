"""Tests des ReportlabRenderer-Adapters (Block 1) -- valides PDF, kein Layout-Assert.

Kein echtes Netz, kein Datei-I/O ausser dem in-memory ``BytesIO``: der Adapter rendert ein
reines ``PdfReportModel`` zu Bytes; wir pruefen NUR, dass valides PDF rauskommt (nicht-leere
Bytes, die mit dem Magic-Header ``%PDF`` beginnen) -- kein Layout-/Pixel-Assert (das fuehrt
reportlab). Auch der leere Scan (0 Hosts) muss ein valides PDF ergeben (nur Kopfzeile).
"""

from domain.export import PdfReportModel
from infrastructure.export_pdf import ReportlabRenderer


def _model(*rows: tuple[str, ...]) -> PdfReportModel:
    return PdfReportModel(
        title="CERNIS PRO — Scan-Bericht",
        scanned_at="2026-06-11T12:00:00",
        cidr="192.168.1.0/24",
        host_count=len(rows),
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
