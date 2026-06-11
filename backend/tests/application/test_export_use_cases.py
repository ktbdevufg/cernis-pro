"""Tests des ExportScan-Use-Case gegen einen Fake-scan-provider + Fake-Renderer.

Keine echten Adapter -- wir testen gegen das ``scan_provider``-Callable + den
``ReportRenderer``-Port. Kern der Behauptungen: alle drei Formate liefern korrekten
``content``/``media_type``/``filename``; eine unbekannte ``scan_id`` -> ``ScanNotFoundError``;
der pdf-Pfad ruft ``renderer.render_pdf`` mit genau dem aus dem Scan gebauten ``PdfReportModel``.
"""

import json

import pytest

from application.export import ExportResult, ExportScan, ScanNotFoundError, ScanProvider
from domain.export import (
    ExportableHost,
    ExportablePort,
    ExportableScan,
    PdfReportModel,
    build_pdf_model,
)

# ── Fakes ────────────────────────────────────────────────────────────────────


class FakeRenderer:
    """In-Memory-Implementierung des ``ReportRenderer``-Protocols.

    Merkt sich das uebergebene Modell (fuer die pdf-Pfad-Behauptung) und liefert ein
    erkennbares, nicht-leeres Bytes-Resultat (kein echtes reportlab).
    """

    def __init__(self) -> None:
        self.calls: list[PdfReportModel] = []

    def render_pdf(self, model: PdfReportModel) -> bytes:
        self.calls.append(model)
        return b"%PDF-FAKE"


def _scan() -> ExportableScan:
    return ExportableScan(
        scan_id=7,
        cidr="10.0.0.0/24",
        host_count=1,
        scanned_at="2026-06-11T09:30:00",
        hosts=(
            ExportableHost(
                ip="10.0.0.5",
                mac="aa:bb:cc:00:11:22",
                vendor="Acme",
                hostname="box.local",
                os_guess="Linux",
                category="server",
                label="Box",
                tags=("a", "b"),
                source="ping",
                ports=(ExportablePort(port=22, protocol="tcp", service="ssh"),),
            ),
        ),
    )


def _provider_for(scan: ExportableScan) -> ScanProvider:
    def _provider(scan_id: int) -> ExportableScan | None:
        return scan if scan_id == scan.scan_id else None

    return _provider


# ── JSON ─────────────────────────────────────────────────────────────────────


def test_export_json_content_and_metadata() -> None:
    scan = _scan()
    use_case = ExportScan(_provider_for(scan), FakeRenderer())

    result = use_case(7, "json")

    assert isinstance(result, ExportResult)
    assert result.media_type == "application/json"
    assert result.filename == "cernis-scan-7.json"
    # Verlustfreier JSON-Inhalt (UTF-8-Bytes), wieder parsebar.
    payload = json.loads(result.content.decode("utf-8"))
    assert payload["scan_id"] == 7
    assert payload["hosts"][0]["ip"] == "10.0.0.5"


# ── CSV ──────────────────────────────────────────────────────────────────────


def test_export_csv_content_and_metadata() -> None:
    scan = _scan()
    use_case = ExportScan(_provider_for(scan), FakeRenderer())

    result = use_case(7, "csv")

    assert result.media_type == "text/csv"
    assert result.filename == "cernis-scan-7.csv"
    text = result.content.decode("utf-8")
    # Header + eine Host-Zeile; die zusammengefassten Ports stehen drin.
    assert text.splitlines()[0].startswith("ip,mac,vendor")
    assert "22/tcp" in text


# ── PDF ──────────────────────────────────────────────────────────────────────


def test_export_pdf_calls_renderer_with_expected_model() -> None:
    """Der pdf-Pfad ruft ``render_pdf`` mit genau dem aus dem Scan gebauten Modell."""
    scan = _scan()
    renderer = FakeRenderer()
    use_case = ExportScan(_provider_for(scan), renderer)

    result = use_case(7, "pdf")

    assert result.media_type == "application/pdf"
    assert result.filename == "cernis-scan-7.pdf"
    assert result.content == b"%PDF-FAKE"
    # Genau ein render_pdf-Aufruf mit dem erwarteten (reinen) Modell.
    assert len(renderer.calls) == 1
    assert renderer.calls[0] == build_pdf_model(scan)


# ── Scan nicht gefunden ───────────────────────────────────────────────────────


def test_unknown_scan_id_raises_scan_not_found() -> None:
    use_case = ExportScan(_provider_for(_scan()), FakeRenderer())
    with pytest.raises(ScanNotFoundError) as exc_info:
        use_case(999, "json")
    assert exc_info.value.scan_id == 999


def test_unknown_scan_id_does_not_render() -> None:
    """Bei unbekannter ID wird der Renderer NICHT gerufen (kein leerer Export)."""
    renderer = FakeRenderer()
    use_case = ExportScan(_provider_for(_scan()), renderer)
    with pytest.raises(ScanNotFoundError):
        use_case(999, "pdf")
    assert renderer.calls == []
