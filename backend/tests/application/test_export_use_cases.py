"""Tests des ExportScan-Use-Case gegen einen Fake-scan-provider + Fake-Renderer.

Keine echten Adapter -- wir testen gegen das ``scan_provider``-Callable + den
``ReportRenderer``-Port. Kern der Behauptungen: alle drei Formate liefern korrekten
``content``/``media_type``/``filename``; eine unbekannte ``scan_id`` -> ``ScanNotFoundError``;
der pdf-Pfad ruft ``renderer.render_pdf`` mit genau dem aus dem Scan gebauten ``PdfReportModel``.
"""

import asyncio
import json

import pytest

from application.export import (
    AnalysisProvider,
    ExportAnalysis,
    ExportLoggingReport,
    ExportResult,
    ExportScan,
    LoggingReportNotFound,
    LoggingReportProvider,
    ScanNotFoundError,
    ScanProvider,
)
from domain.export import (
    ExportableAnalysis,
    ExportableFinding,
    ExportableHost,
    ExportableLoggingEvent,
    ExportableLoggingReport,
    ExportableLoggingRtt,
    ExportablePort,
    ExportableScan,
    PdfReportModel,
    build_analysis_pdf_model,
    build_logging_report_pdf_model,
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


# ── Block 2: ExportAnalysis (async, Fake-analysis_provider + Fake-Renderer) ────
#
# Alle drei Formate liefern korrekten content/media_type/filename; der pdf-Pfad ruft
# render_pdf mit genau dem aus der Analyse gebauten Modell; der Provider wird awaited (async).


def _analysis() -> ExportableAnalysis:
    return ExportableAnalysis(
        generated_at="2026-06-11T12:34:56+00:00",
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


def _analysis_provider_for(analysis: ExportableAnalysis) -> AnalysisProvider:
    async def _provider() -> ExportableAnalysis:
        return analysis

    return _provider


def test_export_analysis_json() -> None:
    use_case = ExportAnalysis(_analysis_provider_for(_analysis()), FakeRenderer())

    result = asyncio.run(use_case("json"))

    assert isinstance(result, ExportResult)
    assert result.media_type == "application/json"
    # Zeitstempel im Dateinamen (kein analysis_id) -- kompakt aus generated_at.
    assert result.filename == "cernis-analysis-20260611-123456.json"
    payload = json.loads(result.content.decode("utf-8"))
    assert payload["finding_count"] == 1
    assert payload["findings"][0]["subject"] == "1.2.3.4:5900"


def test_export_analysis_csv() -> None:
    use_case = ExportAnalysis(_analysis_provider_for(_analysis()), FakeRenderer())

    result = asyncio.run(use_case("csv"))

    assert result.media_type == "text/csv"
    assert result.filename == "cernis-analysis-20260611-123456.csv"
    text = result.content.decode("utf-8")
    assert text.splitlines()[0].startswith("severity,title,subject")
    assert "1.2.3.4:5900" in text


def test_export_analysis_pdf_calls_renderer_with_expected_model() -> None:
    analysis = _analysis()
    renderer = FakeRenderer()
    use_case = ExportAnalysis(_analysis_provider_for(analysis), renderer)

    result = asyncio.run(use_case("pdf"))

    assert result.media_type == "application/pdf"
    assert result.filename == "cernis-analysis-20260611-123456.pdf"
    assert result.content == b"%PDF-FAKE"
    assert len(renderer.calls) == 1
    assert renderer.calls[0] == build_analysis_pdf_model(analysis)


def test_export_analysis_empty_is_valid() -> None:
    """Eine leere Analyse (0 findings) ist ein gueltiger Export (kein Fehler)."""
    empty = ExportableAnalysis(generated_at="2026-06-11T00:00:00+00:00")
    use_case = ExportAnalysis(_analysis_provider_for(empty), FakeRenderer())

    result = asyncio.run(use_case("json"))

    payload = json.loads(result.content.decode("utf-8"))
    assert payload["finding_count"] == 0
    assert payload["findings"] == []


# ── Block 3: ExportLoggingReport (sync, Fake-report_provider + Fake-Renderer) ──
#
# Alle drei Formate liefern korrekten content/media_type/filename (sprechend:
# CERNISPRO_<bereinigtes-Label>_<YYYY-MM-DD_HHMM>, gebaut aus dem Report);
# since/until werden an den Provider durchgereicht; der pdf-Pfad ruft render_pdf mit genau dem
# aus dem Report gebauten Modell; eine unbekannte task_id -> LoggingReportNotFound (kein Render).


def _report() -> ExportableLoggingReport:
    return ExportableLoggingReport(
        task_label="WLAN-Gast",
        task_purpose="Stabilitaet pruefen",
        target_id="abc123",
        generated_at="2026-06-11T15:30:00+00:00",
        period_from="2026-06-11T14:00:00",
        period_to="2026-06-11T15:00:00",
        uptime_pct=99.5,
        avg_rtt_ms=12.5,
        downtime_mins=1.5,
        sample_count=2,
        rtt_points=(
            ExportableLoggingRtt(ts=1_749_640_200.0, rtt_ms=12.5, loss_pct=0.0, alive=True),
        ),
        events=(ExportableLoggingEvent(ts=1_749_640_230.0, event_type="down", rtt_ms=-1.0),),
    )


def _report_provider_for(
    report: ExportableLoggingReport, known_id: str = "abc123"
) -> LoggingReportProvider:
    """Fake-Provider: bekannte task_id -> Report, sonst None. Merkt sich since/until."""

    def _provider(
        task_id: str, since: float | None, until: float | None
    ) -> ExportableLoggingReport | None:
        _provider.calls.append((task_id, since, until))  # type: ignore[attr-defined]
        return report if task_id == known_id else None

    _provider.calls = []  # type: ignore[attr-defined]
    return _provider


def test_export_logging_json() -> None:
    use_case = ExportLoggingReport(_report_provider_for(_report()), FakeRenderer())

    result = use_case("abc123", "json", None, None)

    assert isinstance(result, ExportResult)
    assert result.media_type == "application/json"
    assert result.filename == "CERNISPRO_WLAN-Gast_2026-06-11_1530.json"
    payload = json.loads(result.content.decode("utf-8"))
    assert payload["task_label"] == "WLAN-Gast"
    assert payload["sample_count"] == 2
    assert len(payload["rtt_points"]) == 1
    assert len(payload["events"]) == 1


def test_export_logging_csv() -> None:
    use_case = ExportLoggingReport(_report_provider_for(_report()), FakeRenderer())

    result = use_case("abc123", "csv", None, None)

    assert result.media_type == "text/csv"
    assert result.filename == "CERNISPRO_WLAN-Gast_2026-06-11_1530.csv"
    text = result.content.decode("utf-8")
    assert text.splitlines()[0].startswith("ts_iso,rtt_ms,loss_pct,alive")
    # Die CSV traegt die RTT-Reihe, nicht die Events.
    assert "down" not in text


def test_export_logging_pdf_calls_renderer_with_expected_model() -> None:
    report = _report()
    renderer = FakeRenderer()
    use_case = ExportLoggingReport(_report_provider_for(report), renderer)

    result = use_case("abc123", "pdf", None, None)

    assert result.media_type == "application/pdf"
    assert result.filename == "CERNISPRO_WLAN-Gast_2026-06-11_1530.pdf"
    assert result.content == b"%PDF-FAKE"
    assert len(renderer.calls) == 1
    assert renderer.calls[0] == build_logging_report_pdf_model(report)


def test_export_logging_passes_since_until_through() -> None:
    """since/until werden unveraendert an den Provider durchgereicht."""
    provider = _report_provider_for(_report())
    use_case = ExportLoggingReport(provider, FakeRenderer())

    use_case("abc123", "json", 100.0, 200.0)

    assert provider.calls == [("abc123", 100.0, 200.0)]  # type: ignore[attr-defined]


def test_unknown_task_id_raises_logging_report_not_found() -> None:
    use_case = ExportLoggingReport(_report_provider_for(_report()), FakeRenderer())
    with pytest.raises(LoggingReportNotFound) as exc_info:
        use_case("nope", "json", None, None)
    assert exc_info.value.task_id == "nope"


def test_unknown_task_id_does_not_render() -> None:
    """Bei unbekannter task_id wird der Renderer NICHT gerufen (kein leerer Export)."""
    renderer = FakeRenderer()
    use_case = ExportLoggingReport(_report_provider_for(_report()), renderer)
    with pytest.raises(LoggingReportNotFound):
        use_case("nope", "pdf", None, None)
    assert renderer.calls == []
