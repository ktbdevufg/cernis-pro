"""End-to-end-Tests des export-Routers (Block 1) gegen app.py via TestClient.

Belegt: ``GET /api/export/scan/{scan_id}?format=...`` liefert je Format Statuscode 200 mit
korrektem Content-Type + ``Content-Disposition``-Download-Header; ein ungueltiges ``format``
ergibt 422 (Pflicht-Literal); eine unbekannte ``scan_id`` ergibt 404 (globaler Handler des
``ScanNotFoundError`` im Composition Root). Der Runner wird via ``dependency_overrides`` durch
einen Fake ersetzt -- kein echter Scan/Repository/reportlab noetig.
"""

from collections.abc import Awaitable, Callable, Iterator
from typing import Literal

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.export import (
    provide_export_analysis,
    provide_export_logging,
    provide_export_scan,
)
from app import create_app
from application.export import ExportResult, LoggingReportNotFound, ScanNotFoundError
from infrastructure.config import AppConfig


@pytest.fixture
def app() -> Iterator[FastAPI]:
    yield create_app(AppConfig())


def _fake_runner(
    known_id: int = 7,
) -> Callable[[int, Literal["csv", "json", "pdf"]], ExportResult]:
    """Ein Fake-ExportScanRunner: bekannte ID -> ExportResult je Format, sonst NotFound."""

    media = {
        "csv": ("text/csv", b"ip,mac\n10.0.0.1,aa:bb"),
        "json": ("application/json", b'{"scan_id": 7}'),
        "pdf": ("application/pdf", b"%PDF-FAKE"),
    }

    def _run(scan_id: int, fmt: Literal["csv", "json", "pdf"]) -> ExportResult:
        if scan_id != known_id:
            raise ScanNotFoundError(scan_id)
        media_type, content = media[fmt]
        return ExportResult(
            content=content, media_type=media_type, filename=f"cernis-scan-{scan_id}.{fmt}"
        )

    return _run


@pytest.mark.parametrize(
    ("fmt", "media_type"),
    [
        ("csv", "text/csv"),
        ("json", "application/json"),
        ("pdf", "application/pdf"),
    ],
)
def test_export_each_format_downloads(app: FastAPI, fmt: str, media_type: str) -> None:
    """Jedes Format: 200 + korrekter Content-Type + Content-Disposition-Download-Header."""
    app.dependency_overrides[provide_export_scan] = lambda: _fake_runner()

    with TestClient(app) as client:
        response = client.get("/api/export/scan/7", params={"format": fmt})

    assert response.status_code == 200
    assert response.headers["content-type"].startswith(media_type)
    assert response.headers["content-disposition"] == f'attachment; filename="cernis-scan-7.{fmt}"'
    assert response.content  # nicht-leerer Body


def test_export_invalid_format_is_422(app: FastAPI) -> None:
    """Ein ungueltiges ``format`` ist 422 (Pflicht-Literal -- FastAPI validiert)."""
    app.dependency_overrides[provide_export_scan] = lambda: _fake_runner()

    with TestClient(app) as client:
        response = client.get("/api/export/scan/7", params={"format": "xml"})

    assert response.status_code == 422


def test_export_missing_format_is_422(app: FastAPI) -> None:
    """Ohne ``format`` ist 422 (Pflicht-Query-Param)."""
    app.dependency_overrides[provide_export_scan] = lambda: _fake_runner()

    with TestClient(app) as client:
        response = client.get("/api/export/scan/7")

    assert response.status_code == 422


def test_export_unknown_scan_id_is_404(app: FastAPI) -> None:
    """Eine unbekannte ``scan_id`` -> 404 (globaler ScanNotFoundError-Handler)."""
    app.dependency_overrides[provide_export_scan] = lambda: _fake_runner()

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/api/export/scan/999", params={"format": "json"})

    assert response.status_code == 404
    assert "999" in response.json()["detail"]


# ── Block 2: GET /api/export/analysis (async Route, kein scan_id) ──────────────


def _fake_analysis_runner() -> Callable[[Literal["csv", "json", "pdf"]], Awaitable[ExportResult]]:
    """Ein Fake-ExportAnalysisRunner: je Format ein ExportResult (async, kein NotFound)."""

    media = {
        "csv": ("text/csv", b"severity,title\nnotable,X"),
        "json": ("application/json", b'{"finding_count": 1}'),
        "pdf": ("application/pdf", b"%PDF-FAKE"),
    }

    async def _run(fmt: Literal["csv", "json", "pdf"]) -> ExportResult:
        media_type, content = media[fmt]
        return ExportResult(
            content=content, media_type=media_type, filename=f"cernis-analysis-20260611.{fmt}"
        )

    return _run


@pytest.mark.parametrize(
    ("fmt", "media_type"),
    [
        ("csv", "text/csv"),
        ("json", "application/json"),
        ("pdf", "application/pdf"),
    ],
)
def test_export_analysis_each_format_downloads(app: FastAPI, fmt: str, media_type: str) -> None:
    """Jedes Format: 200 + korrekter Content-Type + Content-Disposition-Download-Header."""
    app.dependency_overrides[provide_export_analysis] = lambda: _fake_analysis_runner()

    with TestClient(app) as client:
        response = client.get("/api/export/analysis", params={"format": fmt})

    assert response.status_code == 200
    assert response.headers["content-type"].startswith(media_type)
    assert (
        response.headers["content-disposition"]
        == f'attachment; filename="cernis-analysis-20260611.{fmt}"'
    )
    assert response.content


def test_export_analysis_invalid_format_is_422(app: FastAPI) -> None:
    """Ein ungueltiges ``format`` ist 422 (Pflicht-Literal -- FastAPI validiert)."""
    app.dependency_overrides[provide_export_analysis] = lambda: _fake_analysis_runner()

    with TestClient(app) as client:
        response = client.get("/api/export/analysis", params={"format": "xml"})

    assert response.status_code == 422


def test_export_analysis_missing_format_is_422(app: FastAPI) -> None:
    """Ohne ``format`` ist 422 (Pflicht-Query-Param)."""
    app.dependency_overrides[provide_export_analysis] = lambda: _fake_analysis_runner()

    with TestClient(app) as client:
        response = client.get("/api/export/analysis")

    assert response.status_code == 422


# ── Block 3: GET /api/export/logging/{task_id} (sync, task_id + since/until) ───


def _fake_logging_runner(
    known_id: str = "abc123",
) -> Callable[[str, Literal["csv", "json", "pdf"], float | None, float | None], ExportResult]:
    """Ein Fake-ExportLoggingRunner: bekannte id -> ExportResult je Format, sonst NotFound.

    Merkt sich die durchgereichten since/until (fuer die Durchreich-Behauptung).
    """

    media = {
        "csv": ("text/csv", b"ts_iso,rtt_ms,loss_pct,alive\n2026-06-11T14:00:00,12.5,0.0,true"),
        "json": ("application/json", b'{"task_label": "X"}'),
        "pdf": ("application/pdf", b"%PDF-FAKE"),
    }

    def _run(
        task_id: str,
        fmt: Literal["csv", "json", "pdf"],
        since: float | None,
        until: float | None,
    ) -> ExportResult:
        _run.calls.append((task_id, since, until))  # type: ignore[attr-defined]
        if task_id != known_id:
            raise LoggingReportNotFound(task_id)
        media_type, content = media[fmt]
        return ExportResult(
            content=content, media_type=media_type, filename=f"cernis-monitoring-{task_id}.{fmt}"
        )

    _run.calls = []  # type: ignore[attr-defined]
    return _run


@pytest.mark.parametrize(
    ("fmt", "media_type"),
    [
        ("csv", "text/csv"),
        ("json", "application/json"),
        ("pdf", "application/pdf"),
    ],
)
def test_export_logging_each_format_downloads(app: FastAPI, fmt: str, media_type: str) -> None:
    """Jedes Format: 200 + korrekter Content-Type + Content-Disposition-Download-Header."""
    app.dependency_overrides[provide_export_logging] = lambda: _fake_logging_runner()

    with TestClient(app) as client:
        response = client.get("/api/export/logging/abc123", params={"format": fmt})

    assert response.status_code == 200
    assert response.headers["content-type"].startswith(media_type)
    assert (
        response.headers["content-disposition"]
        == f'attachment; filename="cernis-monitoring-abc123.{fmt}"'
    )
    assert response.content


def test_export_logging_passes_since_until(app: FastAPI) -> None:
    """``since``/``until`` werden als Query-Floats an den Runner durchgereicht."""
    runner = _fake_logging_runner()
    app.dependency_overrides[provide_export_logging] = lambda: runner

    with TestClient(app) as client:
        response = client.get(
            "/api/export/logging/abc123",
            params={"format": "json", "since": 100.0, "until": 200.0},
        )

    assert response.status_code == 200
    assert runner.calls == [("abc123", 100.0, 200.0)]  # type: ignore[attr-defined]


def test_export_logging_open_period_is_none(app: FastAPI) -> None:
    """Ohne ``since``/``until`` reicht der Router ``None`` durch (offener Zeitraum)."""
    runner = _fake_logging_runner()
    app.dependency_overrides[provide_export_logging] = lambda: runner

    with TestClient(app) as client:
        response = client.get("/api/export/logging/abc123", params={"format": "csv"})

    assert response.status_code == 200
    assert runner.calls == [("abc123", None, None)]  # type: ignore[attr-defined]


def test_export_logging_invalid_format_is_422(app: FastAPI) -> None:
    app.dependency_overrides[provide_export_logging] = lambda: _fake_logging_runner()

    with TestClient(app) as client:
        response = client.get("/api/export/logging/abc123", params={"format": "xml"})

    assert response.status_code == 422


def test_export_logging_missing_format_is_422(app: FastAPI) -> None:
    app.dependency_overrides[provide_export_logging] = lambda: _fake_logging_runner()

    with TestClient(app) as client:
        response = client.get("/api/export/logging/abc123")

    assert response.status_code == 422


def test_export_logging_unknown_task_id_is_404(app: FastAPI) -> None:
    """Eine unbekannte ``task_id`` -> 404 (globaler LoggingReportNotFound-Handler)."""
    app.dependency_overrides[provide_export_logging] = lambda: _fake_logging_runner()

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/api/export/logging/nope", params={"format": "json"})

    assert response.status_code == 404
    assert "nope" in response.json()["detail"]
