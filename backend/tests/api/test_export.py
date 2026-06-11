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

from api.export import provide_export_analysis, provide_export_scan
from app import create_app
from application.export import ExportResult, ScanNotFoundError
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
