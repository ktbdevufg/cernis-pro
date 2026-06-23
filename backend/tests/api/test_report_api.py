"""End-to-end-Test der report-API (Sicherheitsbericht, Etappe 2c) gegen app.py via TestClient.

Deckt ``GET /api/report/security`` ab: der Lese-Runner ist ein Fake-Double (geprueft wird
der Wire-Vertrag der ``SecurityReportOut`` -- Score-Felder, die drei offenen + drei
quittierten Listen, ``device_count`` und die zwei ehrlichen Statusfelder ``has_scan`` /
``rogue_dhcp_checked_ts``). Der Runner wird -- wie ``test_dns_watch_api.py`` -- analog
app.py per ``dependency_overrides`` verdrahtet.

Zwei Faelle: voller Bericht (Score + alle Listen + Rogue-Pruefdatum) und Leerfall
(``has_scan`` False, Score 100, leere Listen, ``rogue_dhcp_checked_ts`` None).
"""

from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.report import (
    CveFindingOut,
    NetFindingOut,
    PortFindingOut,
    ScoreContributionOut,
    ScoreOut,
    SecurityReportOut,
    provide_security_report,
)
from app import create_app
from infrastructure.config import AppConfig


class _FakeSecurityReportRunner:
    """Fake-Runner: liefert eine feste, schon api-projizierte Sicht (keine echten Quellen)."""

    def __init__(self, report: SecurityReportOut) -> None:
        self._report = report
        self.calls = 0

    async def __call__(self) -> SecurityReportOut:
        self.calls += 1
        return self._report


@pytest.fixture
def app() -> Iterator[FastAPI]:
    """Frisch gebaute App (Lifespan via TestClient pro Test -- kein Loop noetig)."""
    yield create_app(AppConfig())


# ── GET: Wire-Vertrag des vollen Berichts ──────────────────────────────────────


def test_get_security_report_liefert_200_und_json_form(app: FastAPI) -> None:
    """``/api/report/security`` -> 200 + erwartete JSON-Form (Score, Listen, Statusfelder)."""
    report = SecurityReportOut(
        score=ScoreOut(
            score=66,
            level="maessig",
            device_count=3,
            total_burden=1.3334,
            critical_devices=1,
            notable_devices=1,
            clean_devices=1,
            contributions=[
                ScoreContributionOut(
                    device_label="nas",
                    worst_severity="critical",
                    burden_value=1.0,
                ),
                ScoreContributionOut(
                    device_label="drucker",
                    worst_severity="notable",
                    burden_value=0.3334,
                ),
            ],
        ),
        port_findings=[
            PortFindingOut(
                device_label="drucker",
                ports="23, 2323",
                severity="critical",
                reason="auffaellige offene Ports (Achse-B-Regel)",
            )
        ],
        cve_findings=[
            CveFindingOut(
                device_label="nas",
                cve_id="CVE-2024-1234",
                cvss_score=9.8,
                severity="CRITICAL",
                service="smb",
            )
        ],
        net_findings=[
            NetFindingOut(
                kind="Rogue-DHCP",
                device_label="10.0.0.5",
                description="Unerwarteter DHCP-Server entdeckt (geprueft 2026-06-23 10:00)",
                severity="critical",
            )
        ],
        acknowledged_port_findings=[],
        acknowledged_cve_findings=[
            CveFindingOut(
                device_label="nas",
                cve_id="CVE-2023-9999",
                cvss_score=5.5,
                severity="MEDIUM",
                service="http",
            )
        ],
        acknowledged_net_findings=[],
        device_count=3,
        has_scan=True,
        rogue_dhcp_checked_ts=1750665600.0,
    )
    runner = _FakeSecurityReportRunner(report)
    app.dependency_overrides[provide_security_report] = lambda: runner

    with TestClient(app) as client:
        response = client.get("/api/report/security")

    assert response.status_code == 200
    assert runner.calls == 1
    assert response.json() == {
        "score": {
            "score": 66,
            "level": "maessig",
            "device_count": 3,
            "total_burden": 1.3334,
            "critical_devices": 1,
            "notable_devices": 1,
            "clean_devices": 1,
            "contributions": [
                {
                    "device_label": "nas",
                    "worst_severity": "critical",
                    "burden_value": 1.0,
                },
                {
                    "device_label": "drucker",
                    "worst_severity": "notable",
                    "burden_value": 0.3334,
                },
            ],
        },
        "port_findings": [
            {
                "device_label": "drucker",
                "ports": "23, 2323",
                "severity": "critical",
                "reason": "auffaellige offene Ports (Achse-B-Regel)",
            }
        ],
        "cve_findings": [
            {
                "device_label": "nas",
                "cve_id": "CVE-2024-1234",
                "cvss_score": 9.8,
                "severity": "CRITICAL",
                "service": "smb",
            }
        ],
        "net_findings": [
            {
                "kind": "Rogue-DHCP",
                "device_label": "10.0.0.5",
                "description": "Unerwarteter DHCP-Server entdeckt (geprueft 2026-06-23 10:00)",
                "severity": "critical",
            }
        ],
        "acknowledged_port_findings": [],
        "acknowledged_cve_findings": [
            {
                "device_label": "nas",
                "cve_id": "CVE-2023-9999",
                "cvss_score": 5.5,
                "severity": "MEDIUM",
                "service": "http",
            }
        ],
        "acknowledged_net_findings": [],
        "device_count": 3,
        "has_scan": True,
        "rogue_dhcp_checked_ts": 1750665600.0,
    }


# ── GET: Leerfall (kein Scan) ist ein Datum, kein Fehler ───────────────────────


def test_get_security_report_leerfall_has_scan_false(app: FastAPI) -> None:
    """Ohne Scan-Basis -> 200, ``has_scan`` False, Score 100, leere Listen, ts None."""
    report = SecurityReportOut(
        score=ScoreOut(
            score=100,
            level="gut",
            device_count=0,
            total_burden=0.0,
            critical_devices=0,
            notable_devices=0,
            clean_devices=0,
            contributions=[],
        ),
        port_findings=[],
        cve_findings=[],
        net_findings=[],
        acknowledged_port_findings=[],
        acknowledged_cve_findings=[],
        acknowledged_net_findings=[],
        device_count=0,
        has_scan=False,
        rogue_dhcp_checked_ts=None,
    )
    runner = _FakeSecurityReportRunner(report)
    app.dependency_overrides[provide_security_report] = lambda: runner

    with TestClient(app) as client:
        response = client.get("/api/report/security")

    assert response.status_code == 200
    assert response.json() == {
        "score": {
            "score": 100,
            "level": "gut",
            "device_count": 0,
            "total_burden": 0.0,
            "critical_devices": 0,
            "notable_devices": 0,
            "clean_devices": 0,
            "contributions": [],
        },
        "port_findings": [],
        "cve_findings": [],
        "net_findings": [],
        "acknowledged_port_findings": [],
        "acknowledged_cve_findings": [],
        "acknowledged_net_findings": [],
        "device_count": 0,
        "has_scan": False,
        "rogue_dhcp_checked_ts": None,
    }
