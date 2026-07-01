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
    DnsAppCountOut,
    DnsBypassReportOut,
    DnsBypassReportRecordingOut,
    DnsBypassReportRowOut,
    DnsBypassResolverOut,
    DnsCategoryCountOut,
    DnsWatchContactRowOut,
    DnsWatchReportOut,
    NetFindingOut,
    OutboundContactRowOut,
    OutboundCountryOut,
    OutboundOperatorOut,
    OutboundReportOut,
    OutboundReportRecordingOut,
    PortFindingOut,
    ScoreContributionOut,
    ScoreOut,
    SecurityReportOut,
    provide_dns_bypass_report,
    provide_dns_bypass_report_pdf,
    provide_dns_bypass_report_recordings,
    provide_dns_watch_report,
    provide_dns_watch_report_pdf,
    provide_outbound_report,
    provide_outbound_report_recordings,
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
                description="Remote-Code-Ausfuehrung in SMB",
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
                description="Veraltete HTTP-Bibliothek",
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
                "description": "Remote-Code-Ausfuehrung in SMB",
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
                "description": "Veraltete HTTP-Bibliothek",
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


# ── Aussenkontakte-Bericht: schlanke Endpunkt-Tests (Etappe 2) ─────────────────


class _FakeOutboundReportRunner:
    """Fake-Runner: liefert eine feste, schon api-projizierte Aussenkontakte-Sicht."""

    def __init__(self, report: OutboundReportOut) -> None:
        self._report = report
        self.recording_id: str | None = "noch-nicht-aufgerufen"

    async def __call__(self, recording_id: str | None) -> OutboundReportOut:
        self.recording_id = recording_id
        return self._report


class _FakeOutboundRecordingsRunner:
    """Fake-Runner: liefert eine feste Dropdown-Liste (keine echten Quellen)."""

    def __init__(self, recordings: list[OutboundReportRecordingOut]) -> None:
        self._recordings = recordings

    async def __call__(self) -> list[OutboundReportRecordingOut]:
        return self._recordings


def test_get_outbound_report_liefert_200_und_json_form(app: FastAPI) -> None:
    """``/api/report/outbound?recording_id=...`` -> 200 + erwartete JSON-Form, id durchgereicht."""
    report = OutboundReportOut(
        recording_label="Büro",
        recording_scope="single",
        contacts_total=2,
        remote_total=1,
        local_total=1,
        connection_total=42,
        countries_total=1,
        operators_total=1,
        tracker_contacts=0,
        threat_contacts=1,
        flagged_contacts=1,
        country_distribution=[OutboundCountryOut(country="USA", count=1)],
        operator_distribution=[OutboundOperatorOut(operator="Google LLC", count=1)],
        contact_rows=[
            OutboundContactRowOut(
                remote_ip="1.2.3.4",
                hostname="böse.example",
                country="USA",
                operator="Google LLC",
                asn="AS15169",
                app_name="firefox",
                first_seen_text="28.06.2026 10:00",
                last_seen_text="28.06.2026 12:00",
                first_seen_ts=1751104800.0,
                last_seen_ts=1751112000.0,
                total_count=30,
                peak_count=5,
                is_local=False,
                tracker_lists=[],
                threat_lists=["Feodo"],
            )
        ],
    )
    runner = _FakeOutboundReportRunner(report)
    app.dependency_overrides[provide_outbound_report] = lambda: runner

    with TestClient(app) as client:
        response = client.get("/api/report/outbound", params={"recording_id": "rec-1"})

    assert response.status_code == 200
    assert runner.recording_id == "rec-1"
    assert response.json() == {
        "recording_label": "Büro",
        "recording_scope": "single",
        "contacts_total": 2,
        "remote_total": 1,
        "local_total": 1,
        "connection_total": 42,
        "countries_total": 1,
        "operators_total": 1,
        "tracker_contacts": 0,
        "threat_contacts": 1,
        "flagged_contacts": 1,
        "country_distribution": [{"country": "USA", "count": 1}],
        "operator_distribution": [{"operator": "Google LLC", "count": 1}],
        "contact_rows": [
            {
                "remote_ip": "1.2.3.4",
                "hostname": "böse.example",
                "country": "USA",
                "operator": "Google LLC",
                "asn": "AS15169",
                "app_name": "firefox",
                "first_seen_text": "28.06.2026 10:00",
                "last_seen_text": "28.06.2026 12:00",
                "first_seen_ts": 1751104800.0,
                "last_seen_ts": 1751112000.0,
                "total_count": 30,
                "peak_count": 5,
                "is_local": False,
                "tracker_lists": [],
                "threat_lists": ["Feodo"],
            }
        ],
    }


def test_get_outbound_report_ohne_recording_id_reicht_none_durch(app: FastAPI) -> None:
    """Ohne ``recording_id`` -> 200 und der Runner bekommt ``None`` (alle Aufzeichnungen)."""
    report = OutboundReportOut(
        recording_label="",
        recording_scope="all",
        contacts_total=0,
        remote_total=0,
        local_total=0,
        connection_total=0,
        countries_total=0,
        operators_total=0,
        tracker_contacts=0,
        threat_contacts=0,
        flagged_contacts=0,
        country_distribution=[],
        operator_distribution=[],
        contact_rows=[],
    )
    runner = _FakeOutboundReportRunner(report)
    app.dependency_overrides[provide_outbound_report] = lambda: runner

    with TestClient(app) as client:
        response = client.get("/api/report/outbound")

    assert response.status_code == 200
    assert runner.recording_id is None


def test_get_outbound_report_recordings_liefert_dropdown_liste(app: FastAPI) -> None:
    """``/api/report/outbound/recordings`` -> 200 + die schlanke Dropdown-Liste (leer = Datum)."""
    runner = _FakeOutboundRecordingsRunner(
        [
            OutboundReportRecordingOut(id="rec-1", label="Büro"),
            OutboundReportRecordingOut(id="rec-2", label="Heimnetz"),
        ]
    )
    app.dependency_overrides[provide_outbound_report_recordings] = lambda: runner

    with TestClient(app) as client:
        response = client.get("/api/report/outbound/recordings")

    assert response.status_code == 200
    assert response.json() == [
        {"id": "rec-1", "label": "Büro"},
        {"id": "rec-2", "label": "Heimnetz"},
    ]


class _FakeDnsWatchReportRunner:
    """Fake-Runner: liefert eine feste, schon api-projizierte DNS-Waechter-Sicht."""

    def __init__(self, report: DnsWatchReportOut) -> None:
        self._report = report
        self.calls = 0

    async def __call__(self) -> DnsWatchReportOut:
        self.calls += 1
        return self._report


class _FakeDnsWatchReportPdfRunner:
    """Fake-PDF-Runner: liefert ein festes Download-Ergebnis (content/media_type/filename)."""

    def __init__(self, content: bytes, media_type: str, filename: str) -> None:
        self._content = content
        self._media_type = media_type
        self._filename = filename

    async def __call__(self) -> object:
        return _FakeDnsWatchPdfResult(
            content=self._content, media_type=self._media_type, filename=self._filename
        )


class _FakeDnsWatchPdfResult:
    """Schmales Ergebnis-Double: genau die drei Attribute, die der PDF-Router liest."""

    def __init__(self, content: bytes, media_type: str, filename: str) -> None:
        self.content = content
        self.media_type = media_type
        self.filename = filename


def test_get_dns_watch_report_liefert_200_und_json_form(app: FastAPI) -> None:
    """``/api/report/dns-watch`` -> 200 + erwartete JSON-Form (Rahmen, Kennzahlen, Listen)."""
    report = DnsWatchReportOut(
        host_scope="local_host",
        expected_servers=["192.168.1.1"],
        doh_providers=["cloudflare-dns.com"],
        contacts_total=2,
        active_total=1,
        acknowledged_total=1,
        expected_active=1,
        open_active=0,
        doh_active=0,
        flagged_active=0,
        category_distribution=[
            DnsCategoryCountOut(category="offen", count=0),
            DnsCategoryCountOut(category="moegliche_doh", count=0),
            DnsCategoryCountOut(category="erwartungsgemaess", count=1),
        ],
        app_distribution=[DnsAppCountOut(app_name="systemd-resolved", count=1)],
        contact_rows=[
            DnsWatchContactRowOut(
                remote_ip="192.168.1.1",
                hostname="fritz.box",
                category="erwartungsgemaess",
                app_name="systemd-resolved",
                port=53,
                connection_count=12,
                acknowledged=False,
            )
        ],
    )
    runner = _FakeDnsWatchReportRunner(report)
    app.dependency_overrides[provide_dns_watch_report] = lambda: runner

    with TestClient(app) as client:
        response = client.get("/api/report/dns-watch")

    assert response.status_code == 200
    assert runner.calls == 1
    assert response.json() == {
        "host_scope": "local_host",
        "expected_servers": ["192.168.1.1"],
        "doh_providers": ["cloudflare-dns.com"],
        "contacts_total": 2,
        "active_total": 1,
        "acknowledged_total": 1,
        "expected_active": 1,
        "open_active": 0,
        "doh_active": 0,
        "flagged_active": 0,
        "category_distribution": [
            {"category": "offen", "count": 0},
            {"category": "moegliche_doh", "count": 0},
            {"category": "erwartungsgemaess", "count": 1},
        ],
        "app_distribution": [{"app_name": "systemd-resolved", "count": 1}],
        "contact_rows": [
            {
                "remote_ip": "192.168.1.1",
                "hostname": "fritz.box",
                "category": "erwartungsgemaess",
                "app_name": "systemd-resolved",
                "port": 53,
                "connection_count": 12,
                "acknowledged": False,
            }
        ],
    }


def test_get_dns_watch_report_pdf_liefert_attachment(app: FastAPI) -> None:
    """``/api/report/dns-watch/pdf`` -> 200 + Content-Disposition attachment + application/pdf."""
    runner = _FakeDnsWatchReportPdfRunner(
        content=b"%PDF-FAKE",
        media_type="application/pdf",
        filename="CERNISPRO_DNS-Waechter-Bericht.pdf",
    )
    app.dependency_overrides[provide_dns_watch_report_pdf] = lambda: runner

    with TestClient(app) as client:
        response = client.get("/api/report/dns-watch/pdf")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/pdf")
    assert (
        response.headers["content-disposition"]
        == 'attachment; filename="CERNISPRO_DNS-Waechter-Bericht.pdf"'
    )
    assert response.content  # nicht-leerer Body


# ── DNS-Umgehungs-Bericht: schlanke Endpunkt-Tests (Etappe 5) ──────────────────
# NEUER, EIGENER Bericht NEBEN dem host-lokalen DNS-Waechter-Bericht: BEZUGSRAHMEN-Wahl
# (recording_id optional) + Recordings-Liste, Muster der Aussenkontakte-Bericht-Tests.


class _FakeDnsBypassReportRunner:
    """Fake-Runner: liefert eine feste, schon api-projizierte DNS-Umgehungs-Sicht."""

    def __init__(self, report: DnsBypassReportOut) -> None:
        self._report = report
        self.recording_id: str | None = "noch-nicht-aufgerufen"

    async def __call__(self, recording_id: str | None) -> DnsBypassReportOut:
        self.recording_id = recording_id
        return self._report


class _FakeDnsBypassRecordingsRunner:
    """Fake-Runner: liefert eine feste Dropdown-Liste (keine echten Quellen)."""

    def __init__(self, recordings: list[DnsBypassReportRecordingOut]) -> None:
        self._recordings = recordings

    async def __call__(self) -> list[DnsBypassReportRecordingOut]:
        return self._recordings


class _FakeDnsBypassReportPdfRunner:
    """Fake-PDF-Runner: liefert ein festes Download-Ergebnis (content/media_type/filename)."""

    def __init__(self, content: bytes, media_type: str, filename: str) -> None:
        self._content = content
        self._media_type = media_type
        self._filename = filename
        self.recording_id: str | None = "noch-nicht-aufgerufen"

    async def __call__(self, recording_id: str | None) -> object:
        self.recording_id = recording_id
        return _FakeDnsWatchPdfResult(
            content=self._content, media_type=self._media_type, filename=self._filename
        )


def test_get_dns_bypass_report_liefert_200_und_json_form(app: FastAPI) -> None:
    """``/api/report/dns-bypass?recording_id=...`` -> 200 + JSON-Form, id durchgereicht."""
    report = DnsBypassReportOut(
        recording_label="Büro-Lauf",
        recording_scope="single",
        expected_servers=["192.168.1.1"],
        queries_total=20,
        bypass_total=8,
        expected_total=12,
        bypass_devices=2,
        resolver_distribution=[DnsBypassResolverOut(dst_ip="8.8.8.8", count=8)],
        bypass_rows=[
            DnsBypassReportRowOut(
                src_ip="10.0.0.5",
                device_name="Laptop",
                dst_ip="8.8.8.8",
                is_doh=False,
                doh_source_name="",
                query_count=8,
                sample_qnames=["example.com", "beispiel.de"],
            )
        ],
    )
    runner = _FakeDnsBypassReportRunner(report)
    app.dependency_overrides[provide_dns_bypass_report] = lambda: runner

    with TestClient(app) as client:
        response = client.get("/api/report/dns-bypass", params={"recording_id": "rec-1"})

    assert response.status_code == 200
    assert runner.recording_id == "rec-1"
    assert response.json() == {
        "recording_label": "Büro-Lauf",
        "recording_scope": "single",
        "expected_servers": ["192.168.1.1"],
        "queries_total": 20,
        "bypass_total": 8,
        "expected_total": 12,
        "bypass_devices": 2,
        "resolver_distribution": [{"dst_ip": "8.8.8.8", "count": 8}],
        "bypass_rows": [
            {
                "src_ip": "10.0.0.5",
                "device_name": "Laptop",
                "dst_ip": "8.8.8.8",
                "is_doh": False,
                "doh_source_name": "",
                "query_count": 8,
                "sample_qnames": ["example.com", "beispiel.de"],
            }
        ],
    }


def test_get_dns_bypass_report_ohne_recording_id_reicht_none_durch(app: FastAPI) -> None:
    """Ohne ``recording_id`` -> 200 und der Runner bekommt ``None`` (alle Aufzeichnungen)."""
    report = DnsBypassReportOut(
        recording_label="",
        recording_scope="all",
        expected_servers=[],
        queries_total=0,
        bypass_total=0,
        expected_total=0,
        bypass_devices=0,
        resolver_distribution=[],
        bypass_rows=[],
    )
    runner = _FakeDnsBypassReportRunner(report)
    app.dependency_overrides[provide_dns_bypass_report] = lambda: runner

    with TestClient(app) as client:
        response = client.get("/api/report/dns-bypass")

    assert response.status_code == 200
    assert runner.recording_id is None


def test_get_dns_bypass_report_recordings_liefert_dropdown_liste(app: FastAPI) -> None:
    """``/api/report/dns-bypass/recordings`` -> 200 + die schlanke Dropdown-Liste (leer = Datum)."""
    runner = _FakeDnsBypassRecordingsRunner(
        [
            DnsBypassReportRecordingOut(id="rec-1", label="Büro"),
            DnsBypassReportRecordingOut(id="rec-2", label="Heimnetz"),
        ]
    )
    app.dependency_overrides[provide_dns_bypass_report_recordings] = lambda: runner

    with TestClient(app) as client:
        response = client.get("/api/report/dns-bypass/recordings")

    assert response.status_code == 200
    assert response.json() == [
        {"id": "rec-1", "label": "Büro"},
        {"id": "rec-2", "label": "Heimnetz"},
    ]


def test_get_dns_bypass_report_pdf_liefert_attachment(app: FastAPI) -> None:
    """``/api/report/dns-bypass/pdf?recording_id=...`` -> 200 + attachment, id durchgereicht."""
    runner = _FakeDnsBypassReportPdfRunner(
        content=b"%PDF-FAKE",
        media_type="application/pdf",
        filename="CERNISPRO_Netzwerk-DNS-Umgehungs-Bericht.pdf",
    )
    app.dependency_overrides[provide_dns_bypass_report_pdf] = lambda: runner

    with TestClient(app) as client:
        response = client.get("/api/report/dns-bypass/pdf", params={"recording_id": "rec-9"})

    assert response.status_code == 200
    assert runner.recording_id == "rec-9"
    assert response.headers["content-type"].startswith("application/pdf")
    assert (
        response.headers["content-disposition"]
        == 'attachment; filename="CERNISPRO_Netzwerk-DNS-Umgehungs-Bericht.pdf"'
    )
    assert response.content  # nicht-leerer Body
