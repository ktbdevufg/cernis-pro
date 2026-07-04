"""End-to-end-Tests der security-REST-API (v2, SEC.6) via TestClient.

Fake-Use-Cases via ``dependency_overrides`` (kein echtes cernis.db, kein Netz). Prueft
die Wire-Form je Route gegen die Altcode-Form. Besonders:
  * cve/lookup-v2 OHNE is_public/risk_level (toter Risk-Pfad DF3/E.6 -- als Vertrag).
  * tls san/warnings als JSON-list (tuple->list-Randwandel, Wire-treu).
  * arp-alerts-dict OHNE id, MIT datetime (die Zeit-Luecken-Heilung end-to-end).
  * die 2 toten Endpunkte (cve/lookup-v1, tls/inspect-single) fehlen bewusst -> 404.
"""

from collections.abc import Sequence
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.security import (
    provide_check_default_creds,
    provide_clear_arp_baseline,
    provide_get_arp_alerts,
    provide_get_arp_baseline,
    provide_inspect_tls,
    provide_lookup_cves,
    provide_run_arp_scan,
    provide_target_scope_guard,
)
from api.security import (
    router as security_router,
)
from domain.security import ArpAlert
from infrastructure.security import is_private_target
from ports.security import (
    ArpAlertRecord,
    ArpBaselineRecord,
    CredFinding,
    CveFinding,
    TlsCertInfo,
    TlsFinding,
)

# ── Fake-Use-Cases (callables wie die echten __call__) ──────────────────────


class _FakeRunArpScan:
    async def __call__(self) -> list[ArpAlert]:
        return [ArpAlert("mac_changed", "192.168.1.10", "AA", "BB", "Acme", "Beta", "high", "msg")]


class _FakeGetArpAlerts:
    def __call__(self, limit: int = 50) -> list[ArpAlertRecord]:
        return [
            ArpAlertRecord(
                "mac_changed",
                "192.168.1.10",
                "AA",
                "BB",
                "Acme",
                "Beta",
                "high",
                "msg",
                ts=1700000000.0,
                datetime="2026-01-01 12:00:00",
            )
        ]


class _FakeGetArpBaseline:
    def __call__(self) -> list[ArpBaselineRecord]:
        return [ArpBaselineRecord("192.168.1.10", "AA", "Acme", 1700000000.0, 1700000100.0)]


class _FakeClearArpBaseline:
    def __init__(self) -> None:
        self.called = False

    def __call__(self) -> None:
        self.called = True


class _FakeLookupCves:
    async def __call__(self, ports: Sequence[dict[str, Any]]) -> list[CveFinding]:
        return [
            CveFinding(
                "CVE-2023-1",
                "desc",
                "CRITICAL",
                9.8,
                "2023-01-01",
                port=22,
                service="ssh",
                url="https://nvd.nist.gov/vuln/detail/CVE-2023-1",
            )
        ]


class _FakeInspectTls:
    async def __call__(self, host: str, ports: Sequence[dict[str, Any]]) -> list[TlsFinding]:
        return [
            TlsFinding(
                host=host,
                port=443,
                reachable=True,
                tls_version="TLSv1.3",
                cipher_name="AES256",
                cipher_bits=256,
                cert=TlsCertInfo(subject="example.com", san=("example.com", "www.example.com")),
                grade="A",
                warnings=("w1", "w2"),
            )
        ]


class _FakeCheckDefaultCreds:
    async def __call__(
        self, host: str, ports: Sequence[dict[str, Any]], vendor: str = ""
    ) -> list[CredFinding]:
        return [CredFinding(host, 80, "http", "admin", "admin", True, "http_basic", "HTTP 200")]


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.include_router(security_router)
    app.dependency_overrides[provide_run_arp_scan] = lambda: _FakeRunArpScan()
    app.dependency_overrides[provide_get_arp_alerts] = lambda: _FakeGetArpAlerts()
    app.dependency_overrides[provide_get_arp_baseline] = lambda: _FakeGetArpBaseline()
    app.dependency_overrides[provide_clear_arp_baseline] = lambda: _FakeClearArpBaseline()
    app.dependency_overrides[provide_lookup_cves] = lambda: _FakeLookupCves()
    app.dependency_overrides[provide_inspect_tls] = lambda: _FakeInspectTls()
    app.dependency_overrides[provide_check_default_creds] = lambda: _FakeCheckDefaultCreds()
    # default-creds ist eine Opt-in-Sonderfunktion: sitzungsweites Arm-Flag + Ziel-
    # Bereichs-Guard (privates Netz). Im bare-FastAPI-Test beides verdrahten wie der
    # Composition Root, damit der 200-Pfad (privates Ziel, freigeschaltet) laeuft.
    app.state.default_creds_armed = True
    app.dependency_overrides[provide_target_scope_guard] = lambda: is_private_target
    return TestClient(app)


# ── ARP-Routen: Wire-Form ───────────────────────────────────────────────────


def test_arp_scan_returns_alerts_and_count(client: TestClient) -> None:
    r = client.post("/api/security/arp-scan")
    assert r.status_code == 200
    body = r.json()
    assert set(body.keys()) == {"alerts", "count"}  # {alerts, count}-Form
    assert body["count"] == 1
    assert body["alerts"][0]["alert_type"] == "mac_changed"


def test_arp_alerts_dict_has_datetime_no_id(client: TestClient) -> None:
    # Zeit-Luecken-Heilung end-to-end: datetime IST da (Frontend rendert es), id NICHT.
    r = client.get("/api/security/arp-alerts")
    assert r.status_code == 200
    alert = r.json()[0]
    assert alert["datetime"] == "2026-01-01 12:00:00"  # Zeit kommt durch
    assert alert["ts"] == 1700000000.0
    assert "id" not in alert  # bewusste Streichung
    assert set(alert.keys()) == {
        "alert_type",
        "ip",
        "old_mac",
        "new_mac",
        "old_vendor",
        "new_vendor",
        "severity",
        "message",
        "ts",
        "datetime",
    }


def test_arp_baseline_dict_has_first_last_seen(client: TestClient) -> None:
    r = client.get("/api/security/arp-baseline")
    assert r.status_code == 200
    b = r.json()[0]
    assert b == {
        "ip": "192.168.1.10",
        "mac": "AA",
        "vendor": "Acme",
        "first_seen": 1700000000.0,
        "last_seen": 1700000100.0,
    }


def test_arp_baseline_delete_returns_ok(client: TestClient) -> None:
    r = client.delete("/api/security/arp-baseline")
    assert r.status_code == 200
    assert r.json() == {"ok": True}


# ── cve/lookup-v2: OHNE Risk-Pfad ───────────────────────────────────────────


def test_cve_lookup_v2_no_risk_fields(client: TestClient) -> None:
    # Frontend schickt external_ip mit -> wird ignoriert, kein Crash.
    r = client.post(
        "/api/cve/lookup-v2",
        json={"ports": [{"port": 22, "service": "ssh"}], "external_ip": "1.2.3.4"},
    )
    assert r.status_code == 200
    cve = r.json()[0]
    # DF3/E.6: is_public/risk_level NICHT in der Response (toter Pfad raus).
    assert "is_public" not in cve
    assert "risk_level" not in cve
    assert set(cve.keys()) == {
        "cve_id",
        "description",
        "severity",
        "cvss_score",
        "published",
        "port",
        "service",
        "url",
    }
    assert cve["severity"] == "CRITICAL"


def test_cve_lookup_v2_without_external_ip_works(client: TestClient) -> None:
    # Nur {ports} -- external_ip/port_forwards sind optional (toter Pfad).
    r = client.post("/api/cve/lookup-v2", json={"ports": [{"port": 22}]})
    assert r.status_code == 200
    assert len(r.json()) == 1


# ── tls/inspect-host: san/warnings als JSON-list ────────────────────────────


def test_tls_inspect_host_san_warnings_are_json_lists(client: TestClient) -> None:
    r = client.post(
        "/api/tls/inspect-host",
        json={"host": "example.com", "ports": [{"port": 443}]},
    )
    assert r.status_code == 200
    t = r.json()[0]
    # tuple -> JSON-list (Wire-treu): echte Arrays, nicht tuple-Repr/String.
    assert t["warnings"] == ["w1", "w2"]
    assert isinstance(t["warnings"], list)
    assert t["cert"]["san"] == ["example.com", "www.example.com"]
    assert isinstance(t["cert"]["san"], list)
    assert t["grade"] == "A"


# ── default-creds ───────────────────────────────────────────────────────────


def test_default_creds_returns_findings(client: TestClient) -> None:
    r = client.post(
        "/api/security/default-creds",
        json={"host": "192.168.1.10", "ports": [{"port": 80, "service": "http"}], "vendor": "ubnt"},
    )
    assert r.status_code == 200
    c = r.json()[0]
    assert c["method"] == "http_basic"
    assert c["success"] is True


# ── tote Endpunkte: bewusst weg (404) ───────────────────────────────────────


def test_dead_endpoints_are_absent(client: TestClient) -> None:
    # cve/lookup (v1) + tls/inspect (single) wurden BEWUSST weggelassen (Frontend ruft
    # sie nie -- F der Lesung). Sie existieren nicht -> 404/405.
    assert client.post("/api/cve/lookup", json={"ports": []}).status_code in (404, 405)
    assert client.post("/api/tls/inspect", json={"host": "h", "port": 443}).status_code in (
        404,
        405,
    )


# ── ECHTER DB->Record->dict-Pfad (Zeit-Luecken-Heilung end-to-end, KEIN Mock) ──


@pytest.fixture
def real_client(tmp_path: Any) -> TestClient:
    """Client mit ECHTEM SqliteArpGuardRepository (tmp-DB) + echten ARP-Use-Cases --
    beweist die Zeit-Heilung ueber den ganzen Pfad DB -> recent_alerts/load_baseline_
    records -> Use-Case -> api-Rand, nicht ueber gemockte Records."""
    from application.security import GetArpAlerts, GetArpBaseline
    from infrastructure.security import SqliteArpGuardRepository

    repo = SqliteArpGuardRepository(tmp_path / "cernis.db")
    app = FastAPI()
    app.include_router(security_router)
    app.dependency_overrides[provide_get_arp_alerts] = lambda: GetArpAlerts(repo)
    app.dependency_overrides[provide_get_arp_baseline] = lambda: GetArpBaseline(repo)
    # repo am Client merken, damit der Test direkt schreiben kann.
    client = TestClient(app)
    client.repo = repo
    return client


def test_arp_alerts_end_to_end_datetime_from_db(real_client: TestClient) -> None:
    # Echte Zeile in die echte DB schreiben (der Adapter setzt ts + datetime selbst).
    real_client.repo.save_alert(
        ArpAlert("mac_changed", "192.168.1.10", "AA", "BB", "Acme", "Beta", "high", "msg")
    )
    r = real_client.get("/api/security/arp-alerts")
    assert r.status_code == 200
    alert = r.json()[0]
    # datetime kommt aus der DB TREU durch den ganzen Pfad (nicht 0/leer) -- die Heilung.
    assert alert["datetime"]  # nicht-leer
    assert len(alert["datetime"]) == len("2026-01-01 00:00:00")
    assert isinstance(alert["ts"], float) and alert["ts"] > 0
    assert "id" not in alert
    assert alert["alert_type"] == "mac_changed"


def test_arp_baseline_end_to_end_first_last_seen_from_db(real_client: TestClient) -> None:
    from domain.security import ArpEntry

    real_client.repo.save_baseline_entry(ArpEntry("192.168.1.10", "AA:AA:AA:11:11:11", "AcmeCorp"))
    r = real_client.get("/api/security/arp-baseline")
    assert r.status_code == 200
    b = r.json()[0]
    # first_seen/last_seen kommen aus der DB durch den api-Rand (nicht fehlend/0).
    assert b["ip"] == "192.168.1.10"
    assert b["mac"] == "AA:AA:AA:11:11:11"
    assert b["vendor"] == "AcmeCorp"
    assert isinstance(b["first_seen"], float) and b["first_seen"] > 0
    assert isinstance(b["last_seen"], float) and b["last_seen"] > 0
