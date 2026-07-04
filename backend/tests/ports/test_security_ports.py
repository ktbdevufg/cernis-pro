"""Strukturtest der security-Ports (SEC.3): Fakes erfuellen die Protocols.

Reine ``typing.Protocol``-Vertraege haben kein Verhalten -- der Verhaltenstest kommt
mit den Adaptern (SEC.4). Hier NUR strukturelle Konformitaet:

* **statisch (mypy):** Jede ``_assert_*``-Funktion nimmt den Port-TYP und bekommt die
  Fake-Instanz uebergeben. Erfuellt ein Fake das Protocol nicht (falsche Signatur,
  fehlende Methode), schlaegt ``uv run mypy`` fehl -- das ist die eigentliche Pruefung.
* **dynamisch (pytest):** Ein Smoke ruft jede Methode einmal und prueft die Typen.

async-Smokes via ``asyncio.run`` (stdlib) -- kein pytest-asyncio (Muster S.3/SEC).
KEIN ``@runtime_checkable`` -> kein ``isinstance``-Konformitaetscheck (mypy traegt das).

ARP-Tabelle + Vendor sind BEWUSST KEINE security-Ports (Wiederverwendung
``ports.scanning.{ArpTablePort, VendorLookupPort}``) -- daher hier nicht getestet.
"""

import asyncio
from collections.abc import Sequence

from domain.security import ArpAlert, ArpEntry
from ports.security import (
    ArpAlertRecord,
    ArpBaselineRecord,
    ArpGuardRepository,
    CredFinding,
    CveFinding,
    CveLookup,
    DefaultCredsChecker,
    PortQuery,
    TlsCertInfo,
    TlsFinding,
    TlsInspector,
)

# ── Fakes ──────────────────────────────────────────────────────────────────


class FakeArpGuardRepository:
    """In-Memory-Fake des ArpGuardRepository."""

    def __init__(self) -> None:
        self._baseline: dict[str, ArpEntry] = {}
        self._alerts: list[ArpAlert] = []

    def load_baseline(self) -> list[ArpEntry]:
        return list(self._baseline.values())

    def load_baseline_records(self) -> list[ArpBaselineRecord]:
        return [
            ArpBaselineRecord(e.ip, e.mac, e.vendor, first_seen=1.0, last_seen=2.0)
            for e in self._baseline.values()
        ]

    def save_baseline_entry(self, entry: ArpEntry) -> None:
        self._baseline[entry.ip] = entry

    def clear_baseline(self) -> None:
        self._baseline.clear()

    def save_alert(self, alert: ArpAlert) -> None:
        self._alerts.append(alert)

    def recent_alerts(self, limit: int) -> list[ArpAlertRecord]:
        return [
            ArpAlertRecord(
                a.alert_type,
                a.ip,
                a.old_mac,
                a.new_mac,
                a.old_vendor,
                a.new_vendor,
                a.severity,
                a.message,
                ts=1.0,
                datetime="t",
            )
            for a in self._alerts[-limit:][::-1]
        ]

    def clear_alerts(self) -> None:
        self._alerts.clear()


class FakeCveLookup:
    async def lookup_for_host(self, ports: Sequence[PortQuery]) -> list[CveFinding]:
        return [
            CveFinding(
                cve_id="CVE-2023-0001",
                description="x",
                severity="HIGH",
                cvss_score=7.5,
                published="2023-01-01",
                port=p.port,
                service=p.service,
                url="https://nvd.nist.gov/vuln/detail/CVE-2023-0001",
            )
            for p in ports
        ]


class FakeTlsInspector:
    async def inspect_host(self, host: str, ports: Sequence[int]) -> list[TlsFinding]:
        return [
            TlsFinding(
                host=host,
                port=p,
                reachable=True,
                tls_version="TLSv1.3",
                cipher_bits=256,
                cert=TlsCertInfo(subject="example.com", san=("example.com",)),
                grade="A",
                warnings=(),
            )
            for p in ports
        ]


class FakeDefaultCredsChecker:
    async def check_host(
        self, host: str, ports: Sequence[PortQuery], vendor: str = ""
    ) -> list[CredFinding]:
        return [
            CredFinding(
                host=host,
                port=p.port,
                service=p.service,
                username="admin",
                password="admin",
                success=True,
                method="http_basic",
                note="HTTP 200",
            )
            for p in ports
        ]

    async def check_host_mit_kandidaten(
        self,
        host: str,
        ports: Sequence[PortQuery],
        kandidaten: Sequence[tuple[str, str]],
    ) -> list[CredFinding]:
        return [
            CredFinding(
                host=host,
                port=p.port,
                service=p.service,
                username=user,
                password=pwd,
                success=True,
                method="http_basic",
                note="HTTP 200",
            )
            for p in ports
            for user, pwd in kandidaten
        ]


# ── statische Konformitaet (mypy traegt die Pruefung) ───────────────────────


def _assert_repo(_p: ArpGuardRepository) -> None: ...
def _assert_cve(_p: CveLookup) -> None: ...
def _assert_tls(_p: TlsInspector) -> None: ...
def _assert_creds(_p: DefaultCredsChecker) -> None: ...


def test_fakes_satisfy_protocols_statically() -> None:
    # Wenn ein Fake das Protocol strukturell nicht erfuellt, faellt mypy hier.
    _assert_repo(FakeArpGuardRepository())
    _assert_cve(FakeCveLookup())
    _assert_tls(FakeTlsInspector())
    _assert_creds(FakeDefaultCredsChecker())


# ── dynamische Smokes ───────────────────────────────────────────────────────


def test_arp_guard_repository_roundtrip() -> None:
    repo = FakeArpGuardRepository()
    repo.save_baseline_entry(ArpEntry("192.168.1.10", "AA:AA:AA:11:11:11", "AcmeCorp"))
    assert repo.load_baseline() == [ArpEntry("192.168.1.10", "AA:AA:AA:11:11:11", "AcmeCorp")]

    alert = ArpAlert(
        alert_type="ip_conflict",
        ip="192.168.1.10, 192.168.1.11",
        old_mac="",
        new_mac="AA:AA:AA:11:11:11",
        old_vendor="",
        new_vendor="AcmeCorp",
        severity="high",
        message="...",
    )
    repo.save_alert(alert)
    # recent_alerts gibt ArpAlertRecord (mit Zeit), nicht ArpAlert.
    recs = repo.recent_alerts(50)
    assert len(recs) == 1 and recs[0].alert_type == "ip_conflict"
    assert recs[0].datetime == "t"  # Zeit im Record

    # clear_alerts laesst baseline unberuehrt (SEC.1-Vertrag 7).
    repo.clear_alerts()
    assert repo.recent_alerts(50) == []
    assert len(repo.load_baseline()) == 1

    repo.clear_baseline()
    assert repo.load_baseline() == []


def test_cve_lookup_smoke() -> None:
    findings = asyncio.run(
        FakeCveLookup().lookup_for_host([PortQuery(22, "ssh"), PortQuery(443, "https")])
    )
    assert [f.port for f in findings] == [22, 443]
    assert all(isinstance(f, CveFinding) for f in findings)


def test_tls_inspector_smoke() -> None:
    findings = asyncio.run(FakeTlsInspector().inspect_host("example.com", [443, 8443]))
    assert [f.port for f in findings] == [443, 8443]
    assert findings[0].cert is not None
    assert findings[0].cert.subject == "example.com"


def test_default_creds_checker_smoke() -> None:
    findings = asyncio.run(
        FakeDefaultCredsChecker().check_host("placeholder", [PortQuery(80, "http")], "ubiquiti")
    )
    assert len(findings) == 1
    assert findings[0].method == "http_basic"
    assert findings[0].success is True
