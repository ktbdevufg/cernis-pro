"""Use-Case-Vertraege der security-Domaene (SEC.5).

RunArpScan: Orchestrierung als Sequenz-Band-Vertrag (wer ruft wen, in welcher
Reihenfolge) + die E.1-Momentaufnahme (clear_alerts VOR dem Scan). Die ERKENNUNG
selbst ist in SEC.2 getestet -- hier NUR die Orchestrierung. Pass-Throughs: trivialer
Durchstich zu den Ports.

Fakes statt echter Adapter (Use-Case kennt nur Ports). Async via asyncio.run.
"""

import asyncio

from application.security import (
    CheckDefaultCreds,
    ClearArpBaseline,
    GetArpAlerts,
    GetArpBaseline,
    InspectTls,
    LookupCves,
    RunArpScan,
)
from domain.security import ArpAlert, ArpEntry
from ports.security import CredFinding, CveFinding, PortQuery, TlsFinding

# ── Fakes ───────────────────────────────────────────────────────────────────


class FakeArpTable:
    def __init__(self, table: dict[str, str]) -> None:
        self._table = table

    async def get_arp_table(self) -> dict[str, str]:
        return dict(self._table)


class FakeVendor:
    def lookup(self, mac: str) -> str:
        return {"AA:AA:AA:11:11:11": "AcmeCorp", "BB:BB:BB:22:22:22": "BetaInc"}.get(
            mac.upper(), "Unknown"
        )


class RecordingRepo:
    """Fake-ArpGuardRepository mit Sequenz-Band (seq) -- wie der A.7a-seq-Test."""

    def __init__(self) -> None:
        self.seq: list[str] = []
        self._baseline: dict[str, ArpEntry] = {}
        self._alerts: list[ArpAlert] = []

    def load_baseline(self) -> list[ArpEntry]:
        self.seq.append("load_baseline")
        return list(self._baseline.values())

    def save_baseline_entry(self, entry: ArpEntry) -> None:
        self.seq.append(f"save_baseline:{entry.ip}")
        self._baseline[entry.ip] = entry

    def clear_baseline(self) -> None:
        self.seq.append("clear_baseline")
        self._baseline.clear()

    def save_alert(self, alert: ArpAlert) -> None:
        self.seq.append(f"save_alert:{alert.alert_type}")
        self._alerts.append(alert)

    def recent_alerts(self, limit: int) -> list[ArpAlert]:
        self.seq.append(f"recent_alerts:{limit}")
        return self._alerts[-limit:][::-1]

    def clear_alerts(self) -> None:
        self.seq.append("clear_alerts")
        self._alerts.clear()


# ── RunArpScan: Orchestrierungs-Sequenz ─────────────────────────────────────


def test_run_arp_scan_sequence_clear_before_detect_and_save() -> None:
    # Baseline kennt .10 mit AA; current bringt .10 mit BB (BetaInc) -> mac_changed.
    repo = RecordingRepo()
    repo._baseline["192.168.1.10"] = ArpEntry("192.168.1.10", "AA:AA:AA:11:11:11", "AcmeCorp")

    uc = RunArpScan(FakeArpTable({"192.168.1.10": "BB:BB:BB:22:22:22"}), FakeVendor(), repo)
    alerts = asyncio.run(uc())

    # Erkennung greift (Orchestrierung reicht Alert durch) -- Detail in SEC.2 getestet.
    assert [a.alert_type for a in alerts] == ["mac_changed"]

    # SEQUENZ-VERTRAG: clear_alerts VOR load_baseline; save_alert VOR save_baseline;
    # clear_alerts vor save_alert (Momentaufnahme-Naht).
    assert repo.seq == [
        "clear_alerts",
        "load_baseline",
        "save_alert:mac_changed",
        "save_baseline:192.168.1.10",
    ]


def test_run_arp_scan_saves_baseline_for_new_device_without_alert() -> None:
    # Neue IP (nicht in Baseline) -> KEIN Alert (SEC.2), aber baseline-Eintrag.
    repo = RecordingRepo()
    uc = RunArpScan(FakeArpTable({"192.168.1.50": "AA:AA:AA:11:11:11"}), FakeVendor(), repo)
    alerts = asyncio.run(uc())
    assert alerts == []
    assert repo.seq == [
        "clear_alerts",
        "load_baseline",
        "save_baseline:192.168.1.50",  # kein save_alert
    ]


# ── E.1 Momentaufnahme: zwei Scans -> nur der zweite sichtbar ───────────────


def test_two_scans_snapshot_only_second_visible() -> None:
    repo = RecordingRepo()
    table = FakeArpTable({"192.168.1.10": "AA:AA:AA:11:11:11"})

    # Scan 1: .10 ist neu -> kein Alert, baseline gesetzt.
    asyncio.run(RunArpScan(table, FakeVendor(), repo)())
    # Manuell einen Alert in die DB legen (als waere Scan 1 einer gewesen).
    repo._alerts.append(ArpAlert("ip_conflict", "x", "", "M", "", "V", "high", "scan1"))
    assert len(repo.recent_alerts(50)) == 1

    # Scan 2: .10 wechselt MAC -> mac_changed. clear_alerts VOR dem Scan entfernt den
    # Scan-1-Alert -> danach NUR der mac_changed aus Scan 2 sichtbar.
    table2 = FakeArpTable({"192.168.1.10": "BB:BB:BB:22:22:22"})
    asyncio.run(RunArpScan(table2, FakeVendor(), repo)())

    visible = repo.recent_alerts(50)
    assert [a.alert_type for a in visible] == ["mac_changed"]  # Scan-1-ip_conflict weg


# MUTATIONSPROBE (dokumentiert + unten ausgefuehrt): entfernt man den
# ``self._repository.clear_alerts()``-Aufruf aus RunArpScan, bleibt der Scan-1-Alert
# erhalten -> test_two_scans_snapshot_only_second_visible wird rot (zwei alert_types
# sichtbar). Das beweist, dass die Momentaufnahme-Naht (E.1) wirklich an RunArpScan
# haengt, nicht zufaellig gruen ist.


# ── detect-Aufruf: RunArpScan ruft mit (current, baseline) ──────────────────


def test_run_arp_scan_passes_current_and_baseline_to_detect() -> None:
    # ip_conflict braucht 2 IPs mit gleicher MAC in CURRENT (tabellen-basiert) ->
    # beweist, dass current vollstaendig an detect geht.
    repo = RecordingRepo()
    uc = RunArpScan(
        FakeArpTable({"192.168.1.10": "BB:BB:BB:22:22:22", "192.168.1.11": "BB:BB:BB:22:22:22"}),
        FakeVendor(),
        repo,
    )
    alerts = asyncio.run(uc())
    assert [a.alert_type for a in alerts] == ["ip_conflict"]
    assert alerts[0].new_vendor == "BetaInc"  # Vendor via VendorLookupPort vorberechnet


# ── Pass-Throughs ───────────────────────────────────────────────────────────


def test_get_arp_alerts_passthrough() -> None:
    repo = RecordingRepo()
    repo._alerts.append(ArpAlert("ip_conflict", "x", "", "M", "", "V", "high", "m"))
    assert len(GetArpAlerts(repo)(limit=10)) == 1
    assert "recent_alerts:10" in repo.seq


def test_get_arp_baseline_passthrough() -> None:
    repo = RecordingRepo()
    repo._baseline["192.168.1.10"] = ArpEntry("192.168.1.10", "AA", "AcmeCorp")
    assert GetArpBaseline(repo)() == [ArpEntry("192.168.1.10", "AA", "AcmeCorp")]


def test_clear_arp_baseline_passthrough() -> None:
    repo = RecordingRepo()
    repo._baseline["192.168.1.10"] = ArpEntry("192.168.1.10", "AA", "AcmeCorp")
    ClearArpBaseline(repo)()
    assert repo.load_baseline() == []
    assert "clear_baseline" in repo.seq


class _FakeCve:
    async def lookup_for_host(self, ports: object) -> list[CveFinding]:
        return [CveFinding("CVE-1", "d", "HIGH", 7.5, "2023", port=22)]


class _FakeTls:
    async def inspect_host(self, host: str, ports: object) -> list[TlsFinding]:
        return [TlsFinding(host=host, port=443, grade="A")]


class _FakeCreds:
    async def check_host(self, host: str, ports: object, vendor: str = "") -> list[CredFinding]:
        return [CredFinding(host, 80, "http", "admin", "admin", True, "http_basic")]


def test_lookup_cves_passthrough() -> None:
    r = asyncio.run(LookupCves(_FakeCve())([PortQuery(22, "ssh")]))
    assert r[0].cve_id == "CVE-1"


def test_inspect_tls_passthrough() -> None:
    r = asyncio.run(InspectTls(_FakeTls())("example.com", [443]))
    assert r[0].grade == "A"


def test_check_default_creds_passthrough() -> None:
    r = asyncio.run(CheckDefaultCreds(_FakeCreds())("h", [PortQuery(80, "http")], "ubnt"))
    assert r[0].method == "http_basic"
