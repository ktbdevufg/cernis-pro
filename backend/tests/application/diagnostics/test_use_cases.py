"""Tests der diagnostics-Use-Cases gegen In-Memory-Fakes der Ports.

Kein echtes dig/traceroute-Tooling noetig -- wir testen gegen die Protocols. Kern der
Behauptungen: ``ResolveDns``/``RunTraceroute`` reichen die Abfrage unveraendert durch
(Pass-Through, ``privileged`` durchgereicht), und ``CheckTraceroutePermission`` liefert die
``{ok, error}``-Naht beider Faelle (privilegierte Methode moeglich / nur unprivilegiert /
Binary fehlt). Async via ``asyncio.run`` (Projektmuster, kein pytest-asyncio).
"""

import asyncio
from collections.abc import Sequence

from application.diagnostics import (
    CheckDiagnosticsTools,
    CheckTraceroutePermission,
    ResolveDns,
    RunTraceroute,
)
from domain.diagnostics import (
    ALL_TOOLS,
    DnsRecord,
    DnsRecordType,
    DnsResult,
    PackageManager,
    TracerouteHop,
    TracerouteResult,
)

# ── In-Memory-Fakes der Ports ────────────────────────────────────────────────


class FakeDnsResolver:
    """In-Memory-Implementierung des ``DnsResolver``-Protocols."""

    def __init__(self, result: DnsResult) -> None:
        self._result = result
        self.calls: list[tuple[str, tuple[DnsRecordType, ...]]] = []

    async def resolve(self, query: str, types: Sequence[DnsRecordType]) -> DnsResult:
        self.calls.append((query, tuple(types)))
        return self._result


class FakeTracerouteRunner:
    """In-Memory-Implementierung des ``TracerouteRunner``-Protocols."""

    def __init__(self, result: TracerouteResult) -> None:
        self._result = result
        self.calls: list[tuple[str, bool]] = []

    async def run(self, target: str, privileged: bool) -> TracerouteResult:
        self.calls.append((target, privileged))
        return self._result


class FakeTraceroutePermission:
    """In-Memory-Implementierung des ``TraceroutePermissionPort``-Protocols."""

    def __init__(self, available: bool = True, permission_error: str | None = None) -> None:
        self._available = available
        self._permission_error = permission_error

    def is_available(self) -> bool:
        return self._available

    def check_permission(self) -> str | None:
        return self._permission_error


class FakeToolDetector:
    """In-Memory-Implementierung des ``ToolDetector``-Protocols.

    ``present`` ist die Menge der "vorhandenen" Tools; alles andere gilt als fehlend.
    ``calls`` belegt, welche Tools ueberhaupt geprueft wurden (Erst- vs. Laufzeit-Fall).
    """

    def __init__(self, present: set[str]) -> None:
        self._present = present
        self.calls: list[str] = []

    def is_available(self, tool: str) -> bool:
        self.calls.append(tool)
        return tool in self._present


class FakePackageManagerDetector:
    """In-Memory-Implementierung des ``PackageManagerDetector``-Protocols."""

    def __init__(self, manager: PackageManager | None) -> None:
        self._manager = manager

    def detect(self) -> PackageManager | None:
        return self._manager


# ── ResolveDns ───────────────────────────────────────────────────────────────


def test_resolve_dns_pass_through() -> None:
    result = DnsResult(
        query="example.com",
        requested_types=("A",),
        records=(DnsRecord(record_type="A", value="1.2.3.4"),),
    )
    fake = FakeDnsResolver(result)
    out = asyncio.run(ResolveDns(fake)("example.com", ["A"]))
    assert out is result
    assert fake.calls == [("example.com", ("A",))]


def test_resolve_dns_empty_records_is_passed_through() -> None:
    # Leere Antwort ist KEIN Fehler -- der Use-Case reicht sie unveraendert durch.
    result = DnsResult(query="nope.invalid", requested_types=("A", "AAAA"), records=())
    fake = FakeDnsResolver(result)
    out = asyncio.run(ResolveDns(fake)("nope.invalid", ["A", "AAAA"]))
    assert out.records == ()


# ── RunTraceroute ────────────────────────────────────────────────────────────


def test_run_traceroute_pass_through_privileged_true() -> None:
    result = TracerouteResult(
        target="example.com",
        privileged=True,
        hops=(TracerouteHop(hop=1, address="1.2.3.4", rtt_ms=0.5),),
    )
    fake = FakeTracerouteRunner(result)
    out = asyncio.run(RunTraceroute(fake)("example.com", True))
    assert out is result
    assert fake.calls == [("example.com", True)]


def test_run_traceroute_pass_through_privileged_false() -> None:
    # ``privileged`` wird UNVERAENDERT durchgereicht (kein Default-Raten).
    result = TracerouteResult(target="example.com", privileged=False, hops=())
    fake = FakeTracerouteRunner(result)
    out = asyncio.run(RunTraceroute(fake)("example.com", False))
    assert out.privileged is False
    assert fake.calls == [("example.com", False)]


# ── CheckTraceroutePermission ({ok, error}-Naht) ──────────────────────────────


def test_check_permission_privileged_method_available() -> None:
    # check_permission None -> privilegierte (genauere) Methode moeglich -> ok=True.
    fake = FakeTraceroutePermission(available=True, permission_error=None)
    result = CheckTraceroutePermission(fake)()
    assert result == {"ok": True, "error": ""}


def test_check_permission_only_unprivileged_with_reason() -> None:
    # check_permission Text -> nur unprivilegierte Methode, ok=False + Begruendung.
    msg = "Die genauere (privilegierte) traceroute-Methode benoetigt Root."
    fake = FakeTraceroutePermission(available=True, permission_error=msg)
    result = CheckTraceroutePermission(fake)()
    assert result == {"ok": False, "error": msg}


def test_check_permission_not_available() -> None:
    # Binary fehlt -> nicht verfuegbar, ok=False + nicht-leerer Grund.
    fake = FakeTraceroutePermission(available=False)
    result = CheckTraceroutePermission(fake)()
    assert result["ok"] is False
    assert result["error"]


def test_check_permission_pass_throughs() -> None:
    fake = FakeTraceroutePermission(available=True, permission_error="x")
    uc = CheckTraceroutePermission(fake)
    assert uc.is_available() is True
    assert uc.check_permission() == "x"


# ── CheckDiagnosticsTools (1b) ────────────────────────────────────────────────


def test_check_tools_none_checks_all_registered_tools() -> None:
    # requested None -> ALL_TOOLS (Erstinstallations-Fall: alle pruefen).
    detector = FakeToolDetector(present={"dig", "traceroute"})
    pm = FakePackageManagerDetector("apt")
    report = CheckDiagnosticsTools(detector, pm)(None)
    assert [s.name for s in report.statuses] == list(ALL_TOOLS)
    assert sorted(detector.calls) == sorted(ALL_TOOLS)
    assert report.install_command is None  # alles da


def test_check_tools_empty_also_checks_all() -> None:
    # Leere Liste verhaelt sich wie None (Erstinstallation: alle).
    detector = FakeToolDetector(present={"dig", "traceroute"})
    report = CheckDiagnosticsTools(detector, FakePackageManagerDetector("apt"))([])
    assert [s.name for s in report.statuses] == list(ALL_TOOLS)


def test_check_tools_subset_checks_only_named() -> None:
    # requested Teilmenge -> nur die genannten geprueft (Laufzeit-Fall).
    detector = FakeToolDetector(present=set())
    report = CheckDiagnosticsTools(detector, FakePackageManagerDetector("apt"))(["dig"])
    assert detector.calls == ["dig"]
    assert [s.name for s in report.statuses] == ["dig"]
    # dig fehlt -> apt-Befehl (dnsutils).
    assert report.install_command == "sudo apt install dnsutils"


def test_check_tools_ignores_unknown_tool() -> None:
    # Unbekanntes Tool wird defensiv ignoriert (nicht geprueft, nicht erfunden).
    detector = FakeToolDetector(present={"dig"})
    report = CheckDiagnosticsTools(detector, FakePackageManagerDetector("apt"))(["dig", "nmap"])
    assert detector.calls == ["dig"]
    assert [s.name for s in report.statuses] == ["dig"]


def test_check_tools_manager_none_means_no_install_command() -> None:
    # Tool fehlt, aber kein Manager erkannt -> install_command ehrlich None (kein Raten).
    detector = FakeToolDetector(present=set())
    report = CheckDiagnosticsTools(detector, FakePackageManagerDetector(None))(["traceroute"])
    assert report.manager is None
    assert report.install_command is None
    assert report.statuses[0].available is False
