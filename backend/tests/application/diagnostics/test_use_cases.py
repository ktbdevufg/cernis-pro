"""Tests der diagnostics-Use-Cases gegen In-Memory-Fakes der Ports.

Kein echtes dig/traceroute-Tooling noetig -- wir testen gegen die Protocols. Kern der
Behauptungen: ``ResolveDns``/``RunTraceroute`` reichen die Abfrage unveraendert durch
(Pass-Through, ``privileged`` durchgereicht), und ``CheckTraceroutePermission`` liefert die
``{ok, error}``-Naht beider Faelle (privilegierte Methode moeglich / nur unprivilegiert /
Binary fehlt). Async via ``asyncio.run`` (Projektmuster, kein pytest-asyncio).
"""

import asyncio
from collections.abc import Sequence

import pytest

from application.diagnostics import (
    DEFAULT_CPNETCHECK_URL,
    CheckDiagnosticsTools,
    CheckExternalReachability,
    CheckTraceroutePermission,
    ExternalCheckError,
    GrabBanner,
    ResolveDns,
    RunTraceroute,
)
from domain.diagnostics import (
    ALL_TOOLS,
    BannerResult,
    DnsRecord,
    DnsRecordType,
    DnsResult,
    ExternalIpResult,
    ExternalPortResult,
    PackageManager,
    TracerouteHop,
    TracerouteResult,
)
from domain.settings import Setting, SettingValue

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


class FakeBannerGrabber:
    """In-Memory-Implementierung des ``BannerGrabber``-Protocols."""

    def __init__(self, result: BannerResult) -> None:
        self._result = result
        self.calls: list[tuple[str, int]] = []

    async def grab(self, target: str, port: int) -> BannerResult:
        self.calls.append((target, port))
        return self._result


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


class FakeReachabilityProvider:
    """In-Memory-Implementierung des ``ExternalReachabilityProvider``-Protocols (2b).

    ``ip``/``port_results`` sind die zurueckgegebenen Werte; ``raise_error`` simuliert einen
    Dienstfehler (``ExternalCheckError``). ``ip_calls``/``port_calls`` belegen, OB und WIE
    der Provider gerufen wurde (zentral fuer den configured=False-Fall: kein Aufruf).
    """

    def __init__(
        self,
        ip: ExternalIpResult | None = None,
        port_results: tuple[ExternalPortResult, ...] = (),
        raise_error: bool = False,
    ) -> None:
        self._ip = ip or ExternalIpResult(ip="203.0.113.7", family="ipv4")
        self._port_results = port_results
        self._raise_error = raise_error
        self.ip_calls: list[tuple[str, str]] = []
        self.port_calls: list[tuple[str, str, tuple[int, ...]]] = []

    async def get_external_ip(self, base_url: str, token: str) -> ExternalIpResult:
        self.ip_calls.append((base_url, token))
        if self._raise_error:
            raise ExternalCheckError("Dienst fehlgeschlagen")
        return self._ip

    async def check_ports(
        self, base_url: str, token: str, ports: Sequence[int]
    ) -> tuple[ExternalIpResult, tuple[ExternalPortResult, ...]]:
        self.port_calls.append((base_url, token, tuple(ports)))
        if self._raise_error:
            raise ExternalCheckError("Dienst fehlgeschlagen")
        return self._ip, self._port_results


class FakeSettingsRepository:
    """In-Memory-Implementierung des ``SettingsRepository``-Protocols (nur ``get`` relevant)."""

    def __init__(self, values: dict[str, SettingValue] | None = None) -> None:
        self._data: dict[str, SettingValue] = dict(values or {})

    def get_all(self) -> dict[str, SettingValue]:
        return dict(self._data)

    def get(self, key: str) -> Setting | None:
        if key not in self._data:
            return None
        return Setting(key=key, value=self._data[key])

    def set(self, setting: Setting) -> None:
        self._data[setting.key] = setting.value

    def delete(self, key: str) -> None:
        self._data.pop(key, None)


class FakeSecretStore:
    """In-Memory-Implementierung des ``SecretStore``-Protocols (nur ``get`` relevant)."""

    def __init__(self, secrets: dict[str, str] | None = None) -> None:
        self._data: dict[str, str] = dict(secrets or {})

    def get(self, key: str) -> str | None:
        return self._data.get(key)

    def set(self, key: str, value: str) -> None:
        self._data[key] = value

    def delete(self, key: str) -> None:
        self._data.pop(key, None)

    def exists(self, key: str) -> bool:
        return key in self._data


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


# ── GrabBanner (2a, Pass-Through) ─────────────────────────────────────────────


def test_grab_banner_pass_through() -> None:
    result = BannerResult(
        target="example.com", port=22, probe="passive", banner="SSH-2.0-OpenSSH", state="ok"
    )
    fake = FakeBannerGrabber(result)
    out = asyncio.run(GrabBanner(fake)("example.com", 22))
    assert out is result
    assert fake.calls == [("example.com", 22)]


def test_grab_banner_no_banner_is_passed_through() -> None:
    # Ein no_banner-Ergebnis (kein erfundener Wert) wird unveraendert durchgereicht.
    result = BannerResult(
        target="example.com", port=443, probe="passive", banner=None, state="no_banner"
    )
    fake = FakeBannerGrabber(result)
    out = asyncio.run(GrabBanner(fake)("example.com", 443))
    assert out.banner is None
    assert out.state == "no_banner"


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


# ── CheckExternalReachability (2b, Modell D) ──────────────────────────────────


def _make_uc(
    provider: FakeReachabilityProvider,
    secrets: dict[str, str] | None = None,
    settings: dict[str, SettingValue] | None = None,
) -> CheckExternalReachability:
    return CheckExternalReachability(
        provider, FakeSettingsRepository(settings), FakeSecretStore(secrets)
    )


def test_external_no_token_not_configured_no_call() -> None:
    # Kein Token -> configured=False, neutraler Hinweis, KEIN Provider-Aufruf.
    provider = FakeReachabilityProvider()
    uc = _make_uc(provider, secrets={}, settings={"cpnetcheck_url": "https://x.example"})
    result = asyncio.run(uc(None))
    assert result.configured is False
    assert result.checked_ip is None
    assert result.ports == ()
    assert result.error and "nicht konfiguriert" in result.error
    # Fake-Provider verifiziert "nicht gerufen".
    assert provider.ip_calls == []
    assert provider.port_calls == []


def test_external_empty_token_not_configured() -> None:
    # Leerer Token (== "") -> wie kein Token: configured=False, kein Aufruf.
    provider = FakeReachabilityProvider()
    uc = _make_uc(provider, secrets={"cpnetcheck_token": ""})
    result = asyncio.run(uc([80]))
    assert result.configured is False
    assert provider.ip_calls == []
    assert provider.port_calls == []


def test_external_token_set_url_absent_uses_default() -> None:
    # Token da, URL nicht gesetzt -> Default-URL greift, Provider wird gerufen.
    provider = FakeReachabilityProvider()
    uc = _make_uc(provider, secrets={"cpnetcheck_token": "geheim"}, settings={})
    result = asyncio.run(uc(None))
    assert result.configured is True
    assert result.checked_ip == "203.0.113.7"
    assert result.family == "ipv4"
    # Default-URL + Token kamen am Provider an (reiner IP-Check).
    assert provider.ip_calls == [(DEFAULT_CPNETCHECK_URL, "geheim")]
    assert provider.port_calls == []


def test_external_empty_url_value_uses_default() -> None:
    # URL-Setting vorhanden, aber leerer Wert -> Default greift (kein leerer Aufruf).
    provider = FakeReachabilityProvider()
    uc = _make_uc(
        provider,
        secrets={"cpnetcheck_token": "geheim"},
        settings={"cpnetcheck_url": ""},
    )
    result = asyncio.run(uc(None))
    assert result.configured is True
    assert provider.ip_calls == [(DEFAULT_CPNETCHECK_URL, "geheim")]


def test_external_both_set_ip_only() -> None:
    # Beides gesetzt, ports None -> reiner IP-Check, Ergebnis korrekt gebaut.
    provider = FakeReachabilityProvider(ip=ExternalIpResult(ip="198.51.100.9", family="ipv6"))
    uc = _make_uc(
        provider,
        secrets={"cpnetcheck_token": "tok"},
        settings={"cpnetcheck_url": "https://dienst.example"},
    )
    result = asyncio.run(uc(None))
    assert result.configured is True
    assert result.checked_ip == "198.51.100.9"
    assert result.family == "ipv6"
    assert result.ports == ()
    assert result.error is None
    assert provider.ip_calls == [("https://dienst.example", "tok")]
    assert provider.port_calls == []


def test_external_both_set_port_check() -> None:
    # Beides gesetzt + ports -> Port-Check, validierte Ports am Provider, Ergebnis gebaut.
    provider = FakeReachabilityProvider(
        ip=ExternalIpResult(ip="203.0.113.7", family="ipv4"),
        port_results=(
            ExternalPortResult(port=80, reachable=True, state="open"),
            ExternalPortResult(port=443, reachable=False, state="filtered"),
        ),
    )
    uc = _make_uc(
        provider,
        secrets={"cpnetcheck_token": "tok"},
        settings={"cpnetcheck_url": "https://dienst.example"},
    )
    result = asyncio.run(uc([80, 80, 443]))
    assert result.configured is True
    assert result.checked_ip == "203.0.113.7"
    assert [p.port for p in result.ports] == [80, 443]
    assert result.ports[1].state == "filtered"
    # Dedup griff client-seitig: 80 nur einmal am Provider.
    assert provider.port_calls == [("https://dienst.example", "tok", (80, 443))]
    assert provider.ip_calls == []


def test_external_provider_error_propagates() -> None:
    # Provider wirft ExternalCheckError -> Durchwurf (nicht verschluckt, kein error-Feld).
    provider = FakeReachabilityProvider(raise_error=True)
    uc = _make_uc(
        provider,
        secrets={"cpnetcheck_token": "tok"},
        settings={"cpnetcheck_url": "https://dienst.example"},
    )
    with pytest.raises(ExternalCheckError):
        asyncio.run(uc(None))


def test_external_empty_port_list_is_ip_only() -> None:
    # Leere Portliste -> wie None: reiner IP-Check (kein Port-Check-Aufruf).
    provider = FakeReachabilityProvider()
    uc = _make_uc(
        provider,
        secrets={"cpnetcheck_token": "tok"},
        settings={"cpnetcheck_url": "https://dienst.example"},
    )
    result = asyncio.run(uc([]))
    assert result.configured is True
    assert provider.ip_calls == [("https://dienst.example", "tok")]
    assert provider.port_calls == []
