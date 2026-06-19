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
    BuildRouteGeo,
    CheckDhcpPermission,
    CheckDiagnosticsTools,
    CheckExternalReachability,
    CheckTraceroutePermission,
    DetectRogueDhcp,
    ExternalCheckError,
    GrabBanner,
    ResolveDns,
    RogueDhcpPermissionError,
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
from domain.interfaces import NetworkInterface
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


class FakeDhcpProbe:
    """In-Memory-Implementierung des ``DhcpProbe``-Protocols (3).

    ``offers`` sind die rohen ``(ip, mac|None)``-Funde; ``calls`` zaehlt, OB der Probe
    ueberhaupt gerufen wurde (zentral fuer die Root-Sperre: bei fehlendem Root NICHT gerufen).
    """

    def __init__(self, offers: list[tuple[str, str | None]] | None = None) -> None:
        self._offers = offers or []
        self.calls = 0

    async def discover(self) -> list[tuple[str, str | None]]:
        self.calls += 1
        return self._offers


class FakeDhcpPermission:
    """In-Memory-Implementierung des ``DhcpPermissionPort``-Protocols (3)."""

    def __init__(self, available: bool = True, permission_error: str | None = None) -> None:
        self._available = available
        self._permission_error = permission_error

    def is_available(self) -> bool:
        return self._available

    def check_permission(self) -> str | None:
        return self._permission_error


class FakeInterfaceDiscovery:
    """In-Memory-Implementierung des ``InterfaceDiscoveryPort``-Protocols (Gateway-Quelle)."""

    def __init__(self, interfaces: list[NetworkInterface] | None = None) -> None:
        self._interfaces = interfaces or []

    async def discover(self) -> list[NetworkInterface]:
        return list(self._interfaces)


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
    # requested None -> ALL_TOOLS (Erstinstallations-Fall: alle pruefen). Block 3 ergaenzt
    # ``nmap`` -> alle drei muessen "present" sein, damit install_command None bleibt.
    detector = FakeToolDetector(present={"dig", "nmap", "traceroute"})
    pm = FakePackageManagerDetector("apt")
    report = CheckDiagnosticsTools(detector, pm)(None)
    assert [s.name for s in report.statuses] == list(ALL_TOOLS)
    assert sorted(detector.calls) == sorted(ALL_TOOLS)
    assert report.install_command is None  # alles da


def test_check_tools_empty_also_checks_all() -> None:
    # Leere Liste verhaelt sich wie None (Erstinstallation: alle).
    detector = FakeToolDetector(present={"dig", "nmap", "traceroute"})
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
    # Unbekanntes Tool wird defensiv ignoriert (nicht geprueft, nicht erfunden). ``nmap`` ist
    # seit Block 3 registriert -- als Beispiel fuer "unbekannt" dient hier ``frobnicate``.
    detector = FakeToolDetector(present={"dig"})
    report = CheckDiagnosticsTools(detector, FakePackageManagerDetector("apt"))(
        ["dig", "frobnicate"]
    )
    assert detector.calls == ["dig"]
    assert [s.name for s in report.statuses] == ["dig"]


def test_check_tools_nmap_is_now_known_and_checked() -> None:
    # Block 3: ``nmap`` ist registriert -> es wird geprueft; fehlt es, kommt der apt-Befehl.
    detector = FakeToolDetector(present=set())
    report = CheckDiagnosticsTools(detector, FakePackageManagerDetector("apt"))(["nmap"])
    assert detector.calls == ["nmap"]
    assert [s.name for s in report.statuses] == ["nmap"]
    assert report.install_command == "sudo apt install nmap"


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


# ── CheckDhcpPermission (3, {ok, error}-Naht) ─────────────────────────────────


def test_dhcp_permission_root_available() -> None:
    # check_permission None -> Root vorhanden, Discovery moeglich -> ok=True.
    fake = FakeDhcpPermission(available=True, permission_error=None)
    assert CheckDhcpPermission(fake)() == {"ok": True, "error": ""}


def test_dhcp_permission_no_root_is_blocked() -> None:
    # check_permission Text -> gesperrt (kein Root), ok=False + Begruendung.
    msg = "Rogue-DHCP-Erkennung benoetigt Root."
    fake = FakeDhcpPermission(available=True, permission_error=msg)
    assert CheckDhcpPermission(fake)() == {"ok": False, "error": msg}


def test_dhcp_permission_nmap_missing() -> None:
    # nmap fehlt -> nicht verfuegbar, ok=False + nicht-leerer Grund.
    result = CheckDhcpPermission(FakeDhcpPermission(available=False))()
    assert result["ok"] is False
    assert result["error"]


# ── DetectRogueDhcp (3) ───────────────────────────────────────────────────────


def _iface(name: str, gateway: str | None, ipv4: str | None = "192.168.1.50") -> NetworkInterface:
    # Ein roher NetworkInterface, wie ihn der Discovery-Port liefert (vor der Klassifikation).
    return NetworkInterface(name=name, ipv4=ipv4, gateway=gateway, is_up=True)


def _detect_uc(
    probe: FakeDhcpProbe,
    permission: FakeDhcpPermission | None = None,
    settings: dict[str, SettingValue] | None = None,
    interfaces: list[NetworkInterface] | None = None,
) -> DetectRogueDhcp:
    return DetectRogueDhcp(
        probe,
        permission or FakeDhcpPermission(available=True, permission_error=None),
        FakeSettingsRepository(settings),
        FakeInterfaceDiscovery(interfaces),
    )


def test_detect_uses_user_list_when_set() -> None:
    # Nutzerliste gesetzt -> sie gilt als Erwartung; das Gateway wird IGNORIERT.
    probe = FakeDhcpProbe(offers=[("192.168.1.1", None), ("192.168.1.66", None)])
    uc = _detect_uc(
        probe,
        settings={"expected_dhcp_servers": ["192.168.1.1"]},
        interfaces=[_iface("eth0", gateway="10.0.0.254")],  # anderes Gateway -- darf nicht ziehen
    )
    result = asyncio.run(uc())
    assert result.expected == ("192.168.1.1",)
    by_ip = {s.ip: s.is_expected for s in result.servers}
    assert by_ip == {"192.168.1.1": True, "192.168.1.66": False}
    assert result.has_unexpected is True


def test_detect_falls_back_to_primary_gateway_when_list_empty() -> None:
    # Keine Nutzerliste -> Gateway des primaeren Interface ist die Erwartung.
    probe = FakeDhcpProbe(offers=[("192.168.1.1", None)])
    uc = _detect_uc(
        probe,
        settings={},
        interfaces=[
            _iface("lo", gateway=None, ipv4="127.0.0.1"),
            _iface("eth0", gateway="192.168.1.1"),
        ],
    )
    result = asyncio.run(uc())
    assert result.expected == ("192.168.1.1",)
    assert result.servers[0].is_expected is True
    assert result.has_unexpected is False


def test_detect_empty_list_value_falls_back_to_gateway() -> None:
    # Setting vorhanden, aber leere Liste -> wie nicht gesetzt: Gateway-Fallback greift.
    probe = FakeDhcpProbe(offers=[("192.168.1.1", None)])
    uc = _detect_uc(
        probe,
        settings={"expected_dhcp_servers": []},
        interfaces=[_iface("eth0", gateway="192.168.1.1")],
    )
    result = asyncio.run(uc())
    assert result.expected == ("192.168.1.1",)


def test_detect_no_gateway_means_empty_expected() -> None:
    # Kein primaeres Interface mit Gateway -> leere Erwartung (alle gefundenen unexpected).
    probe = FakeDhcpProbe(offers=[("192.168.1.1", None)])
    uc = _detect_uc(
        probe,
        settings={},
        interfaces=[_iface("eth0", gateway=None, ipv4=None)],
    )
    result = asyncio.run(uc())
    assert result.expected == ()
    assert result.servers[0].is_expected is False
    assert result.has_unexpected is True


def test_detect_ignores_non_string_list_entries() -> None:
    # Typfremde Eintraege in der Liste werden defensiv uebersprungen (nicht erfunden).
    probe = FakeDhcpProbe(offers=[("192.168.1.1", None)])
    uc = _detect_uc(
        probe,
        settings={"expected_dhcp_servers": [123, "192.168.1.1", ""]},
        interfaces=[_iface("eth0", gateway="10.9.9.9")],
    )
    result = asyncio.run(uc())
    # Nur der gueltige String-Eintrag zaehlt -> Gateway-Fallback wird NICHT gezogen.
    assert result.expected == ("192.168.1.1",)


def test_detect_blocks_without_root_probe_not_called() -> None:
    # Kein Root -> RogueDhcpPermissionError, der Probe wird NICHT gerufen (ehrliche Sperre).
    probe = FakeDhcpProbe(offers=[("192.168.1.1", None)])
    permission = FakeDhcpPermission(available=True, permission_error="braucht Root")
    uc = _detect_uc(probe, permission=permission)
    with pytest.raises(RogueDhcpPermissionError):
        asyncio.run(uc())
    assert probe.calls == 0


def test_detect_blocks_when_nmap_missing_probe_not_called() -> None:
    # nmap fehlt -> RogueDhcpPermissionError, Probe NICHT gerufen.
    probe = FakeDhcpProbe(offers=[("192.168.1.1", None)])
    permission = FakeDhcpPermission(available=False)
    uc = _detect_uc(probe, permission=permission)
    with pytest.raises(RogueDhcpPermissionError):
        asyncio.run(uc())
    assert probe.calls == 0


# ── Route zum Ziel (ADR 0036): BuildRouteGeo (Hauptpfad) + EnrichRouteOrgs (Nachladung) ──


def _route_uc(result: TracerouteResult, geo: dict[str, dict[str, str | None]]) -> BuildRouteGeo:
    """Baut BuildRouteGeo mit einem Fake-traceroute + einem Dict-basierten Geo-Callable.

    Das Geo-Callable ist quellen-agnostisch (IP -> rohes dict): es nennt resolver NICHT.
    Eine IP ohne Eintrag in ``geo`` liefert ein leeres dict (ehrliche Leerwerte, kein Fehler).
    """
    runner = FakeTracerouteRunner(result)
    return BuildRouteGeo(RunTraceroute(runner), lambda ip: geo.get(ip, {}))


def test_route_hop_with_geo_is_enriched() -> None:
    # Ein antwortender Hop mit Geo-Treffer: country + asn werden uebernommen, asn_org bleibt
    # None (Hauptpfad ist lokal+synchron, der Org-Name kommt optional ueber die Nachladung).
    result = TracerouteResult(
        target="1.1.1.1",
        privileged=False,
        hops=(TracerouteHop(hop=1, address="1.1.1.1", rtt_ms=4.2),),
    )
    geo = {"1.1.1.1": {"country": "AU", "asn": "13335", "asn_org": None}}
    out = asyncio.run(_route_uc(result, geo)("1.1.1.1", False))
    assert out["target"] == "1.1.1.1"
    assert out["privileged"] is False
    assert out["hops"] == [
        {
            "hop": 1,
            "address": "1.1.1.1",
            "rtt_ms": 4.2,
            "country": "AU",
            "asn": "13335",
            "asn_org": None,
        }
    ]


def test_route_hop_without_geo_has_honest_empty_values() -> None:
    # Ein antwortender Hop OHNE Geo-Treffer (z. B. private IP): country/asn/asn_org ehrlich
    # None -- der Hop bleibt, mit leeren Geo-Feldern (kein erfundener Wert, kein Weglassen).
    result = TracerouteResult(
        target="example.com",
        privileged=False,
        hops=(TracerouteHop(hop=1, address="192.168.0.1", rtt_ms=0.8),),
    )
    out = asyncio.run(_route_uc(result, {})("example.com", False))
    assert out["hops"] == [
        {
            "hop": 1,
            "address": "192.168.0.1",
            "rtt_ms": 0.8,
            "country": None,
            "asn": None,
            "asn_org": None,
        }
    ]


def test_route_non_responding_hop_stays_as_null_gap_no_geo_lookup() -> None:
    # Ein nicht-antwortender Hop (address=None) bleibt als Luecke sichtbar UND wird NICHT
    # per Geo angefragt (ein Geo-Callable, das bei Aufruf wirft, beweist das).
    result = TracerouteResult(
        target="1.1.1.1",
        privileged=True,
        hops=(
            TracerouteHop(hop=1, address="10.0.0.1", rtt_ms=1.0),
            TracerouteHop(hop=2, address=None, rtt_ms=None),
        ),
    )

    looked_up: list[str] = []

    def geo_lookup(ip: str) -> dict[str, str | None]:
        # Wird nur fuer antwortende Hops (echte address) gerufen -- die Liste beweist es.
        looked_up.append(ip)
        return {"country": "US", "asn": "7922", "asn_org": None}

    uc = BuildRouteGeo(RunTraceroute(FakeTracerouteRunner(result)), geo_lookup)
    out = asyncio.run(uc("1.1.1.1", True))
    hops = out["hops"]
    assert isinstance(hops, list)
    assert hops[1] == {
        "hop": 2,
        "address": None,
        "rtt_ms": None,
        "country": None,
        "asn": None,
        "asn_org": None,
    }
    # Der Geo-Lookup wurde NUR fuer den antwortenden Hop (10.0.0.1) gerufen, NICHT fuer die Luecke.
    assert looked_up == ["10.0.0.1"]


def test_route_empty_result_yields_empty_hops() -> None:
    # Kein Hop ermittelt -> ehrlich leere Hop-Liste (kein Fehler, kein erfundener Hop).
    result = TracerouteResult(target="1.1.1.1", privileged=False, hops=())
    out = asyncio.run(_route_uc(result, {})("1.1.1.1", False))
    assert out == {"target": "1.1.1.1", "privileged": False, "hops": []}


def test_route_privileged_is_passed_through() -> None:
    # Die privileged-Wahl wird unveraendert an RunTraceroute durchgereicht (bewusste Wahl).
    runner = FakeTracerouteRunner(TracerouteResult(target="1.1.1.1", privileged=True, hops=()))
    uc = BuildRouteGeo(RunTraceroute(runner), lambda ip: {})
    asyncio.run(uc("1.1.1.1", True))
    assert runner.calls == [("1.1.1.1", True)]
