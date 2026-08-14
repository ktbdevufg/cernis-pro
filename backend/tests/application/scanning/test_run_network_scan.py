"""Tests fuer ``RunNetworkScan`` (S.5) -- gegen Fake-Implementierungen aller Ports.

Reine application-Schicht: KEIN echtes Netz, KEINE Adapter, KEINE Infrastruktur.
Konfigurierbare Fakes steuern die Szenarien. Async-Smokes via ``asyncio.run``
(kein ``pytest-asyncio``, wie in der ganzen scanning-Migration).

Schwerpunkte:
* Voller Durchlauf: erwartete ``ScanEvent``-Sequenz (am S.1-Contract orientiert)
  + ``ScanHistory.save`` am Ende mit den angereicherten Hosts.
* mDNS/SSDP werden per IP dem passenden Host zugeordnet (S.5-Vorbau).
* Fehlerpfade: ``NmapScanError``/``FritzAuthError``-artige Exceptions propagieren
  durch den Generator HINDURCH (Entscheidung S.5: Durchwerfen an S.6).
* Edge: keine lebenden Hosts; mehrere CIDRs.
"""

import asyncio
from collections.abc import AsyncIterator, Sequence

import pytest

from application.scanning import RunNetworkScan
from application.scanning.use_cases import _group_by_mac
from domain.scanning import (
    DiscoveredHost,
    DiscoveryEvent,
    DiscoveryHostFound,
    DiscoveryTick,
    EnrichedHost,
    HostEnriched,
    HostFound,
    Info,
    MdnsService,
    PhaseChanged,
    PortInfo,
    PortInterception,
    ScanCompleted,
    ScanConfig,
    ScanEvent,
    ScanRecord,
    ScanStarted,
    ScanSummary,
    SsdpService,
)
from ports.scanning import PortScannerPort

# ── Konfigurierbare Fakes ───────────────────────────────────────────────────


class _FakeDiscovery:
    """Yieldet pro CIDR die vorgegebenen Hosts (je ein Tick + HostFound)."""

    def __init__(self, hosts_per_cidr: dict[str, list[DiscoveredHost]]) -> None:
        self._hosts = hosts_per_cidr

    async def discover(
        self, cidr: str, ping_timeout: float, max_concurrent: int
    ) -> AsyncIterator[DiscoveryEvent]:
        hosts = self._hosts.get(cidr, [])
        total = max(len(hosts), 1)
        for i, host in enumerate(hosts, start=1):
            yield DiscoveryTick(completed=i, total=total)
            yield DiscoveryHostFound(host=host)
        if not hosts:
            yield DiscoveryTick(completed=1, total=1)


class _FakePortScanner:
    def __init__(self, ports_per_ip: dict[str, list[PortInfo]] | None = None) -> None:
        self._ports = ports_per_ip or {}
        # Jede gescannte IP in Aufrufreihenfolge -- belegt, wie oft und wogegen
        # gemessen wurde (Gegenprobe: EINMAL je Scan, nicht je Geraet).
        self.scanned_ips: list[str] = []

    async def scan(
        self, ip: str, ports: Sequence[int], mode: str, timeout: float, max_concurrent: int
    ) -> list[PortInfo]:
        self.scanned_ips.append(ip)
        return self._ports.get(ip, [])


class _InterceptingPortScanner:
    """Simuliert einen LOKALEN Abfaenger: bestimmte Ports antworten auf JEDER Adresse.

    ``intercepted_on`` sind die Adressen, auf denen die ``intercepted``-Ports
    zusaetzlich antworten -- ``None`` heisst "auf allen" (der echte Abfaenger-Fall).
    Damit laesst sich auch der Teilfall bauen, in dem ein Port nur auf ZWEI der
    drei Kontroll-Adressen antwortet (dann ist es kein Abfaenger, sondern ein
    ping-stilles Geraet, und es darf NICHT gefiltert werden).
    """

    def __init__(
        self,
        *,
        real_ports: dict[str, list[PortInfo]] | None = None,
        intercepted: Sequence[PortInfo] = (),
        intercepted_on: set[str] | None = None,
    ) -> None:
        self._real = real_ports or {}
        self._intercepted = list(intercepted)
        self._intercepted_on = intercepted_on
        self.scanned_ips: list[str] = []

    async def scan(
        self, ip: str, ports: Sequence[int], mode: str, timeout: float, max_concurrent: int
    ) -> list[PortInfo]:
        self.scanned_ips.append(ip)
        result = list(self._real.get(ip, []))
        if self._intercepted_on is None or ip in self._intercepted_on:
            known = {info.port for info in result}
            result.extend(info for info in self._intercepted if info.port not in known)
        return result


class _RaisingPortScanner:
    """Wirft eine beliebige Exception -- simuliert NmapScanError aus dem Adapter."""

    def __init__(self, exc: Exception) -> None:
        self._exc = exc

    async def scan(
        self, ip: str, ports: Sequence[int], mode: str, timeout: float, max_concurrent: int
    ) -> list[PortInfo]:
        raise self._exc


class _FakeVendor:
    def lookup(self, mac: str) -> str:
        return "ACME" if mac else ""


class _FakeResolver:
    def __init__(self, names: dict[str, str] | None = None) -> None:
        self._names = names or {}

    async def resolve(self, ip: str, timeout: float) -> str:
        return self._names.get(ip, "")

    async def smb_info(self, ip: str) -> tuple[str, str]:
        return ("", "")


class _FakeMdns:
    def __init__(self, services: list[MdnsService] | None = None) -> None:
        self._services = services or []

    async def discover(self, duration: float) -> list[MdnsService]:
        return self._services


class _FakeSsdp:
    def __init__(self, services: list[SsdpService] | None = None) -> None:
        self._services = services or []

    async def discover(self, timeout: float) -> list[SsdpService]:
        return self._services


class _FakeIpv6:
    """Identitaet (kein NDP) -- praegt nur, dass enrich aufgerufen wird."""

    def __init__(self) -> None:
        self.called_with: list[EnrichedHost] | None = None

    async def enrich(self, hosts: Sequence[EnrichedHost]) -> list[EnrichedHost]:
        self.called_with = list(hosts)
        return list(hosts)


class _FakeArpTable:
    """Liefert eine feste ARP-Tabelle. Default leer -> ARP-Merge inaktiv."""

    def __init__(self, table: dict[str, str] | None = None) -> None:
        self._table = table or {}

    async def get_arp_table(self) -> dict[str, str]:
        return self._table


class _FakeFritzHosts:
    """Liefert feste Fritz-Hosts. Default leer -> Fritz-Merge inaktiv."""

    def __init__(self, hosts: list[DiscoveredHost] | None = None) -> None:
        self._hosts = hosts or []

    async def get_hosts(self) -> list[DiscoveredHost]:
        return self._hosts


class _FakeScanHistory:
    def __init__(self) -> None:
        self.saved: tuple[str, tuple[EnrichedHost, ...]] | None = None
        # Das Gegenproben-Ergebnis, mit dem ``save`` gerufen wurde (Befund 53).
        self.saved_interception: PortInterception | None = None

    def save(
        self, cidr: str, hosts: Sequence[EnrichedHost], interception: PortInterception
    ) -> None:
        self.saved = (cidr, tuple(hosts))
        self.saved_interception = interception

    def clear_all(self) -> None:
        """Verwirft den zuletzt gespeicherten Scan (No-op-Vertrag fuer den Fake)."""
        self.saved = None
        self.saved_interception = None

    # list/get gehoeren zum Port-Protocol; der Use-Case ruft sie nicht, aber der
    # Fake muss den Vertrag strukturell vollstaendig erfuellen (mypy).
    def list(self, limit: int) -> list[ScanSummary]:
        return []

    def get(self, scan_id: int) -> ScanRecord | None:
        return None


def _make_use_case(
    *,
    discovery: _FakeDiscovery,
    port_scanner: PortScannerPort | None = None,
    resolver: _FakeResolver | None = None,
    mdns: _FakeMdns | None = None,
    ssdp: _FakeSsdp | None = None,
    ipv6: _FakeIpv6 | None = None,
    fritz_hosts: _FakeFritzHosts | None = None,
    arp_table: _FakeArpTable | None = None,
    history: _FakeScanHistory | None = None,
) -> tuple[RunNetworkScan, _FakeIpv6, _FakeScanHistory]:
    # Die Fakes erfuellen die Port-Protocols strukturell (mypy-geprueft, kein ignore noetig).
    ipv6 = ipv6 or _FakeIpv6()
    history = history or _FakeScanHistory()
    use_case = RunNetworkScan(
        discovery=discovery,
        port_scanner=port_scanner or _FakePortScanner(),
        vendor_lookup=_FakeVendor(),
        resolver=resolver or _FakeResolver(),
        mdns=mdns or _FakeMdns(),
        ssdp=ssdp or _FakeSsdp(),
        ipv6=ipv6,
        fritz_hosts=fritz_hosts or _FakeFritzHosts(),  # default leer -> Merge inaktiv
        arp_table=arp_table or _FakeArpTable(),  # default leer -> Merge inaktiv
        scan_history=history,
    )
    return use_case, ipv6, history


def _run(use_case: RunNetworkScan, config: ScanConfig) -> list[ScanEvent]:
    async def _collect() -> list[ScanEvent]:
        return [ev async for ev in use_case.run(config)]

    return asyncio.run(_collect())


# ── Voller Durchlauf ─────────────────────────────────────────────────────────


def test_full_run_event_sequence_and_save() -> None:
    host = DiscoveredHost(ip="192.168.1.2", mac="AA:BB:CC:DD:EE:01", rtt_ms=1.0)
    discovery = _FakeDiscovery({"192.168.1.0/30": [host]})
    scanner = _FakePortScanner({"192.168.1.2": [PortInfo(port=22, state="open", service="ssh")]})
    use_case, ipv6, history = _make_use_case(discovery=discovery, port_scanner=scanner)

    config = ScanConfig(
        cidrs=("192.168.1.0/30",),
        port_scan=True,
        mdns_scan=False,
        ssdp_scan=False,
        resolve_hostnames=False,
    )
    events = _run(use_case, config)

    # Event-Sequenz (am S.1-Contract orientiert).
    types = [type(e).__name__ for e in events]
    assert types == [
        "ScanStarted",
        "PhaseChanged",  # discovery running
        "Progress",  # discovery tick
        "HostFound",
        "PhaseChanged",  # discovery done
        # Gegenprobe auf abgefangene Ports (Befund 53): das /30 hat nach Abzug des
        # gefundenen Hosts nur EINE freie Adresse -- zu wenig fuer die drei
        # Kontroll-Adressen. Der "nicht geprueft"-Zustand wird BENANNT, daher
        # dieser Info-Eintrag im Strom (statt stiller Nicht-Pruefung).
        "Info",
        "PhaseChanged",  # enrich running
        "HostEnriched",
        "Progress",  # enrich
        "ScanCompleted",
    ]

    assert events[0] == ScanStarted(cidr="192.168.1.0/30", total_hosts=2)
    assert events[1] == PhaseChanged(phase="discovery", status="running", total=2)
    assert isinstance(events[3], HostFound)
    assert events[3].ip == "192.168.1.2"
    assert events[3].vendor == "ACME"
    assert events[3].is_unknown is True
    assert events[4] == PhaseChanged(phase="discovery", status="done", alive_count=1)
    assert isinstance(events[5], Info)  # Gegenprobe: "nicht geprueft" (siehe oben)
    assert events[6] == PhaseChanged(phase="enrich", status="running", total=1)

    host_enriched = events[7]
    assert isinstance(host_enriched, HostEnriched)
    assert host_enriched.host.ip == "192.168.1.2"
    assert host_enriched.host.ports == (PortInfo(port=22, state="open", service="ssh"),)
    # SSH allein -> classify_host: Linux-Server (verhaltensgleich Altcode).
    assert host_enriched.host.category == "server"
    assert host_enriched.host.os_guess == "Linux"
    assert isinstance(events[-1], ScanCompleted)
    assert events[-1].total_found == 1

    # IPv6-enrich + ScanHistory.save am Ende aufgerufen.
    assert ipv6.called_with is not None
    assert history.saved is not None
    saved_cidr, saved_hosts = history.saved
    assert saved_cidr == "192.168.1.0/30"
    assert len(saved_hosts) == 1
    assert saved_hosts[0].ip == "192.168.1.2"


# ── mDNS/SSDP-Zuordnung per IP ──────────────────────────────────────────────


def test_mdns_ssdp_assigned_by_ip() -> None:
    host_a = DiscoveredHost(ip="10.0.0.2", mac="AA:00:00:00:00:01")
    host_b = DiscoveredHost(ip="10.0.0.3", mac="AA:00:00:00:00:02")
    discovery = _FakeDiscovery({"10.0.0.0/29": [host_a, host_b]})
    mdns = _FakeMdns(
        [
            MdnsService(name="cast", type="_googlecast._tcp.local.", ip="10.0.0.2", is_ndi=True),
            MdnsService(name="other", type="_http._tcp.local.", ip="10.0.0.99"),  # kein Host
        ]
    )
    ssdp = _FakeSsdp([SsdpService(server="UPnP", st="rootdevice", ip="10.0.0.3")])
    use_case, _, _ = _make_use_case(discovery=discovery, mdns=mdns, ssdp=ssdp)

    config = ScanConfig(
        cidrs=("10.0.0.0/29",),
        port_scan=False,
        mdns_scan=True,
        ssdp_scan=True,
        resolve_hostnames=False,
    )
    events = _run(use_case, config)
    enriched = {e.host.ip: e.host for e in events if isinstance(e, HostEnriched)}

    # host_a bekommt den mDNS-Dienst (per ip), is_ndi durchgereicht.
    assert len(enriched["10.0.0.2"].mdns_services) == 1
    assert enriched["10.0.0.2"].mdns_services[0].type == "_googlecast._tcp.local."
    assert enriched["10.0.0.2"].is_ndi is True
    assert enriched["10.0.0.2"].ssdp_services == ()
    # host_b bekommt den SSDP-Dienst, keinen mDNS.
    assert enriched["10.0.0.3"].mdns_services == ()
    assert len(enriched["10.0.0.3"].ssdp_services) == 1
    # Der mDNS-Dienst fuer 10.0.0.99 (kein Host) taucht nirgends auf.
    assert "10.0.0.99" not in enriched


# ── ARP-Merge (S.7b) ────────────────────────────────────────────────────────


def test_arp_merge_adds_only_ping_silent_hosts() -> None:
    """ARP-only-Host wird angehaengt (source="arp", rtt_ms=None); bekannte IP NICHT."""
    ping_host = DiscoveredHost(ip="192.168.1.2", mac="AA:BB:CC:DD:EE:01", rtt_ms=1.0)
    discovery = _FakeDiscovery({"192.168.1.0/24": [ping_host]})
    # ARP enthaelt den Ping-Host (muss uebersprungen werden) UND einen neuen Host.
    arp = _FakeArpTable(
        {
            "192.168.1.2": "FF:FF:FF:FF:FF:FF",  # schon gefunden -> skip, kein Doppel/MAC-Nachtrag
            "192.168.1.50": "DE:AD:BE:EF:00:01",  # ARP-only -> hinzufuegen
        }
    )
    use_case, _, _ = _make_use_case(discovery=discovery, arp_table=arp)

    config = ScanConfig(
        cidrs=("192.168.1.0/24",),
        port_scan=False,
        mdns_scan=False,
        ssdp_scan=False,
        resolve_hostnames=False,
    )
    events = _run(use_case, config)

    found = [e for e in events if isinstance(e, HostFound)]
    # Genau ein Ping-Host + ein ARP-Host -- die bekannte IP wird NICHT verdoppelt.
    assert {f.ip for f in found} == {"192.168.1.2", "192.168.1.50"}
    ping_frame = next(f for f in found if f.ip == "192.168.1.2")
    arp_frame = next(f for f in found if f.ip == "192.168.1.50")

    # Ping-Host unveraendert -- keine MAC-Ueberschreibung aus ARP.
    assert ping_frame.mac == "AA:BB:CC:DD:EE:01"
    assert ping_frame.source == "ping"

    # ARP-Host: source="arp", rtt_ms=None (kein Zweit-Ping, Entscheidung 4A),
    # vendor wie der Ping-Pfad (lookup ueber die MAC).
    assert arp_frame.source == "arp"
    assert arp_frame.rtt_ms is None
    assert arp_frame.mac == "DE:AD:BE:EF:00:01"
    assert arp_frame.vendor == "ACME"
    assert arp_frame.is_unknown is True

    # alive_count zaehlt den ARP-Host mit (len(discovered) NACH dem Merge).
    disc_done = next(
        e
        for e in events
        if isinstance(e, PhaseChanged) and e.phase == "discovery" and e.status == "done"
    )
    assert disc_done.alive_count == 2


def test_arp_duplicate_of_living_host_becomes_additional_ip() -> None:
    """ARP-Eintrag mit MAC eines lebenden Ping-Hosts wird zur additional_ip gruppiert."""
    # Realfall: FritzBox per Ping (mac), ARP-Cache haengt eine zweite IP mit
    # DERSELBEN MAC dran (anderer Gross-/Kleinschreibung) -- ein Proxy-ARP-Duplikat.
    # Kein MAC-Vorfilter mehr: das Duplikat landet in discovered und wird von der
    # MAC-Gruppierung als additional_ip des primaeren Hosts eingesammelt (verlustfrei).
    ping_host = DiscoveredHost(ip="192.168.0.1", mac="AA:BB:CC:DD:EE:FF", rtt_ms=1.0)
    discovery = _FakeDiscovery({"192.168.0.0/24": [ping_host]})
    arp = _FakeArpTable(
        {
            "192.168.0.202": "aa:bb:cc:dd:ee:ff",  # gleiche MAC, andere IP -> additional_ip
        }
    )
    use_case, _, history = _make_use_case(discovery=discovery, arp_table=arp)

    config = ScanConfig(
        cidrs=("192.168.0.0/24",),
        port_scan=False,
        mdns_scan=False,
        ssdp_scan=False,
        resolve_hostnames=False,
    )
    events = _run(use_case, config)

    # Genau EIN enriched Host (der Ping-Host mit der niedrigsten rtt); die ARP-IP
    # landet als additional_ip, KEIN separater Host fuer .0.202.
    enriched = [e for e in events if isinstance(e, HostEnriched)]
    assert len(enriched) == 1
    primary = enriched[0].host
    assert primary.ip == "192.168.0.1"
    assert primary.additional_ips == ("192.168.0.202",)

    # alive_count zaehlt die gruppierte Sicht (ein Geraet).
    disc_done = next(
        e
        for e in events
        if isinstance(e, PhaseChanged) and e.phase == "discovery" and e.status == "done"
    )
    assert disc_done.alive_count == 1

    # Der gespeicherte Scan enthaelt genau den einen primaeren Host mit der Zusatz-IP.
    assert history.saved is not None
    assert len(history.saved[1]) == 1
    assert history.saved[1][0].ip == "192.168.0.1"
    assert history.saved[1][0].additional_ips == ("192.168.0.202",)


def test_arp_host_runs_through_enrich() -> None:
    """Der ARP-only-Host laeuft wie ein Ping-Host durch die Enrich-Phase."""
    discovery = _FakeDiscovery({"10.0.0.0/24": []})  # kein Ping-Host
    arp = _FakeArpTable({"10.0.0.7": "DE:AD:BE:EF:00:07"})
    scanner = _FakePortScanner({"10.0.0.7": [PortInfo(port=22, state="open", service="ssh")]})
    use_case, ipv6, history = _make_use_case(
        discovery=discovery, arp_table=arp, port_scanner=scanner
    )

    config = ScanConfig(
        cidrs=("10.0.0.0/24",),
        port_scan=True,
        mdns_scan=False,
        ssdp_scan=False,
        resolve_hostnames=False,
    )
    events = _run(use_case, config)

    enriched = [e for e in events if isinstance(e, HostEnriched)]
    assert len(enriched) == 1
    assert enriched[0].host.ip == "10.0.0.7"
    assert enriched[0].host.ports == (PortInfo(port=22, state="open", service="ssh"),)
    # ARP-Host ist Teil des gespeicherten Scans + der IPv6-Batch.
    assert history.saved is not None
    assert history.saved[1][0].ip == "10.0.0.7"
    assert ipv6.called_with is not None and ipv6.called_with[0].ip == "10.0.0.7"
    assert isinstance(events[-1], ScanCompleted)
    assert events[-1].total_found == 1


def test_arp_skips_host_outside_scanned_cidrs() -> None:
    """ARP-Eintrag ausserhalb der config-CIDRs wird uebersprungen (_in_any_cidr)."""
    discovery = _FakeDiscovery({"192.168.1.0/24": []})
    arp = _FakeArpTable(
        {
            "192.168.1.50": "DE:AD:BE:EF:00:01",  # im Netz -> hinzufuegen
            "10.99.99.99": "DE:AD:BE:EF:00:02",  # ausserhalb -> skip
            "not-an-ip": "DE:AD:BE:EF:00:03",  # unsauberer Output -> skip (ValueError)
        }
    )
    use_case, _, _ = _make_use_case(discovery=discovery, arp_table=arp)

    config = ScanConfig(
        cidrs=("192.168.1.0/24",),
        port_scan=False,
        mdns_scan=False,
        ssdp_scan=False,
        resolve_hostnames=False,
    )
    events = _run(use_case, config)

    found = {f.ip for f in events if isinstance(f, HostFound)}
    assert found == {"192.168.1.50"}


def test_arp_hostfound_is_in_discovery_phase() -> None:
    """Der ARP-HostFound kommt VOR PhaseChanged(discovery, done), noch in der Discovery-Phase."""
    discovery = _FakeDiscovery({"192.168.1.0/24": []})
    arp = _FakeArpTable({"192.168.1.50": "DE:AD:BE:EF:00:01"})
    use_case, _, _ = _make_use_case(discovery=discovery, arp_table=arp)

    config = ScanConfig(
        cidrs=("192.168.1.0/24",),
        port_scan=False,
        mdns_scan=False,
        ssdp_scan=False,
        resolve_hostnames=False,
    )
    events = _run(use_case, config)

    types = [type(e).__name__ for e in events]
    arp_found_idx = next(
        i for i, e in enumerate(events) if isinstance(e, HostFound) and e.source == "arp"
    )
    disc_done_idx = next(
        i
        for i, e in enumerate(events)
        if isinstance(e, PhaseChanged) and e.phase == "discovery" and e.status == "done"
    )
    # naechstes PhaseChanged NACH discovery-done ist enrich-running.
    enrich_running_idx = types.index("PhaseChanged", disc_done_idx + 1)
    assert arp_found_idx < disc_done_idx < enrich_running_idx


# ── FritzBox-Merge (S.7c) ─────────────────────────────────────────────────────


def test_fritz_merge_adds_only_unknown_hosts() -> None:
    """Fritz-only-Host wird angehaengt (source="fritzbox", rtt_ms=None); bekannte IP NICHT."""
    ping_host = DiscoveredHost(ip="192.168.1.2", mac="AA:BB:CC:DD:EE:01", rtt_ms=1.0)
    discovery = _FakeDiscovery({"192.168.1.0/24": [ping_host]})
    fritz = _FakeFritzHosts(
        [
            # Box meldet den Ping-Host (skip) UND ein ping-stilles iPad (anhaengen).
            DiscoveredHost(ip="192.168.1.2", mac="FF:FF:FF:FF:FF:FF", source="fritzbox"),
            DiscoveredHost(ip="192.168.1.77", mac="DE:AD:BE:EF:00:99", source="fritzbox"),
        ]
    )
    use_case, _, _ = _make_use_case(discovery=discovery, fritz_hosts=fritz)

    config = ScanConfig(
        cidrs=("192.168.1.0/24",),
        port_scan=False,
        mdns_scan=False,
        ssdp_scan=False,
        resolve_hostnames=False,
    )
    events = _run(use_case, config)

    found = [e for e in events if isinstance(e, HostFound)]
    assert {f.ip for f in found} == {"192.168.1.2", "192.168.1.77"}
    ping_frame = next(f for f in found if f.ip == "192.168.1.2")
    fritz_frame = next(f for f in found if f.ip == "192.168.1.77")

    # Ping-Host unveraendert -- keine Ueberschreibung durch die Fritz-Meldung.
    assert ping_frame.mac == "AA:BB:CC:DD:EE:01"
    assert ping_frame.source == "ping"

    # Fritz-Host: source="fritzbox", rtt_ms=None (kein Zweit-Ping, Entscheidung 4A).
    assert fritz_frame.source == "fritzbox"
    assert fritz_frame.rtt_ms is None
    assert fritz_frame.mac == "DE:AD:BE:EF:00:99"
    assert fritz_frame.vendor == "ACME"

    disc_done = next(
        e
        for e in events
        if isinstance(e, PhaseChanged) and e.phase == "discovery" and e.status == "done"
    )
    assert disc_done.alive_count == 2  # Ping + Fritz


def test_fritz_skips_host_outside_scanned_cidrs() -> None:
    """Fritz-Host ausserhalb der config-CIDRs wird uebersprungen (_in_any_cidr)."""
    discovery = _FakeDiscovery({"192.168.1.0/24": []})
    fritz = _FakeFritzHosts(
        [
            DiscoveredHost(ip="192.168.1.77", mac="DE:AD:BE:EF:00:01", source="fritzbox"),
            DiscoveredHost(ip="10.0.0.5", mac="DE:AD:BE:EF:00:02", source="fritzbox"),  # ausserhalb
        ]
    )
    use_case, _, _ = _make_use_case(discovery=discovery, fritz_hosts=fritz)

    config = ScanConfig(
        cidrs=("192.168.1.0/24",),
        port_scan=False,
        mdns_scan=False,
        ssdp_scan=False,
        resolve_hostnames=False,
    )
    events = _run(use_case, config)

    found = {f.ip for f in events if isinstance(f, HostFound)}
    assert found == {"192.168.1.77"}


def test_fritz_host_runs_through_enrich() -> None:
    """Der Fritz-only-Host laeuft wie ein Ping-Host durch die Enrich-Phase."""
    discovery = _FakeDiscovery({"10.0.0.0/24": []})
    fritz = _FakeFritzHosts(
        [DiscoveredHost(ip="10.0.0.9", mac="DE:AD:BE:EF:00:09", source="fritzbox")]
    )
    scanner = _FakePortScanner({"10.0.0.9": [PortInfo(port=80, state="open", service="http")]})
    use_case, ipv6, history = _make_use_case(
        discovery=discovery, fritz_hosts=fritz, port_scanner=scanner
    )

    config = ScanConfig(
        cidrs=("10.0.0.0/24",),
        port_scan=True,
        mdns_scan=False,
        ssdp_scan=False,
        resolve_hostnames=False,
    )
    events = _run(use_case, config)

    enriched = [e for e in events if isinstance(e, HostEnriched)]
    assert len(enriched) == 1
    assert enriched[0].host.ip == "10.0.0.9"
    assert enriched[0].host.ports == (PortInfo(port=80, state="open", service="http"),)
    assert history.saved is not None and history.saved[1][0].ip == "10.0.0.9"
    assert ipv6.called_with is not None and ipv6.called_with[0].ip == "10.0.0.9"


def test_fritz_merged_before_arp_same_ip_only_once() -> None:
    """Liefern Fritz UND ARP dieselbe IP, gewinnt Fritz (laeuft zuerst) -- nur einmal."""
    discovery = _FakeDiscovery({"192.168.1.0/24": []})
    # Gewoehnliche MACs auf beiden Seiten: der Test prueft die REIHENFOLGE
    # (Fritz vor ARP), nicht die Eignung -- eine Gruppen-MAC wuerde den Eintrag
    # seit Befund 55 verwerfen und die Aussage des Tests unterlaufen.
    fritz = _FakeFritzHosts(
        [DiscoveredHost(ip="192.168.1.50", mac="BA:BB:BB:BB:BB:BB", source="fritzbox")]
    )
    arp = _FakeArpTable({"192.168.1.50": "AA:AA:AA:AA:AA:AA"})  # gleiche IP -> ARP skippt sie
    use_case, _, _ = _make_use_case(discovery=discovery, fritz_hosts=fritz, arp_table=arp)

    config = ScanConfig(
        cidrs=("192.168.1.0/24",),
        port_scan=False,
        mdns_scan=False,
        ssdp_scan=False,
        resolve_hostnames=False,
    )
    events = _run(use_case, config)

    found = [f for f in events if isinstance(f, HostFound) and f.ip == "192.168.1.50"]
    assert len(found) == 1
    # Fritz lief zuerst -> die Fritz-Meldung (source/mac) gewinnt, ARP wird verworfen.
    assert found[0].source == "fritzbox"
    assert found[0].mac == "BA:BB:BB:BB:BB:BB"


def test_fritz_hostfound_is_in_discovery_phase() -> None:
    """Der Fritz-HostFound kommt VOR PhaseChanged(discovery, done)."""
    discovery = _FakeDiscovery({"192.168.1.0/24": []})
    fritz = _FakeFritzHosts(
        [DiscoveredHost(ip="192.168.1.50", mac="DE:AD:BE:EF:00:01", source="fritzbox")]
    )
    use_case, _, _ = _make_use_case(discovery=discovery, fritz_hosts=fritz)

    config = ScanConfig(
        cidrs=("192.168.1.0/24",),
        port_scan=False,
        mdns_scan=False,
        ssdp_scan=False,
        resolve_hostnames=False,
    )
    events = _run(use_case, config)

    fritz_found_idx = next(
        i for i, e in enumerate(events) if isinstance(e, HostFound) and e.source == "fritzbox"
    )
    disc_done_idx = next(
        i
        for i, e in enumerate(events)
        if isinstance(e, PhaseChanged) and e.phase == "discovery" and e.status == "done"
    )
    assert fritz_found_idx < disc_done_idx


# ── Befund 55: nur echte Host-Adressen kommen in die Geraeteliste ───────────


def _merge_config(*cidrs: str) -> ScanConfig:
    """Minimal-Config fuer die Merge-Tests: nur Discovery, keine Anreicherung."""
    return ScanConfig(
        cidrs=cidrs,
        port_scan=False,
        mdns_scan=False,
        ssdp_scan=False,
        resolve_hostnames=False,
    )


def test_arp_skips_broadcast_address() -> None:
    """Die Broadcast-Adresse aus der ARP-Tabelle wird nicht als Geraet gefuehrt."""
    discovery = _FakeDiscovery({"192.168.1.0/24": []})
    arp = _FakeArpTable({"192.168.1.255": "DE:AD:BE:EF:00:01"})
    use_case, _, _ = _make_use_case(discovery=discovery, arp_table=arp)

    events = _run(use_case, _merge_config("192.168.1.0/24"))

    assert [e for e in events if isinstance(e, HostFound)] == []


def test_arp_skips_network_address() -> None:
    """Dasselbe fuer die Netzadresse."""
    discovery = _FakeDiscovery({"192.168.1.0/24": []})
    arp = _FakeArpTable({"192.168.1.0": "DE:AD:BE:EF:00:01"})
    use_case, _, _ = _make_use_case(discovery=discovery, arp_table=arp)

    events = _run(use_case, _merge_config("192.168.1.0/24"))

    assert [e for e in events if isinstance(e, HostFound)] == []


def test_fritz_skips_network_and_broadcast_address() -> None:
    """Der Filter greift auch auf dem Fritz-Weg, nicht nur ueber ARP."""
    discovery = _FakeDiscovery({"192.168.1.0/24": []})
    fritz = _FakeFritzHosts(
        [
            DiscoveredHost(ip="192.168.1.0", mac="DE:AD:BE:EF:00:01", source="fritzbox"),
            DiscoveredHost(ip="192.168.1.255", mac="DE:AD:BE:EF:00:02", source="fritzbox"),
        ]
    )
    use_case, _, _ = _make_use_case(discovery=discovery, fritz_hosts=fritz)

    events = _run(use_case, _merge_config("192.168.1.0/24"))

    assert [e for e in events if isinstance(e, HostFound)] == []


def test_arp_keeps_ordinary_address_alongside_discarded_ones() -> None:
    """Der Filter entfernt nicht mehr als er soll -- die gewoehnliche IP kommt durch."""
    discovery = _FakeDiscovery({"192.168.1.0/24": []})
    arp = _FakeArpTable(
        {
            "192.168.1.0": "DE:AD:BE:EF:00:01",  # Netzadresse -> verworfen
            "192.168.1.50": "DE:AD:BE:EF:00:02",  # gewoehnlich -> bleibt
            "192.168.1.255": "DE:AD:BE:EF:00:03",  # Broadcast -> verworfen
        }
    )
    use_case, _, _ = _make_use_case(discovery=discovery, arp_table=arp)

    events = _run(use_case, _merge_config("192.168.1.0/24"))

    found = {f.ip for f in events if isinstance(f, HostFound)}
    assert found == {"192.168.1.50"}


def test_arp_skips_broadcast_mac_at_ordinary_address() -> None:
    """Broadcast-MAC verwirft den Eintrag, auch wenn die IP unauffaellig ist."""
    discovery = _FakeDiscovery({"192.168.1.0/24": []})
    arp = _FakeArpTable({"192.168.1.60": "FF:FF:FF:FF:FF:FF"})
    use_case, _, _ = _make_use_case(discovery=discovery, arp_table=arp)

    events = _run(use_case, _merge_config("192.168.1.0/24"))

    assert [e for e in events if isinstance(e, HostFound)] == []


def test_arp_skips_multicast_mac_at_ordinary_address() -> None:
    """Multicast-MAC ebenso -- gesetztes I/G-Bit im ersten Oktett."""
    discovery = _FakeDiscovery({"192.168.1.0/24": []})
    arp = _FakeArpTable({"192.168.1.61": "01:00:5E:00:00:FB"})
    use_case, _, _ = _make_use_case(discovery=discovery, arp_table=arp)

    events = _run(use_case, _merge_config("192.168.1.0/24"))

    assert [e for e in events if isinstance(e, HostFound)] == []


def test_slash31_and_slash32_are_not_wrongly_emptied() -> None:
    """Bei /31 und /32 wird NICHT faelschlich alles verworfen (stdlib-Sonderfall)."""
    discovery = _FakeDiscovery({"10.0.0.0/31": [], "10.9.9.9/32": []})
    arp = _FakeArpTable(
        {
            "10.0.0.0": "DE:AD:BE:EF:00:01",  # im /31 ein regulaerer Host
            "10.0.0.1": "DE:AD:BE:EF:00:02",  # ebenso
            "10.9.9.9": "DE:AD:BE:EF:00:03",  # die einzige Adresse des /32
        }
    )
    use_case, _, _ = _make_use_case(discovery=discovery, arp_table=arp)

    events = _run(use_case, _merge_config("10.0.0.0/31", "10.9.9.9/32"))

    found = {f.ip for f in events if isinstance(f, HostFound)}
    assert found == {"10.0.0.0", "10.0.0.1", "10.9.9.9"}


def test_ping_sweep_host_with_empty_mac_still_passes() -> None:
    """Der Ping-Sweep-Weg bleibt unveraendert -- er laeuft nicht ueber den Filter."""
    ping_host = DiscoveredHost(ip="192.168.1.5", mac="", rtt_ms=2.0)
    discovery = _FakeDiscovery({"192.168.1.0/24": [ping_host]})
    use_case, _, _ = _make_use_case(discovery=discovery)

    events = _run(use_case, _merge_config("192.168.1.0/24"))

    found = [f for f in events if isinstance(f, HostFound)]
    assert len(found) == 1
    assert found[0].ip == "192.168.1.5"
    assert found[0].mac == ""


def test_arp_skips_multicast_and_loopback_even_inside_covering_cidrs() -> None:
    """Ein CIDR, das sie umfasst, macht aus ihnen kein Geraet."""
    # 127.0.0.0/24 statt /8: die Aussage haengt daran, dass das CIDR die geprueften
    # Adressen UMFASST (127.0.0.1 liegt in beiden), nicht an seiner Groesse. Ein /8
    # liegt seit der Netzgroessen-Schranke (S88-P2) ueber der Obergrenze.
    discovery = _FakeDiscovery({"224.0.0.0/24": [], "127.0.0.0/24": []})
    arp = _FakeArpTable(
        {
            "224.0.0.251": "DE:AD:BE:EF:00:01",  # Multicast
            "127.0.0.1": "DE:AD:BE:EF:00:02",  # Loopback
        }
    )
    use_case, _, _ = _make_use_case(discovery=discovery, arp_table=arp)

    events = _run(use_case, _merge_config("224.0.0.0/24", "127.0.0.0/24"))

    assert [e for e in events if isinstance(e, HostFound)] == []


# ── Fehlerpfad: Adapter-Exception propagiert (Durchwerfen an S.6) ───────────


class _FakeNmapError(Exception):
    """Steht stellvertretend fuer NmapScanError/FritzAuthError aus infrastructure."""


def test_adapter_exception_propagates_through_generator() -> None:
    host = DiscoveredHost(ip="10.0.0.2", mac="AA:00:00:00:00:01")
    discovery = _FakeDiscovery({"10.0.0.0/30": [host]})
    scanner = _RaisingPortScanner(_FakeNmapError("nmap_timeout"))
    use_case, _, history = _make_use_case(discovery=discovery, port_scanner=scanner)

    config = ScanConfig(cidrs=("10.0.0.0/30",), port_scan=True, mdns_scan=False, ssdp_scan=False)

    # Die Exception wird NICHT gefangen -- sie propagiert aus dem Generator.
    with pytest.raises(_FakeNmapError):
        _run(use_case, config)

    # ScanHistory.save wurde NICHT erreicht (Abbruch vor dem Speichern).
    assert history.saved is None


# ── Edge-Faelle ──────────────────────────────────────────────────────────────


def test_no_alive_hosts() -> None:
    discovery = _FakeDiscovery({"10.0.0.0/30": []})  # niemand lebt
    use_case, _ipv6, history = _make_use_case(discovery=discovery)

    config = ScanConfig(cidrs=("10.0.0.0/30",), port_scan=False, mdns_scan=False, ssdp_scan=False)
    events = _run(use_case, config)

    assert not [e for e in events if isinstance(e, HostFound)]
    assert not [e for e in events if isinstance(e, HostEnriched)]
    assert isinstance(events[-1], ScanCompleted)
    assert events[-1].total_found == 0
    # save wird trotzdem aufgerufen (leerer Scan ist ein gueltiger Scan).
    assert history.saved is not None
    assert history.saved[1] == ()


def test_multiple_cidrs_aggregated() -> None:
    discovery = _FakeDiscovery(
        {
            "10.0.0.0/30": [DiscoveredHost(ip="10.0.0.1", mac="AA:00:00:00:00:01")],
            "10.0.1.0/30": [DiscoveredHost(ip="10.0.1.1", mac="AA:00:00:00:00:02")],
        }
    )
    use_case, _, history = _make_use_case(discovery=discovery)

    config = ScanConfig(
        cidrs=("10.0.0.0/30", "10.0.1.0/30"),
        port_scan=False,
        mdns_scan=False,
        ssdp_scan=False,
        resolve_hostnames=False,
    )
    events = _run(use_case, config)

    found = [e for e in events if isinstance(e, HostFound)]
    assert {f.ip for f in found} == {"10.0.0.1", "10.0.1.1"}
    assert events[0] == ScanStarted(cidr="10.0.0.0/30,10.0.1.0/30", total_hosts=4)
    assert isinstance(events[-1], ScanCompleted)
    assert events[-1].total_found == 2
    assert history.saved is not None
    assert history.saved[0] == "10.0.0.0/30,10.0.1.0/30"


# ── Gegenprobe: lokal abgefangene Ports (Befund 53) ─────────────────────────
#
# Testnetz durchgehend 192.168.1.0/29 mit den Geraeten .2 und .4. Die Auswahl
# (``pick_control_addresses``) liefert dort die drei Kontroll-Adressen .1, .3, .5
# -- gleichmaessig gestreut ueber die verbleibenden Kandidaten .1/.3/.5/.6.

_CONTROL_IPS = ("192.168.1.1", "192.168.1.3", "192.168.1.5")


def _interception_config(cidr: str = "192.168.1.0/29") -> ScanConfig:
    """Scan-Config mit Portscan an, alles andere aus (nur die Gegenprobe im Blick)."""
    return ScanConfig(
        cidrs=(cidr,),
        port_scan=True,
        mdns_scan=False,
        ssdp_scan=False,
        resolve_hostnames=False,
    )


def _open_ports_by_ip(events: list[ScanEvent]) -> dict[str, set[int]]:
    """Offene Port-Nummern je enriched Host."""
    return {
        e.host.ip: {p.port for p in e.host.ports} for e in events if isinstance(e, HostEnriched)
    }


def test_port_answering_on_all_three_controls_is_removed_from_every_host() -> None:
    """Test 1: Ein auf ALLEN drei Kontroll-Adressen antwortender Port verschwindet ueberall."""
    hosts = [
        DiscoveredHost(ip="192.168.1.2", mac="AA:BB:CC:DD:EE:01", rtt_ms=1.0),
        DiscoveredHost(ip="192.168.1.4", mac="AA:BB:CC:DD:EE:02", rtt_ms=2.0),
    ]
    discovery = _FakeDiscovery({"192.168.1.0/29": hosts})
    scanner = _InterceptingPortScanner(
        real_ports={
            "192.168.1.2": [PortInfo(port=22, state="open", service="ssh")],
            "192.168.1.4": [PortInfo(port=80, state="open", service="http")],
        },
        # Port 25 wird lokal abgefangen -> antwortet auf JEDER Adresse.
        intercepted=[PortInfo(port=25, state="open", service="smtp")],
    )
    use_case, _, history = _make_use_case(discovery=discovery, port_scanner=scanner)

    events = _run(use_case, _interception_config())
    open_ports = _open_ports_by_ip(events)

    # Der abgefangene Port 25 ist bei BEIDEN Geraeten weg; die echten bleiben.
    assert open_ports == {"192.168.1.2": {22}, "192.168.1.4": {80}}

    # Am Ergebnis steht, was erkannt wurde und worauf geprueft wurde.
    assert history.saved_interception is not None
    assert history.saved_interception.checked is True
    assert history.saved_interception.intercepted_ports == (25,)
    assert history.saved_interception.control_ips == _CONTROL_IPS


def test_port_answering_on_only_two_controls_stays() -> None:
    """Test 2: Antwortet ein Port nur auf ZWEI der drei Kontroll-Adressen, bleibt er stehen.

    Fachlich: ein ping-stilles Geraet auf einer Kontroll-Adresse darf den Befund
    nicht kippen. Nur "auf ALLEN drei" gilt als abgefangen.
    """
    host = DiscoveredHost(ip="192.168.1.2", mac="AA:BB:CC:DD:EE:01", rtt_ms=1.0)
    discovery = _FakeDiscovery({"192.168.1.0/29": [host]})
    scanner = _InterceptingPortScanner(
        real_ports={"192.168.1.2": [PortInfo(port=22, state="open", service="ssh")]},
        intercepted=[PortInfo(port=25, state="open", service="smtp")],
        # Nur zwei der drei Kontroll-Adressen antworten auf 25.
        intercepted_on={"192.168.1.1", "192.168.1.3", "192.168.1.2"},
    )
    use_case, _, history = _make_use_case(discovery=discovery, port_scanner=scanner)

    events = _run(use_case, _interception_config())

    # Port 25 bleibt beim Geraet stehen -- keine Mehrheitsregel, nur Einstimmigkeit.
    assert _open_ports_by_ip(events) == {"192.168.1.2": {22, 25}}
    assert history.saved_interception is not None
    assert history.saved_interception.checked is True
    assert history.saved_interception.intercepted_ports == ()


def test_ports_answering_on_no_control_are_untouched() -> None:
    """Test 3: Ports, die auf keiner Kontroll-Adresse antworten, bleiben unberuehrt."""
    host = DiscoveredHost(ip="192.168.1.2", mac="AA:BB:CC:DD:EE:01", rtt_ms=1.0)
    discovery = _FakeDiscovery({"192.168.1.0/29": [host]})
    # Kontroll-Adressen liefern NICHTS (kein Abfaenger) -- der Normalfall.
    scanner = _FakePortScanner(
        {
            "192.168.1.2": [
                PortInfo(port=22, state="open", service="ssh"),
                PortInfo(port=443, state="open", service="https"),
            ]
        }
    )
    use_case, _, history = _make_use_case(discovery=discovery, port_scanner=scanner)

    events = _run(use_case, _interception_config())

    assert _open_ports_by_ip(events) == {"192.168.1.2": {22, 443}}
    # "Geprueft, nichts gefunden" -- ausdruecklich checked=True mit leerer Liste.
    assert history.saved_interception is not None
    assert history.saved_interception.checked is True
    assert history.saved_interception.intercepted_ports == ()


def test_too_few_control_addresses_means_not_checked_and_no_filtering() -> None:
    """Test 4: Ohne drei geeignete Adressen wird NICHT gefiltert -- Zustand "nicht geprueft".

    /30 hat genau zwei Host-Adressen; eine davon ist das gefundene Geraet, es
    bleibt eine einzige Kandidatin -- zu wenig. Kein stiller Rueckfall auf eine
    oder zwei Adressen, und der Unterschied zu "geprueft, nichts gefunden" muss
    am Ergebnis ablesbar sein.
    """
    host = DiscoveredHost(ip="192.168.1.1", mac="AA:BB:CC:DD:EE:01", rtt_ms=1.0)
    discovery = _FakeDiscovery({"192.168.1.0/30": [host]})
    scanner = _InterceptingPortScanner(
        real_ports={"192.168.1.1": [PortInfo(port=22, state="open", service="ssh")]},
        intercepted=[PortInfo(port=25, state="open", service="smtp")],
    )
    use_case, _, history = _make_use_case(discovery=discovery, port_scanner=scanner)

    events = _run(use_case, _interception_config("192.168.1.0/30"))

    # Es wurde NICHT gefiltert: Port 25 steht trotz "antwortet ueberall" noch da.
    assert _open_ports_by_ip(events) == {"192.168.1.1": {22, 25}}

    saved = history.saved_interception
    assert saved is not None
    # "nicht geprueft" -- unterscheidbar von "geprueft, nichts gefunden" (Test 3):
    # dort checked=True, hier checked=False MIT Grund.
    assert saved.checked is False
    assert saved.intercepted_ports == ()
    assert saved.control_ips == ()
    assert saved.reason != ""

    # Und es wird benannt: ein Info-Protokolleintrag im Ereignisstrom.
    infos = [e.message for e in events if isinstance(e, Info)]
    assert len(infos) == 1
    assert "Gegenprobe" in infos[0]


def test_os_detection_sees_the_cleaned_port_list() -> None:
    """Test 5: Die Betriebssystem-Erkennung sieht die BEREINIGTE Portliste.

    Konstruktion: 22 + 9100 klassifiziert als Drucker (9100 = Jetdirect schlaegt
    durch). Wird 9100 lokal abgefangen und bleibt nur 22 (SSH) uebrig, muss der
    Host als Linux-Server herauskommen -- die Bereinigung greift also VOR
    ``classify_host``, und zwar sowohl fuer ``os_guess`` als auch ``category``.
    """
    host = DiscoveredHost(ip="192.168.1.2", mac="AA:BB:CC:DD:EE:01", rtt_ms=1.0)

    # Referenzmessung OHNE Abfaenger: 22 + 9100 -> Drucker.
    plain = _FakePortScanner(
        {
            "192.168.1.2": [
                PortInfo(port=22, state="open", service="ssh"),
                PortInfo(port=9100, state="open", service="jetdirect"),
            ]
        }
    )
    use_case, _, _ = _make_use_case(
        discovery=_FakeDiscovery({"192.168.1.0/29": [host]}), port_scanner=plain
    )
    reference = [e for e in _run(use_case, _interception_config()) if isinstance(e, HostEnriched)]
    assert reference[0].host.os_guess == "Printer"
    assert reference[0].host.category == "printer"

    # Jetzt derselbe Host, aber 9100 wird lokal abgefangen.
    scanner = _InterceptingPortScanner(
        real_ports={"192.168.1.2": [PortInfo(port=22, state="open", service="ssh")]},
        intercepted=[PortInfo(port=9100, state="open", service="jetdirect")],
    )
    use_case2, _, _ = _make_use_case(
        discovery=_FakeDiscovery({"192.168.1.0/29": [host]}), port_scanner=scanner
    )
    events = _run(use_case2, _interception_config())

    enriched = [e for e in events if isinstance(e, HostEnriched)]
    assert len(enriched) == 1
    assert {p.port for p in enriched[0].host.ports} == {22}
    # Ohne den abgefangenen 9100 faellt die Klassifikation anders aus.
    assert enriched[0].host.os_guess == "Linux"
    assert enriched[0].host.category == "server"


def test_interception_result_reaches_the_saved_scan_record() -> None:
    """Test 6: Die erkannten Ports stehen am Ergebnis und ueberleben den Weg in den Record."""
    host = DiscoveredHost(ip="192.168.1.2", mac="AA:BB:CC:DD:EE:01", rtt_ms=1.0)
    discovery = _FakeDiscovery({"192.168.1.0/29": [host]})
    scanner = _InterceptingPortScanner(
        real_ports={"192.168.1.2": [PortInfo(port=22, state="open", service="ssh")]},
        intercepted=[
            PortInfo(port=25, state="open", service="smtp"),
            PortInfo(port=143, state="open", service="imap"),
        ],
    )
    use_case, _, history = _make_use_case(discovery=discovery, port_scanner=scanner)

    _run(use_case, _interception_config())

    saved = history.saved_interception
    assert saved is not None
    # Beide erkannten Ports, sortiert, und die Zahl der geprueften Adressen.
    assert saved.intercepted_ports == (25, 143)
    assert len(saved.control_ips) == 3
    assert saved.checked is True


def test_interception_result_also_travels_on_the_completion_event() -> None:
    """S86-A11/B1: Das Gegenproben-Ergebnis reist AUSSERDEM im Abschluss-Ereignis.

    Der Live-Weg braucht den Hinweis zu genau DIESEM Lauf; der Record-Weg (Test 6)
    bleibt daneben unveraendert bestehen.
    """
    host = DiscoveredHost(ip="192.168.1.2", mac="AA:BB:CC:DD:EE:01", rtt_ms=1.0)
    discovery = _FakeDiscovery({"192.168.1.0/29": [host]})
    scanner = _InterceptingPortScanner(
        real_ports={"192.168.1.2": [PortInfo(port=22, state="open", service="ssh")]},
        intercepted=[PortInfo(port=25, state="open", service="smtp")],
    )
    use_case, _, history = _make_use_case(discovery=discovery, port_scanner=scanner)

    events = _run(use_case, _interception_config())

    completed = events[-1]
    assert isinstance(completed, ScanCompleted)
    assert completed.total_found == 1  # unveraendert
    assert completed.interception.checked is True
    assert completed.interception.intercepted_ports == (25,)
    # Ereignis und Record tragen DASSELBE Ergebnis -- eine Messung, zwei Wege.
    assert completed.interception == history.saved_interception


def test_completion_event_without_findings_carries_an_empty_list() -> None:
    """Geprueft und nichts gefunden: ``checked`` true, ``intercepted_ports`` leer."""
    host = DiscoveredHost(ip="192.168.1.2", mac="AA:BB:CC:DD:EE:01", rtt_ms=1.0)
    discovery = _FakeDiscovery({"192.168.1.0/29": [host]})
    use_case, _, _ = _make_use_case(discovery=discovery, port_scanner=_FakePortScanner())

    events = _run(use_case, _interception_config())

    completed = events[-1]
    assert isinstance(completed, ScanCompleted)
    assert completed.interception.checked is True
    assert completed.interception.intercepted_ports == ()


def test_interception_failure_does_not_break_the_scan_and_does_not_filter() -> None:
    """Test 7: Faellt die Gegenprobe mit einer Ausnahme aus, laeuft der Scan weiter.

    Es wird NICHT gefiltert, und der Zustand ist derselbe "nicht geprueft" wie in
    Test 4 -- nur mit anderem Grund.
    """

    class _FailOnControlScanner:
        """Wirft NUR fuer die Kontroll-Adressen; die Geraete-Scans laufen normal."""

        def __init__(self) -> None:
            self.scanned_ips: list[str] = []

        async def scan(
            self, ip: str, ports: Sequence[int], mode: str, timeout: float, max_concurrent: int
        ) -> list[PortInfo]:
            self.scanned_ips.append(ip)
            if ip in _CONTROL_IPS:
                raise _FakeNmapError("Gegenprobe kaputt")
            return [PortInfo(port=25, state="open", service="smtp")]

    host = DiscoveredHost(ip="192.168.1.2", mac="AA:BB:CC:DD:EE:01", rtt_ms=1.0)
    discovery = _FakeDiscovery({"192.168.1.0/29": [host]})
    use_case, _, history = _make_use_case(discovery=discovery, port_scanner=_FailOnControlScanner())

    events = _run(use_case, _interception_config())

    # Der Scan lief VOLLSTAENDIG durch -- bis ScanCompleted, inkl. save.
    assert isinstance(events[-1], ScanCompleted)
    assert events[-1].total_found == 1
    # Auch das Abschluss-Ereignis traegt den "nicht geprueft"-Zustand -- der
    # Live-Weg darf ihn nicht als "geprueft, nichts gefunden" missdeuten.
    assert events[-1].interception.checked is False
    assert history.saved is not None

    # Es wurde NICHT gefiltert: Port 25 steht beim Geraet.
    assert _open_ports_by_ip(events) == {"192.168.1.2": {25}}

    saved = history.saved_interception
    assert saved is not None
    assert saved.checked is False  # derselbe Zustand wie Test 4
    assert saved.intercepted_ports == ()
    assert "_FakeNmapError" in saved.reason

    infos = [e.message for e in events if isinstance(e, Info)]
    assert len(infos) == 1
    assert "Gegenprobe" in infos[0]


def test_interception_probe_runs_once_per_scan_not_per_host() -> None:
    """Test 8: Die Gegenprobe laeuft EINMAL je Scan -- belegt ueber die Attrappen-Aufrufe."""
    hosts = [
        DiscoveredHost(ip="192.168.1.2", mac="AA:BB:CC:DD:EE:01", rtt_ms=1.0),
        DiscoveredHost(ip="192.168.1.4", mac="AA:BB:CC:DD:EE:02", rtt_ms=2.0),
    ]
    discovery = _FakeDiscovery({"192.168.1.0/29": hosts})
    scanner = _FakePortScanner()
    use_case, _, _ = _make_use_case(discovery=discovery, port_scanner=scanner)

    _run(use_case, _interception_config())

    # Genau drei Kontroll-Messungen (eine je Kontroll-Adresse) fuer den ganzen
    # Scan -- NICHT drei je Geraet. Bei zwei Geraeten waeren das sonst sechs.
    control_calls = [ip for ip in scanner.scanned_ips if ip in _CONTROL_IPS]
    assert control_calls == list(_CONTROL_IPS)

    # Insgesamt: 3 Kontroll-Messungen + 2 Geraete-Messungen.
    assert len(scanner.scanned_ips) == 5
    assert scanner.scanned_ips[:3] == list(_CONTROL_IPS)  # Gegenprobe VOR dem Enrich


# ── MAC-Gruppierung: eine MAC = ein Geraet (Proxy-ARP/Spoofing) ─────────────


def test_group_by_mac_picks_lowest_rtt_and_collects_additional_ips() -> None:
    """Drei IPs mit DERSELBEN MAC -> ein primaerer Host (niedrigster rtt) + additional_ips."""
    a = DiscoveredHost(ip="172.18.0.1", mac="AA:BB:CC:DD:EE:01", rtt_ms=1.0)
    b = DiscoveredHost(ip="172.18.2.1", mac="AA:BB:CC:DD:EE:01", rtt_ms=700.0)
    c = DiscoveredHost(ip="172.18.2.2", mac="aa:bb:cc:dd:ee:01", rtt_ms=90.0)
    grouped, extra = _group_by_mac([a, b, c])

    # Genau ein Host fuer diese MAC: der mit dem niedrigsten rtt (172.18.0.1).
    assert len(grouped) == 1
    assert grouped[0].ip == "172.18.0.1"
    # Die weiteren IPs (sortiert) als additional_ips unter mac.lower().
    assert extra["aa:bb:cc:dd:ee:01"] == ("172.18.2.1", "172.18.2.2")


def test_group_by_mac_none_rtt_is_worst() -> None:
    """rtt_ms=None zaehlt als schlechtester Wert -> nie primaer, wenn ein echter rtt existiert."""
    a = DiscoveredHost(ip="10.0.0.1", mac="AA:00:00:00:00:01", rtt_ms=None)
    b = DiscoveredHost(ip="10.0.0.2", mac="AA:00:00:00:00:01", rtt_ms=5.0)
    grouped, extra = _group_by_mac([a, b])

    assert len(grouped) == 1
    assert grouped[0].ip == "10.0.0.2"  # echter rtt schlaegt None
    assert extra["aa:00:00:00:00:01"] == ("10.0.0.1",)


def test_group_by_mac_empty_macs_stay_separate() -> None:
    """Hosts mit LEERER MAC werden NICHT zusammengefasst -- jeder bleibt eigenstaendig."""
    a = DiscoveredHost(ip="10.0.0.5", mac="", rtt_ms=1.0)
    b = DiscoveredHost(ip="10.0.0.6", mac="", rtt_ms=2.0)
    grouped, extra = _group_by_mac([a, b])

    assert {h.ip for h in grouped} == {"10.0.0.5", "10.0.0.6"}
    assert extra == {}  # leere MAC ist keine Identitaet -> keine Gruppe


def test_group_by_mac_keeps_stable_order() -> None:
    """Reihenfolge stabil am ersten Vorkommen der MAC; kein Umsortieren der Tabelle."""
    a = DiscoveredHost(ip="10.0.0.1", mac="AA", rtt_ms=10.0)
    b = DiscoveredHost(ip="10.0.0.2", mac="BB", rtt_ms=1.0)
    c = DiscoveredHost(ip="10.0.0.3", mac="AA", rtt_ms=1.0)  # niedrigster rtt der AA-Gruppe
    grouped, _ = _group_by_mac([a, b, c])

    # AA erscheint zuerst (Position von a), obwohl c der primaere Host ist.
    assert [h.ip for h in grouped] == ["10.0.0.3", "10.0.0.2"]


def test_proxy_arp_macs_collapse_to_one_host_with_additional_ips() -> None:
    """Voller Lauf: drei Ping-Hosts mit gleicher MAC -> ein enriched Host + additional_ips."""
    # Realfall FRITZ!Box Proxy-ARP: dieselbe MAC antwortet auf mehrere IPs.
    hosts = [
        DiscoveredHost(ip="172.18.0.1", mac="AA:BB:CC:DD:EE:01", rtt_ms=1.0),
        DiscoveredHost(ip="172.18.2.1", mac="AA:BB:CC:DD:EE:01", rtt_ms=700.0),
        DiscoveredHost(ip="172.18.2.2", mac="AA:BB:CC:DD:EE:01", rtt_ms=90.0),
    ]
    # /20 statt /16: die drei IPs (172.18.0.1, 172.18.2.1, 172.18.2.2) liegen
    # saemtlich in 172.18.0.0/20 -- die Aussage des Tests (gleiche MAC auf mehreren
    # IPs faellt zu EINEM Host zusammen) bleibt unberuehrt. Ein /16 liegt seit der
    # Netzgroessen-Schranke (S88-P2) ueber der Obergrenze, ein /20 genau darauf.
    discovery = _FakeDiscovery({"172.18.0.0/20": hosts})
    use_case, _, history = _make_use_case(discovery=discovery)

    config = ScanConfig(
        cidrs=("172.18.0.0/20",),
        port_scan=False,
        mdns_scan=False,
        ssdp_scan=False,
        resolve_hostnames=False,
    )
    events = _run(use_case, config)

    # Genau EIN enriched Host fuer die MAC, mit der niedrigsten-rtt-IP.
    enriched = [e for e in events if isinstance(e, HostEnriched)]
    assert len(enriched) == 1
    primary = enriched[0].host
    assert primary.ip == "172.18.0.1"
    assert primary.additional_ips == ("172.18.2.1", "172.18.2.2")

    # discovery-done + scan_complete zaehlen die gruppierte Sicht (ein Geraet).
    disc_done = next(
        e
        for e in events
        if isinstance(e, PhaseChanged) and e.phase == "discovery" and e.status == "done"
    )
    assert disc_done.alive_count == 1
    assert isinstance(events[-1], ScanCompleted)
    assert events[-1].total_found == 1

    # Der gespeicherte Scan enthaelt genau den einen primaeren Host.
    assert history.saved is not None
    assert len(history.saved[1]) == 1
    assert history.saved[1][0].ip == "172.18.0.1"
    assert history.saved[1][0].additional_ips == ("172.18.2.1", "172.18.2.2")
