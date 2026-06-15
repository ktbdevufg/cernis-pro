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
from domain.scanning import (
    DiscoveredHost,
    DiscoveryEvent,
    DiscoveryHostFound,
    DiscoveryTick,
    EnrichedHost,
    HostEnriched,
    HostFound,
    MdnsService,
    PhaseChanged,
    PortInfo,
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

    async def scan(
        self, ip: str, ports: Sequence[int], mode: str, timeout: float, max_concurrent: int
    ) -> list[PortInfo]:
        return self._ports.get(ip, [])


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

    def save(self, cidr: str, hosts: Sequence[EnrichedHost]) -> None:
        self.saved = (cidr, tuple(hosts))

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
    assert events[5] == PhaseChanged(phase="enrich", status="running", total=1)

    host_enriched = events[6]
    assert isinstance(host_enriched, HostEnriched)
    assert host_enriched.host.ip == "192.168.1.2"
    assert host_enriched.host.ports == (PortInfo(port=22, state="open", service="ssh"),)
    # SSH allein -> classify_host: Linux-Server (verhaltensgleich Altcode).
    assert host_enriched.host.category == "server"
    assert host_enriched.host.os_guess == "Linux"
    assert events[-1] == ScanCompleted(total_found=1)

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


def test_arp_merge_skips_phantom_duplicate_of_living_host() -> None:
    """ARP-Eintrag mit MAC eines lebenden Ping-Hosts ist ein Alias -- kein neues Geraet."""
    # Realfall: FritzBox per Ping (mac), ARP-Cache haengt eine zweite IP mit
    # DERSELBEN MAC dran (anderer Gross-/Kleinschreibung) -- ein Cache-Artefakt.
    ping_host = DiscoveredHost(ip="192.168.0.1", mac="AA:BB:CC:DD:EE:FF", rtt_ms=1.0)
    discovery = _FakeDiscovery({"192.168.0.0/24": [ping_host]})
    arp = _FakeArpTable(
        {
            "192.168.0.202": "aa:bb:cc:dd:ee:ff",  # gleiche MAC, andere IP -> Phantom, skip
        }
    )
    use_case, _, _ = _make_use_case(discovery=discovery, arp_table=arp)

    config = ScanConfig(
        cidrs=("192.168.0.0/24",),
        port_scan=False,
        mdns_scan=False,
        ssdp_scan=False,
        resolve_hostnames=False,
    )
    events = _run(use_case, config)

    found = [e for e in events if isinstance(e, HostFound)]
    # Nur der Ping-Host -- das Phantom-Duplikat erscheint NICHT.
    assert {f.ip for f in found} == {"192.168.0.1"}
    assert "192.168.0.202" not in {f.ip for f in found}

    # alive_count enthaelt das Phantom NICHT.
    disc_done = next(
        e
        for e in events
        if isinstance(e, PhaseChanged) and e.phase == "discovery" and e.status == "done"
    )
    assert disc_done.alive_count == 1


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
    assert events[-1] == ScanCompleted(total_found=1)


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
    fritz = _FakeFritzHosts(
        [DiscoveredHost(ip="192.168.1.50", mac="FF:FF:FF:FF:FF:FF", source="fritzbox")]
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
    assert found[0].mac == "FF:FF:FF:FF:FF:FF"


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
    assert events[-1] == ScanCompleted(total_found=0)
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
    assert events[-1] == ScanCompleted(total_found=2)
    assert history.saved is not None
    assert history.saved[0] == "10.0.0.0/30,10.0.1.0/30"
