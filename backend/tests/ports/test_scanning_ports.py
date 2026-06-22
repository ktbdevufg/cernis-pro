"""Strukturtest der scanning-Ports (S.3): Fakes erfuellen die Protocols.

Reine ``typing.Protocol``-Vertraege haben kein Verhalten -- der Verhaltenstest
kommt mit den Adaptern (S.4). Hier wird NUR die strukturelle Konformitaet
geprueft:

* **statisch (mypy):** Jede ``_assert_*``-Funktion nimmt den Port-TYP als
  Parameter und bekommt die Fake-Instanz uebergeben. Erfuellt ein Fake das
  Protocol nicht (falsche Signatur, fehlende Methode), schlaegt ``uv run mypy``
  fehl -- das ist die eigentliche Pruefung.
* **dynamisch (pytest):** Ein minimaler Smoke ruft jede Methode einmal auf und
  prueft, dass die Domaenen-Rueckgabetypen herauskommen (inkl. des nativen
  async-Generators von ``HostDiscoveryPort``).

Die async-Smokes werden ueber ``asyncio.run`` (stdlib) getrieben -- BEWUSST kein
``pytest-asyncio``/``anyio``-Marker: das Projekt hat bisher keinen async-Test und
keine solche Test-Dependency; eine in einem reinen Ports-Schritt einzufuehren
waere Scope-Ausweitung. ``asyncio.run`` reicht fuer den Strukturnachweis.

KEIN ``@runtime_checkable`` an den Ports -> bewusst KEIN ``isinstance``-Check fuer
die Konformitaet; die traegt mypy, nicht die Laufzeit. (Die ``isinstance``-Checks
unten unterscheiden nur die beiden Yield-Varianten -- das ist Datenpruefung, keine
Protocol-Konformitaetspruefung.)
"""

import asyncio
from collections.abc import AsyncIterator, Sequence

from domain.scanning import (
    DiscoveredHost,
    DiscoveryEvent,
    DiscoveryHostFound,
    DiscoveryTick,
    EnrichedHost,
    MdnsService,
    PortInfo,
    ScanRecord,
    ScanSummary,
    SsdpService,
)
from ports.scanning import (
    ArpTablePort,
    FritzHostsPort,
    HostDiscoveryPort,
    HostnameResolverPort,
    Ipv6EnrichmentPort,
    MdnsPort,
    PortScannerPort,
    ScanHistoryRepository,
    SsdpPort,
    VendorLookupPort,
)

# ── Fakes: minimale, vertragstreue Implementierungen ────────────────────────


class _FakeDiscovery:
    async def discover(
        self, cidr: str, ping_timeout: float, max_concurrent: int
    ) -> AsyncIterator[DiscoveryEvent]:
        yield DiscoveryTick(completed=1, total=1)
        yield DiscoveryHostFound(host=DiscoveredHost(ip="10.0.0.2"))


class _FakePortScanner:
    async def scan(
        self,
        ip: str,
        ports: Sequence[int],
        mode: str,
        timeout: float,
        max_concurrent: int,
    ) -> list[PortInfo]:
        return [PortInfo(port=22, state="open", service="ssh")]


class _FakeResolver:
    async def resolve(self, ip: str, timeout: float) -> str:
        return "host.local"

    async def smb_info(self, ip: str) -> tuple[str, str]:
        return ("NBNAME", "WORKGROUP")


class _FakeVendor:
    def lookup(self, mac: str) -> str:
        return "ACME Corp"


class _FakeMdns:
    async def discover(self, duration: float) -> list[MdnsService]:
        return [MdnsService(name="_http._tcp")]


class _FakeSsdp:
    async def discover(self, timeout: float) -> list[SsdpService]:
        return [SsdpService(server="Linux/1.0 UPnP/1.0")]


class _FakeIpv6:
    async def enrich(self, hosts: Sequence[EnrichedHost]) -> list[EnrichedHost]:
        return list(hosts)


class _FakeFritz:
    async def get_hosts(self) -> list[DiscoveredHost]:
        return []  # keine Fritz konfiguriert -> Leer-Zustand, kein Fehler


class _FakeArpTable:
    async def get_arp_table(self) -> dict[str, str]:
        return {"10.0.0.2": "AA:BB:CC:00:00:00"}


class _FakeScanHistory:
    def save(self, cidr: str, hosts: Sequence[EnrichedHost]) -> None:
        return None

    def list(self, limit: int) -> list[ScanSummary]:
        return [ScanSummary(scan_id=1, cidr="10.0.0.0/24", host_count=0)]

    def get(self, scan_id: int) -> ScanRecord | None:
        if scan_id == 1:
            return ScanRecord(scan_id=1, cidr="10.0.0.0/24", hosts=())
        return None

    def clear_all(self) -> None:
        """No-op fuer den Fake (kein interner Speicher zu leeren)."""


# ── Statische Konformitaet: mypy prueft die Zuweisung an den Port-Typ ───────


def _assert_discovery(_: HostDiscoveryPort) -> None: ...
def _assert_port_scanner(_: PortScannerPort) -> None: ...
def _assert_resolver(_: HostnameResolverPort) -> None: ...
def _assert_vendor(_: VendorLookupPort) -> None: ...
def _assert_mdns(_: MdnsPort) -> None: ...
def _assert_ssdp(_: SsdpPort) -> None: ...
def _assert_ipv6(_: Ipv6EnrichmentPort) -> None: ...
def _assert_fritz(_: FritzHostsPort) -> None: ...
def _assert_arp(_: ArpTablePort) -> None: ...
def _assert_history(_: ScanHistoryRepository) -> None: ...


def test_fakes_satisfy_ports_statically() -> None:
    """mypy-Beweis: jeder Fake genuegt seinem Port (Konformitaet rein statisch)."""
    _assert_discovery(_FakeDiscovery())
    _assert_port_scanner(_FakePortScanner())
    _assert_resolver(_FakeResolver())
    _assert_vendor(_FakeVendor())
    _assert_mdns(_FakeMdns())
    _assert_ssdp(_FakeSsdp())
    _assert_ipv6(_FakeIpv6())
    _assert_fritz(_FakeFritz())
    _assert_arp(_FakeArpTable())
    _assert_history(_FakeScanHistory())


# ── Dynamischer Smoke: Methoden aufrufbar, Domaenentypen kommen heraus ──────


def test_discovery_yields_tick_and_found() -> None:
    port: HostDiscoveryPort = _FakeDiscovery()

    async def _collect() -> list[DiscoveryEvent]:
        return [ev async for ev in port.discover("10.0.0.0/30", 1.0, 8)]

    events = asyncio.run(_collect())
    assert any(isinstance(e, DiscoveryTick) for e in events)
    assert any(isinstance(e, DiscoveryHostFound) for e in events)


def test_enrichment_ports_return_domain_types() -> None:
    scanner: PortScannerPort = _FakePortScanner()
    resolver: HostnameResolverPort = _FakeResolver()
    mdns: MdnsPort = _FakeMdns()
    ssdp: SsdpPort = _FakeSsdp()
    fritz: FritzHostsPort = _FakeFritz()

    async def _exercise() -> None:
        assert (await scanner.scan("10.0.0.2", [22], "socket", 0.5, 100))[0].port == 22
        assert await resolver.resolve("10.0.0.2", 1.0) == "host.local"
        assert await resolver.smb_info("10.0.0.2") == ("NBNAME", "WORKGROUP")
        assert (await mdns.discover(2.0))[0].name == "_http._tcp"
        assert (await ssdp.discover(2.0))[0].server.startswith("Linux")
        assert await fritz.get_hosts() == []

    asyncio.run(_exercise())


def test_vendor_lookup_is_sync() -> None:
    vendor: VendorLookupPort = _FakeVendor()
    assert vendor.lookup("AA:BB:CC:00:00:00") == "ACME Corp"


def test_arp_table_returns_ip_mac_map() -> None:
    arp: ArpTablePort = _FakeArpTable()
    assert asyncio.run(arp.get_arp_table()) == {"10.0.0.2": "AA:BB:CC:00:00:00"}


def test_ipv6_enrich_preserves_hosts() -> None:
    ipv6: Ipv6EnrichmentPort = _FakeIpv6()
    hosts = [EnrichedHost(ip="10.0.0.2", mac="AA:BB:CC:00:00:00")]
    assert asyncio.run(ipv6.enrich(hosts)) == hosts


def test_scan_history_roundtrip_shape() -> None:
    repo: ScanHistoryRepository = _FakeScanHistory()
    repo.save("10.0.0.0/24", ())
    summaries = repo.list(20)
    assert summaries[0].cidr == "10.0.0.0/24"
    assert isinstance(repo.get(1), ScanRecord)
    assert repo.get(999) is None
