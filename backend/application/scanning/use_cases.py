"""Use-Cases der scanning-Domaene -- der Orchestrator ``RunNetworkScan``.

Orchestriert die scanning-Ports (Discovery, PortScanner, Vendor, Resolver, Mdns,
Ssdp, Ipv6, ScanHistory) + die reine Domaenenlogik ``classify_host``. Kennt
``domain/`` und ``ports/``, NIEMALS ``infrastructure/`` oder ``modules/``
(maschinell per import-linter erzwungen). Alle Ports kommen per
Constructor-Injection als Protocol-Typ herein -- nie ein konkreter Adapter.
Kein Framework-Import (kein FastAPI/Starlette): ``run`` ist ein nativer
async-Generator typisierter Domaenen-Events (``ScanEvent``); die Uebersetzung in
WS-Frames bleibt der api-Schicht (S.6) vorbehalten.

Fluss (am S.1-Characterization-Contract des ``/ws/scan`` ausgerichtet):

1. ``ScanStarted`` (cidr-Anzeige + Gesamt-Hostzahl).
2. mDNS/SSDP als Hintergrund-Tasks STARTEN (``create_task``) -- sie laufen
   parallel zur Discovery, wie im Altcode. Eingesammelt werden sie erst nach der
   Discovery-Phase (so ueberlappt die Lauschzeit mit dem Ping-Sweep).
3. ``PhaseChanged(discovery, running)``.
4. Discovery-Generator je CIDR durchlaufen: ``DiscoveryTick`` -> ``Progress``,
   ``DiscoveryHostFound`` -> ``HostFound``.
4b. ARP-Merge (S.7b): ARP-only-Hosts (im OS-Neighbor-Cache, aber ping-still) als
   synthetische ``DiscoveredHost(source="arp")`` anhaengen + ``HostFound`` yielden
   -- noch in der Discovery-Phase, vor ``done``.
5. ``PhaseChanged(discovery, done, alive_count)`` -- ``alive_count`` inkl. ARP-Hosts.
6. mDNS/SSDP einsammeln (per IP gruppiert).
7. ``PhaseChanged(enrich, running, total)``.
8. Pro lebendem Host: Hostname/SMB-Aufloesung, PortScan, mDNS/SSDP zuordnen,
   ``classify_host`` -> ``HostEnriched`` + ``Progress``.
9. IPv6-Anreicherung EINMAL ueber ALLE Hosts am Ende (Altcode-treu, der
   ``Ipv6EnrichmentPort`` arbeitet batch-weise).
10. ``ScanHistory.save`` -> ``ScanCompleted``.

BEWUSST AUFGESCHOBENE LUECKEN (KEINE vergessenen Schritte -- siehe S.6-Merkposten):

* FritzHosts-Merge: Der Altcode merged zusaetzliche Hosts aus der FRITZ!Box-
  DHCP-Tabelle (``FritzHostsPort.get_hosts``) in die Discovery-Liste -- faengt
  ping-blockierende Geraete (iPads o.ae.). Das ist hier NICHT enthalten: der
  ``FritzHostsPort`` ist daher (noch) NICHT injiziert -- ein ungenutzter Port
  saehe wie ein Bug aus. Kommt mit der S.6-Verdrahtung, wenn das Merge-Verhalten
  (Fritz-Hosts ausserhalb des gescannten Subnetzes? Reihenfolge der
  ``HostFound``-Events?) entschieden ist.
* devices-Persistenz: Der Altcode ruft pro Host ``update_device_from_scan``
  (v2: ``RecordScannedHost``). Das ist ein Seiteneffekt, KEIN Teil der
  Event-Sequenz, und eine scanning->devices-Domaenenkopplung. Bleibt aus dem
  Use-Case heraus; die ``EnrichedHost`` -> ``ScannedHost``-Projektion +
  ``RecordScannedHost``-Aufruf gehoeren in die S.6-Verdrahtung.

HostFound-Timing: Der ``HostDiscoveryPort``-Adapter (Variante A, S.4b) buendelt
alle ``DiscoveryHostFound`` NACH den ``DiscoveryTick``s (entkoppelt vom
Fortschritt). Der Use-Case gibt diese Reihenfolge UNVERAENDERT weiter (kein
Umsortieren) -- ob die api-Schicht die v1-interleaved-Reihenfolge wiederherstellt,
ist eine S.6-Entscheidung (siehe Merkposten).

Fehlerpfad (Entscheidung S.5): ``NmapScanError`` / ``FritzAuthError`` (Adapter-
Exceptions aus ``infrastructure``) werden hier NICHT gefangen -- sie propagieren
durch den Generator hindurch; S.6 (api) faengt sie und baut den sauberen
``error``-Frame. So bleibt der Use-Case import-sauber (kennt nur Ports), und die
Fehler-Uebersetzung sitzt an EINER Stelle.

Invalid-CIDR: ``ScanConfig.__post_init__`` (domain) wirft beim Konstruieren der
Config -- der Use-Case sieht nie ein invalides CIDR. Die ``error``-Frame-
Uebersetzung des ``ValueError`` ist S.6-Sache (die api baut die Config aus dem
WS-JSON).
"""

import asyncio
from collections.abc import AsyncIterator
from ipaddress import ip_address, ip_network
from typing import assert_never

from domain.scanning import (
    DiscoveredHost,
    DiscoveryHostFound,
    DiscoveryTick,
    EnrichedHost,
    HostEnriched,
    HostFound,
    MdnsService,
    PhaseChanged,
    PortInfo,
    Progress,
    ScanCompleted,
    ScanConfig,
    ScanEvent,
    ScanRecord,
    ScanStarted,
    ScanSummary,
    SsdpService,
    classify_host,
)
from ports.scanning import (
    ArpTablePort,
    HostDiscoveryPort,
    HostnameResolverPort,
    Ipv6EnrichmentPort,
    MdnsPort,
    PortScannerPort,
    ScanHistoryRepository,
    SsdpPort,
    VendorLookupPort,
)

# Port-Timeout je Verbindungsversuch im socket-Modus. ``ScanConfig`` kennt keinen
# eigenen Wert; der Altcode nutzte den ``scan_ports_socket``-Default (0.5 s).
_PORT_TIMEOUT = 0.5
# Resolver-Timeout (Altcode: 1.5 s je Host, ``main.ws_scan``).
_RESOLVE_TIMEOUT = 1.5
# SSDP-Sammelfenster (Altcode: 4.0 s, ``main.ws_scan``).
_SSDP_TIMEOUT = 4.0
# Top-100-Ports als Default, wenn die Config keine eigenen Ports vorgibt. Bewusst
# als Konstante im Use-Case (domain-nah), nicht aus ``modules`` importiert.
_TOP_100_PORTS: tuple[int, ...] = (
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    119,
    123,
    135,
    139,
    143,
    161,
    194,
    389,
    443,
    445,
    465,
    500,
    514,
    515,
    548,
    554,
    587,
    631,
    636,
    993,
    995,
    1080,
    1194,
    1433,
    1723,
    2049,
    2082,
    2083,
    3000,
    3306,
    3389,
    3478,
    4000,
    5000,
    5001,
    5060,
    5353,
    5432,
    5900,
    6379,
    7000,
    8080,
    8081,
    8443,
    8888,
    9000,
    9100,
    9200,
    10000,
    27017,
    32400,
    5960,
    5961,
    5962,
    5963,
    7788,
)


def _in_any_cidr(ip_str: str, cidrs: tuple[str, ...]) -> bool:
    """True, wenn ``ip_str`` in einem der ``cidrs`` liegt (``_in_any_net``-Aequivalent).

    Begrenzt den ARP-Merge auf das gescannte Netz -- ein ARP-Cache enthaelt auch
    Eintraege ausserhalb des Scans (Gateway anderer Interfaces o.ae.). Die CIDRs
    sind in ``ScanConfig.__post_init__`` bereits validiert; nur die zu pruefende
    ``ip_str`` kann ungueltig sein (z.B. unsauberer ARP-Output) -> dann False.
    """
    try:
        addr = ip_address(ip_str)
    except ValueError:
        return False
    return any(addr in ip_network(c, strict=False) for c in cidrs)


def _group_by_ip[T: (MdnsService, SsdpService)](services: list[T]) -> dict[str, tuple[T, ...]]:
    """Gruppiert Dienste nach ihrer ``ip`` (group_by_ip-Aequivalent des Altcodes).

    Dienste ohne ``ip`` (leeres Feld) fallen heraus -- sie koennen keinem Host
    zugeordnet werden. Reihenfolge je IP bleibt die Fundreihenfolge.
    """
    grouped: dict[str, list[T]] = {}
    for service in services:
        if service.ip:
            grouped.setdefault(service.ip, []).append(service)
    return {ip: tuple(items) for ip, items in grouped.items()}


class RunNetworkScan:
    """Orchestriert einen Netzwerk-Scan und yieldet typisierte ``ScanEvent``."""

    def __init__(
        self,
        discovery: HostDiscoveryPort,
        port_scanner: PortScannerPort,
        vendor_lookup: VendorLookupPort,
        resolver: HostnameResolverPort,
        mdns: MdnsPort,
        ssdp: SsdpPort,
        ipv6: Ipv6EnrichmentPort,
        arp_table: ArpTablePort,
        scan_history: ScanHistoryRepository,
    ) -> None:
        self._discovery = discovery
        self._port_scanner = port_scanner
        self._vendor_lookup = vendor_lookup
        self._resolver = resolver
        self._mdns = mdns
        self._ssdp = ssdp
        self._ipv6 = ipv6
        self._arp_table = arp_table
        self._scan_history = scan_history

    async def run(self, config: ScanConfig) -> AsyncIterator[ScanEvent]:
        """Fuehrt den Scan aus und yieldet die Ereignisse in S.1-Contract-Reihenfolge."""
        total_hosts = sum(
            # num_addresses - 2 (Netz-/Broadcast-Adresse), altcode-treu; nie negativ.
            max(ip_network(c, strict=False).num_addresses - 2, 0)
            for c in config.cidrs
        )
        cidr_display = ",".join(config.cidrs)
        yield ScanStarted(cidr=cidr_display, total_hosts=total_hosts)

        # mDNS/SSDP parallel zur Discovery starten (eingesammelt wird nach Discovery).
        mdns_task = (
            asyncio.create_task(self._mdns.discover(config.mdns_duration))
            if config.mdns_scan
            else None
        )
        ssdp_task = (
            asyncio.create_task(self._ssdp.discover(_SSDP_TIMEOUT)) if config.ssdp_scan else None
        )

        yield PhaseChanged(phase="discovery", status="running", total=total_hosts)

        # ── Discovery ueber alle CIDRs ────────────────────────────────────────
        discovered: list[DiscoveredHost] = []
        for cidr in config.cidrs:
            async for event in self._discovery.discover(
                cidr, config.ping_timeout, config.max_concurrent_ping
            ):
                match event:
                    case DiscoveryTick(completed=tick_completed, total=tick_total):
                        # Fortschritt ueber den jeweiligen CIDR (Adapter zaehlt je CIDR).
                        pct = round(tick_completed / tick_total * 100) if tick_total else 100
                        yield Progress(
                            phase="discovery",
                            completed=tick_completed,
                            total=tick_total,
                            pct=pct,
                        )
                    case DiscoveryHostFound(host=host):
                        discovered.append(host)
                        vendor = self._vendor_lookup.lookup(host.mac) if host.mac else ""
                        yield HostFound(
                            ip=host.ip,
                            mac=host.mac,
                            vendor=vendor,
                            rtt_ms=host.rtt_ms,
                            is_unknown=bool(host.mac),
                            source=host.source,
                        )
                    case _:
                        # Exhaustiveness: mypy prueft, dass DiscoveryEvent vollstaendig
                        # behandelt ist -- ein neuer Event-Typ ohne case bricht hier.
                        assert_never(event)

        # ── ARP-Merge: Hosts, die der Ping-Sweep nicht fand (S.7b) ───────────
        # Faengt ping-stille Geraete, die im OS-Neighbor-Cache stehen (z.B. per
        # frueheren Traffic gelernt). Zweite ``get_arp_table()``-Abfrage NEBEN der
        # adapter-internen MAC-Zuordnung (S.4b) -- bewusst akzeptiert (Entscheidung
        # 3A): der Cache ist billig, und die Tabelle durch den HostDiscoveryPort-
        # Vertrag durchzureichen waere ein grosser Eingriff fuer eine Mikro-
        # Optimierung. Nur ARP-ONLY-Hosts werden angehaengt; Ping-Hosts haben ihre
        # MAC schon -- kein Doppel, kein MAC-Nachtrag (Altcode-treu).
        discovered_ips = {host.ip for host in discovered}
        for arp_ip, arp_mac in (await self._arp_table.get_arp_table()).items():
            if arp_ip in discovered_ips:
                continue
            if not _in_any_cidr(arp_ip, config.cidrs):
                continue
            # Bewusste Abweichung vom Altcode (Entscheidung 4A): KEIN Zweit-Ping zum
            # RTT-Messen. Ein ARP-only-Host hat per Definition gerade NICHT auf Ping
            # geantwortet (sonst stuende er in ``discovered_ips``) -- ein zweiter Ping
            # liefert fast sicher erneut Timeout -> None. Wir setzen ``rtt_ms=None``
            # direkt; das spart einen ``ping_host``-Port, den wir sonst nirgends
            # brauchen, und ist observable nahezu identisch.
            arp_host = DiscoveredHost(
                ip=arp_ip, mac=arp_mac, rtt_ms=None, is_alive=True, source="arp"
            )
            discovered.append(arp_host)
            discovered_ips.add(arp_ip)
            vendor = self._vendor_lookup.lookup(arp_host.mac) if arp_host.mac else ""
            yield HostFound(
                ip=arp_host.ip,
                mac=arp_host.mac,
                vendor=vendor,
                rtt_ms=arp_host.rtt_ms,
                is_unknown=bool(arp_host.mac),
                source=arp_host.source,
            )

        # alive_count zaehlt die ARP-Hosts mit (Altcode: len(discovered) NACH dem Merge).
        yield PhaseChanged(phase="discovery", status="done", alive_count=len(discovered))

        # ── mDNS/SSDP einsammeln + per IP gruppieren (group_by_ip-Aequivalent) ──
        # Die parallelen Tasks werden hier awaited; die Dienste tragen seit dem
        # S.5-Vorbau ihre ``ip`` und werden im Enrich dem passenden Host zugeordnet.
        mdns_by_ip = _group_by_ip(await mdns_task) if mdns_task is not None else {}
        ssdp_by_ip = _group_by_ip(await ssdp_task) if ssdp_task is not None else {}

        # ── Enrich ────────────────────────────────────────────────────────────
        yield PhaseChanged(phase="enrich", status="running", total=len(discovered))
        enriched_hosts: list[EnrichedHost] = []
        total = len(discovered)
        for index, host in enumerate(discovered, start=1):
            enriched = await self._enrich_host(
                host,
                config,
                mdns_by_ip.get(host.ip, ()),
                ssdp_by_ip.get(host.ip, ()),
            )
            enriched_hosts.append(enriched)
            yield HostEnriched(host=enriched)
            pct = round(index / total * 100) if total else 100
            yield Progress(phase="enrich", completed=index, total=total, pct=pct)

        # ── IPv6 einmal ueber ALLE Hosts (Altcode-treu, batch) ───────────────
        enriched_hosts = await self._ipv6.enrich(enriched_hosts)

        # ── Persistenz + Abschluss ───────────────────────────────────────────
        self._scan_history.save(cidr_display, enriched_hosts)
        yield ScanCompleted(total_found=len(discovered))

    async def _enrich_host(
        self,
        host: DiscoveredHost,
        config: ScanConfig,
        mdns_services: tuple[MdnsService, ...],
        ssdp_services: tuple[SsdpService, ...],
    ) -> EnrichedHost:
        """Reichert einen einzelnen Host an (Hostname/SMB/Ports/Dienste/Klassifikation).

        ``mdns_services``/``ssdp_services`` sind die dem Host (per IP) zugeordneten
        Dienste -- leer, wenn keine fuer diese IP gefunden wurden.
        """
        vendor = self._vendor_lookup.lookup(host.mac) if host.mac else ""

        hostname = ""
        if config.resolve_hostnames:
            hostname = await self._resolver.resolve(host.ip, _RESOLVE_TIMEOUT)

        smb_name, smb_domain = "", ""
        if config.smb_scan:
            smb_name, smb_domain = await self._resolver.smb_info(host.ip)

        ports: tuple[PortInfo, ...] = ()
        if config.port_scan:
            scanned = await self._port_scanner.scan(
                host.ip,
                config.custom_ports or _TOP_100_PORTS,
                config.port_mode,
                _PORT_TIMEOUT,
                config.max_concurrent_ports,
            )
            ports = tuple(scanned)

        # Fingerprinting bekommt die mDNS-Dienste (altcode-treu: _ipp/_googlecast etc.
        # fliessen in die Klassifikation ein). ``is_ndi`` aus den mDNS-Diensten.
        classification = classify_host(
            ports=ports,
            vendor=vendor,
            mdns_services=mdns_services,
            hostname=hostname,
        )
        is_ndi = any(s.is_ndi for s in mdns_services)

        return EnrichedHost(
            ip=host.ip,
            mac=host.mac,
            vendor=vendor,
            rtt_ms=host.rtt_ms,
            hostname=hostname,
            smb_name=smb_name,
            smb_domain=smb_domain,
            os_guess=classification.os_guess,
            scan_method=config.port_mode if config.port_scan else "socket",
            ports=ports,
            mdns_services=mdns_services,
            ssdp_services=ssdp_services,
            is_ndi=is_ndi,
            is_unknown=bool(host.mac),
            category=classification.category,
        )


# ── Duenne REST-Use-Cases (Lese-Pfade fuer die scanning-api, S.6) ───────────
# Trivial (ein Port-Aufruf), aber die EINZIGE Schicht, die der api-Ring ansprechen
# darf (api -> nur application). Muster wie GetDevices/GetDevice (devices D.6):
# Constructor-Injection des Ports, kein State, kein Framework.


class GetScanHistory:
    """Liste der letzten Scans (ohne Host-Blob), neueste zuerst."""

    def __init__(self, scan_history: ScanHistoryRepository) -> None:
        self._scan_history = scan_history

    def __call__(self, limit: int) -> list[ScanSummary]:
        return self._scan_history.list(limit)


class GetScanDetail:
    """Ein Scan mit seinen vollen Hosts, oder ``None`` wenn die ID unbekannt ist.

    Gibt ``None`` unveraendert weiter -- das 404-Mapping macht der Router (api),
    nicht der Use-Case (analog ``DeviceNotFoundError`` bleibt das HTTP-Detail in
    der api-Schicht).
    """

    def __init__(self, scan_history: ScanHistoryRepository) -> None:
        self._scan_history = scan_history

    def __call__(self, scan_id: int) -> ScanRecord | None:
        return self._scan_history.get(scan_id)


class LookupVendor:
    """Hersteller zur OUI einer MAC, oder ``""`` wenn nicht gefunden (synchroner Lookup)."""

    def __init__(self, vendor_lookup: VendorLookupPort) -> None:
        self._vendor_lookup = vendor_lookup

    def __call__(self, mac: str) -> str:
        return self._vendor_lookup.lookup(mac)


class GetArpTable:
    """System-ARP-/Neighbor-Cache als ``{ip: mac}`` (Lese-Pfad fuer ``/api/arp``).

    Asynchron, weil der Port die blockierende ``ip neigh``-Abfrage ueber
    ``run_in_executor`` kapselt. Leerer Cache -> ``{}`` (kein Sonderfall).
    """

    def __init__(self, arp_table: ArpTablePort) -> None:
        self._arp_table = arp_table

    async def __call__(self) -> dict[str, str]:
        return await self._arp_table.get_arp_table()
