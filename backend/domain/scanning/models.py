"""Domaenenmodelle der scanning-Domaene -- reine Wertobjekte (stdlib, ADR 0002).

Kein Framework, kein I/O, KEIN Import aus anderen Domaenen: scanning kennt nur
seine eigenen Modelle. Die Projektion ``EnrichedHost`` -> ``devices.ScannedHost``
passiert spaeter im Use-Case (application), bewusst NICHT hier (keine
Domaene-zu-Domaene-Kopplung).

``ScanConfig`` validiert die CIDRs via stdlib ``ipaddress`` -- reine Formatpruefung,
kein Netzwerk-I/O.
"""

import ipaddress
from dataclasses import dataclass


@dataclass(frozen=True)
class ScanConfig:
    """Geparste Scan-Konfiguration (Multi-CIDR bereits gesplittet)."""

    cidrs: tuple[str, ...]
    ping_timeout: float = 1.5
    port_scan: bool = True
    port_mode: str = "socket"
    mdns_scan: bool = True
    mdns_duration: float = 8.0
    resolve_hostnames: bool = True
    smb_scan: bool = False
    ssdp_scan: bool = True
    max_concurrent_ping: int = 64
    max_concurrent_ports: int = 100
    custom_ports: tuple[int, ...] | None = None

    def __post_init__(self) -> None:
        if not self.cidrs:
            raise ValueError("ScanConfig braucht mindestens ein CIDR")
        for cidr in self.cidrs:
            # Reine Formatpruefung (stdlib, kein I/O); deckt den "Invalid CIDR"-Fall ab.
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError as exc:
                raise ValueError(f"Invalid CIDR: {cidr}") from exc
        if self.ping_timeout <= 0:
            raise ValueError("ping_timeout muss > 0 sein")
        if self.mdns_duration <= 0:
            raise ValueError("mdns_duration muss > 0 sein")
        if self.max_concurrent_ping <= 0:
            raise ValueError("max_concurrent_ping muss > 0 sein")
        if self.max_concurrent_ports <= 0:
            raise ValueError("max_concurrent_ports muss > 0 sein")


@dataclass(frozen=True)
class DiscoveredHost:
    """Ergebnis der Discovery-Phase (eigenes Domaenen-Modell, unabhaengig von modules.discovery)."""

    ip: str
    mac: str = ""
    rtt_ms: float | None = None
    is_alive: bool = True
    source: str = "ping"


@dataclass(frozen=True)
class PortInfo:
    """Ein offener Port mit Zustand und (optional) Servicename."""

    port: int
    state: str
    service: str = ""


@dataclass(frozen=True)
class MdnsService:
    """Ein per mDNS gefundener Dienst. ``properties`` als (key, value)-Paare (frozen-tauglich)."""

    name: str = ""
    type: str = ""
    port: int = 0
    hostname: str = ""
    is_ndi: bool = False
    properties: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class SsdpService:
    """Ein per SSDP gefundener Dienst."""

    server: str = ""
    st: str = ""
    location: str = ""


@dataclass(frozen=True)
class HostClassification:
    """Ergebnis des Fingerprintings (die erzeugende Funktion kommt in S.2b)."""

    os_guess: str
    category: str


@dataclass(frozen=True)
class EnrichedHost:
    """Reiches Ergebnis pro Host -- was in host_detail/scan_history landet."""

    ip: str
    mac: str
    vendor: str = ""
    rtt_ms: float | None = None
    hostname: str = ""
    smb_name: str = ""
    smb_domain: str = ""
    os_guess: str = ""
    os_accuracy: int = 0
    scan_method: str = "socket"
    ports: tuple[PortInfo, ...] = ()
    mdns_services: tuple[MdnsService, ...] = ()
    ssdp_services: tuple[SsdpService, ...] = ()
    is_ndi: bool = False
    is_unknown: bool = False
    category: str = ""
    label: str = ""
    tags: tuple[str, ...] = ()
    notes: str = ""


@dataclass(frozen=True)
class ScanSummary:
    """Listen-View eines gespeicherten Scans -- OHNE den Host-Blob.

    Was ``ScanHistoryRepository.list()`` liefert (Charakterisierung S.1:
    ``get_scan_history`` ohne ``result_json``). ``host_count`` ist die im Scan
    gefundene Host-Anzahl; der eigentliche Inhalt kommt erst per ``get(scan_id)``.
    """

    scan_id: int
    cidr: str
    host_count: int


@dataclass(frozen=True)
class ScanRecord:
    """Detail eines gespeicherten Scans -- die vollen Hosts (host_detail/scan_history).

    Was ``ScanHistoryRepository.get(scan_id)`` liefert (Charakterisierung S.1:
    ``get_scan_by_id`` mit ``hosts``-Round-trip). Die Hosts sind die reichen
    Domaenen-Objekte ``EnrichedHost``; die JSON-(De-)Serialisierung ist Sache des
    Adapters (S.4), nicht der Domaene.
    """

    scan_id: int
    cidr: str
    hosts: tuple[EnrichedHost, ...]
