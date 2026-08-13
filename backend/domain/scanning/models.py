"""Domaenenmodelle der scanning-Domaene -- reine Wertobjekte (stdlib, ADR 0002).

Kein Framework, kein I/O, KEIN Import aus anderen Domaenen: scanning kennt nur
seine eigenen Modelle. Die Projektion ``EnrichedHost`` -> ``devices.ScannedHost``
passiert spaeter im Use-Case (application), bewusst NICHT hier (keine
Domaene-zu-Domaene-Kopplung).

``ScanConfig`` validiert die CIDRs via stdlib ``ipaddress`` -- reine Formatpruefung,
kein Netzwerk-I/O.
"""

import ipaddress
from dataclasses import dataclass, field


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
class PortInterception:
    """Ergebnis der EINEN Gegenprobe je Scan gegen lokal abgefangene Ports.

    Fachliche Lage (Befund 53): Auf der messenden Maschine kann ein
    Sicherheitsprogramm bestimmte Ports LOKAL abfangen. Der Verbindungsaufbau
    gelingt dann gegen JEDE Adresse -- auch gegen eine, an der kein Geraet
    existiert. Ein so gemessener Port ist keine Eigenschaft des entfernten
    Geraets, sondern des messenden Rechners; er darf nicht als offener Port
    fortgeschrieben und nicht sicherheitsbewertet werden.

    ``checked`` trennt die beiden Zustaende, die nach aussen NICHT dasselbe sind:

    * ``checked=True``  -- die Gegenprobe lief. ``intercepted_ports`` ist dann
      das Ergebnis; leer heisst "geprueft, nichts gefunden".
    * ``checked=False`` -- die Gegenprobe lief NICHT (zu wenige geeignete
      Kontroll-Adressen, oder sie ist mit einer Ausnahme ausgefallen). Es wurde
      NICHT gefiltert. ``reason`` benennt den Grund im Klartext. KEIN stiller
      Rueckfall auf weniger Adressen oder auf gar keine Pruefung -- ein "wir
      haben nicht geprueft" muss vom "wir haben geprueft und nichts gefunden"
      unterscheidbar bleiben (ADR 0001: keine stillen Fallbacks).

    ``control_ips`` sind die tatsaechlich gemessenen Kontroll-Adressen (leer,
    wenn nicht geprueft wurde); ihre Anzahl macht nachvollziehbar, auf wie
    vielen Adressen der Befund beruht.
    """

    checked: bool = False
    control_ips: tuple[str, ...] = ()
    intercepted_ports: tuple[int, ...] = ()
    reason: str = ""


@dataclass(frozen=True)
class MdnsService:
    """Ein per mDNS gefundener Dienst. ``properties`` als (key, value)-Paare (frozen-tauglich)."""

    name: str = ""
    type: str = ""
    port: int = 0
    hostname: str = ""
    is_ndi: bool = False
    properties: tuple[tuple[str, str], ...] = ()
    ip: str = ""


@dataclass(frozen=True)
class SsdpService:
    """Ein per SSDP gefundener Dienst."""

    server: str = ""
    st: str = ""
    location: str = ""
    ip: str = ""


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
    ipv6: str = ""
    ipv6_all: tuple[str, ...] = ()
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
    # Herkunft des Hosts in der Discovery-Phase: "ping" (Sweep), "arp"
    # (OS-Neighbor-Cache, S.7b) oder "fritzbox" (FRITZ!Box-DHCP, S.7c). Default
    # "ping" -- ein nicht-gemergter Host IST ein Ping-Host, und kein Aufrufer
    # bricht. Wird seit S.7f aus ``DiscoveredHost.source`` durchgereicht, sodass
    # die Quelle die Enrich-Phase ueberlebt und in ScanHistory/host_detail landet.
    source: str = "ping"
    # Weitere IPs, die dieselbe MAC im Discovery beantwortet hat (MAC-Gruppierung):
    # leer im Normalfall, gefuellt bei Proxy-ARP der FRITZ!Box ODER ARP-Spoofing.
    # Default leeres Tuple, damit bestehende Konstruktionen unveraendert valide bleiben.
    additional_ips: tuple[str, ...] = ()


@dataclass(frozen=True)
class ScanSummary:
    """Listen-View eines gespeicherten Scans -- OHNE den Host-Blob.

    Was ``ScanHistoryRepository.list()`` liefert (Charakterisierung S.1:
    ``get_scan_history`` ohne ``result_json``). ``host_count`` ist die im Scan
    gefundene Host-Anzahl; der eigentliche Inhalt kommt erst per ``get(scan_id)``.
    ``scanned_at`` ist der ISO-Zeitstempel der DB-Spalte (S.1-REST-Contract).
    """

    scan_id: int
    cidr: str
    host_count: int
    scanned_at: str = ""


@dataclass(frozen=True)
class ScanRecord:
    """Detail eines gespeicherten Scans -- die vollen Hosts (host_detail/scan_history).

    Was ``ScanHistoryRepository.get(scan_id)`` liefert (Charakterisierung S.1:
    ``get_scan_by_id`` mit ``hosts``-Round-trip). Die Hosts sind die reichen
    Domaenen-Objekte ``EnrichedHost``; die JSON-(De-)Serialisierung ist Sache des
    Adapters (S.4), nicht der Domaene. ``host_count``/``scanned_at`` spiegeln die
    DB-Spalten (S.1-REST-Contract: ``get_scan_by_id`` liefert beide mit).
    """

    scan_id: int
    cidr: str
    hosts: tuple[EnrichedHost, ...]
    host_count: int = 0
    scanned_at: str = ""
    # Ergebnis der Gegenprobe gegen lokal abgefangene Ports (Befund 53). Sitzt am
    # RECORD, nicht am Host: der Abfaenger ist eine Eigenschaft des messenden
    # Rechners, nicht eines einzelnen Ziels -- die Gegenprobe laeuft EINMAL je
    # Scan. Der Default (``checked=False``) gilt fuer Altbestand aus der Zeit vor
    # dieser Etappe: dort wurde nicht geprueft, und genau das sagt der Wert aus.
    interception: PortInterception = field(default_factory=PortInterception)
