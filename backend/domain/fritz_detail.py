"""Domaenenmodell der FritzBox-Detailansicht: reine Wertobjekte.

Reine Domaenenlogik (stdlib + dataclasses, ADR 0002) -- KEIN Wissen ueber
TR-064/SOAP, HTTP oder die Uhr. Diese Typen beschreiben NUR die fachliche Form
einer FRITZ!Box-Momentaufnahme (WAN/DSL/WLAN/Clients/Log/Portfreigaben); die
Projektion der v1-``modules.fritzbox``-Objekte auf diese Typen passiert im
Infrastructure-Adapter (Ring 4), nicht hier.

Alle dataclasses sind ``frozen`` (unveraenderliche Wertobjekte). Das Aggregat
``FritzDetail`` hat sinnvolle Leer-Defaults fuer JEDES Unter-Objekt, sodass ein
"nicht erreichbar"-Zustand (``reachable=False``) ohne Pflichtfelder baubar ist --
"nicht konfiguriert/nicht erreichbar" ist ein legitimer Leer-Zustand, KEIN Fehler
(Muster wie ``FritzHostsPort`` -> ``[]``). Ein Auth-Fehler ist dagegen ein Fehler
und wird NICHT ueber dieses Modell ausgedrueckt (er fliegt als Exception aus dem
Adapter, siehe Ring 4).
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class FritzWanStatus:
    """WAN-/Internet-Verbindungsstatus (Uptime, externe IPs, Durchsatz, Volumen)."""

    connected: bool = False
    uptime_secs: int = 0
    ip_external: str = ""
    ip_external_v6: str = ""
    upstream_kbps: int = 0
    downstream_kbps: int = 0
    bytes_sent: int = 0
    bytes_recv: int = 0


@dataclass(frozen=True)
class FritzDslStatus:
    """DSL-Leitungswerte (nur bei DSL-Modellen befuellt; bei Fiber 0/False)."""

    sync: bool = False
    downstream_kbps: int = 0
    upstream_kbps: int = 0
    snr_downstream: float = 0.0
    snr_upstream: float = 0.0
    attn_downstream: float = 0.0
    attn_upstream: float = 0.0


@dataclass(frozen=True)
class FritzWlanBand:
    """Ein WLAN-Band (2.4 oder 5 GHz): an/aus, SSID, Kanal, verbundene Clients."""

    enabled: bool = False
    ssid: str = ""
    channel: int = 0
    clients: int = 0


@dataclass(frozen=True)
class FritzDeviceInfo:
    """Geraete-Stammdaten der Box: Modell, Firmware, Fiber-Flag, Host-Anzahl."""

    model: str = ""
    firmware: str = ""
    is_fiber: bool = False
    total_hosts: int = 0


@dataclass(frozen=True)
class FritzWlanClient:
    """Ein verbundener WLAN-Client (MAC/IP/Hostname, Signal, Speed, Band)."""

    mac: str
    ip: str = ""
    hostname: str = ""
    signal_dbm: int = 0
    speed_mbps: int = 0
    band: str = ""


@dataclass(frozen=True)
class FritzLogEntry:
    """Ein Eintrag des Ereignisprotokolls (laufende ID, Zeitstempel, Text)."""

    id: int
    timestamp: str = ""
    message: str = ""


@dataclass(frozen=True)
class FritzPortForwarding:
    """Eine Portfreigabe-Regel (Protokoll, externer Port -> interner Host/Port)."""

    enabled: bool = False
    description: str = ""
    protocol: str = ""
    external_port: int = 0
    internal_ip: str = ""
    internal_port: int = 0


@dataclass(frozen=True)
class FritzDetail:
    """Aggregat der Detailansicht: ein vollstaendiger FRITZ!Box-Schnappschuss.

    ``reachable=False`` ist der vertragliche Leer-Zustand (Box nicht
    konfiguriert/nicht erreichbar) -- KEIN Fehler. ``auth_error`` markiert den
    Sonderfall, dass die Box zwar antwortet, aber die Credentials zurueckweist
    (der Adapter uebersetzt das zusaetzlich in eine ``FritzAuthError``-Exception;
    das Flag bleibt fuer eine evtl. tolerante Projektion erhalten).

    Alle Unter-Objekte haben Leer-Defaults -> ``FritzDetail(reachable=False)`` ist
    ohne Pflichtfelder baubar. Die Sequenz-Felder sind ``tuple`` (unveraenderlich).
    """

    reachable: bool = False
    host: str = ""
    auth_error: bool = False
    device: FritzDeviceInfo = field(default_factory=FritzDeviceInfo)
    wan: FritzWanStatus = field(default_factory=FritzWanStatus)
    dsl: FritzDslStatus = field(default_factory=FritzDslStatus)
    wlan_24: FritzWlanBand = field(default_factory=FritzWlanBand)
    wlan_5: FritzWlanBand = field(default_factory=FritzWlanBand)
    wlan_clients: tuple[FritzWlanClient, ...] = ()
    log: tuple[FritzLogEntry, ...] = ()
    port_forwardings: tuple[FritzPortForwarding, ...] = ()
