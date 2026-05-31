"""Ports der scanning-Domaene: Vertraege fuer Netz-Discovery, Anreicherung und
Scan-Historie.

Neun Vertraege, gruppiert nach Scan-Pipeline-Phase:

* **Discovery** -- ``HostDiscoveryPort`` (wer lebt?), ``PortScannerPort`` (welche
  Ports offen?).
* **Anreicherung** -- ``HostnameResolverPort``, ``VendorLookupPort``,
  ``MdnsPort``, ``SsdpPort``, ``Ipv6EnrichmentPort``, ``FritzHostsPort``.
* **Persistenz** -- ``ScanHistoryRepository`` (Muster wie ``DeviceRepository``,
  gleiche ``cernis.db``).

Bewusste Entscheidung: KEIN ``@runtime_checkable`` (Muster wie settings/devices).
Die Vertragspruefung laeuft statisch ueber mypy und ueber die Verdrahtung im
Composition Root (``app.py``), nicht zur Laufzeit per ``isinstance``.

I/O-Methoden sind ``async``; einzige Ausnahme ist ``VendorLookupPort.lookup`` --
ein reiner In-Memory-OUI-Lookup ohne I/O, daher synchron. ``nmap`` (PortScanner),
SMB-Info (Resolver), IPv6-NDP und Fritz-TR-064 sind blockierend; der jeweilige
Adapter (S.4) kapselt das ueber ``run_in_executor``, sodass die Port-Methode
trotzdem ``async`` bleibt -- der Use-Case (S.5) sieht eine einheitlich
asynchrone Schnittstelle.

``ports/`` kennt NUR ``domain/scanning``-Typen + stdlib. KEIN ``modules/``-Import
hier -- die (eingezaeunte) Altcode-Ausnahme gilt ausschliesslich fuer die
scanning-Infrastructure-Adapter (ADR 0007), nie fuer die Ports.

Import von ``domain`` ist erlaubt -- der import-linter-Contract verbietet nur die
Gegenrichtung (domain -> ports) sowie Importe aus ``infrastructure``/``api``.
"""

from collections.abc import AsyncIterator, Sequence
from typing import Protocol

from domain.scanning import (
    DiscoveredHost,
    DiscoveryEvent,
    EnrichedHost,
    MdnsService,
    PortInfo,
    ScanRecord,
    ScanSummary,
    SsdpService,
)

# ── Discovery ─────────────────────────────────────────────────────────────


class HostDiscoveryPort(Protocol):
    """Ping-basierte Host-Discovery eines CIDR -- nativer async-Generator.

    Variante A: der Adapter besitzt die Ping-Schleife selbst und yieldet
    inkrementell (KEINE Queue-Bruecke, kein ``modules.discover_subnet``-Callback).
    Pro abgearbeitetem Host kommt ein ``DiscoveryTick`` (Fortschritt), und fuer
    jeden lebenden Host zusaetzlich ein ``DiscoveryHostFound``.
    """

    def discover(
        self, cidr: str, ping_timeout: float, max_concurrent: int
    ) -> AsyncIterator[DiscoveryEvent]:
        """Pingt alle Adressen des ``cidr`` und yieldet Fortschritt + Funde.

        ``ping_timeout`` (Sekunden) je Host, ``max_concurrent`` begrenzt die
        gleichzeitig laufenden Pings. Der Strom ist endlich: nach dem letzten
        Host endet die Iteration. Ein invalides ``cidr`` ist ein Fehler (keine
        stille Leer-Iteration) -- die Formatpruefung liegt bereits in
        ``ScanConfig`` (domain), der Adapter darf sich darauf verlassen.
        """
        ...


class PortScannerPort(Protocol):
    """Port-Scan eines einzelnen Hosts (socket-async oder nmap-blockierend)."""

    async def scan(
        self,
        ip: str,
        ports: Sequence[int],
        mode: str,
        timeout: float,
        max_concurrent: int,
    ) -> list[PortInfo]:
        """Scannt ``ports`` auf ``ip`` und liefert die offenen als ``PortInfo``.

        ``mode`` waehlt das Verfahren (``"socket"`` async, ``"nmap"``
        blockierend -- der Adapter kapselt nmap ueber ``run_in_executor``,
        diese Methode bleibt ``async``). ``timeout`` je Port, ``max_concurrent``
        begrenzt parallele Verbindungsversuche im socket-Modus. Keine offenen
        Ports -> ``[]``, niemals ``None``.
        """
        ...


# ── Anreicherung ────────────────────────────────────────────────────────────


class HostnameResolverPort(Protocol):
    """Reverse-DNS und (optional) SMB-Namensaufloesung eines Hosts."""

    async def resolve(self, ip: str, timeout: float) -> str:
        """Reverse-DNS-Name zu ``ip``, oder ``""`` wenn nicht aufloesbar.

        ``""`` ist hier ein legitimer Zustand ("kein PTR-Record"), kein Fehler.
        """
        ...

    async def smb_info(self, ip: str) -> tuple[str, str]:
        """SMB-(Name, Domaene) eines Hosts als Tupel; je ``""`` wenn unbekannt.

        Blockierend im Altcode (``get_smb_info``); der Adapter kapselt das ueber
        ``run_in_executor``, die Methode bleibt ``async``.
        """
        ...


class VendorLookupPort(Protocol):
    """OUI-basierte Hersteller-Aufloesung einer MAC -- reiner In-Memory-Lookup."""

    def lookup(self, mac: str) -> str:
        """Hersteller zur OUI von ``mac``, oder ``""`` wenn nicht gefunden.

        SYNCHRON: kein I/O, nur ein Lookup in der in den Adapter geladenen
        OUI-Datenbank. ``""`` (unbekannt) ist ein legitimer Zustand, kein Fehler.
        """
        ...


class MdnsPort(Protocol):
    """mDNS-/Bonjour-Dienst-Discovery im lokalen Segment."""

    async def discover(self, duration: float) -> list[MdnsService]:
        """Lauscht ``duration`` Sekunden und liefert die gefundenen Dienste.

        Nichts gefunden -> ``[]``, niemals ``None``.
        """
        ...


class SsdpPort(Protocol):
    """SSDP-/UPnP-Dienst-Discovery im lokalen Segment."""

    async def discover(self, timeout: float) -> list[SsdpService]:
        """Sendet M-SEARCH, sammelt ``timeout`` Sekunden lang Antworten.

        Nichts gefunden -> ``[]``, niemals ``None``.
        """
        ...


class Ipv6EnrichmentPort(Protocol):
    """Reichert bereits gefundene Hosts um IPv6-Erkenntnisse an (NDP/EUI-64)."""

    async def enrich(self, hosts: Sequence[EnrichedHost]) -> list[EnrichedHost]:
        """Liefert die Hosts angereichert zurueck (gleiche Anzahl, gleiche Reihenfolge).

        Blockierende NDP-Tabellen-Abfrage im Altcode (``enrich_with_ipv6``); der
        Adapter kapselt das ueber ``run_in_executor``, die Methode bleibt
        ``async``. Keine IPv6-Daten verfuegbar -> die Hosts kommen unveraendert
        zurueck (kein Sonderfall-Handling beim Aufrufer).
        """
        ...


class FritzHostsPort(Protocol):
    """Bekannte Hosts einer FRITZ!Box (TR-064) -- optional.

    Liefert eine LEERE Liste, wenn keine FRITZ!Box konfiguriert oder erreichbar
    ist -- KEIN Sonderfall-Handling in der Domaene/im Use-Case (ADR 0001: kein
    stiller unsicherer Fallback, aber "nicht konfiguriert" ist ein legitimer
    Leer-Zustand, kein Fehler).
    """

    async def get_hosts(self) -> list[DiscoveredHost]:
        """Bekannte Hosts der FRITZ!Box, oder ``[]`` ohne konfigurierte Box.

        TR-064 ist blockierend; der Adapter kapselt das ueber ``run_in_executor``,
        die Methode bleibt ``async``.
        """
        ...


# ── Persistenz ──────────────────────────────────────────────────────────────


class ScanHistoryRepository(Protocol):
    """Persistenz der Scan-Historie (Muster wie ``DeviceRepository``, gleiche DB).

    Reine Mechanik: die JSON-(De-)Serialisierung der Hosts liegt im Adapter
    (S.4), nicht in der Domaene. ``save`` nimmt die fertigen Domaenen-Objekte.
    """

    def save(self, cidr: str, hosts: Sequence[EnrichedHost]) -> None:
        """Legt einen Scan-Eintrag an (``cidr`` + die gefundenen Hosts)."""
        ...

    def list(self, limit: int) -> list[ScanSummary]:
        """Letzte Scans als Listen-View (ohne Host-Blob), neueste zuerst.

        Auf ``limit`` begrenzt. Leere Historie -> ``[]``, niemals ``None``.
        """
        ...

    def get(self, scan_id: int) -> ScanRecord | None:
        """Ein Scan mit seinen vollen Hosts, oder ``None`` wenn unbekannt.

        ``None`` ist ein legitimer Zustand ("Scan-ID gibt es nicht"), kein Fehler.
        """
        ...
