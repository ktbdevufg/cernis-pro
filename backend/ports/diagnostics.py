"""Ports der diagnostics-Domaene: Vertraege fuer DNS-Aufloesung + traceroute.

Drei Vertraege, getrennt nach Belang:

* ``DnsResolver`` -- die DNS-DATEN-Quelle. ``resolve`` loest einen Namen fuer eine Menge
  angefragter Eintragsarten auf. Sie ruft blockierendes System-Tooling (``dig``) und ist
  daher ``async`` (Muster ``ports.process.ProcessProvider.list_processes``); der Adapter
  kapselt das Blockierende ueber ``run_in_executor``. BEWUSST KEIN Rechte-Port fuer DNS:
  Namensaufloesung braucht keine besonderen Rechte (kein Root-Thema).
* ``TracerouteRunner`` -- die traceroute-DATEN-Quelle. ``run`` misst den Pfad zum Ziel.
  ``privileged=True`` waehlt die genauere (Root-)Methode, ``False`` die unprivilegierte
  (ungenauere) -- bewusste Nutzerwahl, kein Default-Raten. Auch ``async`` (blockierendes
  ``traceroute``-Binary im Adapter ueber ``run_in_executor``).
* ``TraceroutePermissionPort`` -- die RECHTE-Abfrage fuer traceroute, bewusst ein eigener
  Port (Muster ``ports.process.ProcessPermissionPort``). Synchron: schnelle, lokale
  Pruefungen ohne Netz-/Loop-I/O. Hier bedeutet "volle Rechte" = die genauere
  (privilegierte) Methode ist moeglich; ohne Rechte wird die unprivilegierte Methode
  verwendet (ehrlicher Hinweis, kein stiller Fallback, S3).

Block 1b (Tool-/Paketmanager-Erkennung) -- zwei synchrone Erkennungs-Vertraege (Muster
``TraceroutePermissionPort``: schnelle, lokale which-Pruefungen ohne Loop-I/O):

* ``ToolDetector`` -- prueft, ob ein EINZELNES Binary nutzbar ist (which-basiert; ob das
  ueber ``shutil.which`` oder anders geschieht, ist Adapter-Sache).
* ``PackageManagerDetector`` -- welcher bekannte Paketmanager im PATH liegt; ``None`` wenn
  keiner. Die Erkennungs-Reihenfolge (welcher gewinnt) legt der Adapter fest, nicht der
  Port -- der Vertrag verlangt nur "der erste gefundene".

Block 2a (Banner-Grabbing) -- ein async DATEN-Vertrag (Muster ``TracerouteRunner``):

* ``BannerGrabber`` -- die Banner-DATEN-Quelle. ``grab`` klopft EINMAL an einen Port und
  liest die Begruessung. ``async`` (blockierendes Socket-I/O im Adapter ueber asyncio
  gekapselt, Muster ``TracerouteRunner``). BEWUSST KEIN Rechte-Port: Banner-Grabbing ist
  ein gewoehnlicher TCP-Connect und braucht keine besonderen Rechte (kein Root-Thema).

Block 2b (externer IP/Port-Check via cpnetcheck) -- ein async DATEN-Vertrag (HTTP-I/O):

* ``ExternalReachabilityProvider`` -- die externe Erreichbarkeits-DATEN-Quelle: ruft einen
  cpnetcheck-konformen Dienst als CLIENT auf (``get_external_ip`` -> die oeffentliche IP;
  ``check_ports`` -> IP + Port-Ergebnisse). ``async`` (HTTP-I/O ueber ``httpx.AsyncClient``
  im Adapter). ``base_url``/``token`` kommen als Parameter herein -- der Port ist REINE
  Mechanik des Aufrufs; der configured-/Konfigurations-Zustand wird NICHT hier, sondern im
  Use-Case entschieden (er liest URL/Token und ruft den Provider nur, wenn beides da ist).
  Dienst-Fehler (HTTP 4xx/5xx, Netzfehler, Timeout, JSON-Parsefehler) sind eine
  application-/infra-eigene Exception (``ExternalCheckError``), KEIN Domaenentyp -- der
  Adapter wirft mit NEUTRALER Meldung (NIE den Token, NIE interne Details).

Block 3 (Rogue-DHCP-Erkennung) -- ein async DATEN-Vertrag + ein synchroner Rechte-Vertrag
(Muster ``TracerouteRunner`` + ``TraceroutePermissionPort``):

* ``DhcpProbe`` -- die Rogue-DHCP-DATEN-Quelle. ``discover`` sendet EIN DHCP DISCOVER ins
  lokale Netz und liefert die ROHE Liste der antwortenden Server als ``(server_ip,
  server_mac|None)``-Tupel -- KEINE Klassifikation hier (das ist Domaene, ``classify_dhcp_
  servers``); der Probe liefert nur die rohen Funde. ``async`` (blockierendes nmap im
  Adapter ueber ``run_in_executor``, Muster ``TracerouteRunner``). Anders als traceroute
  gibt es hier KEINEN rootless-Fallback -- rohe DHCP-Pakete brauchen Root; der Rechte-Port
  riegelt VOR dem Aufruf ab (kein blindes Laufen gegen fehlendes Root).
* ``DhcpPermissionPort`` -- die RECHTE-Abfrage fuer Rogue-DHCP, eigener Port (Muster
  ``TraceroutePermissionPort``). Synchron: schnelle, lokale Pruefungen ohne Netz-/Loop-I/O.
  Anders als traceroute (das eine ungenauere rootless-Methode hat) ist Rogue-DHCP
  ROOT-PFLICHTIG ohne Alternative: ``check_permission`` ``None`` = Root vorhanden (Discovery
  moeglich), sonst die Begruendung "muss als Root gestartet werden" -- eine EHRLICHE SPERRE,
  kein stiller Fallback (S3) und keine Selbst-Eskalation (CLAUDE.md). KEIN distro-
  spezifischer Install-Befehl hier (das deckt Block 1b/``TOOL_PACKAGES`` ab).

Block 3 (Persistenz des LETZTEN Rogue-DHCP-Stands, ADR 0038) -- ein synchroner Speicher-
Vertrag + zwei frozen Lese-Datentraeger (Muster ``ports.security.ArpAlertRecord``/
``ArpBaselineRecord``: Lese-Views als frozen dataclasses im Port-Ring, NICHT in domain):

* ``RogueDhcpStore`` -- der Speicher fuer den letzten Rogue-DHCP-Stand. ``save_latest``
  ueberschreibt IMMER denselben einen Datensatz (kein Verlauf -- YAGNI), ``load_latest``
  liest ihn (oder ``None`` = noch nie geprueft). Synchron (lokaler SQLite-Treffer ohne Netz-
  /Loop-I/O, Muster der uebrigen SQLite-Repos -- die rufen ihre Adapter ebenfalls synchron).
  PORT-NEUTRALE Typen im Vertrag (keine ``domain.diagnostics``-Objekte): die Server-Liste
  geht als ``(ip, mac|None, is_expected)``-Tupel herein und kommt als ``RogueDhcpServerRecord``
  heraus -- analog dem security-Port, der seine Persistenz ueber eigene Record-Typen fuehrt
  (``ArpAlertRecord``), NICHT ueber die zeitfreien Domaenentypen. ``checked_ts`` (Unix-ts,
  float) setzt der AUFRUFER (Composition Root, ``time.time()``) -- der Store erzeugt KEINE
  Wanduhr selbst (zeitfrei, Muster der zeitfreien Use-Cases/Adapter, S3-konform).
* ``RogueDhcpServerRecord`` -- ein gespeicherter Server als frozen Lese-View (ip/mac/
  is_expected). Spiegelt ``domain.DhcpServer``, ist aber bewusst ein eigener Port-Typ (der
  Port-Vertrag bleibt domain-frei, Muster ``ArpBaselineRecord`` vs. ``ArpEntry``).
* ``LatestRogueDhcp`` -- der gebuendelte letzte Stand als frozen Lese-View: ``servers``
  (Liste ``RogueDhcpServerRecord``), ``expected`` (Liste str), ``has_unexpected`` (bool) +
  ``checked_ts`` (float, WANN gemessen wurde). Was ``load_latest`` liefert (oder ``None``).

Bewusste Entscheidung: KEIN ``@runtime_checkable`` (Muster wie settings/devices/
scanning/capture/interfaces/traffic/process). Die Vertragspruefung laeuft statisch ueber
mypy und ueber die Verdrahtung im Composition Root (``app.py``), nicht zur Laufzeit per
``isinstance``.

``ports/`` kennt NUR ``domain/diagnostics``-Typen + stdlib/typing. KEIN ``modules/``-
und kein ``infrastructure/``-Import -- import-linter-Contract "ports kennen hoechstens
domain". Import von ``domain`` ist erlaubt (nur die Gegenrichtung ist verboten).
"""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from domain.diagnostics import (
    BannerResult,
    DnsRecordType,
    DnsResult,
    ExternalIpResult,
    ExternalPortResult,
    PackageManager,
    TracerouteResult,
)


class DnsResolver(Protocol):
    """Daten-Quelle der diagnostics-Domaene: DNS-Aufloesung (kein Rechte-Thema)."""

    async def resolve(self, query: str, types: Sequence[DnsRecordType]) -> DnsResult:
        """Loest ``query`` fuer die angefragten ``types`` auf -> ``DnsResult``.

        Liefert die gefundenen Eintraege gebuendelt als ``DnsResult`` (``query`` +
        angefragte Typen + Eintraege). Keine Antwort (NXDOMAIN/leer) -> ``records`` LEER,
        NICHT ``None`` und KEIN Fehler -- die leere Antwort ist ein gueltiges Ergebnis.
        Ein echter Fehler (fehlendes ``dig``-Binary) ist eine Exception, kein leeres
        Ergebnis.

        Blockierendes System-Tooling (``dig``) im Adapter; ueber ``run_in_executor``
        gekapselt, die Methode bleibt ``async``. KEIN Rechte-Port: Namensaufloesung
        braucht keine besonderen Rechte.
        """
        ...


class TracerouteRunner(Protocol):
    """Daten-Quelle der diagnostics-Domaene: Pfad-Messung zum Ziel (traceroute)."""

    async def run(self, target: str, privileged: bool) -> TracerouteResult:
        """Misst den Pfad zu ``target`` -> ``TracerouteResult``.

        ``privileged=True`` waehlt die genauere (Root-)Methode (z. B. ICMP), ``False`` die
        unprivilegierte UDP-Default-Methode -- bewusste Nutzerwahl, kein Default-Raten.
        Nicht-antwortende Hops erscheinen als Luecke (``address``/``rtt_ms`` ``None``),
        NICHT weggelassen. Kein Hop ermittelbar -> ``hops`` leer (kein Fehler). Ein echter
        Fehler (fehlendes ``traceroute``-Binary) ist eine Exception.

        Blockierendes System-Tooling (``traceroute``) im Adapter; ueber
        ``run_in_executor`` gekapselt, die Methode bleibt ``async``.
        """
        ...


class TraceroutePermissionPort(Protocol):
    """Rechte-Abfrage fuer traceroute (eigener Port; synchron wie process/capture)."""

    def is_available(self) -> bool:
        """``True``, wenn das ``traceroute``-Binary grundsaetzlich nutzbar ist.

        Reiner Verfuegbarkeits-Check (Binary im PATH), unabhaengig von Berechtigungen --
        die prueft ``check_permission``. Schnelle lokale Pruefung, daher synchron (Muster
        ``ports.process.ProcessPermissionPort.is_available``).
        """
        ...

    def check_permission(self) -> str | None:
        """``None`` = privilegierte (genauere) Methode moeglich, sonst Begruendung+Hinweis.

        ``None`` heisst "privilegierte Methode moeglich" (Root) -- die genauere Messung
        ist verfuegbar. Ein nicht-leerer String ist die Begruendung: die genauere Methode
        braucht Root; ohne Root wird die unprivilegierte (ungenauere) Methode verwendet.
        KEIN stiller Fallback (ADR 0001/S3): die fehlende Berechtigung wird benannt, nicht
        verschwiegen. KEIN distro-spezifischer Install-Befehl hier (das ist Block 1b).
        Schnelle lokale Pruefung, daher synchron.
        """
        ...


class ToolDetector(Protocol):
    """Erkennungs-Vertrag (1b): ist ein einzelnes System-Binary nutzbar? (which-basiert)."""

    def is_available(self, tool: str) -> bool:
        """``True``, wenn das Binary ``tool`` nutzbar (im PATH) ist, sonst ``False``.

        Reiner Verfuegbarkeits-Check eines EINZELNEN Binaries -- ob ueber ``shutil.which``
        oder anders, ist Adapter-Sache. Schnelle lokale Pruefung, daher synchron (Muster
        ``TraceroutePermissionPort.is_available``).
        """
        ...


class BannerGrabber(Protocol):
    """Daten-Quelle der diagnostics-Domaene (2a): TCP-Banner eines Ports lesen."""

    async def grab(self, target: str, port: int) -> BannerResult:
        """Klopft EINMAL an ``target:port`` und liest die Begruessung -> ``BannerResult``.

        Bestimmt ueber ``domain.probe_for_port`` die Methode (``passive`` -- kurz lauschen,
        der Dienst gruesst selbst; ``http_head`` -- EINE minimale HTTP-HEAD-Anfrage senden)
        und liest die Begruessungszeile bzw. den Server-Header. Ehrliche Semantik (kein
        erfundener Banner): ``state`` benennt ``ok``/``no_banner``/``closed``/``filtered``,
        ``banner`` ist NUR bei ``ok`` nicht-``None``.

        Blockierendes Socket-I/O im Adapter; ueber asyncio gekapselt (Muster
        ``TracerouteRunner``), die Methode bleibt ``async``. KEIN Rechte-Port: ein
        gewoehnlicher TCP-Connect braucht keine besonderen Rechte. SICHERHEITS-GRENZE: der
        Adapter sendet NIE mehr als die eine minimale Standard-Anfrage (keine
        konfigurierbaren Payloads) -- Banner-Grabbing bleibt Diagnose, kein Byte-Sender.
        """
        ...


class PackageManagerDetector(Protocol):
    """Erkennungs-Vertrag (1b): welcher bekannte Paketmanager liegt im PATH?"""

    def detect(self) -> PackageManager | None:
        """Der erste gefundene bekannte Paketmanager, sonst ``None``.

        ``None`` heisst "kein bekannter Paketmanager im PATH" -- dann liefert die Domaene
        ehrlich keinen Install-Befehl (KEIN Raten). Die Erkennungs-Reihenfolge (welcher
        Manager gewinnt, wenn mehrere da sind) legt der Adapter fest, nicht dieser Vertrag.
        Schnelle lokale which-Pruefung, daher synchron.
        """
        ...


class ExternalReachabilityProvider(Protocol):
    """Daten-Quelle der diagnostics-Domaene (2b): externer cpnetcheck-Dienst als CLIENT.

    Ruft einen cpnetcheck-konformen Dienst ueber HTTPS auf. ``base_url``/``token`` kommen
    als Parameter herein -- der Port ist REINE Mechanik des Aufrufs; ob das Feature
    konfiguriert ist (URL/Token gesetzt), entscheidet der Use-Case, NICHT dieser Vertrag.
    ``async`` (HTTP-I/O ueber ``httpx.AsyncClient`` im Adapter, Muster ``TracerouteRunner``
    fuer die async-Naht). Dienst-Fehler (HTTP 4xx/5xx, Netzfehler, Timeout, JSON-
    Parsefehler) sind eine application-/infra-eigene Exception (``ExternalCheckError``) mit
    NEUTRALER Meldung -- KEIN Domaenentyp, NIE Token/interne Details.
    """

    async def get_external_ip(self, base_url: str, token: str) -> ExternalIpResult:
        """Fragt die oeffentliche IP von CERNIS beim externen Dienst ab -> ``ExternalIpResult``.

        ``GET <base_url>/v1/myip`` mit ``Authorization: Bearer <token>`` -> die aus Sicht
        des Dienstes sichtbare oeffentliche Adresse + Familie. Ein Dienst-/Netzfehler ist
        eine ``ExternalCheckError`` (neutrale Meldung), KEIN leeres/erfundenes Ergebnis.
        """
        ...

    async def check_ports(
        self, base_url: str, token: str, ports: Sequence[int]
    ) -> tuple[ExternalIpResult, tuple[ExternalPortResult, ...]]:
        """Prueft, ob ``ports`` von aussen erreichbar sind -> (IP, Port-Ergebnisse).

        ``POST <base_url>/v1/portcheck`` mit Bearer-Token + JSON ``{"ports": [...],
        "protocol": "tcp"}`` -> die gepruefte IP + je Port ein ``ExternalPortResult``
        (reachable + state). ``ports`` ist bereits client-seitig validiert (Bereich/max/
        dedup, ``domain.validate_requested_ports``) -- der Dienst setzt seine Whitelist
        zusaetzlich durch. Ein Dienst-/Netzfehler ist eine ``ExternalCheckError`` (neutrale
        Meldung), KEIN leeres/erfundenes Ergebnis.
        """
        ...


class DhcpProbe(Protocol):
    """Daten-Quelle der diagnostics-Domaene (3): Rogue-DHCP-Discovery (rohe Offers)."""

    async def discover(self) -> list[tuple[str, str | None]]:
        """Sendet EIN DHCP DISCOVER und liefert die rohen Offers -> ``(ip, mac|None)``-Liste.

        Liefert je antwortendem DHCP-Server ein ``(server_ip, server_mac|None)``-Tupel
        (``mac`` ehrlich ``None``, wenn nmap sie nicht ausweist -- KEIN erfundener Wert).
        Kein antwortender Server -> ``[]`` (vertraglicher Leer-Zustand, KEIN Fehler). KEINE
        Klassifikation hier (erwartet vs. unerwartet) -- das ist Domaene
        (``classify_dhcp_servers``); der Probe liefert nur die rohen Funde.

        Blockierendes System-Tooling (``nmap --script broadcast-dhcp-discover``) im Adapter;
        ueber ``run_in_executor`` gekapselt, die Methode bleibt ``async`` (Muster
        ``TracerouteRunner``). ROOT-PFLICHTIG (rohe DHCP-Pakete): der Aufrufer (Use-Case)
        prueft VORHER ueber ``DhcpPermissionPort`` -- der Probe laeuft NIE blind gegen
        fehlendes Root. Ein echter Fehler (fehlendes ``nmap``-Binary) ist eine Exception,
        kein leeres Ergebnis.
        """
        ...


class DhcpPermissionPort(Protocol):
    """Rechte-Abfrage fuer Rogue-DHCP (eigener Port; synchron wie traceroute/process).

    Anders als ``TraceroutePermissionPort`` (das eine ungenauere rootless-Methode kennt)
    ist Rogue-DHCP ROOT-PFLICHTIG OHNE Alternative -- rohe DHCP-Pakete brauchen Root. Darum
    ist ``check_permission`` hier eine EHRLICHE SPERRE (kein Fallback-Hinweis), kein stiller
    Rueckfall (S3) und keine Selbst-Eskalation (CLAUDE.md).
    """

    def is_available(self) -> bool:
        """``True``, wenn ``nmap`` grundsaetzlich nutzbar ist (Binary im PATH), sonst ``False``.

        Reiner Verfuegbarkeits-Check (unabhaengig von Berechtigungen -- die prueft
        ``check_permission``). Schnelle lokale Pruefung, daher synchron (Muster
        ``TraceroutePermissionPort.is_available``).
        """
        ...

    def check_permission(self) -> str | None:
        """``None`` = Root vorhanden (Discovery moeglich), sonst die Sperr-Begruendung.

        ``None`` heisst "Root vorhanden" -- das DHCP DISCOVER (rohe Pakete) ist moeglich.
        Ein nicht-leerer String ist die Begruendung: Rogue-DHCP braucht Root, es gibt KEINE
        rootless Alternative -> CERNIS PRO muss als Root gestartet werden. EHRLICHE SPERRE
        (kein stiller Fallback, S3); KEINE Selbst-Eskalation. KEIN distro-spezifischer
        Install-Befehl hier (das deckt Block 1b/``TOOL_PACKAGES`` ab). Schnelle lokale
        Pruefung, daher synchron.
        """
        ...


# ── Block 3: Persistenz des letzten Rogue-DHCP-Stands (ADR 0038) ───────────────


@dataclass(frozen=True)
class RogueDhcpServerRecord:
    """Ein gespeicherter DHCP-Server als frozen Lese-View (ADR 0038).

    Spiegelt ``domain.diagnostics.DhcpServer`` (ip/mac/is_expected), ist aber bewusst ein
    EIGENER Port-Typ -- der Port-Vertrag bleibt domain-frei (Muster ``ArpBaselineRecord``
    vs. ``ArpEntry``: der security-Port fuehrt seine Persistenz ueber eigene Record-Typen,
    NICHT ueber die Domaenentypen). ``mac`` ist ehrlich ``None``, wenn nmap sie nicht
    lieferte (kein erfundener Wert -- die None-Semantik ueberlebt den Round-trip).
    """

    ip: str
    mac: str | None
    is_expected: bool


@dataclass(frozen=True)
class LatestRogueDhcp:
    """Der letzte bekannte Rogue-DHCP-Stand als frozen Lese-View (ADR 0038).

    Was ``RogueDhcpStore.load_latest`` liefert (oder ``None`` = noch nie geprueft).
    ``servers`` sind die gefundenen Server (``RogueDhcpServerRecord``), ``expected`` die
    zugrunde gelegte Erwartungsmenge (str-Liste), ``has_unexpected`` ob mindestens ein
    gefundener Server nicht erwartet war -- 1:1 zum ``RogueDhcpResult`` der Domaene, ergaenzt
    um ``checked_ts`` (Unix-ts, float: WANN gemessen wurde). Der spaetere Sicherheitsbericht
    rendert den Stand samt Datum, OHNE selbst einen root-pflichtigen Probe auszuloesen.
    """

    servers: tuple[RogueDhcpServerRecord, ...]
    expected: tuple[str, ...]
    has_unexpected: bool
    checked_ts: float


class RogueDhcpStore(Protocol):
    """Persistenz des LETZTEN Rogue-DHCP-Stands (ADR 0038) -- ein Datensatz, ueberschreibend.

    Speichert IMMER nur den letzten Lauf (kein Verlauf -- YAGNI): ``save_latest``
    ueberschreibt denselben einen Datensatz, ``load_latest`` liest ihn. Zweck: der spaetere
    Sicherheitsbericht zeigt den letzten bekannten Stand mit Datum, ohne selbst einen aktiven
    (root-pflichtigen) DHCP-Probe auszuloesen.

    Synchron (lokaler SQLite-Treffer ohne Netz-/Loop-I/O, Muster der uebrigen SQLite-Repos).
    PORT-NEUTRALE Typen im Vertrag (keine ``domain.diagnostics``-Objekte): die Server gehen
    als rohe ``(ip, mac|None, is_expected)``-Tupel herein und kommen als
    ``RogueDhcpServerRecord`` heraus.
    """

    def save_latest(
        self,
        result_servers: Sequence[tuple[str, str | None, bool]],
        result_expected: Sequence[str],
        has_unexpected: bool,
        checked_ts: float,
    ) -> None:
        """Speichert den letzten Stand UEBERSCHREIBEND (genau ein Datensatz).

        ``result_servers`` sind die gefundenen Server als rohe ``(ip, mac|None,
        is_expected)``-Tupel (port-neutral -- kein Domaenentyp), ``result_expected`` die
        zugrunde gelegte Erwartungsmenge (str-Liste), ``has_unexpected`` ob mindestens einer
        unerwartet war. ``checked_ts`` (Unix-ts, float) setzt der AUFRUFER (Composition Root,
        ``time.time()``) -- der Store erzeugt KEINE Wanduhr selbst (zeitfrei, S3-konform).
        Ein bereits vorhandener Stand wird ersetzt (kein Verlauf).
        """
        ...

    def load_latest(self) -> LatestRogueDhcp | None:
        """Liest den letzten gespeicherten Stand -> ``LatestRogueDhcp`` oder ``None``.

        ``None`` heisst "noch nie geprueft" (leerer Speicher) -- ehrliche Abwesenheit, KEIN
        leerer Ersatz-Stand. Sonst der letzte Stand inkl. ``checked_ts`` (WANN gemessen
        wurde); die ``mac=None``-Semantik der Server ueberlebt den Round-trip.
        """
        ...
