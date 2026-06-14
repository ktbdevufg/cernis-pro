"""Adapter fuer ``SniSnifferPort`` -- passiver SNI-Sniff (scapy) + Prozess-Zuordnung.

Setzt die im Spike (``/home/kbach/spike_sni.py``) ERPROBTE Technik produktiv um:
60 SNIs erfasst, 93 % einem Prozess zugeordnet, Zuordnungs-Delta median 177 ms. Die
capture-Domaene wird NICHT angefasst (ihr ``PacketSummary``-Parser liest den
TCP-Payload nicht und nutzt Layer-Zugriff, der fuer das ClientHello untauglich ist) --
darum eine eigene Domaene mit eigenem Adapter.

GETEILTES scapy (kein Duplikat): die scapy-Symbole (``HAS_SCAPY``/``AsyncSniffer``/
``TCP``/``IP``/``IPv6``) kommen aus ``infrastructure.capture._scapy`` -- geteilte
Infrastruktur (der Cache-Dir-Fix + die breite Probe leben dort an EINER Stelle).
``_scapy`` wird hier NICHT veraendert. Kein import-linter-Contract verbietet diesen
infra-internen Quergriff (die Contracts sind schicht-, nicht domaenen-intern;
``independence`` gilt nur fuer ``domain.*``).

ERPROBTE LEHREN aus dem Spike (1:1 uebernommen):

* **Payload LAYER-UNABHAENGIG:** ``raw = bytes(pkt[TCP])[dataofs*4:]`` -- NICHT
  ``bytes(pkt[TCP].payload)`` (das reserialisiert dissektiert und weicht vom Draht ab
  -> 0 Treffer). Wir serialisieren den TCP-Layer und schneiden den Header ab.
* **ClientHello MANUELL aus den Rohbytes geparst** (``parse_sni`` -- reine Funktion
  OHNE scapy-Abhaengigkeit, gut testbar): TLS-Record 0x16 -> Handshake 0x01 ->
  ServerName-Extension 0x0000 -> Hostname. Robuste Laengen-/Offset-Pruefung, bei
  Abschneidung/Fehler ``None`` (still skippen, kein Crash).
* **Billiger prn:** der Sniff-Callback parst NUR + haengt an. KEINE psutil-
  Namensaufloesung im Callback (die wuerde den libpcap-Lesepfad per GIL aushungern --
  der reale "0 Pakete"-Bug des Spikes).
* **Poller in EIGENEM daemon-Thread:** periodische ``(ip,port)->pid``-Snapshots, NICHT
  im Sniff-Thread. Pro Snapshot nur die billige Tabelle; den Prozessnamen loest erst
  ``observed()`` NACH dem Match auf. psutil-Naht GENAU wie
  ``infrastructure/traffic_linux.py`` (``net_connections(kind="inet")``, defensive
  Namensaufloesung ``except psutil.Error -> None``).

AGGREGAT statt Strom (anders als ``ScapyPacketSniffer``): der Adapter haelt die rohen
Hits + die Snapshots intern; ``observed()`` ordnet sie ueber die Domaene
(``match_snapshot``) zu und liefert die Momentaufnahme. Kein async-Strom, kein
Callback-Geflecht im Use-Case.

START-FEHLER (Port-Vertrag, S3-frei): ``start`` startet den ``AsyncSniffer``, wartet
die Alive-Probe ab und wirft bei totem Thread ``SniError`` -- KEINE stille Leer-
Erfassung. Der Aufrufer (StartSni-Naht) prueft ``check_permission`` zusaetzlich vorher.

Plattform: NUR Linux x64 (``check_permission`` ueber die ``AF_PACKET``-Raw-Socket-
Probe, ``_pick_iface`` ueber die Default-Route / ``/sys/class/net``).
"""

import os
import re
import socket
import struct
import subprocess
import threading
import time
from collections import deque
from typing import Any

import psutil
import structlog

from domain.sni import ObservedSni, match_snapshot, normalize_hostname
from infrastructure.capture import _scapy
from infrastructure.sni.errors import SniError

_logger = structlog.get_logger(__name__)

# Alive-Probe-Fenster (Muster ScapyPacketSniffer): dem Sniffer-Thread kurz Zeit
# lassen, sofort zu sterben -- Permission-Fehler schlagen instantan zu.
_ALIVE_PROBE_SECS = 0.8

# Poll-Intervall des Socket-Pollers (Spike: 0.5 s -- selten + billig, damit der
# libpcap-Lesepfad nicht ausgehungert wird).
_POLL_INTERVAL_SECS = 0.5

# BPF-Filter wie im Spike: nur TCP:443 (dort sitzt der TLS-ClientHello).
_SNI_FILTER = "tcp port 443"

# Obergrenze der gehaltenen Hits/Snapshots. Der passive Sniff hat (anders als der
# capture-``max_packets``) KEIN natuerliches Ende -- ohne Deckel waechst der Puffer
# in einem langen Lauf unbegrenzt. Der Deckel sitzt HIER im Adapter (nicht im
# Use-Case): die beiden Listen werden aus den Hintergrund-Threads beschrieben, ein
# ``deque(maxlen=...)`` ist der natuerliche, thread-lokale Ringpuffer am Schreib-Ort
# (aelteste raus). Der Use-Case bleibt darum zustandslos (haelt nur den Adapter).
_MAX_HITS = 5000
_MAX_SNAPSHOTS = 600  # ~5 min bei 0.5 s-Intervall -- deckt jeden Hit-Zeitpunkt ab


# ── Reiner ClientHello-Parser (das Herzstueck, OHNE scapy-Abhaengigkeit) ──────


def parse_sni(payload: bytes) -> str | None:
    """Manuelles TLS-Byte-Parsing aus der ROHEN TCP-Payload. Hostname oder ``None``.

    Reine Funktion (nimmt rohe ``bytes``, gibt ``hostname|None``) -- gut testbar ohne
    Netz/scapy. Struktur (RFC 8446 / 6066), big-endian:

      TLS-Record:    [type=22(0x16)][version 2B][record_len 2B][handshake...]
      Handshake:     [type=1(ClientHello)][hs_len 3B][version 2B][random 32B]
                     [session_id len 1B + data][cipher_suites len 2B + data]
                     [compression len 1B + data][extensions len 2B + data]
      Extension SNI: [type=0x0000][ext_len 2B][server_name_list len 2B]
                     [name_type=0(host_name)][name_len 2B][hostname]

    Jeder Fehlerfall (kein TLS-Handshake, kein ClientHello, ServerHello, abgeschnittener/
    fragmentierter Record, keine SNI-Extension) -> ``None``, NIE ein Crash. Ein ueber
    mehrere TCP-Segmente fragmentierter ClientHello (Lese-Offset laeuft ueber das Paket
    hinaus) wird ebenfalls still zu ``None`` (kein Reassembly hier -- der naechste frische
    Verbindungsaufbau liefert i. d. R. einen unfragmentierten ClientHello).
    """
    # 1. TLS-Record-Header (5 B) + erstes Byte == 0x16 (Handshake)?
    if len(payload) < 6 or payload[0] != 0x16:
        return None
    # 2. Handshake-Typ == 0x01 (ClientHello)?  (Byte direkt nach dem 5B-Recordheader)
    if payload[5] != 0x01:
        return None

    # Ab hier IST es ein ClientHello. Alles, was jetzt out-of-bounds laeuft, ist ein
    # unvollstaendiger/fragmentierter ClientHello -> None (kein Crash).
    try:
        pos = 5
        pos += 4  # handshake type (1B) + handshake length (3B)
        pos += 2  # client_version
        pos += 32  # random
        # session_id
        if pos + 1 > len(payload):
            return None
        sid_len = payload[pos]
        pos += 1 + sid_len
        # cipher_suites
        if pos + 2 > len(payload):
            return None
        cs_len = struct.unpack(">H", payload[pos : pos + 2])[0]
        pos += 2 + cs_len
        # compression_methods
        if pos + 1 > len(payload):
            return None
        comp_len = payload[pos]
        pos += 1 + comp_len
        # extensions-Block
        if pos + 2 > len(payload):
            return None
        ext_total = struct.unpack(">H", payload[pos : pos + 2])[0]
        pos += 2
        end = pos + ext_total
        while pos + 4 <= len(payload) and pos + 4 <= end:
            ext_type = struct.unpack(">H", payload[pos : pos + 2])[0]
            ext_len = struct.unpack(">H", payload[pos + 2 : pos + 4])[0]
            pos += 4
            if ext_type == 0x0000:  # server_name
                # server_name_list len (2B), name_type (1B), name_len (2B), host
                if pos + 5 > len(payload):
                    return None
                name_type = payload[pos + 2]
                if name_type != 0x00:  # nur host_name unterstuetzt
                    return None
                name_len = struct.unpack(">H", payload[pos + 3 : pos + 5])[0]
                host_start = pos + 5
                host_end = host_start + name_len
                if host_end > len(payload):
                    return None
                host = payload[host_start:host_end]
                return host.decode("ascii", errors="replace")
            pos += ext_len
        # Alle vorhandenen Extensions durch, keine SNI-Extension gefunden.
        return None
    except (IndexError, struct.error):
        return None


# ── Roh-TCP-Payload + Interface-Ermittlung (Spike-Technik, layer-unabhaengig) ──


def _raw_tcp_payload(pkt: Any) -> bytes:
    """Holt die ROHEN TCP-Payload-Bytes, layer-unabhaengig (bewiesener Spike-Weg).

    ``tcp = pkt[TCP]; raw = bytes(tcp)[tcp.dataofs*4:]`` -- bewusst NICHT
    ``bytes(pkt[TCP].payload)`` (reserialisiert dissektiert, weicht vom Draht ab).
    ``dataofs`` ist in 32-Bit-Worten; Header-Laenge = ``dataofs * 4``. Fehlt/0 ->
    Standard-Header (20 B).
    """
    tcp = pkt[_scapy.TCP]
    raw_tcp = bytes(tcp)
    hdr_len = (tcp.dataofs or 5) * 4
    if hdr_len < 20 or hdr_len > len(raw_tcp):
        hdr_len = 20
    return raw_tcp[hdr_len:]


def _pick_iface() -> str:
    """Ermittelt den Interface-NAMEN (String) fuer den Sniff -- dynamisch, robust.

    EXAKT die Spike-Strategie (``_pick_iface``): scapy nie als ``conf.iface``-Objekt
    uebergeben (auf dieser VM ist scapys Interface-DB leer -> ``sniff(iface=None)``
    liefert 0 Pakete), sondern IMMER ein nicht-leerer String.

      1. ``conf.iface``, falls scapy doch einen brauchbaren Namen kennt (-> ``str``).
      2. Interface der Default-Route (``ip route show default``) -- der echte
         Ausgangspfad ins Netz.
      3. Erstes Nicht-Loopback-Interface aus ``/sys/class/net``.

    Gibt IMMER einen String zurueck (oder wirft, wenn gar nichts gefunden wird).
    """
    if _scapy.HAS_SCAPY:
        from scapy.config import conf

        cand = conf.iface
        if cand is not None and str(cand) not in ("", "None"):
            return str(cand)

    try:
        out = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        ).stdout
        match = re.search(r"\bdev\s+(\S+)", out)
        if match:
            return match.group(1)
    except (OSError, subprocess.SubprocessError):
        pass

    for name in sorted(os.listdir("/sys/class/net")):
        if name != "lo":
            return name

    raise SniError("Kein nutzbares Netzwerk-Interface gefunden.")


# ── psutil-Naht (GENAU wie traffic_linux: net_connections + defensiver Name) ──


def _snapshot_sockets() -> dict[tuple[str, int], int | None]:
    """Aktuelle ``(remote_ip, remote_port) -> pid``, indexiert nach REMOTE-Endpunkt.

    Naht wie ``traffic_linux._list_connections_sync``: ``net_connections(kind="inet")``.
    BILLIG gehalten (Lehre aus dem Spike): hier NUR die PID sammeln, KEINE
    Namensaufloesung (die ist teuer und wuerde den Sniff aushungern -- sie passiert
    erst in ``observed()`` NACH dem Match). ``pid`` kann ``None`` sein (rootless sieht
    psutil fremde Sockets ohne PID -- ehrlich uebernommen).
    """
    table: dict[tuple[str, int], int | None] = {}
    for conn in psutil.net_connections(kind="inet"):
        if not conn.raddr:
            continue
        table[(conn.raddr.ip, conn.raddr.port)] = conn.pid
    return table


def _resolve_app_name(pid: int | None) -> str | None:
    """PID -> Prozessname; defensiv -- GENAU wie ``traffic_linux._resolve_app_name``.

    Wird ERST in ``observed()`` (nach dem Match) gerufen, nie im Poller-Loop. psutil-
    Fehler (``NoSuchProcess``/``AccessDenied``) bedeuten "nicht (mehr) zuordenbar" ->
    ``None``, KEIN Crash.
    """
    if pid is None:
        return None
    try:
        return str(psutil.Process(pid).name())
    except psutil.Error:
        return None


# ── Roh-Hit (intern; das, was der billige prn anhaengt) ───────────────────────


class _RawHit:
    """Ein roher SNI-Hit aus dem Sniff-Thread (vor der Prozess-Zuordnung).

    Bewusst KEIN ``domain.ObservedSni``: der Sniff-Pfad kennt die Zuordnung noch
    nicht (die rechnet ``observed()`` ueber die Domaene). Eine schlanke interne Klasse
    statt eines dicts haelt die Felder typsicher beieinander.
    """

    __slots__ = ("hostname", "monotonic_ts", "remote_ip", "remote_port")

    def __init__(
        self, hostname: str, remote_ip: str, remote_port: int, monotonic_ts: float
    ) -> None:
        self.hostname = hostname
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.monotonic_ts = monotonic_ts


class ScapySniSniffer:
    """Erfuellt ``SniSnifferPort`` strukturell -- haelt ``AsyncSniffer`` + Poller-Thread.

    Eine Instanz haelt hoechstens einen laufenden Sniff. Die rohen Hits
    (``_raw_hits``) und die periodischen Socket-Snapshots (``_snapshots``) liegen hier
    intern; ``observed()`` ordnet sie ueber die Domaene zu. Die beiden Hintergrund-
    Threads (scapy-``AsyncSniffer`` mit eigenem Thread + der psutil-Poller) sind ueber
    ``_stop_poll`` (Event) und das ``AsyncSniffer``-Lifecycle entkoppelt -- KEINE
    geteilte blockierende Ressource (Lehre aus dem Spike).
    """

    def __init__(self) -> None:
        self._sniffer: Any = None
        self._poller: threading.Thread | None = None
        self._stop_poll = threading.Event()
        # Ringpuffer (deque mit maxlen): aelteste raus, am thread-lokalen Schreib-Ort.
        self._raw_hits: deque[_RawHit] = deque(maxlen=_MAX_HITS)
        # Snapshots als (monotonic_ts, table) -- genau die Form, die die Domaene
        # (``match_snapshot``) erwartet.
        self._snapshots: deque[tuple[float, dict[tuple[str, int], int | None]]] = deque(
            maxlen=_MAX_SNAPSHOTS
        )

    # -- Sniff-Callback (laeuft IM Sniffer-Thread -- BILLIG halten) ------------

    def _on_packet(self, pkt: Any) -> None:
        """scapy-Callback: rohe TCP-Payload greifen, SNI parsen, anhaengen. BILLIG.

        KEINE psutil-Arbeit hier (das wuerde den libpcap-Lesepfad aushungern -- der
        reale Spike-Bug). Nur parsen + bei Treffer einen ``_RawHit`` anhaengen. Ein
        Paket ohne TCP/IP oder ohne SNI wird still uebersprungen. ``except Exception``:
        ein einzelnes kaputtes Paket darf den Sniff-Thread nicht killen.
        """
        try:
            if not pkt.haslayer(_scapy.TCP):
                return
            raw = _raw_tcp_payload(pkt)
            if not raw:
                return
            host = parse_sni(raw)
            host = normalize_hostname(host) if host is not None else None
            if host is None:
                return
            # Ziel-IP/Port (Gegenstelle): IPv6 vor IPv4 (Muster ScapyPacketSniffer).
            if pkt.haslayer(_scapy.IPv6):
                remote_ip = str(pkt[_scapy.IPv6].dst)
            elif pkt.haslayer(_scapy.IP):
                remote_ip = str(pkt[_scapy.IP].dst)
            else:
                return  # ohne IP-Layer keine sinnvolle Gegenstelle
            remote_port = int(pkt[_scapy.TCP].dport)
            self._raw_hits.append(_RawHit(host, remote_ip, remote_port, time.monotonic()))
        except Exception as exc:  # ein kaputtes Paket killt den Sniff nicht
            _logger.warning("sni_parse_failed", error=str(exc))

    # -- Poller (eigener daemon-Thread -- entkoppelt vom Sniff) ----------------

    def _poll_loop(self) -> None:
        """Pollt die Socket-Tabelle periodisch (eigener Thread, billig, entkoppelt).

        Legt nur leichte ``(monotonic_ts, table)``-Snapshots ab (kein Name -- der
        kommt in ``observed()``). Laeuft, bis ``_stop_poll`` gesetzt ist. Ein psutil-
        Fehler killt den Poller nicht (leerer Snapshot statt Crash) -- so bleibt die
        Zuordnung best-effort statt zerbrechlich.
        """
        while not self._stop_poll.is_set():
            ts = time.monotonic()
            try:
                self._snapshots.append((ts, _snapshot_sockets()))
            except Exception as exc:
                _logger.warning("sni_poll_failed", error=str(exc))
                self._snapshots.append((ts, {}))
            self._stop_poll.wait(_POLL_INTERVAL_SECS)

    # -- Lifecycle (Port-Vertrag) ----------------------------------------------

    def start(self, interface: str | None) -> None:
        """Startet den passiven Sniff (idempotent gegenueber einem aktiven Lauf).

        Spinnt den scapy-``AsyncSniffer`` (billiger prn, ``store=0``) + den psutil-
        Poller-Thread auf. ``interface`` ``None`` -> ``_pick_iface`` (String, NIE das
        ``conf.iface``-Objekt -- Spike-Lehre). Frischer Puffer je Start. Toter
        Sniffer-Thread nach der Alive-Probe -> ``SniError`` (Permission/Geraet), KEINE
        stille Leer-Erfassung.
        """
        if not _scapy.HAS_SCAPY:
            raise SniError("SNI capture requires libpcap/scapy. Install it and restart CERNIS PRO.")
        if self.is_running():
            return  # bereits aktiv -- nicht doppelt starten

        # Frischer Puffer je Lauf (ein start() ist eine frische Erfassung).
        self._raw_hits = deque(maxlen=_MAX_HITS)
        self._snapshots = deque(maxlen=_MAX_SNAPSHOTS)
        self._stop_poll = threading.Event()

        iface = interface or _pick_iface()
        try:
            sniffer = _scapy.AsyncSniffer(
                iface=iface,
                filter=_SNI_FILTER,
                prn=self._on_packet,
                store=0,
            )
            sniffer.start()
        except Exception as exc:
            self._sniffer = None
            raise SniError(f"SNI capture failed to start: {exc}") from exc

        self._sniffer = sniffer

        # Alive-Probe (Muster ScapyPacketSniffer): dem Thread kurz Zeit zum sofortigen
        # Sterben geben (Permission-Fehler schlagen instantan zu).
        time.sleep(_ALIVE_PROBE_SECS)
        thread = getattr(sniffer, "thread", None)
        if not (thread and thread.is_alive()):
            self._sniffer = None
            raise SniError(
                "SNI capture failed -- raw socket not accessible.\n"
                "Fix: sudo setcap cap_net_raw+eip /usr/bin/cernis-backend"
            )

        # Poller erst NACH erfolgreicher Sniff-Probe starten (kein verwaister Thread,
        # falls der Sniff scheitert).
        self._poller = threading.Thread(target=self._poll_loop, daemon=True)
        self._poller.start()

    def stop(self) -> None:
        """Stoppt einen laufenden Sniff (idempotent). Erfasste Daten bleiben erhalten.

        Haelt den Poller (Event setzen + joinen) und den ``AsyncSniffer`` (join) an.
        Kein laufender Sniff -> No-op. Die ``_raw_hits``/``_snapshots`` werden NICHT
        geleert (ein letzter ``observed()``-Abruf nach dem Stop liefert noch die
        Momentaufnahme; der naechste ``start()`` setzt den Puffer frisch).
        """
        self._stop_poll.set()
        poller = self._poller
        if poller is not None:
            poller.join(timeout=2)
            self._poller = None
        sniffer = self._sniffer
        if sniffer is None:
            return
        self._sniffer = None
        try:
            sniffer.stop(join=True)
        except Exception as exc:
            _logger.warning("sni_stop_failed", error=str(exc))

    def is_running(self) -> bool:
        """``True``, solange der Sniffer-Thread tatsaechlich laeuft (``thread.is_alive``)."""
        sniffer = self._sniffer
        if sniffer is None:
            return False
        thread = getattr(sniffer, "thread", None)
        return bool(thread and thread.is_alive())

    def observed(self) -> list[ObservedSni]:
        """Momentaufnahme: jedem rohen Hit den naechsten Snapshot zuordnen + Name aufloesen.

        Schwere Arbeit (Zuordnung + Namensaufloesung) lebt HIER, nicht im Sniff-/
        Poller-Pfad. Pro Hit: ``match_snapshot`` (Domaene) liefert ``(pid, delta_ms)``,
        ``_resolve_app_name`` (psutil, NACH dem Match) den Prozessnamen. Eine Kopie der
        Snapshot-Liste, damit der parallel laufende Poller sie waehrend der Iteration
        nicht unter uns veraendert.
        """
        snapshots = list(self._snapshots)
        result: list[ObservedSni] = []
        for hit in list(self._raw_hits):
            pid, delta_ms = match_snapshot(
                hit.remote_ip, hit.remote_port, hit.monotonic_ts, snapshots
            )
            result.append(
                ObservedSni(
                    hostname=hit.hostname,
                    remote_ip=hit.remote_ip,
                    remote_port=hit.remote_port,
                    monotonic_ts=hit.monotonic_ts,
                    app_name=_resolve_app_name(pid),
                    pid=pid,
                    delta_ms=delta_ms,
                )
            )
        return result

    def check_permission(self) -> str | None:
        """Prueft, ob der Sniff moeglich ist; Fehlertext oder ``None`` wenn OK.

        NUR Linux x64 (Muster ``ScapyPacketSniffer.check_permission``): ``AF_PACKET``-
        Raw-Socket probieren. ``PermissionError`` -> ``cap_net_raw``-Fix-Hinweis (kein
        stiller Fallback, S3). ``OSError`` -> ``None`` ("inconclusive" -- kein
        Permission-Fehler, scapy darf es versuchen).
        """
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            s.close()
            return None
        except PermissionError:
            return (
                "Permission denied -- SNI capture requires root or CAP_NET_RAW.\n"
                "Fix: sudo setcap cap_net_raw+eip /usr/bin/cernis-backend"
            )
        except OSError:
            return None  # inconclusive -- kein Rechte-Fehler, scapy darf es versuchen

    def is_available(self) -> bool:
        """``True``, wenn scapy verfuegbar ist (reiner Verfuegbarkeits-Check)."""
        return bool(_scapy.HAS_SCAPY)
