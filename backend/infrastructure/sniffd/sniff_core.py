"""Der scapy-gebundene Sniff-Kern des Helfers -- NUR der rohe Sniff.

PORTIERT aus ``infrastructure/sni/sni_sniffer.py``, aber ausschliesslich der rohe
Sniff-Teil: ``parse_sni`` (manuelles ClientHello-Parsing), ``_raw_tcp_payload``
(layer-unabhaengiger TCP-Payload), ``_pick_iface`` (Interface-Ermittlung) und der
billige prn-Callback, der pro Treffer ein rohes Hit-``dict`` baut. KEIN psutil,
KEINE Prozess-Zuordnung, kein ``match_snapshot``, kein ``deque`` -- die teure
Zuordnung bleibt im Backend.

ETAPPE 3a: Zusaetzlich die pcap- und LLDP-Kerne, PORTIERT aus den Backend-Adaptern
(``capture/packet_sniffer.py`` + ``capture/lldp_sniffer.py``), verhaltensgleich,
aber OHNE asyncio/Domaenenmodelle -- der Helfer ist ein eigener Prozess (kein
Eventloop) und reicht reine ``dict``s ueber IPC:

* ``parse_packet`` -- ein scapy-Paket zu einem reinen Summary-``dict`` (statt
  ``domain.PacketSummary``); fehlende Felder weggelassen, Parse-Fehler -> ``None``.
* ``start_pcap_sniff`` -- ``AsyncSniffer``-Dauerstrom (``count=max_packets``,
  optionaler BPF-Filter); ``on_packet(dict)`` pro Paket, ``on_raw(pkt)`` fuers
  spaetere ``wrpcap``, ``on_finished()`` bei Selbst-Ende (max_packets).
* ``run_lldp_sniff`` -- blockierender, zeitbegrenzter LLDP/CDP-Sniff -> Nachbar-
  ``dict``-Liste (dedupliziert per ``source_mac``).
* ``export_pcap`` -- gesammelte Rohpakete als ``.pcap`` schreiben (best-effort).

GETEILTES scapy (kein Duplikat): die scapy-Symbole kommen aus
``infrastructure.sniffd._scapy`` -- ``_scapy`` wird hier NICHT veraendert und
NICHT neu importiert. ``normalize_hostname`` kommt aus ``domain.sni``
(infra->domain ist contract-legal).

promisc=False: SNI braucht nur den eigenen TLS-Traffic; ``promisc=False`` vermeidet
zusaetzlich den VMware-Promiscuous-Dialog.

Plattform: NUR Linux x64 (``check_raw_permission`` ueber die ``AF_PACKET``-Raw-
Socket-Probe, ``_pick_iface`` ueber die Default-Route / ``/sys/class/net``).
"""

import contextlib
import os
import re
import socket
import struct
import subprocess
import threading
import time
from collections.abc import Callable
from typing import Any

import structlog

from domain.sni import normalize_hostname
from infrastructure.sniffd import _scapy

_logger = structlog.get_logger(__name__)

# Alive-Probe-Fenster (Muster ScapyPacketSniffer): dem Sniffer-Thread kurz Zeit
# lassen, sofort zu sterben -- Permission-Fehler schlagen instantan zu.
_ALIVE_PROBE_SECS = 0.8

# BPF-Filter wie im Original: nur TCP:443 (dort sitzt der TLS-ClientHello).
_SNI_FILTER = "tcp port 443"

# BPF-Filter AS-IS aus lldp_sniffer.py: LLDP-EtherType + CDP-Multicast-MAC.
_LLDP_CDP_FILTER = "ether proto 0x88cc or ether dst 01:00:0c:cc:cc:cc"

# BPF-Filter fuer den DNS-Sniff: Port 53 (UDP und TCP -- ``port`` deckt beide L4 ab).
_DNS_FILTER = "port 53"

# Ein roher Hit ueber IPC ist exakt dieses dict.
RawHitDict = dict[str, Any]


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

    Gibt IMMER einen String zurueck (oder wirft ``RuntimeError``, wenn gar nichts
    gefunden wird -- hier KEIN ``SniError``, der Helfer ist von der sni-Domaene
    entkoppelt).
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

    raise RuntimeError("Kein nutzbares Netzwerk-Interface gefunden.")


# ── Permission-Probe (AF_PACKET-Raw-Socket, wie im Original) ──────────────────


def check_raw_permission(zweck: str = "Packet capture") -> str | None:
    """Prueft, ob der rohe Sniff moeglich ist; Fehlertext oder ``None`` wenn OK.

    NUR Linux x64 (Muster ``ScapyPacketSniffer.check_permission``): ``AF_PACKET``-
    Raw-Socket probieren. ``PermissionError`` -> ``cap_net_raw``-Fix-Hinweis (kein
    stiller Fallback, S3). ``OSError`` -> ``None`` ("inconclusive" -- kein
    Permission-Fehler, scapy darf es versuchen).

    Der Fix-Text nennt bewusst KEINEN ``/usr/bin/cernis-backend``-Pfad mehr: die
    Cap sitzt kuenftig auf ``cernis-sniffd``, nicht auf dem Backend.

    Der Fehlertext ist GETEILT: derselbe Helfer bedient SNI-, DNS-, pcap- und
    LLDP-Sniff. ``zweck`` benennt den konkreten Aufrufer (z. B. ``"SNI capture"``,
    ``"DNS capture"``), damit die Meldung ehrlich ist -- ein DNS-Sniff darf nicht
    "SNI capture" melden. Der stabile Substring ``CAP_NET_RAW`` bleibt in JEDER
    Variante erhalten (daran haengt die Rechte-Klassifikation der sni-Domaene).
    """
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        s.close()
        return None
    except PermissionError:
        return f"Permission denied -- {zweck} requires root or CAP_NET_RAW."
    except OSError:
        return None  # inconclusive -- kein Rechte-Fehler, scapy darf es versuchen


# ── Roher Sniff-Lifecycle (AsyncSniffer + billiger prn) ───────────────────────


def start_raw_sniff(
    on_hit: Callable[[RawHitDict], None],
    interface: str | None,
    stop_event: threading.Event,
) -> Any:
    """Startet den passiven SNI-Sniff und ruft ``on_hit`` pro rohem Treffer.

    Spinnt den scapy-``AsyncSniffer`` (billiger prn, ``store=0``, ``promisc=False``)
    auf. ``interface`` ``None`` -> ``_pick_iface`` (String, NIE das ``conf.iface``-
    Objekt -- Spike-Lehre). Der prn-Callback parst NUR + ruft ``on_hit`` mit dem
    rohen Hit-``dict`` -- KEINE psutil-Arbeit (das wuerde den libpcap-Lesepfad
    aushungern -- der reale "0 Pakete"-Bug des Spikes).

    ``promisc=False``: SNI braucht nur den eigenen TLS-Traffic; das vermeidet den
    VMware-Promiscuous-Dialog.

    Toter Sniffer-Thread nach der Alive-Probe (``_ALIVE_PROBE_SECS``) ->
    ``RuntimeError`` mit Text "raw socket not accessible -- requires CAP_NET_RAW",
    KEINE stille Leer-Erfassung.

    Das ``stop_event`` ist der Stop-Schalter des Aufrufers; der Sniff wird ueber das
    zurueckgegebene Sniffer-Handle (``.stop(join=True)``) beendet -- der Aufrufer
    haelt beides. Gibt das ``AsyncSniffer``-Handle zurueck.
    """
    if not _scapy.HAS_SCAPY:
        raise RuntimeError("SNI capture requires libpcap/scapy. Install it and restart.")

    iface = interface or _pick_iface()

    def _on_packet(pkt: Any) -> None:
        """scapy-Callback: rohe TCP-Payload greifen, SNI parsen, ``on_hit`` rufen. BILLIG.

        KEINE psutil-Arbeit hier (das wuerde den libpcap-Lesepfad aushungern -- der
        reale Spike-Bug). Nur parsen + bei Treffer ein rohes Hit-``dict`` an
        ``on_hit`` reichen. Ein Paket ohne TCP/IP oder ohne SNI wird still
        uebersprungen. ``except Exception``: ein einzelnes kaputtes Paket darf den
        Sniff-Thread nicht killen.
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
            on_hit(
                {
                    "hostname": host,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "monotonic_ts": time.monotonic(),
                }
            )
        except Exception as exc:  # ein kaputtes Paket killt den Sniff nicht
            _logger.warning("sni_parse_failed", error=str(exc))

    try:
        sniffer = _scapy.AsyncSniffer(
            iface=iface,
            filter=_SNI_FILTER,
            prn=_on_packet,
            store=0,
            promisc=False,
        )
        sniffer.start()
    except Exception as exc:
        raise RuntimeError(f"SNI capture failed to start: {exc}") from exc

    # Alive-Probe (Muster ScapyPacketSniffer): dem Thread kurz Zeit zum sofortigen
    # Sterben geben (Permission-Fehler schlagen instantan zu). Das ``stop_event``
    # darf die Probe vorzeitig beenden (sauberer Stop direkt nach dem Start).
    stop_event.wait(_ALIVE_PROBE_SECS)
    thread = getattr(sniffer, "thread", None)
    if not (thread and thread.is_alive()):
        with contextlib.suppress(Exception):
            sniffer.stop(join=True)
        # scapy legt eine im Sniffer-Thread aufgetretene Ausnahme in
        # ``sniffer.exception`` ab (fehlt/None, wenn keine hinterlegt ist).
        # Den stabilen Substring "CAP_NET_RAW" IMMER erhalten (daran haengt
        # die Rechte-Klassifikation der sni-Domaene), aber die echte Ursache
        # sichtbar machen statt sie pauschal zu verschlucken.
        thread_exc = getattr(sniffer, "exception", None)
        if thread_exc is not None:
            raise RuntimeError(
                "raw socket not accessible -- requires CAP_NET_RAW "
                f"(Sniffer-Thread-Fehler: {thread_exc})"
            ) from thread_exc
        raise RuntimeError("raw socket not accessible -- requires CAP_NET_RAW")

    return sniffer


# ── DNS-Sniff-Lifecycle (netzweit, promisc=True -- ADR 0042) ──────────────────


def start_dns_sniff(
    on_query: Callable[[dict[str, Any]], None],
    interface: str | None,
    stop_event: threading.Event,
) -> Any:
    """Startet den passiven, netzweiten DNS-Sniff und ruft ``on_query`` pro Anfrage.

    STRUKTUR wie ``start_raw_sniff`` (billiger prn, ``store=0``, Alive-Probe), nur
    das Parsing + ``promisc`` unterscheiden sich. Der prn-Callback bestimmt Quell-/
    Ziel-IP + L4, filtert auf ANFRAGEN (Ziel-Port 53) und reicht pro Anfrage ein
    reines Query-``dict`` (``src_ip``/``dst_ip``/``l4``/``monotonic_ts``, optional
    ``qname``) an ``on_query`` -- KEINE psutil-Arbeit (das wuerde den libpcap-
    Lesepfad aushungern -- der reale Spike-Bug).

    ``promisc=True`` IST der Unterschied zu SNI/pcap: der netzweite Anspruch
    (fremde Geraete) verlangt den Promiscuous-Modus -- nur so wird fremder DNS-
    Traffic ueberhaupt sichtbar (soweit die Netz-Position ihn durchlaesst). Das ist
    bewusst (ADR 0042).

    Toter Sniffer-Thread nach der Alive-Probe (``_ALIVE_PROBE_SECS``) ->
    ``RuntimeError`` mit Text "raw socket not accessible -- requires CAP_NET_RAW",
    KEINE stille Leer-Erfassung. Gibt das ``AsyncSniffer``-Handle zurueck.
    """
    if not _scapy.HAS_SCAPY:
        raise RuntimeError("DNS capture requires libpcap/scapy. Install it and restart.")

    iface = interface or _pick_iface()

    def _on_packet(pkt: Any) -> None:
        """scapy-Callback: DNS-Anfrage klassifizieren, ``on_query`` rufen. BILLIG.

        Nur IP-Pakete mit Port-53-Beteiligung; Quell-/Ziel-IP (IPv6 vor IPv4), L4
        + Ziel-Port. Nur ANFRAGEN (``dport == 53``) zaehlen -- Antworten
        (``sport == 53``) werden ignoriert. ``except Exception``: ein einzelnes
        kaputtes Paket darf den Sniff-Thread nicht killen.
        """
        try:
            # Nur IP-Pakete mit Port-53-Beteiligung; Quell-IP + Ziel-IP bestimmen
            # (IPv6 vor IPv4, Muster ScapyPacketSniffer).
            if pkt.haslayer(_scapy.IPv6):
                src_ip = str(pkt[_scapy.IPv6].src)
                dst_ip = str(pkt[_scapy.IPv6].dst)
            elif pkt.haslayer(_scapy.IP):
                src_ip = str(pkt[_scapy.IP].src)
                dst_ip = str(pkt[_scapy.IP].dst)
            else:
                return
            # L4 + Ziel-Port ermitteln (nur Port 53 interessiert; der BPF-Filter deckt
            # es grob ab, aber wir pruefen den ZIEL-Port sauber, damit nur ANFRAGEN
            # (dport==53) zaehlen, keine Antworten).
            if pkt.haslayer(_scapy.UDP):
                l4 = "udp"
                dport = int(pkt[_scapy.UDP].dport)
            elif pkt.haslayer(_scapy.TCP):
                l4 = "tcp"
                dport = int(pkt[_scapy.TCP].dport)
            else:
                return
            # Nur ANFRAGEN: Ziel-Port 53 (das Geraet fragt einen Resolver).
            # Antworten (sport==53) ignorieren.
            if dport != 53:
                return
            # Optional den abgefragten Namen mitschicken, wenn scapy DNS parst
            # (best-effort, wie parse_packet).
            qname = None
            if pkt.haslayer(_scapy.DNS):
                try:
                    qd = pkt[_scapy.DNS].qd
                    if qd is not None and getattr(qd, "qname", None):
                        qname = qd.qname.decode("ascii", errors="replace").rstrip(".")
                except Exception:
                    qname = None
            query: dict[str, Any] = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "l4": l4,
                "monotonic_ts": time.monotonic(),
            }
            if qname:
                query["qname"] = qname
            on_query(query)
        except Exception as exc:  # ein kaputtes Paket killt den Sniff nicht
            _logger.warning("dns_parse_failed", error=str(exc))

    try:
        # promisc=True IST der Unterschied -- netzweiter Anspruch, ADR 0042.
        sniffer = _scapy.AsyncSniffer(
            iface=iface,
            filter=_DNS_FILTER,
            prn=_on_packet,
            store=0,
            promisc=True,
        )
        sniffer.start()
    except Exception as exc:
        raise RuntimeError(f"DNS capture failed to start: {exc}") from exc

    # Alive-Probe (Muster ScapyPacketSniffer): dem Thread kurz Zeit zum sofortigen
    # Sterben geben (Permission-Fehler schlagen instantan zu). Das ``stop_event``
    # darf die Probe vorzeitig beenden (sauberer Stop direkt nach dem Start).
    stop_event.wait(_ALIVE_PROBE_SECS)
    thread = getattr(sniffer, "thread", None)
    if not (thread and thread.is_alive()):
        with contextlib.suppress(Exception):
            sniffer.stop(join=True)
        # scapy legt eine im Sniffer-Thread aufgetretene Ausnahme in
        # ``sniffer.exception`` ab (fehlt/None, wenn keine hinterlegt ist).
        # Den stabilen Substring "CAP_NET_RAW" IMMER erhalten (daran haengt
        # die Rechte-Klassifikation der sni-Domaene), aber die echte Ursache
        # sichtbar machen statt sie pauschal zu verschlucken.
        thread_exc = getattr(sniffer, "exception", None)
        if thread_exc is not None:
            raise RuntimeError(
                "raw socket not accessible -- requires CAP_NET_RAW "
                f"(Sniffer-Thread-Fehler: {thread_exc})"
            ) from thread_exc
        raise RuntimeError("raw socket not accessible -- requires CAP_NET_RAW")

    return sniffer


# ── pcap-Kern (Dauerstrom) -- PORTIERT aus capture/packet_sniffer.py ───────────


def parse_packet(pkt: Any) -> dict[str, Any] | None:
    """scapy-Paket -> reines Summary-``dict`` (oder ``None`` bei Parse-Fehler).

    Verhaltensgleich zu ``ScapyPacketSniffer._parse_packet``, aber statt eines
    ``domain.PacketSummary`` ein reines ``dict`` mit denselben Feldern (timestamp,
    src_mac, dst_mac, is_ipv6, src_ip, dst_ip, protocol, src_port, dst_port, info,
    length). FEHLENDE Felder werden weggelassen (nicht ``None``-gefuellt). Ether-
    MACs, IPv6 vor IPv4, ICMP/TCP/UDP, TCP-Flag-String, Port-Verfeinerung
    (443->HTTPS, 80->HTTP, 22->SSH, 5353->mDNS), DNS-qname. ``timestamp`` setzt der
    Helfer (scapy liefert keinen). Ein Parse-Fehler ergibt ``None`` (das Paket wird
    verworfen) -- der vom Vertrag vorgesehene "uninteressantes/kaputtes Paket"-Fall,
    KEIN S3-Fang.
    """
    try:
        summary: dict[str, Any] = {"timestamp": time.time()}

        if pkt.haslayer(_scapy.Ether):
            summary["src_mac"] = pkt[_scapy.Ether].src
            summary["dst_mac"] = pkt[_scapy.Ether].dst

        if pkt.haslayer(_scapy.IPv6):
            summary["is_ipv6"] = True
            summary["src_ip"] = str(pkt[_scapy.IPv6].src)
            summary["dst_ip"] = str(pkt[_scapy.IPv6].dst)
            summary["protocol"] = "IPv6"
        elif pkt.haslayer(_scapy.IP):
            summary["src_ip"] = pkt[_scapy.IP].src
            summary["dst_ip"] = pkt[_scapy.IP].dst
            if pkt.haslayer(_scapy.ICMP):
                summary["protocol"] = "ICMP"
                summary["info"] = f"Type {pkt[_scapy.ICMP].type}"
            elif pkt.haslayer(_scapy.TCP):
                summary["protocol"] = "TCP"
                sport = pkt[_scapy.TCP].sport
                dport = pkt[_scapy.TCP].dport
                summary["src_port"] = sport
                summary["dst_port"] = dport
                flags = pkt[_scapy.TCP].flags
                flag_str = ""
                if flags & 0x02:
                    flag_str += "SYN "
                if flags & 0x10:
                    flag_str += "ACK "
                if flags & 0x01:
                    flag_str += "FIN "
                if flags & 0x04:
                    flag_str += "RST "
                summary["info"] = flag_str.strip()
                if dport == 443 or sport == 443:
                    summary["protocol"] = "HTTPS"
                elif dport == 80 or sport == 80:
                    summary["protocol"] = "HTTP"
                elif dport == 22 or sport == 22:
                    summary["protocol"] = "SSH"
            elif pkt.haslayer(_scapy.UDP):
                summary["protocol"] = "UDP"
                summary["src_port"] = pkt[_scapy.UDP].sport
                summary["dst_port"] = pkt[_scapy.UDP].dport
                if pkt.haslayer(_scapy.DNS):
                    summary["protocol"] = "DNS"
                    try:
                        qd = pkt[_scapy.DNS].qd
                        summary["info"] = qd.qname.decode() if qd else ""
                    except Exception:
                        pass
                elif summary["dst_port"] == 5353:
                    summary["protocol"] = "mDNS"
        else:
            summary["protocol"] = "L2"

        summary["length"] = len(pkt)
        return summary
    except Exception as exc:
        _logger.warning("packet_parse_failed", error=str(exc))
        return None


def start_pcap_sniff(
    on_packet: Callable[[dict[str, Any]], None],
    on_raw: Callable[[Any], None],
    interface: str | None,
    bpf_filter: str,
    max_packets: int,
    stop_event: threading.Event,
    on_finished: Callable[[], None] | None = None,
) -> Any:
    """Startet den pcap-Dauerstrom und ruft Callbacks pro Paket / bei Selbst-Ende.

    AsyncSniffer-Aufbau wie ``ScapyPacketSniffer.stream``, ABER ohne asyncio (der
    Helfer ist ein eigener Prozess, kein Eventloop): der ``prn``-Callback parst per
    ``parse_packet`` und reicht das ``dict`` an ``on_packet``; das ROH-Paket geht
    an ``on_raw`` (der Server sammelt es fuer den spaeteren ``wrpcap``-Export).
    ``promisc=False`` (wie SNI; vermeidet den VMware-Dialog). ``count=max_packets``,
    ``filter=bpf_filter`` (nur wenn nicht leer), ``iface=interface`` oder
    ``_pick_iface()``.

    ``on_finished`` (optional) ist der ``finished_callback`` des ``AsyncSniffer``:
    scapy ruft ihn, wenn der Sniff von SELBST endet (``max_packets`` erreicht) --
    so kann der Server dem Strom-Ende ein ``STOPPED`` folgen lassen, ohne zu pollen.

    Toter Sniffer-Thread nach der Alive-Probe -> ``RuntimeError`` mit Text "raw
    socket not accessible -- requires CAP_NET_RAW" (Muster ``start_raw_sniff``,
    KEINE stille Leer-Erfassung). Gibt das ``AsyncSniffer``-Handle zurueck.
    """
    if not _scapy.HAS_SCAPY:
        raise RuntimeError("Packet capture requires libpcap/scapy. Install it and restart.")

    iface = interface or _pick_iface()

    def _on_packet(pkt: Any) -> None:
        """scapy-Callback: parsen, ``on_raw`` + ``on_packet`` rufen. BILLIG.

        Reihenfolge wie im Original (``_enqueue``): nur wenn ``parse_packet`` ein
        dict liefert, wird das Roh-Paket gesammelt -- so passen PACKET-Strom und
        die ``wrpcap``-Sammlung zusammen (gleiche Pakete). ``except Exception``:
        ein einzelnes kaputtes Paket darf den Sniff-Thread nicht killen.
        """
        try:
            summary = parse_packet(pkt)
            if summary is None:
                return
            on_raw(pkt)
            on_packet(summary)
        except Exception as exc:  # ein kaputtes Paket killt den Sniff nicht
            _logger.warning("pcap_packet_failed", error=str(exc))

    kwargs: dict[str, Any] = {"prn": _on_packet, "store": 0, "count": max_packets, "promisc": False}
    kwargs["iface"] = iface
    if bpf_filter:
        kwargs["filter"] = bpf_filter

    try:
        sniffer = _scapy.AsyncSniffer(**kwargs)
        # finished_callback nach dem Bau setzen (Konstruktor-Signatur variiert).
        if on_finished is not None:
            sniffer.finished_callback = lambda *_args: on_finished()
        sniffer.start()
    except Exception as exc:
        raise RuntimeError(f"Packet capture failed to start: {exc}") from exc

    # Alive-Probe (Muster ScapyPacketSniffer): dem Thread kurz Zeit zum sofortigen
    # Sterben geben. Das ``stop_event`` darf die Probe vorzeitig beenden.
    stop_event.wait(_ALIVE_PROBE_SECS)
    thread = getattr(sniffer, "thread", None)
    if not (thread and thread.is_alive()):
        with contextlib.suppress(Exception):
            sniffer.stop(join=True)
        # scapy legt eine im Sniffer-Thread aufgetretene Ausnahme in
        # ``sniffer.exception`` ab (fehlt/None, wenn keine hinterlegt ist).
        # Den stabilen Substring "CAP_NET_RAW" IMMER erhalten (daran haengt
        # die Rechte-Klassifikation der sni-Domaene), aber die echte Ursache
        # sichtbar machen statt sie pauschal zu verschlucken.
        thread_exc = getattr(sniffer, "exception", None)
        if thread_exc is not None:
            raise RuntimeError(
                "raw socket not accessible -- requires CAP_NET_RAW "
                f"(Sniffer-Thread-Fehler: {thread_exc})"
            ) from thread_exc
        raise RuntimeError("raw socket not accessible -- requires CAP_NET_RAW")

    return sniffer


# ── LLDP-Kern (einmalig, zeitbegrenzt) -- PORTIERT aus capture/lldp_sniffer.py ─


def _parse_lldp_neighbor(pkt: Any) -> dict[str, Any] | None:
    """LLDP-Paket -> Nachbar-``dict`` (AS-IS ``ScapyLldpSniffer._parse_lldp``)."""
    try:
        neighbor: dict[str, Any] = {
            "source_mac": pkt[_scapy.Ether].src,
            "protocol": "LLDP",
        }
        if pkt.haslayer(_scapy.LLDPDUChassisID):
            neighbor["chassis_id"] = str(pkt[_scapy.LLDPDUChassisID].id)
        if pkt.haslayer(_scapy.LLDPDUPortID):
            neighbor["port_id"] = str(pkt[_scapy.LLDPDUPortID].id)
        if pkt.haslayer(_scapy.LLDPDUSystemName):
            neighbor["system_name"] = str(pkt[_scapy.LLDPDUSystemName].system_name)
        if pkt.haslayer(_scapy.LLDPDUSystemDescription):
            neighbor["system_desc"] = str(pkt[_scapy.LLDPDUSystemDescription].description)[:200]
        if pkt.haslayer(_scapy.LLDPDUPortDescription):
            neighbor["port_desc"] = str(pkt[_scapy.LLDPDUPortDescription].description)
        return neighbor
    except Exception as exc:
        _logger.warning("lldp_parse_failed", error=str(exc))
        return None


def _parse_cdp_neighbor(pkt: Any) -> dict[str, Any] | None:
    """CDP-Paket -> Nachbar-``dict`` (AS-IS ``ScapyLldpSniffer._parse_cdp``)."""
    try:
        src_mac = pkt[_scapy.Ether].src if pkt.haslayer(_scapy.Ether) else ""
        neighbor: dict[str, Any] = {"source_mac": src_mac, "protocol": "CDP"}
        if pkt.haslayer(_scapy.CDPMsgDeviceID):
            name = str(pkt[_scapy.CDPMsgDeviceID].val)
            neighbor["system_name"] = name
            neighbor["chassis_id"] = name
        if pkt.haslayer(_scapy.CDPMsgPortID):
            neighbor["port_id"] = str(pkt[_scapy.CDPMsgPortID].val)
        if pkt.haslayer(_scapy.CDPMsgSoftwareVersion):
            neighbor["system_desc"] = str(pkt[_scapy.CDPMsgSoftwareVersion].val)[:200]
        if pkt.haslayer(_scapy.CDPMsgPlatform):
            neighbor["capabilities"] = [str(pkt[_scapy.CDPMsgPlatform].val)]
        return neighbor
    except Exception as exc:
        _logger.warning("cdp_parse_failed", error=str(exc))
        return None


def _dispatch_neighbor(pkt: Any) -> dict[str, Any] | None:
    """EtherType/MAC-Dispatch (AS-IS ``ScapyLldpSniffer._dispatch``).

    LLDP: EtherType ``0x88cc``. CDP: Ziel-MAC ``01:00:0c:cc:cc:cc``. Andere Pakete
    -> ``None`` (vom BPF-Filter eigentlich schon ausgeschlossen).
    """
    if not pkt.haslayer(_scapy.Ether):
        return None
    if pkt[_scapy.Ether].type == 0x88CC:
        return _parse_lldp_neighbor(pkt)
    if pkt[_scapy.Ether].dst.lower() == "01:00:0c:cc:cc:cc":
        return _parse_cdp_neighbor(pkt)
    return None


def run_lldp_sniff(interface: str | None, duration: float) -> list[dict[str, Any]]:
    """Blockierender, zeitbegrenzter LLDP/CDP-Sniff -> deduplizierte Nachbarliste.

    AS-IS ``ScapyLldpSniffer._sniff_blocking``, aber ``dict`` statt ``LLDPNeighbor``:
    ``_scapy.sniff(timeout=duration, filter=_LLDP_CDP_FILTER, prn=...)``, dedupliziert
    per ``source_mac`` (LETZTER gewinnt -- AS-IS zum Altcode-dict). Fehlt
    ``scapy.contrib`` (``HAS_SCAPY_CONTRIB`` False) -> ``[]`` + ``structlog``-Warn
    (S3-Heilung wie Original: kein Crash, der Betreiber sieht es strukturiert).
    Sniff-Fehler werden GELOGGT (Wire unveraendert), keine Nachbarn -> ``[]``.
    """
    if not (_scapy.HAS_SCAPY and _scapy.HAS_SCAPY_CONTRIB):
        _logger.warning(
            "lldp_capture_unavailable",
            has_scapy=_scapy.HAS_SCAPY,
            has_contrib=_scapy.HAS_SCAPY_CONTRIB,
        )
        return []

    neighbors: dict[str, dict[str, Any]] = {}

    def _handle(pkt: Any) -> None:
        neighbor = _dispatch_neighbor(pkt)
        if neighbor:
            neighbors[neighbor["source_mac"]] = neighbor

    try:
        kwargs: dict[str, Any] = {
            "filter": _LLDP_CDP_FILTER,
            "timeout": duration,
            "prn": _handle,
            "store": 0,
        }
        if interface:
            kwargs["iface"] = interface
        _scapy.sniff(**kwargs)
    except Exception as exc:
        _logger.warning("lldp_capture_failed", error=str(exc))

    return list(neighbors.values())


# ── pcap-Export -- PORTIERT aus capture/packet_sniffer.py::export_pcap ─────────


def export_pcap(raw_packets: list[Any], path: str) -> bool:
    """Schreibt ``raw_packets`` als pcap nach ``path`` (best-effort).

    ``True`` bei Erfolg, ``False`` wenn nichts zu schreiben war (scapy fehlt oder
    leere Liste) oder das Schreiben fehlschlug (AS-IS ``ScapyPacketSniffer.export_pcap``).
    Fehlschlag wird GELOGGT (kein stiller S3-Fang), das Ergebnis bleibt ``False``.
    """
    if not (_scapy.HAS_SCAPY and raw_packets):
        return False
    try:
        _scapy.wrpcap(path, raw_packets)
        return True
    except Exception as exc:
        _logger.warning("pcap_export_failed", path=path, error=str(exc))
        return False
