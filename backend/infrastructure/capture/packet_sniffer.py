"""Adapter fuer ``PacketSnifferPort`` -- v2-nativer scapy-Dauer-Capture (C.3).

v2-NATIV gegen scapy, KEIN ``modules``-Import (cve/tls-Stil, KEIN ADR 0007): der
scapy-gebundene Kern ist klein (~100 Zeilen) und haengt an nichts Unportiertem.
Wuerde man ``modules.pcap`` wrappen, bekaeme man die mutablen Alt-dataclasses
zurueck und muesste sie auf die frozen Domaenenmodelle mappen -- MEHR Code plus
eine Extra-Naht. Zudem ist der Alt-Broadcast-Pfad (``_subscribers``/``prn`` mit
stillem ``except: pass``) kaputt und SOLL ersetzt werden; ihn zu importieren waere
das Gegenteil der C.3-Reparatur.

THREAD->LOOP-NAHT (Variante A, abgenommen): ``AsyncSniffer.prn`` laeuft im
Sniffer-EIGENEN Thread (scapy startet einen ``threading.Thread``). Der ``stream``-
Generator laeuft im Eventloop. Die Bruecke ist eine ``asyncio.Queue``: ``prn``
parst das Paket IM Thread (``_parse_packet``) und schiebt das ``PacketSummary``
ueber ``loop.call_soon_threadsafe(q.put_nowait, ps)`` thread-sicher in die Queue;
der Generator ``await q.get()`` zieht es im Loop heraus und yieldet es. KEIN
``run_coroutine_threadsafe`` -- im Thread laeuft keine Coroutine, nur ein
``put_nowait``. Broadcast/Stats/Ringpuffer treibt der Use-Case (C.5) NACH dem
``yield``, alles im Eventloop -- der Sniffer-Thread sieht weder WS noch Stats.

START-FEHLER (Port-Vertrag, S3-frei): ``stream`` startet den ``AsyncSniffer``,
wartet die Alive-Probe ab (``time.sleep(0.8)`` + ``thread.is_alive()``, AS-IS aus
``modules/pcap.py`` Z.345-348 -- Permission-Fehler killen den Thread sofort) und
wirft bei totem Thread ``CaptureError`` -- KEINE stille Leer-Iteration, KEINE
scapy-Roh-Exception. Der Aufrufer prueft ``check_permission`` zusaetzlich vorher.

Plattform: NUR Linux x64. Windows/macOS-Pfade des Altcodes
(``_resolve_windows_iface``, BPF-Glob, Npcap-Registry) sind bewusst WEGGELASSEN.
"""

import asyncio
import socket
import time
from collections.abc import AsyncIterator
from typing import Any

import structlog

from domain.capture import PacketSummary
from infrastructure.capture import _scapy
from infrastructure.capture.errors import CaptureError

_logger = structlog.get_logger(__name__)

# Sentinel: signalisiert dem Generator das Strom-Ende (Stop oder max_packets).
_SENTINEL = object()

# Alive-Probe-Fenster: dem Sniffer-Thread kurz Zeit lassen, sofort zu sterben
# (Permission-Fehler schlagen instantan zu). AS-IS aus modules/pcap.py.
_ALIVE_PROBE_SECS = 0.8

# Ringpuffer-Trim macht der USE-CASE (C.5), NICHT der Adapter. Der Adapter haelt
# nur die scapy-Rohpakete fuer wrpcap, wachsend bis max_packets (AS-IS).


class ScapyPacketSniffer:
    """Erfuellt ``PacketSnifferPort`` strukturell -- haelt den ``AsyncSniffer``.

    Eine Instanz haelt hoechstens einen laufenden Sniffer. ``_raw_packets`` sammelt
    die scapy-Rohpakete des laufenden Captures fuer ``export_pcap`` (sie verlassen
    den Adapter NIE Richtung Domaene -- die Domaene kennt nur ``PacketSummary``).
    """

    def __init__(self) -> None:
        self._sniffer: Any = None
        self._raw_packets: list[Any] = []

    def _parse_packet(self, pkt: Any) -> PacketSummary | None:
        """scapy-Paket -> ``PacketSummary`` (laeuft IM Sniffer-Thread).

        Verhaltensgleich zu ``modules/pcap._parse_packet`` (Z.78-133): Ether-MACs,
        IPv6 vor IPv4, ICMP/TCP/UDP, TCP-Flag-String, Port-basierte Protokoll-
        Verfeinerung (443->HTTPS, 80->HTTP, 22->SSH, 5353->mDNS), DNS-qname. Ein
        Parse-Fehler ergibt ``None`` (das Paket wird verworfen) -- das ist KEIN
        S3-Fang, sondern der vom Vertrag vorgesehene "uninteressantes/kaputtes
        Paket"-Fall; ``timestamp`` setzt der Adapter (scapy liefert keinen).
        """
        try:
            ps_kwargs: dict[str, Any] = {"timestamp": time.time()}

            if pkt.haslayer(_scapy.Ether):
                ps_kwargs["src_mac"] = pkt[_scapy.Ether].src
                ps_kwargs["dst_mac"] = pkt[_scapy.Ether].dst

            if pkt.haslayer(_scapy.IPv6):
                ps_kwargs["is_ipv6"] = True
                ps_kwargs["src_ip"] = str(pkt[_scapy.IPv6].src)
                ps_kwargs["dst_ip"] = str(pkt[_scapy.IPv6].dst)
                ps_kwargs["protocol"] = "IPv6"
            elif pkt.haslayer(_scapy.IP):
                ps_kwargs["src_ip"] = pkt[_scapy.IP].src
                ps_kwargs["dst_ip"] = pkt[_scapy.IP].dst
                if pkt.haslayer(_scapy.ICMP):
                    ps_kwargs["protocol"] = "ICMP"
                    ps_kwargs["info"] = f"Type {pkt[_scapy.ICMP].type}"
                elif pkt.haslayer(_scapy.TCP):
                    ps_kwargs["protocol"] = "TCP"
                    sport = pkt[_scapy.TCP].sport
                    dport = pkt[_scapy.TCP].dport
                    ps_kwargs["src_port"] = sport
                    ps_kwargs["dst_port"] = dport
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
                    ps_kwargs["info"] = flag_str.strip()
                    if dport == 443 or sport == 443:
                        ps_kwargs["protocol"] = "HTTPS"
                    elif dport == 80 or sport == 80:
                        ps_kwargs["protocol"] = "HTTP"
                    elif dport == 22 or sport == 22:
                        ps_kwargs["protocol"] = "SSH"
                elif pkt.haslayer(_scapy.UDP):
                    ps_kwargs["protocol"] = "UDP"
                    ps_kwargs["src_port"] = pkt[_scapy.UDP].sport
                    ps_kwargs["dst_port"] = pkt[_scapy.UDP].dport
                    if pkt.haslayer(_scapy.DNS):
                        ps_kwargs["protocol"] = "DNS"
                        try:
                            qd = pkt[_scapy.DNS].qd
                            ps_kwargs["info"] = qd.qname.decode() if qd else ""
                        except Exception:
                            pass
                    elif ps_kwargs["dst_port"] == 5353:
                        ps_kwargs["protocol"] = "mDNS"
            else:
                ps_kwargs["protocol"] = "L2"

            ps_kwargs["length"] = len(pkt)
            return PacketSummary(**ps_kwargs)
        except Exception as exc:
            _logger.warning("packet_parse_failed", error=str(exc))
            return None

    async def stream(
        self, interface: str | None, bpf_filter: str, max_packets: int
    ) -> AsyncIterator[PacketSummary]:
        """Startet den Sniff und yieldet je erfasstem Paket ein ``PacketSummary``.

        ``prn`` (im Sniffer-Thread) parst und schiebt thread-sicher in eine
        ``asyncio.Queue``; dieser Generator (im Eventloop) zieht heraus und yieldet.
        Endet, wenn ``max_packets`` erreicht ist (scapy beendet den Thread -> der
        ``finished_callback`` schiebt das Sentinel) oder ``stop`` gerufen wurde.
        Bei totem Sniffer-Thread (Alive-Probe) -> ``CaptureError``.
        """
        if not _scapy.HAS_SCAPY:
            raise CaptureError(
                "Packet Capture requires libpcap/scapy. Install it and restart CERNIS PRO."
            )

        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[Any] = asyncio.Queue()
        self._raw_packets = []

        def _enqueue(pkt: Any) -> None:
            # Laeuft IM Sniffer-Thread: parsen + thread-sicher in die Queue schieben.
            ps = self._parse_packet(pkt)
            if ps is None:
                return
            self._raw_packets.append(pkt)
            loop.call_soon_threadsafe(queue.put_nowait, ps)

        def _finished(*_args: Any) -> None:
            # scapy ruft das, wenn der Sniff von selbst endet (max_packets/timeout):
            # Sentinel thread-sicher nachreichen, damit der Generator sauber stoppt.
            loop.call_soon_threadsafe(queue.put_nowait, _SENTINEL)

        kwargs: dict[str, Any] = {"prn": _enqueue, "store": 0, "count": max_packets}
        if interface:
            kwargs["iface"] = interface
        if bpf_filter:
            kwargs["filter"] = bpf_filter

        try:
            sniffer = _scapy.AsyncSniffer(**kwargs)
            # finished_callback nach dem Bau setzen (Konstruktor-Signatur variiert).
            sniffer.finished_callback = _finished
            sniffer.start()
        except Exception as exc:
            self._sniffer = None
            raise CaptureError(f"Capture failed to start: {exc}") from exc

        self._sniffer = sniffer

        # Alive-Probe (AS-IS): dem Thread kurz Zeit zum sofortigen Sterben geben.
        # Blockierendes sleep in den Executor, damit der Eventloop frei bleibt.
        await loop.run_in_executor(None, time.sleep, _ALIVE_PROBE_SECS)
        thread = getattr(sniffer, "thread", None)
        if not (thread and thread.is_alive()):
            self._sniffer = None
            raise CaptureError(
                "Capture failed -- raw socket not accessible.\n"
                "Fix: sudo setcap cap_net_raw+eip /usr/bin/cernis-backend"
            )

        # Strom: aus der Queue ziehen, bis das Sentinel kommt (Stop/Selbst-Ende).
        try:
            while True:
                item = await queue.get()
                if item is _SENTINEL:
                    break
                yield item
        finally:
            # Generator-Ende (auch bei GeneratorExit/Abbruch durch den Use-Case):
            # Sniffer sicher stoppen, damit kein Thread weiterlaeuft.
            self.stop()

    def stop(self) -> None:
        """Stoppt einen laufenden Capture-Strom (idempotent).

        Joint den Sniffer-Thread (``stop(join=True)``). Das Sentinel kommt ueber
        ``finished_callback`` in die Queue, sodass ein parallel laufender
        ``stream``-Generator sauber endet. Kein laufender Strom -> No-op.
        """
        sniffer = self._sniffer
        if sniffer is None:
            return
        self._sniffer = None
        try:
            sniffer.stop(join=True)
        except Exception as exc:
            _logger.warning("capture_stop_failed", error=str(exc))

    def is_running(self) -> bool:
        """``True``, solange der Sniffer-Thread tatsaechlich laeuft.

        Spiegelt den ECHTEN Thread-Zustand (Altcode-``.running`` blieb nach Crash
        ``True`` -- hier ``thread.is_alive()``).
        """
        sniffer = self._sniffer
        if sniffer is None:
            return False
        thread = getattr(sniffer, "thread", None)
        return bool(thread and thread.is_alive())

    def export_pcap(self, path: str) -> bool:
        """Schreibt die gesammelten Rohpakete als pcap nach ``path`` (best-effort).

        ``True`` bei Erfolg, ``False`` wenn nichts zu schreiben war oder das
        Schreiben fehlschlug (AS-IS ``_save_pcap``). Fehlschlag wird geloggt
        (kein stiller S3-Fang), das Ergebnis bleibt ``False`` (Wire unveraendert).
        """
        if not (_scapy.HAS_SCAPY and self._raw_packets):
            return False
        try:
            _scapy.wrpcap(path, self._raw_packets)
            return True
        except Exception as exc:
            _logger.warning("pcap_export_failed", path=path, error=str(exc))
            return False

    def check_permission(self) -> str | None:
        """Prueft, ob Capture moeglich ist; Fehlertext oder ``None`` wenn OK.

        NUR Linux x64 (AS-IS Linux-Zweig aus ``modules/pcap._check_capture_permission``
        Z.241-253): ``AF_PACKET``-Raw-Socket probieren. ``PermissionError`` ->
        ``cap_net_raw``-Fix-Hinweis (kein stiller Fallback, S3). ``OSError`` ->
        ``None`` ("inconclusive" -- KEIN Permission-Fehler, scapy darf es versuchen;
        AS-IS und kein S3-Verstoss, da kein echter Fehler verschluckt wird).
        """
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            s.close()
            return None
        except PermissionError:
            return (
                "Permission denied -- packet capture requires root or CAP_NET_RAW.\n"
                "Fix: sudo setcap cap_net_raw+eip /usr/bin/cernis-backend"
            )
        except OSError:
            return None  # inconclusive -- kein Rechte-Fehler, scapy darf es versuchen

    def is_available(self) -> bool:
        """``True``, wenn scapy verfuegbar ist (reiner Verfuegbarkeits-Check)."""
        return _scapy.HAS_SCAPY
