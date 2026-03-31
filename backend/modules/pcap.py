"""
CERNIS PRO Packet Capture
Live packet capture with filtering, statistics, and pcap export.
Requires scapy (pip install scapy) or tcpdump fallback.
"""
import asyncio
import threading
import time
import os
import tempfile
from dataclasses import dataclass, field, asdict
from collections import defaultdict
from typing import Optional, Callable

try:
    # Scapy Cache in beschreibbares Verzeichnis umleiten (verhindert PermissionError)
    import os as _os, tempfile as _tmp
    if not _os.environ.get('SCAPY_CACHE_DIR'):
        _os.environ['SCAPY_CACHE_DIR'] = _tmp.gettempdir()
    from scapy.all import sniff, wrpcap, rdpcap, Ether, IP, IPv6, TCP, UDP, ICMP, DNS
    HAS_SCAPY = True
except Exception:
    HAS_SCAPY = False


# ── Data structures ───────────────────────────────────────────

@dataclass
class PacketSummary:
    timestamp: float
    src_ip: str       = ""
    dst_ip: str       = ""
    src_mac: str      = ""
    dst_mac: str      = ""
    protocol: str     = ""
    src_port: int     = 0
    dst_port: int     = 0
    length: int       = 0
    info: str         = ""
    is_ipv6: bool     = False

    def to_dict(self):
        return asdict(self)


@dataclass
class CaptureStats:
    total_packets: int   = 0
    total_bytes: int     = 0
    protocols: dict      = field(default_factory=dict)
    top_talkers: dict    = field(default_factory=dict)  # ip -> bytes
    top_ports: dict      = field(default_factory=dict)   # port -> count
    start_time: float    = field(default_factory=time.time)

    def to_dict(self):
        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "duration_secs": round(time.time() - self.start_time, 1),
            "protocols": dict(sorted(self.protocols.items(), key=lambda x: x[1], reverse=True)),
            "top_talkers": dict(sorted(self.top_talkers.items(), key=lambda x: x[1], reverse=True)[:10]),
            "top_ports": dict(sorted(self.top_ports.items(), key=lambda x: x[1], reverse=True)[:20]),
        }


# ── Capture state ─────────────────────────────────────────────

_capture_running = False
_capture_packets: list[PacketSummary] = []
_capture_stats = CaptureStats()
_subscribers: list[Callable] = []
_pcap_file: Optional[str] = None
_raw_packets = []


def _parse_packet(pkt) -> Optional[PacketSummary]:
    """Extract summary info from a packet."""
    try:
        ps = PacketSummary(timestamp=time.time())

        if pkt.haslayer(Ether):
            ps.src_mac = pkt[Ether].src
            ps.dst_mac = pkt[Ether].dst

        if pkt.haslayer(IPv6):
            ps.is_ipv6 = True
            ps.src_ip = str(pkt[IPv6].src)
            ps.dst_ip = str(pkt[IPv6].dst)
            ps.protocol = "IPv6"
        elif pkt.haslayer(IP):
            ps.src_ip = pkt[IP].src
            ps.dst_ip = pkt[IP].dst
            if pkt.haslayer(ICMP):
                ps.protocol = "ICMP"
                ps.info = f"Type {pkt[ICMP].type}"
            elif pkt.haslayer(TCP):
                ps.protocol = "TCP"
                ps.src_port = pkt[TCP].sport
                ps.dst_port = pkt[TCP].dport
                flags = pkt[TCP].flags
                flag_str = ""
                if flags & 0x02: flag_str += "SYN "
                if flags & 0x10: flag_str += "ACK "
                if flags & 0x01: flag_str += "FIN "
                if flags & 0x04: flag_str += "RST "
                ps.info = flag_str.strip()
                if ps.dst_port == 443 or ps.src_port == 443:
                    ps.protocol = "HTTPS"
                elif ps.dst_port == 80 or ps.src_port == 80:
                    ps.protocol = "HTTP"
                elif ps.dst_port == 22 or ps.src_port == 22:
                    ps.protocol = "SSH"
            elif pkt.haslayer(UDP):
                ps.protocol = "UDP"
                ps.src_port = pkt[UDP].sport
                ps.dst_port = pkt[UDP].dport
                if pkt.haslayer(DNS):
                    ps.protocol = "DNS"
                    try:
                        ps.info = pkt[DNS].qd.qname.decode() if pkt[DNS].qd else ""
                    except Exception:
                        pass
                elif ps.dst_port == 5353:
                    ps.protocol = "mDNS"
        else:
            ps.protocol = "L2"

        ps.length = len(pkt)
        return ps
    except Exception:
        return None


def _update_stats(ps: PacketSummary):
    global _capture_stats
    _capture_stats.total_packets += 1
    _capture_stats.total_bytes += ps.length
    proto = ps.protocol or "Other"
    _capture_stats.protocols[proto] = _capture_stats.protocols.get(proto, 0) + 1
    if ps.src_ip:
        _capture_stats.top_talkers[ps.src_ip] = \
            _capture_stats.top_talkers.get(ps.src_ip, 0) + ps.length
    if ps.dst_port:
        p = str(ps.dst_port)
        _capture_stats.top_ports[p] = _capture_stats.top_ports.get(p, 0) + 1


def _handle_packet(pkt):
    global _capture_packets, _raw_packets
    ps = _parse_packet(pkt)
    if not ps:
        return
    _update_stats(ps)
    _raw_packets.append(pkt)
    _capture_packets.append(ps)
    if len(_capture_packets) > 10000:
        _capture_packets = _capture_packets[-5000:]

    for cb in list(_subscribers):
        try:
            cb(ps)
        except Exception:
            pass


def subscribe(cb: Callable):
    _subscribers.append(cb)

def unsubscribe(cb: Callable):
    if cb in _subscribers:
        _subscribers.remove(cb)


async def start_capture(interface: str = None, bpf_filter: str = "",
                         max_packets: int = 10000) -> bool:
    """Start background packet capture."""
    global _capture_running, _capture_packets, _capture_stats, _raw_packets, _pcap_file
    if not HAS_SCAPY:
        return False
    if _capture_running:
        return True

    _capture_running = True
    _capture_packets = []
    _raw_packets = []
    _capture_stats = CaptureStats()
    _pcap_file = os.path.join(tempfile.gettempdir(), f"cernis_capture_{int(time.time())}.pcap")

    def _run():
        kwargs = {"prn": _handle_packet, "store": 0, "count": max_packets}
        if interface:
            kwargs["iface"] = interface
        if bpf_filter:
            kwargs["filter"] = bpf_filter
        try:
            sniff(**kwargs)
        except Exception as e:
            print(f"Capture error: {e}")
        finally:
            global _capture_running
            _capture_running = False
            if _raw_packets:
                try:
                    wrpcap(_pcap_file, _raw_packets)
                except Exception:
                    pass

    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, _run)
    return True


def stop_capture():
    global _capture_running
    _capture_running = False


def get_capture_status() -> dict:
    return {
        "running": _capture_running,
        "packets": len(_capture_packets),
        "stats": _capture_stats.to_dict(),
        "pcap_available": bool(_pcap_file and os.path.exists(_pcap_file or "")),
        "pcap_path": _pcap_file,
    }


def get_recent_packets(limit: int = 100) -> list[dict]:
    return [p.to_dict() for p in _capture_packets[-limit:]]


def get_pcap_path() -> Optional[str]:
    if _pcap_file and os.path.exists(_pcap_file):
        return _pcap_file
    return None


def check_available() -> bool:
    return HAS_SCAPY
