"""
CERNIS PRO Packet Capture
Live packet capture with filtering, statistics, and pcap export.
Requires scapy (pip install scapy).
"""
import time
import os
import platform
import tempfile
from dataclasses import dataclass, field, asdict
from typing import Optional, Callable

try:
    # Scapy Cache in beschreibbares Verzeichnis umleiten (verhindert PermissionError)
    import os as _os, tempfile as _tmp
    if not _os.environ.get('SCAPY_CACHE_DIR'):
        _os.environ['SCAPY_CACHE_DIR'] = _tmp.gettempdir()
    from scapy.all import (
        sniff, wrpcap, Ether, IP, IPv6, TCP, UDP, ICMP, DNS, AsyncSniffer,
    )
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
_capture_error = ""
_sniffer: Optional["AsyncSniffer"] = None


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


# ── Permission check ─────────────────────────────────────────

def _resolve_windows_iface(name: str) -> Optional[str]:
    """Map a Windows adapter name (from ipconfig) to a Scapy interface name.
    ipconfig returns e.g. 'Ethernet-Adapter Ethernet0', Scapy wants 'Ethernet0'."""
    if platform.system() != "Windows" or not HAS_SCAPY:
        return name
    try:
        from scapy.arch.windows import get_windows_if_list
        scapy_ifaces = get_windows_if_list()
        # Direct match first
        for iface in scapy_ifaces:
            if iface.get("name", "") == name:
                return name
        # Strip German/English adapter prefix: "Ethernet-Adapter X" -> "X", "Wireless LAN adapter X" -> "X"
        stripped = name
        for prefix in ["Ethernet-Adapter ", "Ethernet adapter ",
                       "Drahtlos-LAN-Adapter ", "Wireless LAN adapter ",
                       "WLAN-Adapter ", "Wi-Fi adapter "]:
            if name.startswith(prefix):
                stripped = name[len(prefix):]
                break
        for iface in scapy_ifaces:
            if iface.get("name", "") == stripped:
                return stripped
        # Substring match: Scapy name contained in adapter name
        for iface in scapy_ifaces:
            sname = iface.get("name", "")
            if sname and sname in name:
                return sname
    except Exception:
        pass
    return name


def _check_capture_permission() -> Optional[str]:
    """Return error message if capture is not possible, None if OK."""
    _sys = platform.system()

    if _sys == "Darwin":
        import glob as _glob
        bpf_devs = sorted(_glob.glob("/dev/bpf*"))
        if not bpf_devs:
            return "No BPF devices found — packet capture unavailable on this system."
        # Scapy needs read-write access to BPF devices
        last_err = None
        for dev in bpf_devs:
            try:
                fd = os.open(dev, os.O_RDWR)
                os.close(fd)
                return None  # success — at least one BPF device is writable
            except PermissionError as e:
                last_err = e
            except OSError as e:
                # EBUSY (device in use) is not a permission problem — try next
                import errno as _errno
                if e.errno == _errno.EBUSY:
                    continue
                last_err = e
        return (
            f"Permission denied ({last_err}). Packet capture requires BPF access on macOS.\n"
            "Fix (resets on reboot): sudo chmod o+rw /dev/bpf*\n"
            "Permanent fix: install Wireshark (sets BPF permissions via ChmodBPF LaunchDaemon)"
        )

    elif _sys == "Linux":
        try:
            import socket as _sock
            s = _sock.socket(_sock.AF_PACKET, _sock.SOCK_RAW, _sock.ntohs(3))
            s.close()
            return None
        except PermissionError:
            return (
                "Permission denied — packet capture requires root or CAP_NET_RAW.\n"
                "Fix: sudo setcap cap_net_raw+eip /usr/bin/cernis-backend"
            )
        except Exception:
            return None  # inconclusive, let scapy try

    return None  # unknown OS, let scapy try


# ── Start / Stop ─────────────────────────────────────────────

async def start_capture(interface: str = None, bpf_filter: str = "",
                         max_packets: int = 10000) -> dict:
    """Start background packet capture using AsyncSniffer. Returns {ok, error}."""
    global _capture_running, _capture_packets, _capture_stats
    global _raw_packets, _pcap_file, _capture_error, _sniffer

    if not HAS_SCAPY:
        return {"ok": False, "error": "scapy not installed"}
    if _capture_running:
        return {"ok": True, "error": ""}

    # Resolve Windows adapter name to Scapy interface name
    if interface and platform.system() == "Windows":
        interface = _resolve_windows_iface(interface)

    # Permission check
    perm_err = _check_capture_permission()
    if perm_err:
        return {"ok": False, "error": perm_err}

    # Reset state
    _capture_error = ""
    _capture_packets = []
    _raw_packets = []
    _capture_stats = CaptureStats()
    _pcap_file = os.path.join(tempfile.gettempdir(), f"cernis_capture_{int(time.time())}.pcap")

    # Build sniff kwargs
    kwargs = {"prn": _handle_packet, "store": 0, "count": max_packets}
    if interface:
        kwargs["iface"] = interface
    if bpf_filter:
        kwargs["filter"] = bpf_filter

    # Use AsyncSniffer — gives us .stop() and synchronous error on .start()
    try:
        _sniffer = AsyncSniffer(**kwargs)
        _sniffer.start()
        # Give the sniffer thread a moment to fail (permission errors happen instantly)
        time.sleep(0.8)
        # Check if thread is actually alive (.running is unreliable — stays True after crash)
        thread_alive = (hasattr(_sniffer, 'thread') and _sniffer.thread
                        and _sniffer.thread.is_alive())
        if not thread_alive:
            # Sniffer thread died immediately — extract error from thread result
            err = ""
            try:
                # AsyncSniffer stores exception in .exception on some versions
                if hasattr(_sniffer, 'exception') and _sniffer.exception:
                    err = str(_sniffer.exception)
            except Exception:
                pass
            _sniffer = None
            if not err:
                if platform.system() == "Darwin":
                    err = ("Capture failed — BPF device not accessible.\n"
                           "Fix (resets on reboot): sudo chmod o+rw /dev/bpf*\n"
                           "Permanent fix: install Wireshark (ChmodBPF LaunchDaemon)")
                else:
                    err = ("Capture failed — raw socket not accessible.\n"
                           "Fix: sudo setcap cap_net_raw+eip /usr/bin/cernis-backend")
            return {"ok": False, "error": err}
    except Exception as e:
        _sniffer = None
        return {"ok": False, "error": f"Capture failed: {e}"}

    _capture_running = True
    return {"ok": True, "error": ""}


def stop_capture():
    global _capture_running, _sniffer
    _capture_running = False

    if _sniffer:
        try:
            _sniffer.stop(join=True)
        except Exception:
            pass
        _sniffer = None

    # Write pcap file so download is available right after stop
    _save_pcap()


def _save_pcap():
    """Write captured packets to pcap file."""
    if _raw_packets and _pcap_file:
        try:
            wrpcap(_pcap_file, _raw_packets)
        except Exception:
            pass


def get_capture_status() -> dict:
    global _capture_running, _sniffer
    # Sync _capture_running with actual sniffer thread state
    if _capture_running and _sniffer:
        thread_alive = (hasattr(_sniffer, 'thread') and _sniffer.thread
                        and _sniffer.thread.is_alive())
        if not thread_alive:
            _capture_running = False
            _save_pcap()
    return {
        "running": _capture_running,
        "packets": len(_capture_packets),
        "stats": _capture_stats.to_dict(),
        "pcap_available": bool(_pcap_file and os.path.exists(_pcap_file or "")),
        "pcap_path": _pcap_file,
        "error": _capture_error,
    }


def get_recent_packets(limit: int = 100) -> list[dict]:
    return [p.to_dict() for p in _capture_packets[-limit:]]


def get_pcap_path() -> Optional[str]:
    if _pcap_file and os.path.exists(_pcap_file):
        return _pcap_file
    return None


def check_available() -> bool:
    return HAS_SCAPY
