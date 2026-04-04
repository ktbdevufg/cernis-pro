"""
CERNIS PRO Network Tools
Traceroute, DNS Lookup, Bandwidth Monitor, Rogue DHCP Detector.
"""
import asyncio
import subprocess
import socket
import platform
import re
import time
import psutil
from dataclasses import dataclass, field, asdict
from typing import Optional

_SYSTEM = platform.system()

try:
    import dns.resolver
    import dns.reversename
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


# ── Traceroute ────────────────────────────────────────────────

@dataclass
class TracerouteHop:
    hop: int
    ip: str
    hostname: str
    rtt_ms: float
    timeout: bool = False


async def traceroute(target: str, max_hops: int = 30) -> list[TracerouteHop]:
    """Run traceroute to target, return list of hops. Cross-platform."""
    if _SYSTEM == "Windows":
        cmd = ["tracert", "-d", "-h", str(max_hops), "-w", "1000", target]
    elif _SYSTEM == "Darwin":
        cmd = ["traceroute", "-m", str(max_hops), "-w", "1", "-q", "1", target]
    else:
        # Use full path — PyInstaller process may not inherit full user PATH
        import shutil as _shutil
        _tr = (
            _shutil.which("traceroute") or
            "/usr/sbin/traceroute" if __import__("os").path.exists("/usr/sbin/traceroute") else
            "/usr/bin/traceroute"
        )
        cmd = [_tr, "-m", str(max_hops), "-w", "1", "-q", "1", "-n", target]

    hops = []
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=90)
        output = stdout.decode("utf-8", errors="replace")

        if _SYSTEM == "Windows":
            # Parse Windows tracert output
            # Format: "  1    <1 ms    <1 ms    <1 ms  192.168.1.1"
            for line in output.splitlines():
                if re.search(r"\*\s+\*\s+\*", line):
                    m = re.match(r"\s*(\d+)", line)
                    if m:
                        hops.append(TracerouteHop(hop=int(m.group(1)), ip="*", hostname="*", rtt_ms=-1, timeout=True))
                    continue
                m = re.match(r"\s*(\d+)\s+(?:<?(\d+)\s*ms|[*])\s+(?:<?\d+\s*ms|[*])\s+(?:<?\d+\s*ms|[*])\s+(\d+\.\d+\.\d+\.\d+)", line)
                if m:
                    rtt = float(m.group(2)) if m.group(2) else 0.5
                    ip = m.group(3)
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except Exception:
                        hostname = ip
                    hops.append(TracerouteHop(hop=int(m.group(1)), ip=ip, hostname=hostname, rtt_ms=rtt))
        else:
            # Linux/macOS traceroute output formats:
            # With -n:    "  1  172.18.0.1  0.653 ms"
            # Without -n: "  1  router.local (172.18.0.1)  0.653 ms"
            # Timeout:    "  1  * * *"
            for line in output.splitlines():
                # Timeout hop
                if re.match(r"^\s*\d+\s+\*", line):
                    m2 = re.match(r"^\s*(\d+)", line)
                    if m2:
                        hops.append(TracerouteHop(hop=int(m2.group(1)), ip="*", hostname="*",
                                                  rtt_ms=-1, timeout=True))
                    continue
                # Format with hostname: "  1  router.local (1.2.3.4)  1.0 ms"
                m = re.match(r"^\s*(\d+)\s+(\S+)\s+\((\S+)\)\s+([\d.]+)\s*ms", line)
                if m:
                    hops.append(TracerouteHop(
                        hop=int(m.group(1)), hostname=m.group(2),
                        ip=m.group(3), rtt_ms=float(m.group(4))
                    ))
                    continue
                # Format without hostname (-n): "  1  1.2.3.4  1.0 ms"
                m = re.match(r"^\s*(\d+)\s+(\d[\d.]+)\s+([\d.]+)\s*ms", line)
                if m:
                    ip = m.group(2)
                    hops.append(TracerouteHop(
                        hop=int(m.group(1)), ip=ip,
                        hostname=ip, rtt_ms=float(m.group(3))
                    ))
    except asyncio.TimeoutError:
        pass
    except Exception as e:
        pass

    return hops


# ── DNS Lookup ────────────────────────────────────────────────

@dataclass
class DNSResult:
    query: str
    record_type: str
    records: list = field(default_factory=list)
    error: str = ""

    def to_dict(self):
        return asdict(self)


async def dns_lookup(query: str, record_types: list[str] = None) -> list[DNSResult]:
    """Perform DNS lookups for multiple record types."""
    if record_types is None:
        record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"]

    results = []
    loop = asyncio.get_event_loop()

    # Check if it's an IP (reverse lookup)
    is_ip = re.match(r"^\d+\.\d+\.\d+\.\d+$", query)

    if is_ip:
        result = DNSResult(query=query, record_type="PTR")
        try:
            if HAS_DNSPYTHON:
                rev = dns.reversename.from_address(query)
                answers = await loop.run_in_executor(None,
                    lambda: dns.resolver.resolve(str(rev), "PTR"))
                result.records = [str(r) for r in answers]
            else:
                host = await loop.run_in_executor(None,
                    lambda: socket.gethostbyaddr(query))
                result.records = [host[0]]
        except Exception as e:
            result.error = str(e)
        return [result]

    for rtype in record_types:
        result = DNSResult(query=query, record_type=rtype)
        try:
            if HAS_DNSPYTHON:
                answers = await loop.run_in_executor(None,
                    lambda rt=rtype: dns.resolver.resolve(query, rt))
                result.records = [str(r) for r in answers]
            else:
                if rtype == "A":
                    infos = await loop.run_in_executor(None,
                        lambda: socket.getaddrinfo(query, None, socket.AF_INET))
                    result.records = list({i[4][0] for i in infos})
                elif rtype == "AAAA":
                    infos = await loop.run_in_executor(None,
                        lambda: socket.getaddrinfo(query, None, socket.AF_INET6))
                    result.records = list({i[4][0] for i in infos})
                else:
                    result.error = "dnspython not installed"
        except Exception as e:
            err = str(e)
            if "NoAnswer" not in err and "NXDOMAIN" not in err:
                result.error = err
        if result.records or result.error:
            results.append(result)

    return results


# ── Bandwidth Monitor ─────────────────────────────────────────

@dataclass
class BandwidthSample:
    interface: str
    timestamp: float
    bytes_sent: int
    bytes_recv: int
    mbps_sent: float
    mbps_recv: float
    packets_sent: int
    packets_recv: int


_bw_last: dict = {}  # interface -> (timestamp, bytes_sent, bytes_recv)


def get_bandwidth_sample(interface: str = None) -> list[BandwidthSample]:
    """Get current bandwidth usage per interface."""
    samples = []
    now = time.time()

    try:
        counters = psutil.net_io_counters(pernic=True)
    except Exception:
        return []

    for iface, stats in counters.items():
        if interface and iface != interface:
            continue
        if iface.startswith("lo"):
            continue

        prev = _bw_last.get(iface)
        mbps_sent = mbps_recv = 0.0

        if prev:
            dt = now - prev[0]
            if dt > 0:
                mbps_sent = (stats.bytes_sent - prev[1]) * 8 / dt / 1_000_000
                mbps_recv = (stats.bytes_recv - prev[2]) * 8 / dt / 1_000_000
                mbps_sent = max(0, round(mbps_sent, 3))
                mbps_recv = max(0, round(mbps_recv, 3))

        _bw_last[iface] = (now, stats.bytes_sent, stats.bytes_recv)

        samples.append(BandwidthSample(
            interface=iface,
            timestamp=now,
            bytes_sent=stats.bytes_sent,
            bytes_recv=stats.bytes_recv,
            mbps_sent=mbps_sent,
            mbps_recv=mbps_recv,
            packets_sent=stats.packets_sent,
            packets_recv=stats.packets_recv,
        ))

    return samples


def get_all_interfaces_bandwidth() -> list[dict]:
    return [asdict(s) for s in get_bandwidth_sample()]


# ── Rogue DHCP Detector ───────────────────────────────────────

@dataclass
class DHCPServer:
    ip: str
    mac: str = ""
    is_known: bool = False
    is_rogue: bool = False


async def detect_rogue_dhcp(known_gateway: str = None, timeout: float = 5.0) -> list[DHCPServer]:
    """
    Detect DHCP servers by sending a DHCP Discover and collecting responses.
    Requires scapy (optional) or falls back to reading DHCP leases.
    Returns list of responding DHCP servers.
    """
    servers = []

    try:
        # Try scapy-based detection first
        from scapy.all import (
            Ether, IP, UDP, BOOTP, DHCP,
            sendp, sniff, conf, get_if_hwaddr
        )

        conf.verb = 0
        iface = conf.iface

        # Build DHCP Discover
        mac = get_if_hwaddr(iface).replace(":", "")
        mac_bytes = bytes.fromhex(mac)

        pkt = (
            Ether(dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac_bytes, xid=0xdeadbeef) /
            DHCP(options=[("message-type", "discover"), "end"])
        )

        found_servers = set()

        def handle_pkt(p):
            if p.haslayer(BOOTP) and p[BOOTP].op == 2:  # BOOTREPLY
                server_ip = p[IP].src
                server_mac = p[Ether].src
                found_servers.add((server_ip, server_mac))

        # Send discover and capture responses
        import threading
        stop_event = threading.Event()

        def send_pkt():
            time.sleep(0.5)
            sendp(pkt, iface=iface, verbose=0)

        threading.Thread(target=send_pkt, daemon=True).start()

        sniff(iface=iface, prn=handle_pkt, timeout=timeout,
              filter="udp and port 68", store=0)

        for ip, mac in found_servers:
            is_known = (known_gateway and ip == known_gateway)
            servers.append(DHCPServer(
                ip=ip, mac=mac,
                is_known=is_known,
                is_rogue=not is_known and bool(known_gateway),
            ))

    except ImportError:
        # Scapy not available — check system DHCP lease file as fallback
        servers = _check_dhcp_leases(known_gateway)
    except Exception as e:
        servers = _check_dhcp_leases(known_gateway)

    return servers


def _check_dhcp_leases(known_gateway: str = None) -> list[DHCPServer]:
    """Fallback: read DHCP lease files to find configured server."""
    servers = []
    lease_files = [
        "/var/db/dhclient.leases",
        "/var/lib/dhclient/dhclient.leases",
        "/tmp/dhclient.leases",
    ]
    # macOS: check via ipconfig
    try:
        import subprocess
        out = subprocess.run(["ipconfig", "getpacket", "en0"],
                             capture_output=True, encoding="utf-8", errors="replace", timeout=3).stdout
        m = re.search(r"server_identifier.*?=\s*{(.+?)}", out, re.DOTALL)
        if m:
            ips = re.findall(r"\d+\.\d+\.\d+\.\d+", m.group(1))
            for ip in ips:
                is_known = known_gateway and ip == known_gateway
                servers.append(DHCPServer(ip=ip, is_known=bool(is_known),
                                          is_rogue=not is_known and bool(known_gateway)))
    except Exception:
        pass

    return servers


def get_scan_profiles_default() -> list[dict]:
    """Return built-in scan profiles."""
    return [
        {
            "id": "quick",
            "name": "Quick Scan",
            "icon": "⚡",
            "description": "Fast ping-only discovery, no port scan",
            "config": {
                "port_scan": False, "mdns_scan": False, "ssdp_scan": False,
                "resolve_hostnames": False, "ping_timeout": 0.5,
                "max_concurrent_ping": 128,
            }
        },
        {
            "id": "standard",
            "name": "Standard Scan",
            "icon": "🔍",
            "description": "Ping + top 100 ports + mDNS",
            "config": {
                "port_scan": True, "port_mode": "socket", "mdns_scan": True,
                "ssdp_scan": True, "resolve_hostnames": True,
                "ping_timeout": 1.5, "max_concurrent_ping": 64,
            }
        },
        {
            "id": "deep",
            "name": "Deep Scan",
            "icon": "🔬",
            "description": "Full port scan with nmap + OS detection",
            "config": {
                "port_scan": True, "port_mode": "nmap", "mdns_scan": True,
                "ssdp_scan": True, "resolve_hostnames": True, "smb_scan": True,
                "ping_timeout": 1.5, "max_concurrent_ping": 32,
            }
        },
        {
            "id": "iot",
            "name": "IoT Scan",
            "icon": "📡",
            "description": "Focus on IoT ports + mDNS/NDI/SSDP",
            "config": {
                "port_scan": True, "port_mode": "socket",
                "mdns_scan": True, "mdns_duration": 10.0,
                "ssdp_scan": True, "resolve_hostnames": True,
                "ping_timeout": 1.5, "max_concurrent_ping": 64,
                "custom_ports": [80, 443, 554, 1883, 5353, 5900, 5960,
                                  7788, 8080, 8443, 8883, 8888, 9000],
            }
        },
        {
            "id": "security",
            "name": "Security Scan",
            "icon": "🛡",
            "description": "CVE-relevant ports, SMB, RDP, Telnet detection",
            "config": {
                "port_scan": True, "port_mode": "socket",
                "mdns_scan": False, "ssdp_scan": False,
                "resolve_hostnames": True, "smb_scan": True,
                "ping_timeout": 1.5, "max_concurrent_ping": 64,
                "custom_ports": [21, 22, 23, 25, 53, 80, 110, 135, 139,
                                  143, 389, 443, 445, 3389, 5900, 6379,
                                  27017, 9200],
            }
        },
    ]


# ── HTTP Banner Grabbing ──────────────────────────────────────

import urllib.request

async def grab_http_banner(ip: str, port: int = 80, https: bool = False,
                            timeout: float = 3.0) -> dict:
    """Fetch HTTP banner info: server, title, headers."""
    scheme = "https" if https or port in [443, 8443, 4443] else "http"
    url = f"{scheme}://{ip}:{port}/"
    result = {"url": url, "status": 0, "server": "", "title": "", "powered_by": "", "error": ""}

    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_OPTIONAL

        req = urllib.request.Request(url, headers={"User-Agent": "CERNIS PRO/1.0"})
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
        loop = asyncio.get_event_loop()

        def _fetch():
            try:
                resp = opener.open(req, timeout=timeout)
                return resp
            except urllib.error.HTTPError as e:
                return e
            except Exception as ex:
                raise ex

        resp = await loop.run_in_executor(None, _fetch)
        result["status"] = resp.code if hasattr(resp, 'code') else 200

        headers = resp.headers
        result["server"]     = headers.get("Server", "")
        result["powered_by"] = headers.get("X-Powered-By", "")
        result["x_generator"]= headers.get("X-Generator", "")

        # Try to extract title from body
        try:
            body = resp.read(4096).decode("utf-8", errors="ignore")
            import re
            m = re.search(r"<title[^>]*>([^<]{1,100})</title>", body, re.IGNORECASE)
            if m:
                result["title"] = m.group(1).strip()
        except Exception:
            pass

    except Exception as e:
        result["error"] = str(e)[:80]

    return result


async def grab_banners_for_host(ip: str, ports: list[dict]) -> list[dict]:
    """Grab HTTP banners for all HTTP/HTTPS ports on a host."""
    http_ports = [p for p in ports if p["port"] in
                  [80, 8080, 8081, 8000, 8888, 3000, 4000, 5000, 9000,
                   443, 8443, 4443, 9443, 2083, 2096]
                  or "http" in p.get("service", "").lower()]
    results = []
    for p in http_ports[:6]:
        r = await grab_http_banner(ip, p["port"])
        if r.get("status") or r.get("server") or r.get("title"):
            results.append(r)
    return results
