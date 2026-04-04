"""
CERNIS PRO IPv6 Full Support
- NDP (Neighbor Discovery Protocol) — discovers link-local hosts
- ICMPv6 ping for IPv6 hosts
- DHCPv6 prefix detection
- IPv6 address classification
"""
import asyncio
import socket
import subprocess
import re
import platform
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class IPv6Host:
    ipv6: str
    mac: str          = ""
    ipv6_type: str    = ""   # "link-local" | "global" | "ula"
    is_alive: bool    = False
    rtt_ms: float     = -1.0
    hostname: str     = ""

    def to_dict(self):
        return asdict(self)


def classify_ipv6(addr: str) -> str:
    """Classify an IPv6 address type."""
    a = addr.lower()
    if a.startswith("fe80"):        return "link-local"
    if a.startswith("fc") or a.startswith("fd"): return "ula"
    if a.startswith("2") or a.startswith("3"):   return "global"
    if a == "::1":                  return "loopback"
    return "other"


def mac_from_eui64(ipv6: str) -> str:
    """Extract MAC address from EUI-64 encoded IPv6 link-local address."""
    # fe80::xxxx:xxff:fexx:xxxx
    m = re.search(r"fe80::([0-9a-f:]+)", ipv6.lower())
    if not m:
        return ""
    parts = m.group(1).split(":")
    if len(parts) != 4:
        return ""
    try:
        b = []
        for p in parts:
            p = p.zfill(4)
            b.append(p[:2])
            b.append(p[2:])
        if b[3].lower() == "ff" and b[4].lower() == "fe":
            # EUI-64: flip bit 6 of first byte
            first = int(b[0], 16) ^ 0x02
            return f"{first:02x}:{b[1]}:{b[2]}:{b[5]}:{b[6]}:{b[7]}"
    except Exception:
        pass
    return ""


async def ping6(addr: str, interface: str = "", timeout: float = 1.0) -> tuple[bool, float]:
    """Ping an IPv6 address. Returns (alive, rtt_ms)."""
    sys = platform.system()
    if sys == "Darwin":
        cmd = ["ping6", "-c", "1", "-W", str(int(timeout * 1000)), "-t", "2"]
        if interface:
            cmd += ["-I", interface]
        cmd.append(addr)
    elif sys == "Windows":
        cmd = ["ping", "-6", "-n", "1", "-w", str(int(timeout * 1000)), addr]
    else:
        cmd = ["ping6", "-c", "1", "-W", str(int(timeout))]
        if interface:
            cmd += ["-I", interface]
        cmd.append(addr)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 1)
        output = stdout.decode("utf-8", errors="replace")
        alive = proc.returncode == 0
        rtt = -1.0
        m = re.search(r"time[=<]([\d.]+)\s*ms", output)
        if m:
            rtt = float(m.group(1))
        return alive, rtt
    except Exception:
        return False, -1.0


def get_ndp_table() -> dict[str, str]:
    """Read NDP neighbor cache. Returns {ipv6: mac}."""
    sys = platform.system()
    ndp: dict[str, str] = {}

    try:
        if sys == "Darwin":
            out = subprocess.run(["ndp", "-a"], capture_output=True, encoding="utf-8", errors="replace", timeout=3).stdout or ""
            for line in out.splitlines():
                m = re.match(r"^([\da-f:]+(?:%\w+)?)\s+([0-9a-f:]{17})", line, re.IGNORECASE)
                if m:
                    ip = m.group(1).split("%")[0]
                    mac = m.group(2).lower()
                    ndp[ip] = mac
        elif sys == "Windows":
            out = subprocess.run(["netsh", "interface", "ipv6", "show", "neighbors"], capture_output=True, encoding="utf-8", errors="replace", timeout=5).stdout or ""
            for line in out.splitlines():
                m = re.match(r"([\da-f:]+(?:%\d+)?)\s+([0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2})", line, re.IGNORECASE)
                if m:
                    ndp[m.group(1).split("%")[0]] = m.group(2).replace("-",":").lower()
        else:
            out = subprocess.run(["ip", "-6", "neigh"], capture_output=True, encoding="utf-8", errors="replace", timeout=3).stdout or ""
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 5:
                    ip = parts[0]
                    mac_idx = parts.index("lladdr") + 1 if "lladdr" in parts else -1
                    if mac_idx > 0 and mac_idx < len(parts):
                        ndp[ip] = parts[mac_idx].lower()
    except Exception:
        pass

    return ndp


async def discover_link_local(interface: str, timeout: float = 3.0) -> list[IPv6Host]:
    """
    Discover IPv6 link-local hosts using multicast ping.
    Pings ff02::1 (all-nodes multicast) on the interface.
    """
    hosts = []
    sys = platform.system()

    # Multicast ping to all-nodes
    try:
        cmd = ["ping6", "-c", "3", "-W", "1000", "-I", interface, "ff02::1%"+interface] \
              if sys == "Darwin" else \
              ["ping6", "-c", "3", "-W", "1", "-I", interface, "ff02::1"]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.communicate(), timeout=timeout + 1)
    except Exception:
        pass

    # Now read NDP table
    await asyncio.sleep(0.5)
    ndp = get_ndp_table()

    for ip, mac in ndp.items():
        ip_type = classify_ipv6(ip)
        if ip_type not in ("link-local", "ula", "global"):
            continue
        # Try to get hostname
        hostname = ""
        try:
            hostname = socket.gethostbyaddr(ip + f"%{interface}" if ip_type == "link-local" else ip)[0]
        except Exception:
            pass

        host = IPv6Host(
            ipv6=ip,
            mac=mac,
            ipv6_type=ip_type,
            is_alive=True,
            hostname=hostname,
        )
        hosts.append(host)

    return hosts


async def scan_ipv6_subnet(cidr6: str, max_concurrent: int = 32,
                            timeout: float = 1.0) -> list[IPv6Host]:
    """
    Scan an IPv6 subnet (e.g. 2001:db8::/120 — small subnets only).
    For large subnets, use discover_link_local instead.
    """
    import ipaddress
    try:
        net = ipaddress.ip_network(cidr6, strict=False)
    except ValueError:
        return []

    if net.num_addresses > 65536:
        return []  # Too large for direct scan

    hosts = list(net.hosts())
    results = []
    semaphore = asyncio.Semaphore(max_concurrent)

    async def _scan(addr):
        async with semaphore:
            alive, rtt = await ping6(str(addr), timeout=timeout)
            if alive:
                results.append(IPv6Host(
                    ipv6=str(addr),
                    ipv6_type=classify_ipv6(str(addr)),
                    is_alive=True,
                    rtt_ms=rtt,
                ))

    await asyncio.gather(*[_scan(h) for h in hosts])
    return results


def enrich_with_ipv6(hosts: list[dict]) -> list[dict]:
    """
    Enrich existing scan results with IPv6 addresses from NDP table.
    Matches by MAC address.
    """
    ndp = get_ndp_table()
    # Build MAC -> IPv6 mapping
    mac_to_ip6: dict[str, list[str]] = {}
    for ip6, mac in ndp.items():
        mac_upper = mac.upper()
        if mac_upper not in mac_to_ip6:
            mac_to_ip6[mac_upper] = []
        mac_to_ip6[mac_upper].append(ip6)

    for host in hosts:
        mac = (host.get("mac") or "").upper()
        if mac in mac_to_ip6:
            addrs = mac_to_ip6[mac]
            # Prefer global, then ULA, then link-local
            global_addrs = [a for a in addrs if classify_ipv6(a) == "global"]
            ula_addrs    = [a for a in addrs if classify_ipv6(a) == "ula"]
            ll_addrs     = [a for a in addrs if classify_ipv6(a) == "link-local"]
            best = (global_addrs or ula_addrs or ll_addrs)
            if best:
                host["ipv6"] = best[0]
                host["ipv6_all"] = addrs
    return hosts
