"""Network interface discovery and information."""
import socket
import subprocess
import platform
import re
from dataclasses import dataclass, field, asdict
from typing import Optional
import ipaddress


@dataclass
class InterfaceInfo:
    name: str
    ipv4: str = ""
    ipv4_prefix: int = 24
    ipv6_link_local: str = ""
    ipv6_global: str = ""
    mac: str = ""
    gateway: str = ""
    mtu: int = 1500
    is_up: bool = True
    is_loopback: bool = False

    def to_dict(self):
        d = asdict(self)
        # compute network CIDR (not host CIDR) for subnet scanning
        if self.ipv4:
            d["subnet_cidr"] = f"{self.ipv4}/{self.ipv4_prefix}"
            try:
                # strict=False computes the network address (e.g. 172.18.0.0/22 from 172.18.1.152/22)
                net = ipaddress.ip_interface(d["subnet_cidr"]).network
                d["network"]       = str(net)
                d["network_cidr"]  = str(net)   # e.g. "172.18.0.0/22" — use this for scanning
                d["broadcast"]     = str(net.broadcast_address)
                d["host_count"]    = net.num_addresses - 2
            except Exception:
                d["network"]      = ""
                d["network_cidr"] = d["subnet_cidr"]
                d["broadcast"]    = ""
                d["host_count"]   = 0
        return d


def _run(cmd: list[str]) -> str:
    try:
        result = subprocess.run(
            cmd, capture_output=True, timeout=5,
            encoding="utf-8", errors="replace"
        )
        return result.stdout or ""
    except Exception:
        return ""


def _get_gateway_macos() -> dict[str, str]:
    """Returns {interface: gateway} mapping on macOS."""
    out = _run(["netstat", "-rn"])
    gateways = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0] == "default":
            iface = parts[-1]
            gw = parts[1]
            if re.match(r"\d+\.\d+\.\d+\.\d+", gw):
                gateways[iface] = gw
    return gateways


def _get_gateway_linux() -> dict[str, str]:
    """Returns {interface: gateway} mapping on Linux."""
    out = _run(["ip", "route"])
    gateways = {}
    for line in out.splitlines():
        if line.startswith("default"):
            m = re.search(r"via (\S+).*dev (\S+)", line)
            if m:
                gateways[m.group(2)] = m.group(1)
    return gateways


def _netmask_to_prefix(netmask: str) -> int:
    try:
        return sum(bin(int(o)).count("1") for o in netmask.split("."))
    except Exception:
        return 24


def get_interfaces() -> list[InterfaceInfo]:
    """Discover all network interfaces with full details."""
    system = platform.system()
    interfaces: dict[str, InterfaceInfo] = {}

    if system == "Darwin":
        # macOS: use ifconfig
        out = _run(["ifconfig"])
        gateways = _get_gateway_macos()
        current = None
        for line in out.splitlines():
            # New interface block
            iface_m = re.match(r"^(\w[\w\d]+):", line)
            if iface_m:
                current = iface_m.group(1)
                interfaces[current] = InterfaceInfo(
                    name=current,
                    is_loopback=(current == "lo0"),
                    gateway=gateways.get(current, ""),
                )
                if "LOOPBACK" in line:
                    interfaces[current].is_loopback = True
                if "<" in line and "UP" not in line:
                    interfaces[current].is_up = False
            elif current:
                iface = interfaces[current]
                # IPv4
                m = re.match(r"\s+inet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-f]+)", line)
                if m:
                    iface.ipv4 = m.group(1)
                    # Convert hex netmask to prefix length
                    mask_hex = int(m.group(2), 16)
                    iface.ipv4_prefix = bin(mask_hex).count("1")
                # IPv6 link-local
                m6 = re.match(r"\s+inet6 (fe80::[^\s]+)%", line, re.IGNORECASE)
                if m6:
                    iface.ipv6_link_local = m6.group(1)
                # IPv6 global
                m6g = re.match(r"\s+inet6 ([0-9a-f:]{10,})(?:\s|$)", line, re.IGNORECASE)
                if m6g and not m6g.group(1).lower().startswith("fe80"):
                    iface.ipv6_global = m6g.group(1)
                # MAC
                m_mac = re.match(r"\s+ether ([0-9a-f:]{17})", line)
                if m_mac:
                    iface.mac = m_mac.group(1)
                # MTU
                m_mtu = re.search(r"mtu (\d+)", line)
                if m_mtu:
                    iface.mtu = int(m_mtu.group(1))

    elif system == "Linux":
        # Linux: use ip addr
        out = _run(["ip", "-o", "addr"])
        gateways = _get_gateway_linux()
        seen = set()
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            iface_name = parts[1]
            if iface_name not in interfaces:
                interfaces[iface_name] = InterfaceInfo(
                    name=iface_name,
                    is_loopback=(iface_name == "lo"),
                    gateway=gateways.get(iface_name, ""),
                )
            iface = interfaces[iface_name]
            family = parts[2]
            addr = parts[3]
            if family == "inet" and "/" in addr:
                ip, prefix = addr.split("/")
                iface.ipv4 = ip
                iface.ipv4_prefix = int(prefix)
            elif family == "inet6":
                ip6 = addr.split("/")[0]
                if ip6.lower().startswith("fe80"):
                    iface.ipv6_link_local = ip6
                else:
                    iface.ipv6_global = ip6

        # Get MACs
        out_link = _run(["ip", "link"])
        current = None
        for line in out_link.splitlines():
            m = re.match(r"^\d+: (\S+?)[@:]", line)
            if m:
                current = m.group(1)
            elif current and current in interfaces:
                m_mac = re.search(r"link/ether ([0-9a-f:]{17})", line)
                if m_mac:
                    interfaces[current].mac = m_mac.group(1)

    elif system == "Windows":
        out = _run(["ipconfig", "/all"])
        gw_raw = {}
        r_out = _run(["route", "print", "0.0.0.0"]) or ""
        for line in r_out.splitlines():
            m = re.match(r"\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)", line)
            if m:
                gw_raw[m.group(2)] = m.group(1)
        current = None
        for line in out.splitlines():
            adapter_m = re.match(r"^(\S[^:]+):\s*$", line)
            if adapter_m:
                raw = adapter_m.group(1).strip()
                if any(k in raw for k in ["Windows IP", "Tunnel", "PPP", "Loopback"]):
                    current = None; continue
                current = raw
                interfaces[current] = InterfaceInfo(name=current, is_loopback=False)
                continue
            if current is None or current not in interfaces: continue
            iface = interfaces[current]
            # MAC: EN "Physical Address" / DE "Physische Adresse"
            m = re.search(r"(?:Physical Address|Physische Adresse)[.\s]+:\s+([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})", line, re.I)
            if m: iface.mac = m.group(1).replace("-",":").lower()
            # IPv4: EN "IPv4 Address" / DE "IPv4-Adresse"
            m = re.search(r"(?:IPv4 Address|IPv4-Adresse)[.\s]+:\s+([\d.]+)", line, re.I)
            if m: iface.ipv4 = re.sub(r"\(.*\)", "", m.group(1)).strip()
            # Subnet: EN "Subnet Mask" / DE "Subnetzmaske"
            m = re.search(r"(?:Subnet Mask|Subnetzmaske)[.\s]+:\s+([\d.]+)", line, re.I)
            if m: iface.ipv4_prefix = _netmask_to_prefix(m.group(1))
            # Gateway: EN "Default Gateway" / DE "Standardgateway"
            m = re.search(r"(?:Default Gateway|Standardgateway)[.\s]+:\s+([\d.]+)", line, re.I)
            if m: iface.gateway = m.group(1)
            # Link-local IPv6: EN / DE "Verbindungslokale IPv6-Adresse"
            m = re.search(r"(?:Link-local IPv6 Address|Verbindungslokale IPv6-Adresse)[.\s]+:\s+(fe80::[^\s(]+)", line, re.I)
            if m: iface.ipv6_link_local = m.group(1)
            # Global IPv6: EN "IPv6 Address" / DE "IPv6-Adresse"
            m = re.search(r"(?:IPv6 Address|IPv6-Adresse)[.\s]+:\s+([0-9a-f:]{10,})", line, re.I)
            if m and not m.group(1).lower().startswith("fe80"): iface.ipv6_global = m.group(1)
            # Media state: EN / DE "Medien getrennt"
            if any(x in line for x in ["Media disconnected", "Medien getrennt", "nicht verbunden"]): iface.is_up = False
        for iface in interfaces.values():
            if not iface.gateway and iface.ipv4 in gw_raw:
                iface.gateway = gw_raw[iface.ipv4]

    result = []
    for iface in interfaces.values():
        if iface.is_loopback:
            continue
        if not iface.ipv4 and not iface.ipv6_link_local:
            continue
        result.append(iface)

    return result
