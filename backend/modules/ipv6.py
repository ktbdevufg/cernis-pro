"""
CERNIS PRO IPv6 Support
- NDP (Neighbor Discovery Protocol) — liest die Nachbartabelle
- MAC-basierte IPv6-Anreicherung bestehender Scan-Ergebnisse
- IPv6 address classification
"""
import subprocess
import os
import re
import platform
from dataclasses import dataclass, asdict

# Externe Kommandos (ndp, netsh, ip -6 neigh) werden mit erzwungener C-Locale
# gestartet, weil lokalisierte Ausgaben (z.B. Zeit= statt time=) das Parsing sonst
# still scheitern lassen.
_C_LOCALE_ENV = {**os.environ, "LC_ALL": "C", "LANG": "C"}


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


def get_ndp_table() -> dict[str, str]:
    """Read NDP neighbor cache. Returns {ipv6: mac}."""
    sys = platform.system()
    ndp: dict[str, str] = {}

    try:
        if sys == "Darwin":
            out = subprocess.run(["ndp", "-a"], capture_output=True, encoding="utf-8", errors="replace", timeout=3, env=_C_LOCALE_ENV).stdout or ""
            for line in out.splitlines():
                m = re.match(r"^([\da-f:]+(?:%\w+)?)\s+([0-9a-f:]{17})", line, re.IGNORECASE)
                if m:
                    ip = m.group(1).split("%")[0]
                    mac = m.group(2).lower()
                    ndp[ip] = mac
        elif sys == "Windows":
            out = subprocess.run(["netsh", "interface", "ipv6", "show", "neighbors"], capture_output=True, encoding="utf-8", errors="replace", timeout=5, env=_C_LOCALE_ENV).stdout or ""
            for line in out.splitlines():
                m = re.match(r"([\da-f:]+(?:%\d+)?)\s+([0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2})", line, re.IGNORECASE)
                if m:
                    ndp[m.group(1).split("%")[0]] = m.group(2).replace("-",":").lower()
        else:
            out = subprocess.run(["ip", "-6", "neigh"], capture_output=True, encoding="utf-8", errors="replace", timeout=3, env=_C_LOCALE_ENV).stdout or ""
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
