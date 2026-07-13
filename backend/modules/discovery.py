"""Host discovery via ICMP ping and ARP."""
import asyncio
import subprocess
import platform
import os
import re
import ipaddress
from dataclasses import dataclass

# Externe Kommandos (ping, arp, ip neigh) werden mit erzwungener C-Locale gestartet,
# weil lokalisierte Ausgaben (z.B. Zeit= statt time=) das Parsing sonst still
# scheitern lassen.
_C_LOCALE_ENV = {**os.environ, "LC_ALL": "C", "LANG": "C"}


@dataclass
class DiscoveredHost:
    ip: str
    mac: str = ""
    rtt_ms: float = -1.0
    is_alive: bool   = False
    from_fritz: bool = False
    source: str      = "ping"


async def ping_host(ip: str, timeout: float = 1.0) -> DiscoveredHost:
    """Ping a single host, return result."""
    system = platform.system()
    if system == "Windows":
        # Windows: nativer ICMP-Echo statt ping.exe. Lokalisierte ping.exe-Ausgabe
        # (deutsch Zeit<, englisch time=) laesst jeden Regex still scheitern; die
        # native iphlpapi liefert Status/RoundTripTime als Zahl. Der Import steht
        # im Windows-Zweig (auf Nicht-Windows nie erreicht).
        from infrastructure.icmp_windows import icmp_echo

        alive, rtt = await icmp_echo(ip, timeout)
        return DiscoveredHost(ip=ip, rtt_ms=rtt, is_alive=alive, source="ping")

    if system == "Darwin":
        cmd = ["ping", "-c", "1", "-W", str(int(timeout * 1000)), "-t", "1", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(timeout)), ip]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            env=_C_LOCALE_ENV,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 0.5)
        output = stdout.decode("utf-8", errors="replace")
        alive = proc.returncode == 0

        rtt = -1.0
        m = re.search(r"(?:(?:time|Zeit)([=<])([\d.]+)\s*ms|(?:Average|Mittelwert)\s*=\s*([\d.]+)\s*ms)", output, re.IGNORECASE)
        if m:
            if m.group(3):
                # Average/Mittelwert line
                rtt = float(m.group(3))
            elif m.group(1) == "<":
                # "Zeit<1ms" means sub-millisecond
                rtt = float(m.group(2)) * 0.5
            else:
                rtt = float(m.group(2))

        return DiscoveredHost(ip=ip, is_alive=alive, rtt_ms=rtt)
    except (asyncio.TimeoutError, Exception):
        return DiscoveredHost(ip=ip, is_alive=False)


def get_arp_table() -> dict[str, str]:
    """Read the system ARP cache: {ip: mac}."""
    system = platform.system()
    arp_map = {}

    if system == "Darwin":
        out = subprocess.run(["arp", "-a"], capture_output=True, encoding="utf-8", errors="replace", env=_C_LOCALE_ENV).stdout or ""
        for line in out.splitlines():
            m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-f:]{17})", line)
            if m:
                arp_map[m.group(1)] = m.group(2)
    elif system == "Windows":
        out = subprocess.run(["arp", "-a"], capture_output=True, encoding="utf-8", errors="replace", env=_C_LOCALE_ENV).stdout or ""
        for line in out.splitlines():
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2})", line, re.IGNORECASE)
            if m:
                arp_map[m.group(1)] = m.group(2).replace("-", ":").lower()
    elif system == "Linux":
        try:
            out = subprocess.run(["ip", "neigh"], capture_output=True, encoding="utf-8", errors="replace", env=_C_LOCALE_ENV).stdout or ""
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 5 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[0]):
                    mac = parts[4] if parts[4] != "FAILED" else ""
                    if mac:
                        arp_map[parts[0]] = mac
        except Exception:
            pass
    return arp_map


async def discover_subnet(
    cidr: str,
    max_concurrent: int = 64,
    timeout: float = 1.0,
    progress_cb=None,
) -> list[DiscoveredHost]:
    """Ping all hosts in a subnet concurrently."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return []

    hosts = list(network.hosts())
    total = len(hosts)
    results = []
    semaphore = asyncio.Semaphore(max_concurrent)
    completed = 0

    async def _scan_one(ip_obj):
        nonlocal completed
        async with semaphore:
            host = await ping_host(str(ip_obj), timeout=timeout)
            completed += 1
            if progress_cb:
                await progress_cb(completed, total, host)
            return host

    tasks = [_scan_one(ip) for ip in hosts]
    results = await asyncio.gather(*tasks)

    # Enrich with ARP
    arp = get_arp_table()
    for host in results:
        if host.ip in arp:
            host.mac = arp[host.ip]

    return [h for h in results if h.is_alive]
