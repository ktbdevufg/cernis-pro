"""Port scanning module using asyncio sockets and optional nmap integration."""
import asyncio
import subprocess
import re
import json
import shutil
import platform
import os
from dataclasses import dataclass, field

# nmap wird mit erzwungener C-Locale gestartet, weil lokalisierte Ausgaben (z.B.
# Zeit= statt time=) das Parsing sonst still scheitern lassen.
_C_LOCALE_ENV = {**os.environ, "LC_ALL": "C", "LANG": "C"}


def _find_nmap() -> str:
    """Return path to nmap binary, searching common Windows install dirs."""
    found = shutil.which("nmap")
    if found:
        return found
    if platform.system() == "Windows":
        for d in [
            os.path.join(os.environ.get("ProgramFiles(x86)", ""), "Nmap"),
            os.path.join(os.environ.get("ProgramFiles", ""), "Nmap"),
        ]:
            exe = os.path.join(d, "nmap.exe")
            if os.path.isfile(exe):
                return exe
    return "nmap"


# Common ports with service names
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 119: "NNTP", 123: "NTP",
    135: "MSRPC", 139: "NetBIOS", 143: "IMAP", 161: "SNMP",
    194: "IRC", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    500: "IKE", 514: "Syslog", 515: "LPD", 548: "AFP", 554: "RTSP",
    587: "SMTP-TLS", 631: "IPP", 636: "LDAPS", 993: "IMAPS",
    995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL",
    1723: "PPTP", 2049: "NFS", 2082: "cPanel", 2083: "cPanel-SSL",
    3000: "Dev-HTTP", 3306: "MySQL", 3389: "RDP", 3478: "STUN",
    4000: "Dev-HTTP", 5000: "UPnP", 5001: "Synology", 5060: "SIP",
    5353: "mDNS", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    7000: "Dev", 8080: "HTTP-Alt", 8081: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "Jupyter", 9000: "PHP-FPM", 9100: "Jetdirect", 9200: "Elasticsearch",
    10000: "Webmin", 27017: "MongoDB", 32400: "Plex",
    # NDI
    5960: "NDI", 5961: "NDI", 5962: "NDI", 5963: "NDI",
    7788: "NDI-Discovery",
}

TOP_100_PORTS = list(COMMON_PORTS.keys())


@dataclass
class PortResult:
    port: int
    state: str  # "open" | "closed" | "filtered"
    service: str = ""
    banner: str = ""


@dataclass
class HostPortScan:
    ip: str
    os_guess: str = ""
    os_accuracy: int = 0
    ports: list[PortResult] = field(default_factory=list)
    scan_method: str = "socket"


async def _check_port(ip: str, port: int, timeout: float = 0.5) -> PortResult:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return PortResult(
            port=port,
            state="open",
            service=COMMON_PORTS.get(port, ""),
        )
    except (asyncio.TimeoutError, ConnectionRefusedError):
        return None
    except Exception:
        return None


async def scan_ports_socket(
    ip: str,
    ports: list[int] | None = None,
    max_concurrent: int = 100,
    timeout: float = 0.5,
) -> HostPortScan:
    """Fast async socket-based port scanner."""
    if ports is None:
        ports = TOP_100_PORTS

    semaphore = asyncio.Semaphore(max_concurrent)

    async def _scan(port):
        async with semaphore:
            return await _check_port(ip, port, timeout)

    results = await asyncio.gather(*[_scan(p) for p in ports])
    open_ports = [r for r in results if r is not None]

    return HostPortScan(ip=ip, ports=open_ports, scan_method="socket")


def scan_with_nmap(ip: str, port_spec: str = "T:1-1024,5353,5900,32400") -> HostPortScan:
    """Use nmap for deep scan with OS detection (requires sudo/nmap installed)."""
    result = HostPortScan(ip=ip, scan_method="nmap")

    try:
        cmd = [
            _find_nmap(), "-sV", "-O", "--osscan-guess",
            "-p", port_spec,
            "--open",
            "-T4",
            "--host-timeout", "30s",
            ip
        ]
        out = subprocess.run(cmd, capture_output=True, encoding="utf-8", errors="replace", timeout=45, env=_C_LOCALE_ENV)
        output = out.stdout

        # Parse open ports
        for line in output.splitlines():
            m = re.match(r"^(\d+)/(tcp|udp)\s+(open\S*)\s+(\S.*?)$", line)
            if m:
                port = int(m.group(1))
                state = m.group(3)
                service_raw = m.group(4).strip()
                result.ports.append(PortResult(
                    port=port,
                    state="open",
                    service=service_raw[:80],
                ))

        # Parse OS guess
        os_m = re.search(r"OS details:\s*(.+)", output)
        if os_m:
            result.os_guess = os_m.group(1).strip()[:100]
        else:
            ag_m = re.search(r"Aggressive OS guesses:\s*(.+?)\s*\((\d+)%\)", output)
            if ag_m:
                result.os_guess = ag_m.group(1).strip()[:100]
                result.os_accuracy = int(ag_m.group(2))

    except FileNotFoundError:
        result.scan_method = "nmap_not_found"
    except subprocess.TimeoutExpired:
        result.scan_method = "nmap_timeout"
    except Exception as e:
        result.scan_method = f"nmap_error"

    return result
