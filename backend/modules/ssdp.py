"""UPnP/SSDP device discovery."""
import asyncio
import socket
import re
from dataclasses import dataclass, field

SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900
SSDP_MX   = 3

SSDP_SEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    f"MX: {SSDP_MX}\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
).encode()


@dataclass
class SSDPDevice:
    ip: str
    location: str = ""
    server: str = ""
    st: str = ""
    usn: str = ""
    friendly_name: str = ""


def _parse_ssdp_response(data: bytes, addr: tuple) -> SSDPDevice:
    text = data.decode(errors="ignore")
    def header(name):
        m = re.search(rf"^{name}:\s*(.+)$", text, re.IGNORECASE | re.MULTILINE)
        return m.group(1).strip() if m else ""

    return SSDPDevice(
        ip=addr[0],
        location=header("LOCATION"),
        server=header("SERVER"),
        st=header("ST"),
        usn=header("USN"),
    )


async def discover_ssdp(timeout: float = 4.0) -> list[SSDPDevice]:
    """Send M-SEARCH and collect SSDP responses."""
    devices: dict[str, SSDPDevice] = {}
    loop = asyncio.get_event_loop()

    def _run():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout)
        sock.sendto(SSDP_SEARCH, (SSDP_ADDR, SSDP_PORT))
        found = {}
        try:
            import time
            end = time.time() + timeout
            while time.time() < end:
                try:
                    data, addr = sock.recvfrom(65507)
                    dev = _parse_ssdp_response(data, addr)
                    found[addr[0]] = dev
                except socket.timeout:
                    break
        finally:
            sock.close()
        return list(found.values())

    return await loop.run_in_executor(None, _run)
