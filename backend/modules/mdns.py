"""mDNS / Bonjour / NDI service discovery using zeroconf."""
import asyncio
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

import structlog

_logger = structlog.get_logger(__name__)

try:
    from zeroconf import Zeroconf, ServiceBrowser, ServiceInfo, ZeroconfServiceTypes
    HAS_ZEROCONF = True
except ImportError:
    HAS_ZEROCONF = False

# S3: kein stiller Leerzustand. Fehlt zeroconf, bleibt die mDNS-Discovery dauerhaft leer --
# das wird EINMAL beim Import gesagt (nicht bei jedem scan()/discover_mdns()-Aufruf, das
# waere Spam). Der leere Rueckgabewert bleibt ein ehrliches Datum, nur nicht mehr stumm.
if not HAS_ZEROCONF:
    _logger.debug(
        "zeroconf nicht verfuegbar -- mDNS-Discovery liefert dauerhaft eine leere Liste"
    )

# NDI uses mDNS with specific service types
NDI_SERVICE_TYPES = [
    "_ndi._tcp.local.",
    "_ndi._udp.local.",
]

BONJOUR_SERVICE_TYPES = [
    "_http._tcp.local.",
    "_https._tcp.local.",
    "_ftp._tcp.local.",
    "_ssh._tcp.local.",
    "_afpovertcp._tcp.local.",
    "_smb._tcp.local.",
    "_rfb._tcp.local.",     # VNC
    "_daap._tcp.local.",    # iTunes
    "_raop._tcp.local.",    # AirPlay
    "_airplay._tcp.local.", # AirPlay 2
    "_googlecast._tcp.local.",
    "_homekit._tcp.local.",
    "_hap._tcp.local.",
    "_printer._tcp.local.",
    "_ipp._tcp.local.",
    "_pdl-datastream._tcp.local.",
    "_device-info._tcp.local.",
    "_services._dns-sd._udp.local.",
] + NDI_SERVICE_TYPES


@dataclass
class MDNSService:
    ip: str
    name: str
    service_type: str
    port: int = 0
    hostname: str = ""
    properties: dict = field(default_factory=dict)
    is_ndi: bool = False


class MDNSScanner:
    def __init__(self):
        self.services: dict[str, MDNSService] = {}  # key = ip+name
        self._lock = threading.Lock()

    def _on_service_added(self, zc: "Zeroconf", service_type: str, name: str):
        try:
            info = zc.get_service_info(service_type, name, timeout=2000)
            if not info:
                return

            for addr in info.parsed_addresses():
                svc = MDNSService(
                    ip=addr,
                    name=info.name,
                    service_type=service_type,
                    port=info.port,
                    hostname=info.server or "",
                    properties={
                        k.decode() if isinstance(k, bytes) else k:
                        v.decode(errors="replace") if isinstance(v, bytes) else str(v)
                        for k, v in (info.properties or {}).items()
                    },
                    is_ndi=service_type in NDI_SERVICE_TYPES,
                )
                key = f"{addr}|{name}"
                with self._lock:
                    self.services[key] = svc
        except Exception as fehler:
            # S3: Best-Effort-Discovery bleibt (kein Re-Raise), aber nicht mehr stumm --
            # ein Dienst, der sich nicht aufloesen laesst, ist sonst unsichtbar.
            _logger.debug(
                "mDNS-Dienst konnte nicht uebernommen werden",
                service_type=service_type,
                name=name,
                fehler=str(fehler),
            )

    def scan(self, duration: float = 5.0, service_types: list[str] | None = None) -> list[MDNSService]:
        if not HAS_ZEROCONF:
            return []

        types_to_scan = service_types or BONJOUR_SERVICE_TYPES

        class _Listener:
            def __init__(self, scanner):
                self.scanner = scanner
            def add_service(self, zc, svc_type, name):
                self.scanner._on_service_added(zc, svc_type, name)
            def remove_service(self, zc, svc_type, name):
                pass
            def update_service(self, zc, svc_type, name):
                self.scanner._on_service_added(zc, svc_type, name)

        zc = Zeroconf()
        listener = _Listener(self)
        browsers = [ServiceBrowser(zc, t, listener) for t in types_to_scan]

        time.sleep(duration)

        zc.close()

        with self._lock:
            return list(self.services.values())


async def discover_mdns(duration: float = 5.0) -> list[MDNSService]:
    """Run mDNS discovery in thread pool (blocking zeroconf)."""
    if not HAS_ZEROCONF:
        return []

    loop = asyncio.get_event_loop()
    scanner = MDNSScanner()
    services = await loop.run_in_executor(None, lambda: scanner.scan(duration))
    return services


def group_by_ip(services: list[MDNSService]) -> dict[str, list[MDNSService]]:
    result: dict[str, list[MDNSService]] = {}
    for svc in services:
        result.setdefault(svc.ip, []).append(svc)
    return result
