"""Linux-Adapter fuer ``InterfaceDiscoveryPort`` (I.3, loest die Uebergangs-Kruecke ab).

Erfuellt den ``InterfaceDiscoveryPort`` strukturell: liefert die aktuell
vorhandenen Netzwerk-Interfaces als ROHE ``domain.interfaces.NetworkInterface``
(ohne ``type``/``status``/``is_primary`` -- die setzt der Use-Case ``ListInterfaces``
ueber die reinen Domaenen-Funktionen). Die Discovery-Logik ist die bewaehrte des
fruheren Uebergangs-Adapters (``ip -o addr`` / ``ip link`` / ``ip route``), aber:

* ``discover`` ist ``async`` und kapselt das blockierende ``ip``-/``/sys``-I/O ueber
  ``run_in_executor`` (Schablone ``infrastructure/scanning/arp_table.py``), sodass
  der Event-Loop frei bleibt.
* ``is_up`` kommt jetzt aus dem ECHTEN Status (``/sys/class/net/{name}/operstate``)
  statt aus dem hardcodeten ``True`` der Kruecke (I.1-Befund: das war eine Luege).
  Siehe ``parse_operstate`` fuer die Fallback-Regel.

SCOPE (CLAUDE.md "Nur Linux x64"): Discovery ist Linux (``ip``-Tooling, ``/sys``).
Andere Plattformen sind nicht Teil von v2.

FILTER (Wire-Kompat, wie die Kruecke): Loopback raus, Interfaces ohne IPv4 UND ohne
IPv6-Link-Local raus. Die ableitbaren Anzeige-Felder ``subnet_cidr``/``broadcast``/
``network`` traegt der Adapter NICHT in die Domaene (I.1: ableitbare Anzeige bleibt
am Rand) -- der api-Serialisierer (I.3) rechnet sie aus ``ipv4``/``ipv4_prefix``.
``network_cidr``/``host_count`` fuellt der Adapter, weil die Domaene sie fuehrt.

Der modules-freie Discovery-Pfad ist self-contained stdlib (``ip``-Subprocess +
``ipaddress``) -- kein ``modules``-Import, der import-linter-Contract "neue Ringe
importieren NICHT modules" bleibt unberuehrt.
"""

import asyncio
import ipaddress
import re
import subprocess

from domain.interfaces import NetworkInterface


def _run(cmd: list[str]) -> str:
    """Fuehrt ein Kommando aus und gibt stdout zurueck (Fehler -> leerer String).

    Best-effort: ein fehlendes Tool / Timeout ist KEIN Fehler des Discovery-Pfads,
    sondern liefert "keine Daten" (leere Liste). ``[]`` ist der vertragliche
    Leer-Zustand des Ports, kein verdecktes Scheitern (kein Sentinel wie nmap).
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=5,
            encoding="utf-8",
            errors="replace",
        )
        return result.stdout or ""
    except Exception:
        return ""


def parse_operstate(operstate: str) -> bool:
    """``/sys/class/net/*/operstate``-String -> ``is_up`` (reine Funktion, testbar).

    - ``"up"`` -> ``True`` (Link aktiv).
    - ``"down"`` -> ``False`` (Link inaktiv).
    - alles andere (insbesondere ``"unknown"``) -> ``True`` (konservativer Fallback).

    Begruendung des ``unknown``->``True``-Fallbacks: viele virtuelle/Punkt-zu-Punkt-
    Interfaces (tun/tap, manche Bridges, loopback) melden dauerhaft ``"unknown"``,
    obwohl sie nutzbar sind. Der fruhere Adapter nahm IMMER ``True`` an -- diesen
    Fallback nur fuer ``unknown`` beizubehalten ist die kleinste, regressionsfreie
    Verschaerfung: explizites ``"down"`` wird jetzt als ``False`` erkannt (die echte
    Verbesserung), der unklare Rest bleibt wie bisher ``True``.
    """
    # Aequivalent zu up->True / down->False / Rest->True: alles ausser explizitem
    # "down" gilt als up (der dokumentierte unknown->True-Fallback ist hierin
    # enthalten -- "unknown" != "down" -> True).
    return operstate.strip().lower() != "down"


def _read_operstate(name: str) -> bool:
    """Liest ``is_up`` aus ``/sys/class/net/{name}/operstate`` (I/O, Linux).

    Nicht lesbar (Datei fehlt / Permission) -> ``True`` (gleicher konservativer
    Fallback wie ``parse_operstate`` fuer ``unknown``): ein nicht ermittelbarer
    Status soll ein Interface nicht faelschlich als ``down`` ausblenden.
    """
    try:
        with open(f"/sys/class/net/{name}/operstate") as state_file:
            return parse_operstate(state_file.read())
    except OSError:
        return True


def parse_gateways(ip_route_output: str) -> dict[str, str]:
    """``{interface: gateway}`` aus ``ip route``-Output (Default-Routen) -- reine Funktion."""
    gateways: dict[str, str] = {}
    for line in ip_route_output.splitlines():
        if line.startswith("default"):
            match = re.search(r"via (\S+).*dev (\S+)", line)
            if match:
                gateways[match.group(2)] = match.group(1)
    return gateways


class _RawInterface:
    """Sammelt die rohen Felder eines Interfaces waehrend des Parsens."""

    def __init__(self, name: str, gateway: str = "") -> None:
        self.name = name
        self.ipv4 = ""
        self.ipv4_prefix = 24
        self.ipv6_link_local = ""
        self.ipv6_global = ""
        self.mac = ""
        self.gateway = gateway
        self.mtu = 1500
        self.is_loopback = name == "lo"


def _parse_addrs(ip_addr_output: str, gateways: dict[str, str]) -> dict[str, _RawInterface]:
    """Parst ``ip -o addr``-Output zu ``{name: _RawInterface}`` (reine Funktion)."""
    interfaces: dict[str, _RawInterface] = {}
    for line in ip_addr_output.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        iface_name = parts[1]
        if iface_name not in interfaces:
            interfaces[iface_name] = _RawInterface(iface_name, gateways.get(iface_name, ""))
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
    return interfaces


def _parse_macs(ip_link_output: str, interfaces: dict[str, _RawInterface]) -> None:
    """Traegt MAC-Adressen aus ``ip link``-Output in ``interfaces`` nach (reine Funktion)."""
    current: str | None = None
    for line in ip_link_output.splitlines():
        head = re.match(r"^\d+: (\S+?)[@:]", line)
        if head:
            current = head.group(1)
        elif current and current in interfaces:
            mac = re.search(r"link/ether ([0-9a-f:]{17})", line)
            if mac:
                interfaces[current].mac = mac.group(1)


def _to_network_interface(raw: _RawInterface) -> NetworkInterface:
    """Bildet ein ``_RawInterface`` auf ein rohes ``NetworkInterface`` ab.

    Fuellt ``network_cidr``/``host_count`` aus ``ipv4``/``ipv4_prefix`` (die Domaene
    fuehrt diese Felder). ``type``/``status``/``is_primary`` bleiben auf Default --
    die setzt der Use-Case. Leere Strings des Roh-Parsers werden zu ``None``
    (Domaene: "fehlend" ist ``None``, nicht ``""``).
    """
    network_cidr: str | None = None
    host_count: int | None = None
    if raw.ipv4:
        try:
            network = ipaddress.ip_interface(f"{raw.ipv4}/{raw.ipv4_prefix}").network
            network_cidr = str(network)
            host_count = max(network.num_addresses - 2, 0)
        except ValueError:
            network_cidr = None
            host_count = None

    return NetworkInterface(
        name=raw.name,
        ipv4=raw.ipv4 or None,
        ipv4_prefix=raw.ipv4_prefix if raw.ipv4 else None,
        ipv6_link_local=raw.ipv6_link_local or None,
        ipv6_global=raw.ipv6_global or None,
        mac=raw.mac or None,
        gateway=raw.gateway or None,
        mtu=raw.mtu,
        is_up=_read_operstate(raw.name),
        is_loopback=raw.is_loopback,
        network_cidr=network_cidr,
        host_count=host_count,
    )


class InterfaceDiscoveryAdapter:
    """Erfuellt das ``InterfaceDiscoveryPort``-Protocol (Executor-Wrapper, Linux)."""

    async def discover(self) -> list[NetworkInterface]:
        """Aktuelle Interfaces als rohe ``NetworkInterface``-Liste.

        Blockierendes ``ip``-/``/sys``-I/O -> ``run_in_executor`` (Loop bleibt frei).
        Keine Interfaces -> ``[]`` (vertraglicher Leer-Zustand, kein Fehler).
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._discover_sync)

    def _discover_sync(self) -> list[NetworkInterface]:
        """Synchroner Discovery-Kern (laeuft im Executor-Thread).

        FILTER (Wire-Kompat): Loopback raus, Interfaces ohne IPv4 UND ohne
        IPv6-Link-Local raus.
        """
        gateways = parse_gateways(_run(["ip", "route"]))
        interfaces = _parse_addrs(_run(["ip", "-o", "addr"]), gateways)
        _parse_macs(_run(["ip", "link"]), interfaces)

        result: list[NetworkInterface] = []
        for raw in interfaces.values():
            if raw.is_loopback:
                continue
            if not raw.ipv4 and not raw.ipv6_link_local:
                continue
            result.append(_to_network_interface(raw))
        return result
