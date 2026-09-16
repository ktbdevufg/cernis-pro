"""macOS-Adapter fuer ``InterfaceDiscoveryPort`` (Spiegelbild von ``interfaces_linux.py``).

Erfuellt den ``InterfaceDiscoveryPort`` strukturell -- exakt wie
``infrastructure/interfaces_linux.py``: Klasse ``InterfaceDiscoveryAdapter`` mit
``async def discover`` ueber einen synchronen Kern ``_discover_sync``, der per
``run_in_executor`` im Thread laeuft (Event-Loop bleibt frei). Rueckgabe sind ROHE
``domain.interfaces.NetworkInterface`` (ohne ``type``/``status``/``is_primary`` --
die setzt der Use-Case ``ListInterfaces`` ueber die reinen Domaenen-Funktionen).

DATENQUELLE (macOS statt ``ip``-Tooling): der Linux-Adapter parst ``ip``-Ausgaben,
die es auf macOS nicht gibt. Hier stattdessen die BSD-Standardwerkzeuge:

* ``ifconfig`` (ohne Argumente = alle Interfaces) -> Name, Flags (``is_up``/Loopback),
  ``mtu``, ``ether`` (MAC), ``inet``+Hex-Netmask (IPv4 + Praefix), ``inet6`` (Link-
  Local vs. global, Zone hinter ``%`` abgeschnitten).
* ``netstat -rn -f inet`` -> Default-Route-Zeile liefert Gateway + Interface.

Je Interface zaehlt die ERSTE ``inet``- bzw. erste globale/erste Link-Local-``inet6``-
Zeile (mehrere sind selten; erste gewinnt, best-effort).

FILTER (identisch zum Linux-Adapter): Loopback raus, Interfaces ohne IPv4 UND ohne
IPv6-Link-Local raus. ``network_cidr``/``host_count`` fuellt der Adapter aus
``ipv4``/``ipv4_prefix`` (die Domaene fuehrt diese Felder). Leere Strings des Roh-
Parsers werden zu ``None`` (Domaene: "fehlend" ist ``None``, nicht ``""``).

Die externen Kommandos werden mit erzwungener C-Locale gestartet (``_C_LOCALE_ENV``,
1:1 wie Linux), damit lokalisierte Ausgaben das Parsing nicht still scheitern lassen.
Der Discovery-Pfad ist self-contained stdlib (``subprocess`` + ``ipaddress`` + ``re``)
-- kein ``modules``-Import, der import-linter-Contract "neue Ringe importieren NICHT
modules" bleibt unberuehrt.
"""

import asyncio
import ipaddress
import os
import re
import subprocess

from domain.interfaces import NetworkInterface

# Externe Kommandos (ifconfig/netstat) werden mit erzwungener C-Locale gestartet,
# weil lokalisierte Ausgaben das Parsing sonst still scheitern lassen.
_C_LOCALE_ENV = {**os.environ, "LC_ALL": "C", "LANG": "C"}

# Interface-Block-Header: ``en12: flags=8963<UP,BROADCAST,...> mtu 1500``. mtu ist
# optional (manche Pseudo-Interfaces nennen keins) -> Default bleibt erhalten.
_HEADER_RE = re.compile(r"^(\S+?): flags=\d+<([^>]*)>(?:.*\bmtu (\d+))?")
# Eingerueckte Block-Zeilen (Tab/Space) -- ``ether``/``inet``/``inet6``.
_ETHER_RE = re.compile(r"^\s+ether ([0-9a-fA-F:]{17})")
_INET_RE = re.compile(r"^\s+inet (\S+) netmask (0x[0-9a-fA-F]+)")
_INET6_RE = re.compile(r"^\s+inet6 (\S+)")
# Loopback: ``lo`` exakt oder ``lo`` + nur Ziffern (``lo0``/``lo1`` -- BSD-Mehrfach-
# Loopback). Praezises Muster (kein startswith), sonst traefe ``lo`` z.B. ``london0``.
_LOOPBACK_RE = re.compile(r"lo\d*")


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
            env=_C_LOCALE_ENV,
        )
        return result.stdout or ""
    except Exception:
        return ""


def parse_gateways(netstat_output: str) -> dict[str, str]:
    """``{interface: gateway}`` aus ``netstat -rn -f inet`` (Default-Routen) -- reine Funktion.

    Zeilen, die mit ``default`` beginnen (Spalten per ``split()``): ``[0]="default"``,
    ``[1]=Gateway``, letzte Spalte = Interface-Name. Es kann mehrere ``default``-Zeilen
    geben (je Interface) -- jede wird dem genannten Interface zugeordnet.
    """
    gateways: dict[str, str] = {}
    for line in netstat_output.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "default":
            gateways[parts[-1]] = parts[1]
    return gateways


class _RawInterface:
    """Sammelt die rohen Felder eines Interfaces waehrend des Parsens.

    Analog zum ``_RawInterface`` des Linux-Adapters; ``is_up`` kommt hier aus den
    ifconfig-Flags (Linux liest stattdessen ``/sys/.../operstate``), ``is_loopback``
    aus dem Namen (``lo``/``lo0``..).
    """

    def __init__(self, name: str, gateway: str = "") -> None:
        self.name = name
        self.ipv4 = ""
        self.ipv4_prefix = 24
        self.ipv6_link_local = ""
        self.ipv6_global = ""
        self.mac = ""
        self.gateway = gateway
        self.mtu = 1500
        self.is_up = True
        self.is_loopback = bool(_LOOPBACK_RE.fullmatch(name))


def _parse_ifconfig(ifconfig_output: str, gateways: dict[str, str]) -> dict[str, _RawInterface]:
    """Parst ``ifconfig``-Output zu ``{name: _RawInterface}`` (reine Funktion).

    Ein Block beginnt am Zeilenanfang mit ``NAME: flags=...<FLAGS> mtu MTU``; Folge-
    zeilen sind eingerueckt. ``is_up`` = ``UP`` in den Flags. Je Interface zaehlt die
    ERSTE ``inet``- bzw. erste globale/erste Link-Local-``inet6``-Zeile. Der IPv4-
    Praefix wird aus der Hex-Netmask abgeleitet (``0xfffffc00`` -> 22 gesetzte Bits).
    Die IPv6-Zone hinter ``%`` wird abgeschnitten (nicht Teil der Adresse).
    """
    interfaces: dict[str, _RawInterface] = {}
    current: _RawInterface | None = None
    for line in ifconfig_output.splitlines():
        header = _HEADER_RE.match(line)
        if header:
            name = header.group(1)
            raw = _RawInterface(name, gateways.get(name, ""))
            raw.is_up = "UP" in header.group(2).split(",")
            if header.group(3):
                raw.mtu = int(header.group(3))
            interfaces[name] = raw
            current = raw
            continue
        if current is None:
            continue
        ether = _ETHER_RE.match(line)
        if ether:
            if not current.mac:
                current.mac = ether.group(1).lower()
            continue
        inet = _INET_RE.match(line)
        if inet and not current.ipv4:
            current.ipv4 = inet.group(1)
            current.ipv4_prefix = bin(int(inet.group(2), 16)).count("1")
            continue
        inet6 = _INET6_RE.match(line)
        if inet6:
            addr6 = inet6.group(1).split("%")[0]
            if addr6.lower().startswith("fe80"):
                if not current.ipv6_link_local:
                    current.ipv6_link_local = addr6
            elif not current.ipv6_global:
                current.ipv6_global = addr6
    return interfaces


def _to_network_interface(raw: _RawInterface) -> NetworkInterface:
    """Bildet ein ``_RawInterface`` auf ein rohes ``NetworkInterface`` ab.

    Fuellt ``network_cidr``/``host_count`` aus ``ipv4``/``ipv4_prefix`` (die Domaene
    fuehrt diese Felder) -- exakt wie der Linux-Adapter. ``type``/``status``/
    ``is_primary`` bleiben auf Default (die setzt der Use-Case). Leere Strings des
    Roh-Parsers werden zu ``None`` (Domaene: "fehlend" ist ``None``, nicht ``""``).
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
        is_up=raw.is_up,
        is_loopback=raw.is_loopback,
        network_cidr=network_cidr,
        host_count=host_count,
    )


class InterfaceDiscoveryAdapter:
    """Erfuellt das ``InterfaceDiscoveryPort``-Protocol (Executor-Wrapper, macOS)."""

    async def discover(self) -> list[NetworkInterface]:
        """Aktuelle Interfaces als rohe ``NetworkInterface``-Liste.

        Blockierendes ``ifconfig``-/``netstat``-I/O -> ``run_in_executor`` (Loop bleibt
        frei). Keine Interfaces -> ``[]`` (vertraglicher Leer-Zustand, kein Fehler).
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._discover_sync)

    def _discover_sync(self) -> list[NetworkInterface]:
        """Synchroner Discovery-Kern (laeuft im Executor-Thread).

        FILTER (Wire-Kompat, identisch zum Linux-Adapter): Loopback raus, Interfaces
        ohne IPv4 UND ohne IPv6-Link-Local raus.
        """
        gateways = parse_gateways(_run(["netstat", "-rn", "-f", "inet"]))
        interfaces = _parse_ifconfig(_run(["ifconfig"]), gateways)

        result: list[NetworkInterface] = []
        for raw in interfaces.values():
            if raw.is_loopback:
                continue
            if not raw.ipv4 and not raw.ipv6_link_local:
                continue
            result.append(_to_network_interface(raw))
        return result
