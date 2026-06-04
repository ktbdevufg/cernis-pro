"""Uebergangs-Adapter: Netzwerk-Interface-Discovery (v2-nativ, modules-frei).

UEBERGANGS-LOESUNG -- wird spaeter durch die vollwertige ``interfaces``-Domaene
ersetzt (eigener Ring + Port, wenn die neuen Domaenen drankommen). Bis dahin
braucht das Frontend (``useInterfaces.js`` -> ``/api/interfaces``) die
Interface-Liste; dieser Adapter liefert sie, OHNE den Altcode
``modules.interfaces`` zu importieren.

Begruendung der Kopie statt eines ``modules``-Imports: ``modules.interfaces.
get_interfaces`` ist self-contained stdlib (``socket``/``subprocess``/``platform``/
``re``/``ipaddress``) -- es haengt an keinem anderen ``modules``-Code. Es gibt KEINEN
ADR-0007-Eintrag fuer diesen Uebergangs-Endpunkt (anders als der monitoring-
``target_source``, der ``modules.interfaces`` ueber die M.4-ADR-0007-Erweiterung
nutzt). Statt den import-linter-Contract "neue Ringe importieren NICHT modules" fuer
eine Uebergangs-Kruecke aufzuweichen, wird die self-contained Logik hier v2-nativ
uebernommen -- ein lokaler, spaeter ersetzbarer Eingriff (CLAUDE.md: systemnahe
Adapter so kapseln, dass ein Wechsel lokal bleibt).

SCOPE (CLAUDE.md "Nur Linux x64"): Der Discovery-Pfad ist Linux (``ip``-Tooling).
macOS/Windows sind via leerer Liste gestubbt, nicht implementiert -- der Altcode
trug die anderen Plattformen mit, aber v2 implementiert nur Linux.

WIRE-FORM: Die zurueckgegebenen dicts tragen exakt die Felder, die der Altcode
``InterfaceInfo.to_dict()`` + der Altcode-``/api/interfaces``-Endpunkt liefern
(inkl. ``subnet_cidr``/``network``/``network_cidr``/``broadcast``/``host_count`` und
``hw_type``/``hw_icon``), damit ``useInterfaces.js``/Toolbar.jsx unveraendert
weiterlaufen.
"""

import ipaddress
import os
import re
import subprocess
from typing import Any


def _run(cmd: list[str]) -> str:
    """Fuehrt ein Kommando aus und gibt stdout zurueck (Fehler -> leerer String).

    Best-effort wie der Altcode-``_run``: ein fehlendes Tool / Timeout ist KEIN
    Fehler des Discovery-Pfads, sondern liefert "keine Daten" (leere Liste).
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


def _gateways_linux() -> dict[str, str]:
    """``{interface: gateway}`` aus ``ip route`` (Default-Routen)."""
    gateways: dict[str, str] = {}
    for line in _run(["ip", "route"]).splitlines():
        if line.startswith("default"):
            match = re.search(r"via (\S+).*dev (\S+)", line)
            if match:
                gateways[match.group(2)] = match.group(1)
    return gateways


def _hw_info_linux(name: str) -> tuple[str, str]:
    """Interface-Typ + Icon via ``/sys/class/net`` (Altcode-Heuristik, Linux)."""
    try:
        if os.path.exists(f"/sys/class/net/{name}/wireless"):
            return "Wi-Fi", "📶"
        type_path = f"/sys/class/net/{name}/type"
        if os.path.exists(type_path):
            with open(type_path) as type_file:
                type_value = type_file.read().strip()
            if type_value == "772":
                return "Loopback", "🔁"
            if type_value == "1":
                return "Ethernet", "🔌"
        # Fallback: Namens-Heuristik (Altcode-treu).
        if name.startswith("wl"):
            return "Wi-Fi", "📶"
        if name.startswith(("eth", "en")):
            return "Ethernet", "🔌"
        if name.startswith("lo"):
            return "Loopback", "🔁"
        if name.startswith(("tun", "tap")):
            return "VPN/Tunnel", "🔒"
        if name.startswith("br"):
            return "Bridge", "🔗"
        if name.startswith(("docker", "veth")):
            return "Virtual", "🖥️"
    except Exception:
        pass
    return "", "🔗"


class _Interface:
    """Sammelt die Felder eines Interfaces waehrend des Parsens (Altcode-Datentraeger)."""

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
        self.is_loopback = name == "lo"

    def to_dict(self) -> dict[str, Any]:
        """Wire-form wie der Altcode ``InterfaceInfo.to_dict`` (inkl. abgeleiteter CIDRs)."""
        data: dict[str, Any] = {
            "name": self.name,
            "ipv4": self.ipv4,
            "ipv4_prefix": self.ipv4_prefix,
            "ipv6_link_local": self.ipv6_link_local,
            "ipv6_global": self.ipv6_global,
            "mac": self.mac,
            "gateway": self.gateway,
            "mtu": self.mtu,
            "is_up": self.is_up,
            "is_loopback": self.is_loopback,
        }
        if self.ipv4:
            data["subnet_cidr"] = f"{self.ipv4}/{self.ipv4_prefix}"
            try:
                # strict=False -> Netzadresse (z. B. 172.18.0.0/22 aus 172.18.1.152/22),
                # das Frontend nutzt ``network_cidr`` als Scan-CIDR.
                network = ipaddress.ip_interface(data["subnet_cidr"]).network
                data["network"] = str(network)
                data["network_cidr"] = str(network)
                data["broadcast"] = str(network.broadcast_address)
                data["host_count"] = network.num_addresses - 2
            except ValueError:
                data["network"] = ""
                data["network_cidr"] = data["subnet_cidr"]
                data["broadcast"] = ""
                data["host_count"] = 0
        return data


def _discover_linux() -> list[_Interface]:
    """Liest Interfaces via ``ip -o addr`` / ``ip link`` (Altcode-Linux-Pfad)."""
    interfaces: dict[str, _Interface] = {}
    gateways = _gateways_linux()

    for line in _run(["ip", "-o", "addr"]).splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        iface_name = parts[1]
        if iface_name not in interfaces:
            interfaces[iface_name] = _Interface(iface_name, gateways.get(iface_name, ""))
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

    # MAC-Adressen aus ``ip link`` nachtragen.
    current: str | None = None
    for line in _run(["ip", "link"]).splitlines():
        head = re.match(r"^\d+: (\S+?)[@:]", line)
        if head:
            current = head.group(1)
        elif current and current in interfaces:
            mac = re.search(r"link/ether ([0-9a-f:]{17})", line)
            if mac:
                interfaces[current].mac = mac.group(1)

    return list(interfaces.values())


def discover_interfaces() -> list[dict[str, Any]]:
    """Aktuelle Netzwerk-Interfaces als Wire-form-dicts (Loopback/leere gefiltert).

    Filtert wie der Altcode: Loopback raus, Interfaces ohne IPv4 UND ohne
    IPv6-Link-Local raus. Reichert je Interface ``hw_type``/``hw_icon`` an. Auf
    Nicht-Linux (gestubbt) -> leere Liste.
    """
    result: list[dict[str, Any]] = []
    for iface in _discover_linux():
        if iface.is_loopback:
            continue
        if not iface.ipv4 and not iface.ipv6_link_local:
            continue
        data = iface.to_dict()
        hw_type, hw_icon = _hw_info_linux(iface.name)
        data["hw_type"] = hw_type
        data["hw_icon"] = hw_icon
        result.append(data)
    return result
