"""Geraete-Fingerprinting der scanning-Domaene -- reine, deterministische Logik.

Verhaltensgleich aus dem Altcode portiert (``main._classify_host``, ~1537-1650):
stdlib only, kein I/O, kein Framework, kein Import aus anderen Domaenen. Die
geordnete First-Match-Regelkette ist 1:1 uebernommen -- ein abweichend
klassifizierendes Geraet waere ein stiller Fehler.

Der vestigiale ``mac``-Parameter des Altcodes (im Funktionskoerper nie benutzt)
entfaellt. ``category`` ist eines von:
router | nas | mobile | desktop | server | iot | printer | tv | unknown.
"""

from domain.scanning.models import HostClassification, MdnsService, PortInfo


def classify_host(
    ports: tuple[PortInfo, ...],
    vendor: str,
    mdns_services: tuple[MdnsService, ...],
    hostname: str,
    fritz_hostname: str = "",
) -> HostClassification:
    """Bestimmt (os_guess, category) per First-Match-Regelkette (verhaltensgleich Altcode)."""
    vendor_l = vendor.lower()
    host_l = (hostname or fritz_hostname or "").lower()
    port_nums = {p.port for p in ports}
    mdns_types = {s.type.lower() for s in mdns_services}

    # ── Router / Gateway ──────────────────────────────────────
    if any(
        x in vendor_l
        for x in [
            "avm",
            "asus",
            "netgear",
            "tp-link",
            "d-link",
            "ubiquiti",
            "mikrotik",
            "cisco",
            "juniper",
            "aruba",
            "fritz",
            "linksys",
            "buffalo",
        ]
    ):
        return HostClassification("Router/Network Device", "router")
    if any(x in host_l for x in ["router", "gateway", "fritzbox", "fritz"]):
        return HostClassification("Router/Network Device", "router")

    # ── NAS ───────────────────────────────────────────────────
    if any(
        x in vendor_l
        for x in [
            "synology",
            "qnap",
            "western digital",
            "wd",
            "buffalo",
            "netgear readynas",
            "seagate",
        ]
    ):
        return HostClassification("NAS (Linux)", "nas")
    if port_nums & {5000, 5001, 5005, 5006} and 22 in port_nums:
        return HostClassification("NAS (Linux)", "nas")

    # ── Printer ───────────────────────────────────────────────
    printer_ports = port_nums & {9100, 515, 631}
    printer_vendor = any(
        x in vendor_l
        for x in [
            "hewlett",
            "hp ",
            "epson",
            "canon",
            "brother",
            "lexmark",
            "xerox",
            "kyocera",
            "ricoh",
        ]
    )
    if printer_ports or "_ipp" in mdns_types or "_pdl-datastream" in mdns_types:
        return HostClassification("Printer", "printer")
    if printer_vendor and not (port_nums & {22, 80, 443, 445, 3389, 8080}):
        return HostClassification("Printer", "printer")

    # ── Smart TV / Streaming ─────────────────────────────────
    if port_nums & {8008, 8009, 8060, 9080} or "_googlecast" in mdns_types:
        return HostClassification("Smart TV / Chromecast", "tv")
    if "nvidia" in vendor_l:
        return HostClassification("Android TV (NVIDIA Shield)", "tv")
    # SIM102: das verschachtelte if des Altcodes zusammengefuehrt -- verhaltensgleich
    # (der innere Zweig kehrte nur zurueck, wenn beide Bedingungen wahr sind).
    if any(
        x in vendor_l
        for x in [
            "lg electronics",
            "sony",
            "philips",
            "hisense",
            "vestel",
            "tcl",
            "vizio",
            "roku",
            "amazon",
        ]
    ) and not (port_nums & {22, 445}):
        return HostClassification("Smart TV", "tv")
    if any(
        x in host_l
        for x in [
            "fire-tv",
            "firetv",
            "roku",
            "shield",
            "androidtv",
            "chromecast",
            "smart-tv",
            "smarttv",
        ]
    ):
        return HostClassification("Smart TV / Streaming", "tv")

    # ── Apple mobile (iOS) ────────────────────────────────────
    if any(x in host_l for x in ["iphone", "ipad", "ipod"]):
        return HostClassification("iOS", "mobile")
    if 62078 in port_nums and "apple" in vendor_l:
        return HostClassification("iOS", "mobile")

    # ── Apple desktop/laptop ──────────────────────────────────
    if "apple" in vendor_l or any(x in host_l for x in ["macbook", "imac", "mac-mini", "mac-pro"]):
        if port_nums & {548, 5009} or "_afpovertcp" in mdns_types:
            return HostClassification("macOS", "desktop")
        if "_airplay" in mdns_types or "_raop" in mdns_types:
            return HostClassification("macOS/iOS", "desktop")
        return HostClassification("Apple", "desktop")

    # ── Android / Mobile ─────────────────────────────────────
    if any(
        x in vendor_l
        for x in [
            "samsung",
            "huawei",
            "xiaomi",
            "oneplus",
            "google",
            "motorola",
            "oppo",
            "realme",
            "nothing",
        ]
    ):
        if port_nums & {8008, 8009, 8443, 9000}:
            return HostClassification("Android TV", "tv")
        return HostClassification("Android", "mobile")
    if any(x in host_l for x in ["android", "galaxy", "pixel", "phone"]):
        return HostClassification("Android", "mobile")

    # ── Linux mit Samba (VOR Windows pruefen) ────────────────
    # SSH + SMB-Ports ohne Port 135 (DCE/RPC) -> Linux mit Samba.
    has_smb = bool(port_nums & {139, 445})
    has_ssh = 22 in port_nums
    has_rpc = 135 in port_nums  # DCE/RPC ist Windows-only
    has_webmin = 10000 in port_nums

    if has_ssh and has_smb and not has_rpc:
        if has_webmin or any(
            x in host_l for x in ["omv", "openmediavault", "nas", "srv", "server"]
        ):
            return HostClassification("Linux NAS (Samba)", "nas")
        if port_nums & {80, 443, 8080, 3306, 5432}:
            return HostClassification("Linux Server (Samba)", "server")
        return HostClassification("Linux (Samba)", "server")

    # ── Raspberry Pi / Linux ──────────────────────────────────
    if "raspberry" in vendor_l or "raspberry" in host_l:
        return HostClassification("Linux (Raspberry Pi)", "iot")

    # ── Windows (Port 135 ODER nur SMB ohne SSH) ─────────────
    if has_rpc:
        if 3389 in port_nums:
            return HostClassification("Windows (RDP)", "desktop")
        return HostClassification("Windows", "desktop")
    if has_smb and not has_ssh:
        if 3389 in port_nums:
            return HostClassification("Windows (RDP)", "desktop")
        return HostClassification("Windows", "desktop")

    # ── Linux Server ─────────────────────────────────────────
    if has_ssh and (80 in port_nums or 443 in port_nums or 8080 in port_nums):
        return HostClassification("Linux Server", "server")
    if has_ssh and port_nums & {25, 110, 143, 3306, 5432, 6379, 27017}:
        return HostClassification("Linux Server", "server")
    if has_ssh:
        return HostClassification("Linux", "server")

    # ── IoT ───────────────────────────────────────────────────
    if port_nums & {1883, 8883} or "_mqtt" in mdns_types:
        return HostClassification("IoT Device (MQTT)", "iot")
    if port_nums & {554, 8554}:
        return HostClassification("IP Camera / NVR", "iot")
    if any(
        x in vendor_l
        for x in ["shelly", "sonoff", "tuya", "espressif", "tasmota", "home assistant"]
    ):
        return HostClassification("Smart Home / IoT", "iot")

    return HostClassification("", "unknown")
