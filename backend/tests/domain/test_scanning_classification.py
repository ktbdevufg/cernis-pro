"""Charakterisierung der Fingerprinting-Regelkette ``classify_host``.

Ein Testfall pro Geraetetyp/Regel + First-Match-Ordnung + Fallback. Inputs an der
Altcode-Logik orientiert (echte Vendor-/Port-/Hostname-/mDNS-Kombinationen).
"""

import pytest

from domain.scanning import MdnsService, PortInfo, classify_host


def _ports(*nums: int) -> tuple[PortInfo, ...]:
    return tuple(PortInfo(port=n, state="open") for n in nums)


def _mdns(*types: str) -> tuple[MdnsService, ...]:
    return tuple(MdnsService(type=t) for t in types)


@pytest.mark.parametrize(
    ("ports", "vendor", "mdns", "hostname", "expected"),
    [
        # Router
        ((), "AVM GmbH", (), "", ("Router/Network Device", "router")),
        ((), "", (), "home-router", ("Router/Network Device", "router")),
        # NAS
        ((), "Synology Inc.", (), "", ("NAS (Linux)", "nas")),
        ((5000, 22), "", (), "", ("NAS (Linux)", "nas")),
        # Printer
        ((9100,), "", (), "", ("Printer", "printer")),
        ((), "HP Inc.", (), "", ("Printer", "printer")),
        ((), "", ("_ipp",), "", ("Printer", "printer")),
        # Smart TV / Streaming
        ((8009,), "", (), "", ("Smart TV / Chromecast", "tv")),
        ((), "", ("_googlecast",), "", ("Smart TV / Chromecast", "tv")),
        ((), "NVIDIA", (), "", ("Android TV (NVIDIA Shield)", "tv")),
        ((), "Sony", (), "", ("Smart TV", "tv")),
        ((), "", (), "my-firetv", ("Smart TV / Streaming", "tv")),
        # iOS / mobile
        ((), "", (), "Johns-iPhone", ("iOS", "mobile")),
        ((62078,), "Apple, Inc.", (), "", ("iOS", "mobile")),
        # Apple desktop
        ((), "Apple, Inc.", (), "", ("Apple", "desktop")),
        ((548,), "Apple, Inc.", (), "", ("macOS", "desktop")),
        ((), "Apple, Inc.", ("_airplay",), "", ("macOS/iOS", "desktop")),
        # Android
        ((), "Samsung Electronics", (), "", ("Android", "mobile")),
        ((8443,), "Samsung Electronics", (), "", ("Android TV", "tv")),
        ((), "", (), "pixel-7", ("Android", "mobile")),
        # Linux mit Samba (vor Windows)
        ((22, 445), "", (), "", ("Linux (Samba)", "server")),
        ((22, 445), "", (), "fileserver", ("Linux NAS (Samba)", "nas")),
        ((22, 445, 80), "", (), "", ("Linux Server (Samba)", "server")),
        # Raspberry
        ((), "Raspberry Pi Foundation", (), "", ("Linux (Raspberry Pi)", "iot")),
        # Windows
        ((135,), "", (), "", ("Windows", "desktop")),
        ((135, 3389), "", (), "", ("Windows (RDP)", "desktop")),
        ((445,), "", (), "", ("Windows", "desktop")),
        # Linux Server
        ((22, 80), "", (), "", ("Linux Server", "server")),
        ((22, 3306), "", (), "", ("Linux Server", "server")),
        ((22,), "", (), "", ("Linux", "server")),
        # IoT
        ((1883,), "", (), "", ("IoT Device (MQTT)", "iot")),
        ((554,), "", (), "", ("IP Camera / NVR", "iot")),
        ((), "Shelly", (), "", ("Smart Home / IoT", "iot")),
        # Fallback
        ((), "", (), "", ("", "unknown")),
    ],
)
def test_classify_host_rule_chain(
    ports: tuple[int, ...],
    vendor: str,
    mdns: tuple[str, ...],
    hostname: str,
    expected: tuple[str, str],
) -> None:
    result = classify_host(_ports(*ports), vendor, _mdns(*mdns), hostname)
    assert (result.os_guess, result.category) == expected


def test_first_match_router_beats_nas_ports() -> None:
    # Router-Vendor UND NAS-Ports: die fruehere Router-Regel gewinnt.
    result = classify_host(_ports(5000, 22), "AVM GmbH", _mdns(), "")
    assert (result.os_guess, result.category) == ("Router/Network Device", "router")


def test_fritz_hostname_used_when_hostname_empty() -> None:
    # host_l = hostname or fritz_hostname: leerer hostname -> fritz_hostname greift.
    result = classify_host(_ports(), "", _mdns(), "", fritz_hostname="myrouter")
    assert (result.os_guess, result.category) == ("Router/Network Device", "router")


def test_empty_inputs_fall_back_without_crash() -> None:
    result = classify_host((), "", (), "")
    assert (result.os_guess, result.category) == ("", "unknown")
