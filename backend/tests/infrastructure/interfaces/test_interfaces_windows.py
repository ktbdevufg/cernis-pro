"""Tests fuer den Windows-Interface-Adapter (nativer GetAdaptersAddresses-Pfad).

Getestet werden die PLATTFORMUNABHAENGIGEN reinen Hilfsfunktionen aus
``interfaces_windows.py`` OHNE echte Windows-API -- deterministisch und auch auf
dem Linux-CI-Runner lauffaehig:

* ``format_mac``: Standard-6-Byte, Laenge 0 (leer), ungewoehnliche Laenge (8 Byte).
* ``network_cidr_and_host_count``: gueltige Eingabe + ungueltige (ValueError -> None).
* ``classify_ipv6``: link-local (``fe80``) gegen global.
* ``_filter_and_map``: Loopback raus, ohne IPv4 UND ohne IPv6-Link-Local raus.

Der ctypes-Kern braucht echte Windows-API -> per ``skipif(sys.platform != "win32")``
markiert (auf Linux sauber uebersprungen, NICHT fehlschlagend). Zusaetzlich der
async-Vertrag auf Nicht-Windows: ``discover`` liefert ``[]`` (via ``asyncio.run``,
Projektmuster wie im Linux-Test, kein pytest-asyncio).
"""

import asyncio
import sys

import pytest

from domain.interfaces import NetworkInterface
from infrastructure.interfaces_windows import (
    InterfaceDiscoveryAdapter,
    _filter_and_map,
    _RawInterface,
    classify_ipv6,
    format_mac,
    network_cidr_and_host_count,
)
from ports.interfaces import InterfaceDiscoveryPort

# ── Struktureller Vertrag ─────────────────────────────────────────────────


def test_conforms_to_discovery_protocol() -> None:
    adapter: InterfaceDiscoveryPort = InterfaceDiscoveryAdapter()
    assert adapter is not None


# ── format_mac ────────────────────────────────────────────────────────────


def test_format_mac_standard_six_bytes() -> None:
    raw = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x00])
    assert format_mac(raw, 6) == "aa:bb:cc:dd:ee:ff"


def test_format_mac_length_zero_is_empty() -> None:
    # Loopback/PPP ohne Hardware-Adresse -> leerer String (Adapter macht None daraus).
    assert format_mac(bytes(8), 0) == ""


def test_format_mac_unusual_length_not_truncated_to_six() -> None:
    # Ungewoehnliche Laenge (z. B. Firewire, 8 Byte) wird 1:1 durchgereicht.
    raw = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
    assert format_mac(raw, 8) == "01:02:03:04:05:06:07:08"


# ── network_cidr_and_host_count ───────────────────────────────────────────


def test_network_cidr_and_host_count_valid() -> None:
    assert network_cidr_and_host_count("192.168.1.152", 22) == ("192.168.0.0/22", 1022)


def test_network_cidr_and_host_count_invalid_returns_none() -> None:
    # Ungueltige Eingabe (ValueError) -> beide None, exakt wie im Linux-Adapter.
    assert network_cidr_and_host_count("not-an-ip", 24) == (None, None)


# ── classify_ipv6 ─────────────────────────────────────────────────────────


def test_classify_ipv6_link_local() -> None:
    assert classify_ipv6("fe80::1234") == "link_local"
    assert classify_ipv6("FE80::DEAD") == "link_local"  # case-insensitive


def test_classify_ipv6_global() -> None:
    assert classify_ipv6("2001:db8::1") == "global"


# ── _filter_and_map (Filter + Abbildung, ohne ctypes) ─────────────────────


def _raw(
    name: str,
    *,
    ipv4: str = "",
    ipv6_link_local: str = "",
    is_loopback: bool = False,
) -> _RawInterface:
    raw = _RawInterface(name)
    raw.ipv4 = ipv4
    raw.ipv6_link_local = ipv6_link_local
    raw.is_loopback = is_loopback
    return raw


def test_filter_and_map_drops_loopback_and_empty() -> None:
    raws = [
        _raw("Loopback", ipv4="127.0.0.1", is_loopback=True),  # Loopback raus
        _raw("Ethernet", ipv4="192.168.1.152"),  # IPv4 -> drin
        _raw("WLAN", ipv6_link_local="fe80::dead"),  # nur IPv6-LL -> drin
        _raw("Leer"),  # ohne IPv4 UND ohne IPv6-LL raus
    ]
    result = _filter_and_map(raws)
    names = {iface.name for iface in result}
    assert names == {"Ethernet", "WLAN"}


def test_filter_and_map_raw_form() -> None:
    raw = _RawInterface("Ethernet")
    raw.ipv4 = "192.168.1.152"
    raw.ipv4_prefix = 22
    raw.mac = "aa:bb:cc:dd:ee:ff"
    raw.gateway = "192.168.0.1"
    raw.ipv6_link_local = "fe80::1234"
    raw.is_up = True

    eth = _filter_and_map([raw])[0]
    assert isinstance(eth, NetworkInterface)
    assert eth.ipv4 == "192.168.1.152"
    assert eth.ipv4_prefix == 22
    assert eth.mac == "aa:bb:cc:dd:ee:ff"
    assert eth.gateway == "192.168.0.1"
    assert eth.ipv6_link_local == "fe80::1234"
    assert eth.is_up is True
    assert eth.is_loopback is False
    # network_cidr/host_count aus ipv4/prefix abgeleitet (Domaene fuehrt sie).
    assert eth.network_cidr == "192.168.0.0/22"
    assert eth.host_count == 1022
    # roh: type/status/is_primary noch auf Default (Use-Case setzt sie spaeter).
    assert eth.type == "unknown"
    assert eth.status == "up"
    assert eth.is_primary is False


def test_filter_and_map_type_from_if_type() -> None:
    # Der Adapter uebernimmt type aus dem numerischen IfType
    # (classify_type_from_if_type), NICHT aus dem Namen: 6 -> ethernet, 71 -> wifi.
    eth_raw = _RawInterface("Ethernet0")
    eth_raw.ipv4 = "192.168.1.152"
    eth_raw.if_type = 6
    wlan_raw = _RawInterface("WLAN")
    wlan_raw.ipv4 = "192.168.1.153"
    wlan_raw.if_type = 71

    by_name = {iface.name: iface for iface in _filter_and_map([eth_raw, wlan_raw])}
    assert by_name["Ethernet0"].type == "ethernet"
    assert by_name["WLAN"].type == "wifi"


def test_filter_and_map_empty_strings_become_none() -> None:
    # Ein Interface nur mit IPv6-LL: leere Roh-Strings werden zu None (Domaene).
    only_ll = _filter_and_map([_raw("WLAN", ipv6_link_local="fe80::dead")])[0]
    assert only_ll.ipv4 is None
    assert only_ll.ipv4_prefix is None
    assert only_ll.mac is None
    assert only_ll.gateway is None
    assert only_ll.network_cidr is None
    assert only_ll.host_count is None


# ── async-Vertrag auf Nicht-Windows: discover() -> [] ─────────────────────


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Auf Windows ruft discover() die echte API -- hier nur der Nicht-Windows-Leerpfad.",
)
def test_discover_empty_on_non_windows() -> None:
    # Vertraglicher Leer-Zustand ausserhalb win32: [] (kein Fehler, kein None).
    result = asyncio.run(InterfaceDiscoveryAdapter().discover())
    assert result == []


# ── Windows-only: echter API-Aufruf (auf Linux-CI sauber uebersprungen) ───


@pytest.mark.skipif(
    sys.platform != "win32",
    reason="Braucht echte Windows-API (GetAdaptersAddresses) -- auf Nicht-Windows uebersprungen.",
)
def test_discover_returns_list_on_windows() -> None:
    result = asyncio.run(InterfaceDiscoveryAdapter().discover())
    assert isinstance(result, list)
    for iface in result:
        assert isinstance(iface, NetworkInterface)
        # Filter-Vertrag: kein Loopback, jedes hat IPv4 ODER IPv6-Link-Local.
        assert iface.is_loopback is False
        assert iface.ipv4 is not None or iface.ipv6_link_local is not None
