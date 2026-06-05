"""Tests fuer den Linux-Interface-Adapter (I.3).

Getestet werden die REINEN Parse-Hilfsfunktionen (operstate/gateways/addrs/macs)
OHNE echtes ``ip``-/``/sys``-Tooling -- deterministisch und hostunabhaengig. Der
async-``discover``-Wrapper wird ueber gemockte ``_run``/``_read_operstate`` belegt
(Form-Treue + Filter + run_in_executor-Pfad), via ``asyncio.run`` (Projektmuster,
kein pytest-asyncio).

Schwerpunkte:
* ``parse_operstate``: up->True, down->False, unknown/leer -> dokumentierter
  Fallback True (die I.1-Verbesserung gegenueber dem hardcodeten True der Kruecke).
* ``parse_gateways``: Default-Route -> {dev: via}.
* ``discover``: rohe NetworkInterface-Form, Filter (Loopback + leere raus),
  echter is_up aus operstate.
"""

import asyncio

import pytest

from domain.interfaces import NetworkInterface
from infrastructure import interfaces_linux
from infrastructure.interfaces_linux import (
    InterfaceDiscoveryAdapter,
    parse_gateways,
    parse_operstate,
)
from ports.interfaces import InterfaceDiscoveryPort

# ── Struktureller Vertrag ─────────────────────────────────────────────────


def test_conforms_to_discovery_protocol() -> None:
    adapter: InterfaceDiscoveryPort = InterfaceDiscoveryAdapter()
    assert adapter is not None


# ── parse_operstate ───────────────────────────────────────────────────────


def test_parse_operstate_up() -> None:
    assert parse_operstate("up") is True
    assert parse_operstate("up\n") is True
    assert parse_operstate("UP") is True


def test_parse_operstate_down() -> None:
    assert parse_operstate("down") is False
    assert parse_operstate("down\n") is False


def test_parse_operstate_unknown_falls_back_to_true() -> None:
    # Dokumentierter Fallback: unklarer/leerer Status -> True (regressionsfrei
    # ggue. der Kruecke, die IMMER True annahm).
    assert parse_operstate("unknown") is True
    assert parse_operstate("") is True
    assert parse_operstate("dormant") is True


# ── parse_gateways ────────────────────────────────────────────────────────


def test_parse_gateways_extracts_default_route() -> None:
    out = (
        "default via 192.168.0.1 dev eth0 proto dhcp metric 100\n"
        "192.168.0.0/22 dev eth0 proto kernel scope link src 192.168.1.152\n"
    )
    assert parse_gateways(out) == {"eth0": "192.168.0.1"}


def test_parse_gateways_no_default() -> None:
    assert parse_gateways("192.168.0.0/22 dev eth0 scope link\n") == {}


# ── discover (gemockte Roh-Outputs) ───────────────────────────────────────


def _fake_outputs(monkeypatch: pytest.MonkeyPatch, operstate: str = "up") -> None:
    """Haengt feste ``ip``-Ausgaben fuer lo + eth0 (mit IP+GW) + idle0 (nur LL) ein."""
    addr_out = (
        "1: lo    inet 127.0.0.1/8 scope host lo\n"
        "2: eth0    inet 192.168.1.152/22 brd 192.168.3.255 scope global eth0\n"
        "2: eth0    inet6 fe80::1234/64 scope link\n"
        "3: idle0    inet6 fe80::dead/64 scope link\n"
    )
    route_out = "default via 192.168.0.1 dev eth0 proto dhcp metric 100\n"
    link_out = (
        "1: lo: <LOOPBACK,UP> mtu 65536\n"
        "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
        "2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500\n"
        "    link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff\n"
    )

    def fake_run(cmd: list[str]) -> str:
        if cmd[:2] == ["ip", "route"]:
            return route_out
        if cmd[:3] == ["ip", "-o", "addr"]:
            return addr_out
        if cmd[:2] == ["ip", "link"]:
            return link_out
        return ""

    monkeypatch.setattr(interfaces_linux, "_run", fake_run)
    monkeypatch.setattr(
        interfaces_linux, "_read_operstate", lambda name: parse_operstate(operstate)
    )


def test_discover_filters_loopback_and_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_outputs(monkeypatch)
    result = asyncio.run(InterfaceDiscoveryAdapter().discover())
    names = {iface.name for iface in result}
    # lo (Loopback) raus; idle0 hat nur IPv6-LL -> bleibt drin; eth0 drin.
    assert "lo" not in names
    assert names == {"eth0", "idle0"}


def test_discover_eth0_raw_form(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_outputs(monkeypatch, operstate="up")
    result = asyncio.run(InterfaceDiscoveryAdapter().discover())
    eth0 = next(i for i in result if i.name == "eth0")

    assert isinstance(eth0, NetworkInterface)
    assert eth0.ipv4 == "192.168.1.152"
    assert eth0.ipv4_prefix == 22
    assert eth0.mac == "aa:bb:cc:dd:ee:ff"
    assert eth0.gateway == "192.168.0.1"
    assert eth0.ipv6_link_local == "fe80::1234"
    assert eth0.is_up is True
    assert eth0.is_loopback is False
    # network_cidr/host_count traegt die Domaene (aus ipv4/prefix abgeleitet).
    assert eth0.network_cidr == "192.168.0.0/22"
    assert eth0.host_count == 1022
    # roh: type/status/is_primary noch auf Default (Use-Case setzt sie spaeter).
    assert eth0.type == "unknown"
    assert eth0.status == "up"
    assert eth0.is_primary is False


def test_discover_reads_real_operstate_down(monkeypatch: pytest.MonkeyPatch) -> None:
    # Der echte is_up-Status kommt aus operstate -- KEIN hardcodetes True mehr.
    _fake_outputs(monkeypatch, operstate="down")
    result = asyncio.run(InterfaceDiscoveryAdapter().discover())
    eth0 = next(i for i in result if i.name == "eth0")
    assert eth0.is_up is False
