"""Tests fuer den Uebergangs-Interface-Adapter (v2-nativ, modules-frei).

Belegt, dass die aus dem Altcode uebernommene self-contained Discovery-Logik die
erwartete Wire-Form baut. ``_run`` wird gemockt (feste ``ip``-Ausgaben statt echtem
Tooling), damit der Test deterministisch + hostunabhaengig laeuft. Schwerpunkte:
CIDR-Ableitung (network_cidr/broadcast/host_count), MAC-Nachtrag aus ``ip link``,
und das Altcode-Filtern (Loopback + Interfaces ohne IP raus).
"""

import pytest

from infrastructure import interfaces


def _fake_ip_outputs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Haengt feste ``ip``-Ausgaben fuer eth0 (mit IP+GW) und lo + ungenutztes if ein."""
    addr_out = (
        "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n"
        "2: eth0    inet 192.168.1.152/22 brd 192.168.3.255 scope global eth0\\       valid_lft\n"
        "2: eth0    inet6 fe80::1234/64 scope link \\       valid_lft forever\n"
        "3: idle0    inet6 fe80::dead/64 scope link \\       valid_lft forever\n"
    )
    route_out = "default via 192.168.0.1 dev eth0 proto dhcp metric 100\n"
    link_out = (
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n"
        "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
        "    link/ether aa:bb:cc:dd:ee:ff brd ff:ff:ff:ff:ff:ff\n"
    )

    def fake_run(cmd: list[str]) -> str:
        if cmd[:3] == ["ip", "-o", "addr"]:
            return addr_out
        if cmd == ["ip", "route"]:
            return route_out
        if cmd == ["ip", "link"]:
            return link_out
        return ""

    monkeypatch.setattr(interfaces, "_run", fake_run)
    # /sys-Probing aus dem Test heraushalten -> fester hw_type/hw_icon.
    monkeypatch.setattr(interfaces, "_hw_info_linux", lambda name: ("Ethernet", "🔌"))


def test_discover_filtert_loopback_und_leere(monkeypatch: pytest.MonkeyPatch) -> None:
    """Loopback (``lo``) und Interfaces ohne IPv4/IPv6-LL fallen raus."""
    # ``idle0`` hat eine fe80-Adresse -> bleibt (IPv6-LL); ``lo`` faellt raus.
    _fake_ip_outputs(monkeypatch)
    result = interfaces.discover_interfaces()
    names = {iface["name"] for iface in result}
    assert "lo" not in names
    assert "eth0" in names
    assert "idle0" in names  # nur IPv6-LL, aber das reicht (Altcode-Filter)


def test_discover_eth0_wire_form(monkeypatch: pytest.MonkeyPatch) -> None:
    """eth0 traegt IP/Prefix/GW/MAC/MTU + die abgeleiteten CIDR-Felder."""
    _fake_ip_outputs(monkeypatch)
    eth0 = next(i for i in interfaces.discover_interfaces() if i["name"] == "eth0")

    assert eth0["ipv4"] == "192.168.1.152"
    assert eth0["ipv4_prefix"] == 22
    assert eth0["gateway"] == "192.168.0.1"
    assert eth0["mac"] == "aa:bb:cc:dd:ee:ff"
    assert eth0["ipv6_link_local"] == "fe80::1234"
    # CIDR-Ableitung: /22-Netz von .152 ist 192.168.0.0/22, host_count = 2^10 - 2.
    assert eth0["subnet_cidr"] == "192.168.1.152/22"
    assert eth0["network_cidr"] == "192.168.0.0/22"
    assert eth0["broadcast"] == "192.168.3.255"
    assert eth0["host_count"] == 1022
    # hw-Anreicherung (gemockt).
    assert eth0["hw_type"] == "Ethernet"
    assert eth0["hw_icon"] == "🔌"
