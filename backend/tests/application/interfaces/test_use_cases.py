"""Tests des ListInterfaces-Use-Case gegen einen In-Memory-Fake des Ports.

Kein echtes ``ip``-Tooling noetig -- wir testen gegen das Protocol. Kern der
Behauptungen: die fachliche Anreicherung (``type``/``status``) passiert im
Use-Case, das Primary-Interface wird deterministisch markiert (ersetzt das
Frontend-Raten), und die Eingangsreihenfolge des Adapters bleibt erhalten.
Async via ``asyncio.run`` (Projektmuster, kein pytest-asyncio).
"""

import asyncio

from application.interfaces import ListInterfaces
from domain.interfaces import NetworkInterface

# ── In-Memory-Fake des Ports ─────────────────────────────────────────────────


class FakeDiscovery:
    """In-Memory-Implementierung des ``InterfaceDiscoveryPort``-Protocols."""

    def __init__(self, interfaces: list[NetworkInterface]) -> None:
        self._interfaces = interfaces
        self.discover_calls = 0

    async def discover(self) -> list[NetworkInterface]:
        self.discover_calls += 1
        return list(self._interfaces)


# ── (a) Anreicherung type/status + Primary-Markierung ─────────────────────────


def test_list_interfaces_enriches_type_and_status_and_marks_primary() -> None:
    fake = FakeDiscovery(
        [
            # roh: type/status/is_primary noch auf Default, werden vom Use-Case gesetzt.
            NetworkInterface(name="lo", ipv4="127.0.0.1", is_loopback=True),
            NetworkInterface(name="wlp3s0", ipv4=None, is_up=True),
            NetworkInterface(name="eth0", ipv4="10.0.0.5", gateway="10.0.0.1", is_up=True),
        ]
    )
    result = asyncio.run(ListInterfaces(fake)())

    by_name = {iface.name: iface for iface in result}
    # type aus classify_type
    assert by_name["lo"].type == "loopback"
    assert by_name["wlp3s0"].type == "wifi"
    assert by_name["eth0"].type == "ethernet"
    # status aus classify_status(is_up, ipv4 is not None)
    assert by_name["lo"].status == "up"  # is_up=True (default) + ipv4 vorhanden
    assert by_name["wlp3s0"].status == "no_ip"  # is_up aber keine ipv4
    assert by_name["eth0"].status == "up"
    # is_primary genau auf dem Default-Route-Kandidaten (eth0: ipv4+gateway+up+!lo)
    assert by_name["eth0"].is_primary is True
    assert by_name["lo"].is_primary is False
    assert by_name["wlp3s0"].is_primary is False


# ── (a2) Vom Adapter gesetzter type bleibt erhalten ──────────────────────────


def test_list_interfaces_preserves_adapter_set_type() -> None:
    # Ein Adapter (z. B. Windows via IfType) liefert bereits einen type != unknown.
    # Der Use-Case darf ihn NICHT ueber die namensbasierte classify_type ueber-
    # schreiben -- der Windows-Anzeigename "Ethernet0" trifft keinen Linux-Praefix.
    fake = FakeDiscovery(
        [
            NetworkInterface(
                name="Ethernet0", ipv4="10.0.0.5", gateway="10.0.0.1", type="ethernet"
            ),
            # unknown -> weiterhin ueber classify_type(name) nachbestimmt (eth0 -> ethernet).
            NetworkInterface(name="eth0", ipv4="10.0.1.5"),
        ]
    )
    result = asyncio.run(ListInterfaces(fake)())

    by_name = {iface.name: iface for iface in result}
    assert by_name["Ethernet0"].type == "ethernet"  # erhalten (nicht auf unknown ueberschrieben)
    assert by_name["eth0"].type == "ethernet"  # unknown -> namensbasiert nachbestimmt


# ── (b) Reihenfolge bewahrt ──────────────────────────────────────────────────


def test_list_interfaces_preserves_order() -> None:
    fake = FakeDiscovery(
        [
            NetworkInterface(name="eth2", ipv4="10.0.2.5", gateway="10.0.2.1"),
            NetworkInterface(name="eth0", ipv4="10.0.0.5", gateway="10.0.0.1"),
            NetworkInterface(name="eth1", ipv4="10.0.1.5", gateway="10.0.1.1"),
        ]
    )
    result = asyncio.run(ListInterfaces(fake)())

    assert [iface.name for iface in result] == ["eth2", "eth0", "eth1"]
    # Stabiler Tie-Break: der ERSTE Kandidat in Eingangsreihenfolge ist primary.
    assert result[0].is_primary is True
    assert result[1].is_primary is False
    assert result[2].is_primary is False


# ── (c) Kein Primary-Kandidat -> nichts is_primary ───────────────────────────


def test_list_interfaces_no_primary_candidate() -> None:
    fake = FakeDiscovery(
        [
            # loopback -> nie Kandidat, auch mit gateway
            NetworkInterface(name="lo", ipv4="127.0.0.1", gateway="127.0.0.1", is_loopback=True),
            # down -> nie Kandidat
            NetworkInterface(name="eth0", ipv4="10.0.0.5", gateway="10.0.0.1", is_up=False),
            # ohne gateway -> nie Kandidat
            NetworkInterface(name="eth1", ipv4="10.0.1.5"),
        ]
    )
    result = asyncio.run(ListInterfaces(fake)())

    assert all(iface.is_primary is False for iface in result)
    # status weiterhin korrekt angereichert (eth0 down)
    by_name = {iface.name: iface for iface in result}
    assert by_name["eth0"].status == "down"


# ── (d) Leere Discovery -> leere Liste, discover genau 1x ─────────────────────


def test_list_interfaces_empty_discovery() -> None:
    fake = FakeDiscovery([])
    result = asyncio.run(ListInterfaces(fake)())

    assert result == []
    assert fake.discover_calls == 1
