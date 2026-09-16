"""Unit-Tests der interfaces-Domaene -- reine Logik, kein I/O.

Prueft die Namens-Klassifikation (``classify_type``), die Status-Ableitung
(``classify_status``), die deterministische Primary-Auswahl (``select_primary``,
ersetzt das Frontend-Raten) und die Projektion ``mark_primary`` sowie die
NetworkInterface-Invariante. Keine Uhr, kein I/O -> rein deterministisch.
"""

import pytest

from domain.interfaces import (
    NetworkInterface,
    classify_status,
    classify_type,
    classify_type_from_if_type,
    mark_primary,
    select_primary,
)


def _iface(name: str, **kwargs: object) -> NetworkInterface:
    """Baut ein NetworkInterface mit sinnvollen Defaults fuer die Auswahl-Tests."""
    return NetworkInterface(name=name, **kwargs)  # type: ignore[arg-type]


# ── classify_type: ein Fall pro Praefix ──────────────────────────────────────


def test_classify_type_wifi() -> None:
    assert classify_type("wlan0") == "wifi"
    assert classify_type("wlp3s0") == "wifi"


def test_classify_type_ethernet() -> None:
    assert classify_type("eth0") == "ethernet"
    assert classify_type("enp0s3") == "ethernet"
    assert classify_type("eno1") == "ethernet"
    assert classify_type("ens33") == "ethernet"


def test_classify_type_loopback() -> None:
    assert classify_type("lo") == "loopback"
    assert classify_type("lo0") == "loopback"
    assert classify_type("lo1") == "loopback"


def test_classify_type_lo_prefix_no_false_match() -> None:
    # 'lo' ist KEIN startswith-Praefix: Namen, die nur zufaellig mit 'lo'
    # beginnen, duerfen NICHT als loopback klassifiziert werden.
    assert classify_type("loooong") == "unknown"
    assert classify_type("london0") == "unknown"
    assert classify_type("lon0") == "unknown"


def test_classify_type_vpn() -> None:
    assert classify_type("tun0") == "vpn"
    assert classify_type("tap0") == "vpn"


def test_classify_type_bridge() -> None:
    assert classify_type("br0") == "bridge"
    assert classify_type("br-1a2b3c") == "bridge"


def test_classify_type_virtual() -> None:
    assert classify_type("docker0") == "virtual"
    assert classify_type("veth1a2b") == "virtual"


def test_classify_type_unknown() -> None:
    assert classify_type("xyz0") == "unknown"
    assert classify_type("ppp0") == "unknown"


def test_classify_type_no_false_match_lo_vs_ethernet() -> None:
    # Abgrenzung: "lo" darf "enp0s3" nicht faelschlich als loopback matchen,
    # und "en"-Interfaces sind ethernet, nicht loopback.
    assert classify_type("enp0s3") == "ethernet"
    assert classify_type("lo") == "loopback"
    # "lo"-Praefix matcht NUR Namen, die mit "lo" beginnen.
    assert classify_type("eth_lo") == "ethernet"


# ── classify_type_from_if_type: numerischer IANA-ifType (Windows-Quelle) ──────


def test_classify_type_from_if_type_ethernet() -> None:
    assert classify_type_from_if_type(6) == "ethernet"


def test_classify_type_from_if_type_wifi() -> None:
    assert classify_type_from_if_type(71) == "wifi"


def test_classify_type_from_if_type_loopback() -> None:
    assert classify_type_from_if_type(24) == "loopback"


def test_classify_type_from_if_type_vpn() -> None:
    assert classify_type_from_if_type(131) == "vpn"


def test_classify_type_from_if_type_bridge() -> None:
    assert classify_type_from_if_type(209) == "bridge"


def test_classify_type_from_if_type_virtual() -> None:
    assert classify_type_from_if_type(53) == "virtual"


def test_classify_type_from_if_type_unknown() -> None:
    # Nicht abgebildeter ifType (z. B. 1 = other) -> unknown.
    assert classify_type_from_if_type(1) == "unknown"


# ── classify_status: alle drei Pfade ─────────────────────────────────────────


def test_classify_status_down() -> None:
    assert classify_status(is_up=False, has_ipv4=True) == "down"
    assert classify_status(is_up=False, has_ipv4=False) == "down"


def test_classify_status_no_ip() -> None:
    assert classify_status(is_up=True, has_ipv4=False) == "no_ip"


def test_classify_status_up() -> None:
    assert classify_status(is_up=True, has_ipv4=True) == "up"


# ── select_primary ───────────────────────────────────────────────────────────


def test_select_primary_single_candidate() -> None:
    ifaces = [
        _iface("lo", is_loopback=True),
        _iface("eth0", ipv4="10.0.0.5", gateway="10.0.0.1"),
    ]
    assert select_primary(ifaces) == "eth0"


def test_select_primary_multiple_candidates_stable_tie_break() -> None:
    # Zwei vollwertige Kandidaten -> der ERSTE in Eingangsreihenfolge gewinnt.
    ifaces = [
        _iface("eth0", ipv4="10.0.0.5", gateway="10.0.0.1"),
        _iface("eth1", ipv4="10.0.1.5", gateway="10.0.1.1"),
    ]
    assert select_primary(ifaces) == "eth0"
    # Reihenfolge umgedreht -> jetzt gewinnt eth1 (Eingangsreihenfolge, nicht Name).
    assert select_primary(list(reversed(ifaces))) == "eth1"


def test_select_primary_none_when_no_candidate() -> None:
    ifaces = [
        _iface("lo", is_loopback=True, ipv4="127.0.0.1"),
        _iface("eth0", ipv4="10.0.0.5"),  # kein gateway
        _iface("eth1", gateway="10.0.0.1"),  # keine ipv4
    ]
    assert select_primary(ifaces) is None


def test_select_primary_skips_loopback_down_and_gatewayless() -> None:
    ifaces = [
        # Loopback mit ipv4+gateway -> trotzdem KEIN Kandidat.
        _iface("lo", is_loopback=True, ipv4="127.0.0.1", gateway="127.0.0.1"),
        # down -> KEIN Kandidat.
        _iface("eth0", is_up=False, ipv4="10.0.0.5", gateway="10.0.0.1"),
        # ohne gateway -> KEIN Kandidat.
        _iface("eth1", ipv4="10.0.1.5"),
        # der einzige echte Kandidat.
        _iface("eth2", ipv4="10.0.2.5", gateway="10.0.2.1"),
    ]
    assert select_primary(ifaces) == "eth2"


def test_select_primary_empty() -> None:
    assert select_primary([]) is None


# ── mark_primary ─────────────────────────────────────────────────────────────


def test_mark_primary_sets_exactly_one() -> None:
    ifaces = [
        _iface("eth0", ipv4="10.0.0.5", gateway="10.0.0.1"),
        _iface("eth1", ipv4="10.0.1.5", gateway="10.0.1.1"),
    ]
    marked = mark_primary(ifaces, "eth1")
    assert [m.is_primary for m in marked] == [False, True]
    # Eingangsreihenfolge bewahrt.
    assert [m.name for m in marked] == ["eth0", "eth1"]


def test_mark_primary_none_marks_nothing() -> None:
    ifaces = [_iface("eth0"), _iface("eth1")]
    marked = mark_primary(ifaces, None)
    assert all(not m.is_primary for m in marked)


def test_mark_primary_unknown_name_marks_nothing() -> None:
    ifaces = [_iface("eth0"), _iface("eth1")]
    marked = mark_primary(ifaces, "wlan9")
    assert all(not m.is_primary for m in marked)


# ── NetworkInterface-Invariante ──────────────────────────────────────────────


def test_network_interface_empty_name_raises() -> None:
    with pytest.raises(ValueError):
        NetworkInterface(name="")


def test_network_interface_defaults_are_none_not_guessed() -> None:
    iface = NetworkInterface(name="eth0")
    assert iface.ipv4 is None
    assert iface.ipv4_prefix is None
    assert iface.network_cidr is None
    assert iface.host_count is None
    assert iface.is_primary is False
    assert iface.type == "unknown"
    assert iface.status == "up"
