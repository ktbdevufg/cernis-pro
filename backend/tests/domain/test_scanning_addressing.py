"""Tests fuer ``domain.scanning.addressing`` (Befund 55) -- reine Domaene.

Kein I/O, keine Fakes: der Helfer rechnet nur. Geprueft wird, dass er genau die
Adressierungsformen verwirft, die nie ein Geraet bezeichnen -- und NICHT mehr.
"""

from domain.scanning.addressing import is_device_address, is_group_mac

# ── is_device_address: geeignete Adressen ───────────────────────────────────


def test_ordinary_host_address_is_suitable() -> None:
    assert is_device_address("192.168.1.50", ("192.168.1.0/24",)) is True


def test_first_and_last_host_address_are_suitable() -> None:
    """Die Raender des Host-Bereichs sind regulaere Hosts -- .1 und .254 im /24."""
    assert is_device_address("192.168.1.1", ("192.168.1.0/24",)) is True
    assert is_device_address("192.168.1.254", ("192.168.1.0/24",)) is True


def test_address_in_second_of_several_cidrs_is_suitable() -> None:
    assert is_device_address("10.0.0.5", ("192.168.1.0/24", "10.0.0.0/24")) is True


# ── is_device_address: ungeeignete Adressen ─────────────────────────────────


def test_network_address_is_not_suitable() -> None:
    assert is_device_address("192.168.1.0", ("192.168.1.0/24",)) is False


def test_broadcast_address_is_not_suitable() -> None:
    assert is_device_address("192.168.1.255", ("192.168.1.0/24",)) is False


def test_address_outside_all_cidrs_is_not_suitable() -> None:
    assert is_device_address("10.99.99.99", ("192.168.1.0/24", "172.16.0.0/24")) is False


def test_unparsable_input_is_not_suitable_and_does_not_raise() -> None:
    assert is_device_address("not-an-ip", ("192.168.1.0/24",)) is False
    assert is_device_address("", ("192.168.1.0/24",)) is False
    assert is_device_address("192.168.1.999", ("192.168.1.0/24",)) is False


def test_empty_cidrs_yield_nothing_suitable() -> None:
    assert is_device_address("192.168.1.50", ()) is False


# ── is_device_address: Sonderformen, auch wenn ein CIDR sie umfasst ─────────


def test_multicast_is_not_suitable_even_inside_a_covering_cidr() -> None:
    """Ein weit gefasstes CIDR macht aus einer Multicast-Adresse kein Geraet."""
    assert is_device_address("224.0.0.251", ("224.0.0.0/24",)) is False
    assert is_device_address("239.255.255.250", ("239.0.0.0/8",)) is False


def test_loopback_is_not_suitable_even_inside_a_covering_cidr() -> None:
    assert is_device_address("127.0.0.1", ("127.0.0.0/8",)) is False


def test_link_local_is_not_suitable_even_inside_a_covering_cidr() -> None:
    assert is_device_address("169.254.10.20", ("169.254.0.0/16",)) is False


# ── is_device_address: /31 und /32 (Sonderfall-Semantik aus interception) ───


def test_slash31_keeps_both_addresses() -> None:
    """Bei /31 fuehrt die stdlib beide Adressen als Hosts -- nichts wird verworfen."""
    assert is_device_address("10.0.0.0", ("10.0.0.0/31",)) is True
    assert is_device_address("10.0.0.1", ("10.0.0.0/31",)) is True


def test_slash32_keeps_its_single_address() -> None:
    assert is_device_address("10.0.0.7", ("10.0.0.7/32",)) is True


def test_slash30_still_excludes_network_and_broadcast() -> None:
    """Die Ausnahme gilt NUR fuer /31 und /32 -- ein /30 schliesst weiter aus."""
    assert is_device_address("10.0.0.0", ("10.0.0.0/30",)) is False
    assert is_device_address("10.0.0.3", ("10.0.0.0/30",)) is False
    assert is_device_address("10.0.0.1", ("10.0.0.0/30",)) is True
    assert is_device_address("10.0.0.2", ("10.0.0.0/30",)) is True


def test_overlapping_cidrs_keep_address_that_is_a_host_in_the_wider_net() -> None:
    """Broadcast des /24 ist im umschliessenden /16 eine gewoehnliche Host-Adresse."""
    assert is_device_address("192.168.1.255", ("192.168.1.0/24", "192.168.0.0/16")) is True
    # Ohne das weitere Netz bleibt sie verworfen.
    assert is_device_address("192.168.1.255", ("192.168.1.0/24",)) is False


# ── is_group_mac ────────────────────────────────────────────────────────────


def test_broadcast_mac_is_a_group_mac() -> None:
    assert is_group_mac("FF:FF:FF:FF:FF:FF") is True
    assert is_group_mac("ff-ff-ff-ff-ff-ff") is True
    assert is_group_mac("ffffffffffff") is True


def test_multicast_mac_is_a_group_mac() -> None:
    """Gesetztes niederwertigstes Bit im ersten Oktett -- 01:00:5e ist IPv4-Multicast."""
    assert is_group_mac("01:00:5E:00:00:FB") is True
    assert is_group_mac("33:33:00:00:00:01") is True  # IPv6-Multicast


def test_ordinary_unicast_mac_is_not_a_group_mac() -> None:
    assert is_group_mac("AA:BB:CC:DD:EE:01") is False
    assert is_group_mac("DE:AD:BE:EF:00:07") is False


def test_empty_or_unreadable_mac_is_not_a_group_mac() -> None:
    """Eine leere MAC ist ein regulaerer Zustand und darf hier nicht haengenbleiben."""
    assert is_group_mac("") is False
    assert is_group_mac(" : : ") is False
    assert is_group_mac("z") is False
