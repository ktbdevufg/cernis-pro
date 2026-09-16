"""Tests der statischen Bekannte-Resolver-Tabelle (reine Domaenen-Daten/Logik).

Prueft: die grossen oeffentlichen Resolver loesen auf (Google/Cloudflare/Quad9/OpenDNS),
IPv6-Pendants loesen schreibweise-unabhaengig auf (kanonisiert), eine unbekannte IP und
ein Nicht-IP-Literal liefern ``None`` (kein Treffer, kein Fehler).
"""

import pytest

from domain.resolver_names import known_resolver_name


@pytest.mark.parametrize(
    ("ip", "erwartet"),
    [
        ("8.8.8.8", "Google Public DNS"),
        ("8.8.4.4", "Google Public DNS"),
        ("1.1.1.1", "Cloudflare DNS"),
        ("1.0.0.1", "Cloudflare DNS"),
        ("9.9.9.9", "Quad9 DNS"),
        ("149.112.112.112", "Quad9 DNS"),
        ("208.67.222.222", "OpenDNS"),
        ("208.67.220.220", "OpenDNS"),
    ],
)
def test_bekannte_ipv4_resolver(ip: str, erwartet: str) -> None:
    assert known_resolver_name(ip) == erwartet


@pytest.mark.parametrize(
    ("ip", "erwartet"),
    [
        ("2001:4860:4860::8888", "Google Public DNS"),
        ("2606:4700:4700::1111", "Cloudflare DNS"),
        ("2620:fe::fe", "Quad9 DNS"),
    ],
)
def test_bekannte_ipv6_resolver(ip: str, erwartet: str) -> None:
    assert known_resolver_name(ip) == erwartet


def test_ipv6_schreibweise_unabhaengig() -> None:
    # Ausgeschriebene Nullen + Grossschreibung muessen denselben Treffer liefern wie die
    # kanonische Kurzform (der Lookup kanonisiert die Eingabe).
    assert known_resolver_name("2606:4700:4700:0:0:0:0:1111") == "Cloudflare DNS"
    assert known_resolver_name("2606:4700:4700::1111".upper()) == "Cloudflare DNS"


def test_unbekannte_ip_ist_none() -> None:
    assert known_resolver_name("10.0.0.1") is None
    assert known_resolver_name("192.168.1.1") is None


def test_kein_ip_literal_ist_none() -> None:
    assert known_resolver_name("dns.google") is None
    assert known_resolver_name("") is None
