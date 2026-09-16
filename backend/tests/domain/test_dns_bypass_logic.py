"""Tests der reinen Umgehungs-Klassifikation (``domain/dns_bypass/logic``).

Deckt ``is_bypass`` voll ab: Ziel in der erwarteten Menge (keine Umgehung), Ziel nicht in
der Menge (Umgehung), leere Menge (alles Umgehung) und die defensive IP-Normalisierung
(strip + lower) gegen die erwartete Menge. Reine Funktion -- kein I/O, keine Fakes noetig.
"""

from domain.dns_bypass import (
    RawDnsQuery,
    is_bypass,
)


def _query(dst_ip: str) -> RawDnsQuery:
    """Baut eine schmale Anfrage -- nur dst_ip ist fuer die Logik relevant."""
    return RawDnsQuery(src_ip="10.0.0.5", dst_ip=dst_ip, l4="udp", qname="")


def test_is_bypass_ziel_erwartet_ist_keine_umgehung() -> None:
    """dst_ip in der erwarteten Menge -> keine Umgehung."""
    assert is_bypass(_query("192.168.0.1"), expected_ips={"192.168.0.1"}) is False


def test_is_bypass_ziel_nicht_erwartet_ist_umgehung() -> None:
    """dst_ip NICHT in der erwarteten Menge -> Umgehung."""
    assert is_bypass(_query("8.8.8.8"), expected_ips={"192.168.0.1"}) is True


def test_is_bypass_leere_menge_ist_immer_umgehung() -> None:
    """Leere erwartete Menge -> jede Anfrage ist Umgehung."""
    assert is_bypass(_query("192.168.0.1"), expected_ips=set()) is True


def test_is_bypass_normalisiert_ziel_ip() -> None:
    """Der Vergleich gegen die erwartete Menge ist defensiv normalisiert (strip + lower)."""
    assert is_bypass(_query("  2001:DB8::1 "), expected_ips={"2001:db8::1"}) is False
