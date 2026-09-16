"""Tests der reinen DNS-Waechter-Klassifikation (``domain/dns_watch/logic``).

Deckt ``is_dns_relevant`` und ``classify`` voll ab: alle drei Kategorien
(erwartungsgemaess/offen/moegliche_doh), der None-Fall (nicht DNS-relevant) und die
defensive IP-Normalisierung (strip + lower) gegen die erwarteten/DoH-Mengen. Reine
Funktionen -- kein I/O, keine Fakes noetig.
"""

from domain.dns_watch import (
    CATEGORY_EXPECTED,
    CATEGORY_OPEN,
    CATEGORY_POSSIBLE_DOH,
    RawDnsConnection,
    classify,
    is_dns_relevant,
)


def _conn(remote_ip: str, remote_port: int | None) -> RawDnsConnection:
    """Baut eine schmale Verbindung -- nur ip/port sind fuer die Logik relevant."""
    return RawDnsConnection(
        remote_ip=remote_ip, remote_port=remote_port, l4=None, app_name=None, pid=None
    )


# ── is_dns_relevant ───────────────────────────────────────────────────────────


def test_is_dns_relevant_port_53_immer_relevant() -> None:
    """Port 53 ist immer DNS-relevant -- unabhaengig von den DoH-IPs."""
    assert is_dns_relevant(_conn("9.9.9.9", 53), doh_provider_ips=set()) is True


def test_is_dns_relevant_port_443_nur_bei_doh_ip() -> None:
    """Port 443 ist nur relevant, wenn die IP in den DoH-Anbieter-IPs steht."""
    doh = {"1.1.1.1"}
    assert is_dns_relevant(_conn("1.1.1.1", 443), doh_provider_ips=doh) is True
    assert is_dns_relevant(_conn("8.8.8.8", 443), doh_provider_ips=doh) is False


def test_is_dns_relevant_andere_ports_irrelevant() -> None:
    """Weder Port 53 noch DoH-443 -> nicht DNS-relevant."""
    assert is_dns_relevant(_conn("1.1.1.1", 80), doh_provider_ips={"1.1.1.1"}) is False
    assert is_dns_relevant(_conn("1.1.1.1", None), doh_provider_ips={"1.1.1.1"}) is False


def test_is_dns_relevant_443_normalisiert_ip() -> None:
    """Der DoH-Vergleich auf Port 443 normalisiert die IP defensiv (strip + lower)."""
    doh = {"2001:db8::1"}
    assert is_dns_relevant(_conn("  2001:DB8::1 ", 443), doh_provider_ips=doh) is True


# ── classify: alle drei Kategorien + None ─────────────────────────────────────


def test_classify_erwartungsgemaess() -> None:
    """Port 53 zu einer erwarteten IP -> erwartungsgemaess."""
    result = classify(
        _conn("192.168.0.1", 53),
        expected_server_ips={"192.168.0.1"},
        doh_provider_ips=set(),
    )
    assert result == CATEGORY_EXPECTED


def test_classify_offen() -> None:
    """Port 53 zu einer NICHT erwarteten IP -> offen (fremder Resolver)."""
    result = classify(
        _conn("8.8.8.8", 53),
        expected_server_ips={"192.168.0.1"},
        doh_provider_ips=set(),
    )
    assert result == CATEGORY_OPEN


def test_classify_moegliche_doh() -> None:
    """Port 443 zu einer DoH-Anbieter-IP -> moegliche_doh."""
    result = classify(
        _conn("1.1.1.1", 443),
        expected_server_ips=set(),
        doh_provider_ips={"1.1.1.1"},
    )
    assert result == CATEGORY_POSSIBLE_DOH


def test_classify_443_ohne_doh_ip_ist_none() -> None:
    """Port 443 zu einer NICHT-DoH-IP ist nicht DNS-relevant -> None."""
    result = classify(
        _conn("8.8.8.8", 443),
        expected_server_ips=set(),
        doh_provider_ips={"1.1.1.1"},
    )
    assert result is None


def test_classify_anderer_port_ist_none() -> None:
    """Weder Port 53 noch DoH-443 -> None (kein Eintrag)."""
    assert (
        classify(_conn("1.1.1.1", 80), expected_server_ips=set(), doh_provider_ips={"1.1.1.1"})
        is None
    )
    assert (
        classify(_conn("1.1.1.1", None), expected_server_ips=set(), doh_provider_ips=set()) is None
    )


# ── Normalisierung ────────────────────────────────────────────────────────────


def test_classify_normalisiert_erwartete_ip() -> None:
    """Der Vergleich gegen die erwarteten IPs ist defensiv normalisiert (strip + lower)."""
    result = classify(
        _conn("  2001:DB8::5 ", 53),
        expected_server_ips={"2001:db8::5"},
        doh_provider_ips=set(),
    )
    assert result == CATEGORY_EXPECTED


def test_classify_normalisiert_doh_ip() -> None:
    """Der Vergleich gegen die DoH-IPs ist ebenfalls normalisiert."""
    result = classify(
        _conn("2606:4700:4700::1111 ", 443),
        expected_server_ips=set(),
        doh_provider_ips={"2606:4700:4700::1111"},
    )
    assert result == CATEGORY_POSSIBLE_DOH
