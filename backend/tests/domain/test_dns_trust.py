"""Tests der reinen DNS-Vertrauens-Domaene (``domain/dns_trust``).

Deckt die reinen Funktionen (``categorize_dns_server`` in ALLEN Prioritaets-
Kombinationen, ``is_private_ip`` fuer RFC1918 v4+v6 / oeffentlich / ungueltig,
``default_trust_for``, ``bypass_verdict`` in ALLEN (Kategorie, Trust)-Kombinationen)
und die drei Uebergangs-Funktionen (``trust``/``reject``/``reset``) voll ab. Reine
Funktionen -- kein I/O, keine Fakes noetig.
"""

from dataclasses import FrozenInstanceError

import pytest

from domain.dns_trust import (
    BypassVerdict,
    DnsServerCategory,
    DnsTrustState,
    TrustedDnsServer,
    bypass_verdict,
    categorize_dns_server,
    default_trust_for,
    is_private_ip,
    reject,
    reset,
    trust,
)


def _server(
    ip: str = "192.168.0.1",
    category: DnsServerCategory = DnsServerCategory.LOCAL_PRIVATE,
    trust_state: DnsTrustState = DnsTrustState.NEUTRAL,
) -> TrustedDnsServer:
    """Baut einen schmalen Server-Record fuer die Uebergangs-Tests."""
    return TrustedDnsServer(
        ip=ip,
        category=category,
        first_seen=100.0,
        last_seen=100.0,
        trust_state=trust_state,
    )


# ── is_private_ip ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "ip",
    [
        "10.0.0.1",  # RFC1918 /8
        "172.16.5.4",  # RFC1918 /12
        "192.168.1.1",  # RFC1918 /16
        "fd00::1",  # ULA (RFC4193)
        "fc00::1",  # ULA
    ],
)
def test_is_private_ip_privat(ip: str) -> None:
    """Private v4- (RFC1918) und v6-Adressen (ULA) sind privat."""
    assert is_private_ip(ip) is True


@pytest.mark.parametrize(
    "ip",
    [
        "8.8.8.8",  # Google Public DNS
        "1.1.1.1",  # Cloudflare
        "9.9.9.9",  # Quad9
        "2001:4860:4860::8888",  # Google v6
    ],
)
def test_is_private_ip_oeffentlich(ip: str) -> None:
    """Oeffentliche Resolver-Adressen sind NICHT privat."""
    assert is_private_ip(ip) is False


@pytest.mark.parametrize(
    "ip",
    ["", "   ", "kein.host.name", "999.999.999.999", "192.168.0.1/24", "muell"],
)
def test_is_private_ip_ungueltig_false(ip: str) -> None:
    """Ungueltige Eingaben -> False (KEIN Werfen, KEIN stiller Erfolg)."""
    assert is_private_ip(ip) is False


def test_is_private_ip_ignoriert_whitespace() -> None:
    """Fuehrender/nachlaufender Whitespace wird abgeschnitten."""
    assert is_private_ip("  10.0.0.1  ") is True


# ── categorize_dns_server (Prioritaet, alle Kombinationen) ────────────────────


def test_categorize_threat_hat_hoechste_prioritaet() -> None:
    """THREAT_LISTED schlaegt bei OEFFENTLICHER IP alle anderen Flags (hoechste Prioritaet)."""
    cat = categorize_dns_server(
        "93.184.216.34",  # oeffentlich -- Threat greift nur hier
        is_gateway=True,
        is_public_resolver=True,
        is_threat_listed=True,
    )
    assert cat is DnsServerCategory.THREAT_LISTED


def test_categorize_threat_bei_privater_ip_ignoriert_gateway() -> None:
    """Threat-Treffer auf private IP ist Bogon-FP -> verworfen; Gateway greift weiter."""
    cat = categorize_dns_server(
        "172.18.0.1",  # privates Gateway, faelschlich threat-gelistet (FireHOL Bogon)
        is_gateway=True,
        is_public_resolver=False,
        is_threat_listed=True,
    )
    assert cat is DnsServerCategory.GATEWAY


def test_categorize_threat_bei_privater_ip_faellt_auf_local_private() -> None:
    """Private IP + threat, ohne Gateway/public -> LOCAL_PRIVATE (Bogon-FP verworfen)."""
    cat = categorize_dns_server(
        "172.18.0.156",  # privater Pi-hole, faelschlich threat-gelistet
        is_gateway=False,
        is_public_resolver=False,
        is_threat_listed=True,
    )
    assert cat is DnsServerCategory.LOCAL_PRIVATE


def test_categorize_gateway_schlaegt_public_und_private() -> None:
    """GATEWAY schlaegt PUBLIC_RESOLVER und LOCAL_PRIVATE (ohne threat)."""
    cat = categorize_dns_server(
        "192.168.0.1",
        is_gateway=True,
        is_public_resolver=True,
        is_threat_listed=False,
    )
    assert cat is DnsServerCategory.GATEWAY


def test_categorize_public_resolver_schlaegt_private() -> None:
    """PUBLIC_RESOLVER schlaegt LOCAL_PRIVATE (ohne threat/gateway)."""
    cat = categorize_dns_server(
        "192.168.0.1",  # privat, aber public-Flag hat Vorrang
        is_gateway=False,
        is_public_resolver=True,
        is_threat_listed=False,
    )
    assert cat is DnsServerCategory.PUBLIC_RESOLVER


def test_categorize_local_private_wenn_privat_und_keine_flags() -> None:
    """Ohne Flags, aber private IP -> LOCAL_PRIVATE (direkter is_private-Check)."""
    cat = categorize_dns_server(
        "10.1.2.3",
        is_gateway=False,
        is_public_resolver=False,
        is_threat_listed=False,
    )
    assert cat is DnsServerCategory.LOCAL_PRIVATE


def test_categorize_unknown_wenn_nichts_zutrifft() -> None:
    """Oeffentliche IP ohne jedes Flag -> UNKNOWN (Auffang)."""
    cat = categorize_dns_server(
        "93.184.216.34",  # oeffentlich (example.com), keine Flags
        is_gateway=False,
        is_public_resolver=False,
        is_threat_listed=False,
    )
    assert cat is DnsServerCategory.UNKNOWN


def test_categorize_gateway_ohne_public_bei_privater_ip() -> None:
    """GATEWAY greift auch, wenn public-Flag aus ist (Gateway vor private)."""
    cat = categorize_dns_server(
        "192.168.0.1",
        is_gateway=True,
        is_public_resolver=False,
        is_threat_listed=False,
    )
    assert cat is DnsServerCategory.GATEWAY


def test_categorize_threat_bei_oeffentlicher_ip_ohne_weitere_flags() -> None:
    """Nur threat-Flag (oeffentliche IP) -> THREAT_LISTED."""
    cat = categorize_dns_server(
        "93.184.216.34",
        is_gateway=False,
        is_public_resolver=False,
        is_threat_listed=True,
    )
    assert cat is DnsServerCategory.THREAT_LISTED


# ── default_trust_for ─────────────────────────────────────────────────────────


def test_default_trust_gateway_ist_trusted() -> None:
    """GATEWAY erhaelt Auto-Vertrauen (TRUSTED) -- ADR 0043."""
    assert default_trust_for(DnsServerCategory.GATEWAY) is DnsTrustState.TRUSTED


@pytest.mark.parametrize(
    "category",
    [
        DnsServerCategory.LOCAL_PRIVATE,
        DnsServerCategory.PUBLIC_RESOLVER,
        DnsServerCategory.UNKNOWN,
        DnsServerCategory.THREAT_LISTED,
    ],
)
def test_default_trust_nicht_gateway_ist_neutral(category: DnsServerCategory) -> None:
    """Alle Nicht-Gateway-Kategorien starten NEUTRAL (Nutzer-Entscheidung noetig)."""
    assert default_trust_for(category) is DnsTrustState.NEUTRAL


# ── bypass_verdict (Drei-Zustands-Urteil, ADR 0043 E4) ────────────────────────


@pytest.mark.parametrize("category", list(DnsServerCategory))
def test_bypass_verdict_trusted_immer_expected(category: DnsServerCategory) -> None:
    """TRUSTED -> EXPECTED, unabhaengig von der Kategorie (bewusste Nutzer-/Auto-Wertung)."""
    assert bypass_verdict(category, DnsTrustState.TRUSTED) is BypassVerdict.EXPECTED


@pytest.mark.parametrize("category", list(DnsServerCategory))
def test_bypass_verdict_rejected_immer_bypass(category: DnsServerCategory) -> None:
    """REJECTED -> BYPASS, unabhaengig von der Kategorie (abgelehnt ist Umgehung)."""
    assert bypass_verdict(category, DnsTrustState.REJECTED) is BypassVerdict.BYPASS


@pytest.mark.parametrize(
    "category",
    [DnsServerCategory.PUBLIC_RESOLVER, DnsServerCategory.THREAT_LISTED],
)
def test_bypass_verdict_neutral_public_oder_threat_ist_bypass(
    category: DnsServerCategory,
) -> None:
    """NEUTRAL + public_resolver/threat_listed -> BYPASS (definitionsgemaess, ohne Aktion)."""
    assert bypass_verdict(category, DnsTrustState.NEUTRAL) is BypassVerdict.BYPASS


@pytest.mark.parametrize(
    "category",
    [
        DnsServerCategory.GATEWAY,
        DnsServerCategory.LOCAL_PRIVATE,
        DnsServerCategory.UNKNOWN,
    ],
)
def test_bypass_verdict_neutral_lokal_gateway_unknown_ist_unclassified(
    category: DnsServerCategory,
) -> None:
    """NEUTRAL + gateway/local_private/unknown -> UNCLASSIFIED (kein Fehlalarm)."""
    assert bypass_verdict(category, DnsTrustState.NEUTRAL) is BypassVerdict.UNCLASSIFIED


# ── Uebergangs-Funktionen (trust / reject / reset) ────────────────────────────


def test_trust_setzt_trusted_und_last_seen() -> None:
    """``trust`` -> TRUSTED, last_seen=now; Kategorie/first_seen unberuehrt."""
    server = _server(trust_state=DnsTrustState.NEUTRAL)
    updated = trust(server, now=200.0)
    assert updated.trust_state is DnsTrustState.TRUSTED
    assert updated.last_seen == 200.0
    assert updated.first_seen == 100.0
    assert updated.category is server.category


def test_reject_setzt_rejected_und_last_seen() -> None:
    """``reject`` -> REJECTED, last_seen=now."""
    server = _server(trust_state=DnsTrustState.TRUSTED)
    updated = reject(server, now=300.0)
    assert updated.trust_state is DnsTrustState.REJECTED
    assert updated.last_seen == 300.0
    assert updated.first_seen == 100.0


def test_reset_setzt_neutral_und_last_seen() -> None:
    """``reset`` -> NEUTRAL, last_seen=now."""
    server = _server(trust_state=DnsTrustState.REJECTED)
    updated = reset(server, now=400.0)
    assert updated.trust_state is DnsTrustState.NEUTRAL
    assert updated.last_seen == 400.0


def test_uebergaenge_lassen_original_unberuehrt() -> None:
    """Die Uebergaenge sind rein -- das Original bleibt unveraendert (frozen)."""
    server = _server(trust_state=DnsTrustState.NEUTRAL)
    trust(server, now=200.0)
    assert server.trust_state is DnsTrustState.NEUTRAL
    assert server.last_seen == 100.0


def test_record_ist_frozen() -> None:
    """``TrustedDnsServer`` ist frozen -- Direkt-Mutation wirft."""
    server = _server()
    with pytest.raises(FrozenInstanceError):
        server.trust_state = DnsTrustState.TRUSTED  # type: ignore[misc]


def test_record_defaults() -> None:
    """Default trust_state=NEUTRAL, display_name='' , notes=''."""
    server = TrustedDnsServer(
        ip="192.168.0.1",
        category=DnsServerCategory.LOCAL_PRIVATE,
        first_seen=1.0,
        last_seen=1.0,
    )
    assert server.trust_state is DnsTrustState.NEUTRAL
    assert server.display_name == ""
    assert server.notes == ""
