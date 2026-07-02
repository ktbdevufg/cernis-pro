"""Reine Ableitungs-Logik des DNS-Vertrauensmodells (kein I/O -- ADR 0043).

Drei reine Funktionen: ``is_private_ip`` (RFC1918/ULA-Test via ``ipaddress``),
``categorize_dns_server`` (feste Prioritaets-Ableitung der Kategorie) und
``default_trust_for`` (Vor-Belegung des Vertrauens-Zustands je Kategorie).

Bewusst KEINE Lookups hier: Topologie (Gateway?), DoH-Liste (oeffentlicher
Resolver?) und THREAT-Blocklist kommen als vorab aufgeloeste Flags herein -- die
echten Nachschlage-Wege faellt spaeter der Composition Root (Import-Regel 5).
Nur ``is_private`` ist reine Fachlogik ohne I/O und wird hier direkt geprueft.
Muster ``domain.blocklist``/``domain.resolver_names``, die ``ipaddress`` schon
so nutzen. Reine Domaene -- nur stdlib.
"""

import ipaddress

from domain.dns_trust.models import DnsServerCategory, DnsTrustState

__all__ = [
    "categorize_dns_server",
    "default_trust_for",
    "is_private_ip",
]


def is_private_ip(ip: str) -> bool:
    """``True``, wenn ``ip`` eine private Adresse ist (RFC1918 v4, ULA/link-local v6).

    Delegiert an ``ipaddress.ip_address(...).is_private`` (deckt v4 UND v6 ab).
    Kein IP-Literal (Hostname, Muell, leer) -> ``False`` -- KEIN Werfen, KEIN
    stiller Erfolg (Muster ``domain.blocklist.ip_in_cidr``). Rein, kein Netz.
    """
    try:
        return ipaddress.ip_address(ip.strip()).is_private
    except ValueError:
        return False


def categorize_dns_server(
    ip: str,
    *,
    is_gateway: bool,
    is_public_resolver: bool,
    is_threat_listed: bool,
) -> DnsServerCategory:
    """Leitet die ``DnsServerCategory`` nach FESTER Prioritaet ab (reine Funktion).

    Prioritaet (hoechste zuerst): THREAT_LISTED > GATEWAY > PUBLIC_RESOLVER >
    LOCAL_PRIVATE > UNKNOWN. Die drei Flags (Gateway/oeffentlich/threat) sind
    vorab aufgeloeste Lookup-Ergebnisse und kommen als Parameter herein -- die
    ECHTEN Lookups (Topologie, DoH-Liste, THREAT-Blocklist) faellt spaeter der
    Composition Root, NICHT hier (Regel 5). Nur ``is_private`` wird hier direkt
    geprueft (reine Fachlogik ohne I/O).
    """
    if is_threat_listed:
        return DnsServerCategory.THREAT_LISTED
    if is_gateway:
        return DnsServerCategory.GATEWAY
    if is_public_resolver:
        return DnsServerCategory.PUBLIC_RESOLVER
    if is_private_ip(ip):
        return DnsServerCategory.LOCAL_PRIVATE
    return DnsServerCategory.UNKNOWN


def default_trust_for(category: DnsServerCategory) -> DnsTrustState:
    """Vor-Belegung des Vertrauens-Zustands je Kategorie (reine Funktion, ADR 0043).

    Nur der ``GATEWAY`` erhaelt Auto-Vertrauen (``TRUSTED``) -- der Router ist der
    erwartete, legitime DNS-Weg des Netzes. Alle anderen Kategorien starten
    ``NEUTRAL``: hier ist eine bewusste Nutzer-Entscheidung noetig, bevor ein
    Server als vertraut gilt.
    """
    if category is DnsServerCategory.GATEWAY:
        return DnsTrustState.TRUSTED
    return DnsTrustState.NEUTRAL
