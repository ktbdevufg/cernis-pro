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
from enum import StrEnum

from domain.dns_trust.models import DnsServerCategory, DnsTrustState

__all__ = [
    "BypassVerdict",
    "bypass_verdict",
    "categorize_dns_server",
    "default_trust_for",
    "is_platform_placeholder",
    "is_private_ip",
]


# Die drei fest eingebauten, funktionslosen Windows-Platzhalter-DNS-Server (dokumentierte
# Microsoft-Konvention): Windows meldet ueber die Adapter-API immer diese IPv6-Adressen als
# DNS-Server, sie beantworten aber KEINE Anfragen. Als IPv6-Adressobjekte gehalten, damit der
# Vergleich normalisiert laeuft (abweichende Schreibweisen -- z. B. voll ausgeschrieben oder
# mit Grossbuchstaben -- werden ebenso erkannt).
_PLATFORM_PLACEHOLDER_IPS = frozenset(
    ipaddress.IPv6Address(addr)
    for addr in ("fec0:0:0:ffff::1", "fec0:0:0:ffff::2", "fec0:0:0:ffff::3")
)


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


def is_platform_placeholder(ip: str) -> bool:
    """``True``, wenn ``ip`` einer der drei funktionslosen Windows-Platzhalter ist (reine Funktion).

    Windows meldet ueber die Adapter-API immer die fest eingebauten IPv6-Adressen
    ``fec0:0:0:ffff::1``, ``fec0:0:0:ffff::2`` und ``fec0:0:0:ffff::3`` als DNS-Server; diese
    beantworten jedoch keine Anfragen (dokumentierte Microsoft-Konvention). Der Vergleich laeuft
    normalisiert ueber ``ipaddress.IPv6Address``-Objekte -- abweichende, aber gleichwertige
    Schreibweisen (voll ausgeschrieben, Grossschreibung, andere Nullkomprimierung) werden damit
    ebenfalls erkannt.

    Kein IPv6-Literal (IPv4, Hostname, Muell, leer) -> ``False`` -- KEIN Werfen, KEIN stiller
    Erfolg (Muster ``is_private_ip``). Rein, kein Netz. Diese Achse (Funktionsfaehigkeit) ist
    von ``category`` (Herkunft) unabhaengig.
    """
    try:
        return ipaddress.IPv6Address(ip.strip()) in _PLATFORM_PLACEHOLDER_IPS
    except ipaddress.AddressValueError:
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

    THREAT_LISTED gilt nur fuer oeffentliche IPs; ein Threat-Treffer auf eine
    private (RFC1918) Adresse ist ein Bogon-False-Positive und wird verworfen --
    dann greift die normale Prioritaet weiter (Gateway > public > local_private
    > unknown).
    """
    if is_threat_listed and not is_private_ip(ip):
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


class BypassVerdict(StrEnum):
    """Drei-Zustands-Urteil des netzweiten Umgehungs-Waechters je Ziel-Server (ADR 0043, E4).

    Der netzweite Waechter kennt kuenftig DREI Zustaende, nicht zwei -- das trennt
    "noch nicht eingeordnet" sauber von "Umgehung":

    * ``EXPECTED``: erwartet, KEIN Befund (der Server ist vertraut).
    * ``BYPASS``: Umgehungs-Befund (abgelehnt ODER per Kategorie definitionsgemaess
      eine Umgehung).
    * ``UNCLASSIFIED``: noch nicht eingeordnet -- KEIN Befund, aber auch nicht erwartet
      (z. B. der eigene Pi-hole/VPN-Resolver vor der Nutzer-Bestaetigung). Wird NICHT
      als Umgehung gezaehlt (kein Fehlalarm), sondern als "bitte bestaetigen" gefuehrt.
    """

    EXPECTED = "expected"
    BYPASS = "bypass"
    UNCLASSIFIED = "unclassified"


# Kategorien, die im Zustand NEUTRAL bereits DEFINITIONSGEMAESS eine Umgehung sind
# (kein Umkehren der Richtung, Schutz bleibt opt-in): ein oeffentlicher Resolver und ein
# Bedrohungslisten-Treffer sind per se eine Umgehung -- sie muessen nicht erst abgelehnt
# werden. Alle uebrigen Kategorien (gateway/local_private/unknown) sind im Zustand NEUTRAL
# lediglich "noch nicht eingeordnet".
_BYPASS_WHEN_NEUTRAL = frozenset(
    {DnsServerCategory.PUBLIC_RESOLVER, DnsServerCategory.THREAT_LISTED}
)


def bypass_verdict(category: DnsServerCategory, trust_state: DnsTrustState) -> BypassVerdict:
    """Kombiniert Kategorie UND Trust-Zustand zum Drei-Zustands-Urteil (reine Funktion, E4).

    Regeln (ADR 0043, E4):

    1. ``TRUSTED`` -> ``EXPECTED`` (Gateway automatisch, plus bestaetigte Resolver).
    2. ``REJECTED`` -> ``BYPASS``.
    3. ``NEUTRAL`` UND Kategorie in {public_resolver, threat_listed} -> ``BYPASS``
       (definitionsgemaess Umgehung, ohne Nutzer-Aktion -- z. B. ``8.8.8.8`` sofort).
    4. ``NEUTRAL`` sonst (gateway/local_private/unknown) -> ``UNCLASSIFIED``
       (der eigene Pi-hole/VPN-Resolver vor der Bestaetigung: kein Fehlalarm).

    Rein, kein I/O, kein Zeit-Bezug -- die (Kategorie, Trust-Zustand)-Ermittlung je IP
    faellt beim Aufrufer (Composition Root / injizierte Naht).
    """
    if trust_state is DnsTrustState.TRUSTED:
        return BypassVerdict.EXPECTED
    if trust_state is DnsTrustState.REJECTED:
        return BypassVerdict.BYPASS
    # ab hier NEUTRAL: nur public_resolver/threat_listed sind schon Umgehung.
    if category in _BYPASS_WHEN_NEUTRAL:
        return BypassVerdict.BYPASS
    return BypassVerdict.UNCLASSIFIED
