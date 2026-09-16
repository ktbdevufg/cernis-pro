"""Die dns_trust-Domaene: DNS-Server-Vertrauensmodell (Etappe 1, Fundament -- ADR 0043).

Ein abgestuftes, nutzer-kuratiertes Vertrauensmodell fuer DNS-Server, das die
starre "erwartete Menge" des netzweiten Umgehungs-Waechters (0042) ersetzt.
Diese Etappe baut NUR die reine Domaene (Werte + Aggregat + reine Ableitungs-/
Uebergangs-Funktionen) -- KEINE Infrastruktur, KEINE Ableitungs-Verdrahtung,
KEIN Waechter-Umbau (spaetere Etappen).

Eigenstaendiges Konzept: KEIN Import aus einer anderen ``domain``-Subdomaene
(insb. NICHT in ``dns_watch``/``dns_bypass`` reingedrueckt). Reine Domaene --
nur stdlib (``ipaddress``/``dataclasses``/``enum``).
"""

from domain.dns_trust.logic import (
    BypassVerdict,
    bypass_verdict,
    canonical_dns_ip,
    categorize_dns_server,
    default_trust_for,
    is_platform_placeholder,
    is_private_ip,
)
from domain.dns_trust.models import (
    DnsServerCategory,
    DnsServerOrigin,
    DnsTrustState,
    TrustedDnsServer,
    reject,
    reset,
    trust,
)

__all__ = [
    "BypassVerdict",
    "DnsServerCategory",
    "DnsServerOrigin",
    "DnsTrustState",
    "TrustedDnsServer",
    "bypass_verdict",
    "canonical_dns_ip",
    "categorize_dns_server",
    "default_trust_for",
    "is_platform_placeholder",
    "is_private_ip",
    "reject",
    "reset",
    "trust",
]
