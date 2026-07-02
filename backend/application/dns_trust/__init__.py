"""Application-Ring des DNS-Server-Vertrauensmodells (ADR 0043, Etappe 3).

Kategorisiert erkannte DNS-Server (reine ``domain.dns_trust``-Logik), reichert sie mit
Bestands-Indizien an und persistiert sie (``ports.dns_trust``); Nutzer-Aktionen
vertrauen/ablehnen/zuruecksetzen sind eigene Use-Cases. Kennt NUR ``domain.dns_trust`` +
``ports.dns_trust`` -- NIE ``infrastructure``/``modules`` (import-linter) und KEINE
Fremd-Domaene. Alle externen Zugriffe kommen als schmale injizierte Protocols/Callables
herein; die echten Lookups faellt erst der Composition Root (app.py, Regel 5).

NOCH KEINE api, KEIN Frontend, KEIN Umbau der bestehenden Waechter-Klassifikation
(``expected_servers``) -- das ist E4/E5/E6.
"""

from application.dns_trust.use_cases import (
    DnsServerPlausibility,
    GatewayProvider,
    ListDnsTrustServers,
    PlausibilityProvider,
    PublicResolverCheck,
    SetDnsServerTrust,
    SyncDnsTrustServer,
    ThreatCheck,
    TrustedDnsServerIps,
)

__all__ = [
    "DnsServerPlausibility",
    "GatewayProvider",
    "ListDnsTrustServers",
    "PlausibilityProvider",
    "PublicResolverCheck",
    "SetDnsServerTrust",
    "SyncDnsTrustServer",
    "ThreatCheck",
    "TrustedDnsServerIps",
]
