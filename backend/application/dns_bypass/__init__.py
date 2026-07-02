"""Application-Ring des DNS-Umgehungs-Waechters (ADR 0042, Etappe 2).

Das Backend-Fundament fuer die netzweite Umgehungs-Sicht: fuehrt die vom Sniffer
erkannten DNS-Anfragen mit der erwarteten-Resolver-Menge zusammen und aggregiert die
Umgehungen je (Quell-Geraet, Ziel-Resolver). Kennt nur ``application/dns_bypass`` und die
reine ``domain/dns_bypass`` (Modelle + Klassifikation), NIE ``infrastructure``/``modules``
(import-linter) und KEINE Fremd-Domaene. Die Quellen kommen quellen-AGNOSTISCH per
Constructor-Injection als schmale Protocols/Callables herein -- die echte Verdrahtung
faellt erst im Composition Root (app.py).

FACHLICHE GRENZE (ADR 0042): die Domaene bekommt die Quell-IP als ROHEN Schluessel. Die
Zuordnung Quell-IP -> Geraet und die DoH-Blocklist-Bewertung liegen NICHT hier, sondern
spaeter im Composition Root (Regel 5).
"""

from application.dns_bypass.recorder import (
    DnsBypassRecorder,
    DnsQuerySource,
    DnsServerTrustLookup,
)
from application.dns_bypass.use_cases import (
    BuildDnsBypass,
    DnsBypassReport,
    DnsQueryProvider,
    ExpectedServersProvider,
    GetDnsBypassReport,
    StartDnsBypassRecording,
    StopDnsBypassRecording,
)
from domain.dns_bypass import (
    AggregatedBypass,
    DnsBypassFinding,
    DnsBypassOverview,
    RawDnsQuery,
)

__all__ = [
    "AggregatedBypass",
    "BuildDnsBypass",
    "DnsBypassFinding",
    "DnsBypassOverview",
    "DnsBypassRecorder",
    "DnsBypassReport",
    "DnsQueryProvider",
    "DnsQuerySource",
    "DnsServerTrustLookup",
    "ExpectedServersProvider",
    "GetDnsBypassReport",
    "RawDnsQuery",
    "StartDnsBypassRecording",
    "StopDnsBypassRecording",
]
