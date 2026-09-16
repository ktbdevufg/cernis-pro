"""Application-Ring des DNS-Waechters (Block 2, Etappe 2d-1).

Das Backend-Fundament fuer die host-lokale DNS-Befund-Sicht DIESES Hosts: fuehrt die
ausgehenden Verbindungen mit zwei editierbaren Listen (erwartete DNS-Server, DoH-
Anbieter) und einer Namens-Anreicherung zusammen. Kennt nur ``application/dns_watch``
und die reine ``domain/dns_watch`` (Modelle + Klassifikation), NIE
``infrastructure``/``modules`` (import-linter). Die Quellen kommen quellen-AGNOSTISCH
per Constructor-Injection als schmale Protocols/Callables herein -- die echte
Verdrahtung faellt erst im Composition Root (app.py).

FACHLICHE GRENZE (S3-ehrlich): die spaeteren Quellen sehen NUR die Verbindungen DIESES
CERNIS-Hosts, nicht netzweit. Die Sicht ist "die DNS-relevanten Aussenkontakte DIESES
Rechners" (``host_scope``-Marker), nichts Netzweites wird vorgetaeuscht.
"""

from application.dns_watch.use_cases import (
    AcknowledgedProvider,
    BuildDnsWatch,
    DnsConnectionsProvider,
    DohProvidersProvider,
    ExpectedServersProvider,
    HostnameProvider,
)
from domain.dns_watch import (
    HOST_SCOPE_LOCAL,
    DnsContact,
    DnsWatchOverview,
    RawDnsConnection,
)

__all__ = [
    "HOST_SCOPE_LOCAL",
    "AcknowledgedProvider",
    "BuildDnsWatch",
    "DnsConnectionsProvider",
    "DnsContact",
    "DnsWatchOverview",
    "DohProvidersProvider",
    "ExpectedServersProvider",
    "HostnameProvider",
    "RawDnsConnection",
]
