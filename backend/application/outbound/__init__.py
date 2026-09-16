"""Application-Ring der outbound-Aggregation (Block 2, Etappe 2a).

Das gemeinsame Backend-Fundament fuer die Aussenkontakt-Sicht DIESES Hosts: fuehrt
drei Quellen (ausgehende Verbindungen, Namen, Geo/Betreiber/ASN) zu einer Sicht
zusammen. Kennt nur ``application/outbound`` (eigene ``models``), NIE
``infrastructure``/``modules`` oder Fremd-Domaenen (import-linter). Die drei Quellen
kommen quellen-AGNOSTISCH per Constructor-Injection als schmale Protocols/Callables
herein -- die echte Verdrahtung faellt erst im Composition Root (app.py).

FACHLICHE GRENZE (S3-ehrlich): die spaeteren Quellen sehen NUR die Verbindungen DIESES
CERNIS-Hosts, nicht netzweit. Die Sicht ist "Aussenkontakte DIESES Rechners"
(``host_scope``-Marker), nichts Netzweites wird vorgetaeuscht.
"""

from application.outbound.models import (
    OutboundContact,
    OutboundOverview,
    RawConnection,
)
from application.outbound.use_cases import (
    HOST_SCOPE_LOCAL,
    BuildOutboundContacts,
    GeoOperatorProvider,
    HostnameProvider,
    OutboundConnectionsProvider,
)

__all__ = [
    "HOST_SCOPE_LOCAL",
    "BuildOutboundContacts",
    "GeoOperatorProvider",
    "HostnameProvider",
    "OutboundConnectionsProvider",
    "OutboundContact",
    "OutboundOverview",
    "RawConnection",
]
