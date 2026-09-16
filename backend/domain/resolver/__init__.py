"""Die resolver-Domaene: wer ist die Gegenstelle? -- Fakten mit Quelle, nie verschmolzen.

resolver beantwortet "wer ist das Gegenueber einer Verbindung?" als eine SAMMLUNG VON
FAKTEN MIT QUELLE (``RemoteEndpointFacts``), nicht als ein verschmolzenes Urteil. Jedes
Feld ist ein ``ResolverFact`` mit eigenem ``SourceTag`` -- Widersprueche zwischen
Quellen (z. B. RDAP- vs. GeoDB-Land) bleiben SICHTBAR statt wegverschmolzen. Die reinen
Funktionen (``confirm_forward``, ``flag_country_conflict``, ``detect_self_signed``,
``service_hint_for_port``) leiten daraus wertneutrale Aussagen ab -- AUFZEIGEN +
EINORDNEN, NIE URTEILEN. Die Rohtypen der Quell-Ports (``RdapRawFacts``,
``GeoAsnRecord``) leben ebenfalls hier; ``ports.resolver`` importiert sie von hier.
"""

from domain.resolver.logic import (
    confirm_forward,
    derive_dyndns,
    detect_self_signed,
    flag_country_conflict,
    service_hint_for_port,
)
from domain.resolver.models import (
    GeoAsnRecord,
    RdapRawFacts,
    RemoteEndpointFacts,
    ResolverFact,
    SourceTag,
    TlsCertDetails,
)

__all__ = [
    "GeoAsnRecord",
    "RdapRawFacts",
    "RemoteEndpointFacts",
    "ResolverFact",
    "SourceTag",
    "TlsCertDetails",
    "confirm_forward",
    "derive_dyndns",
    "detect_self_signed",
    "flag_country_conflict",
    "service_hint_for_port",
]
