"""Die dns_watch-Domaene: Modelle + reine Klassifikations-Logik (Block 2, Etappe 2d).

Host-lokaler DNS-Waechter (Variante A): entscheidet je ausgehender Verbindung DIESES
Hosts, ob sie DNS-relevant ist und in welche von drei Kategorien sie faellt
(``erwartungsgemaess``/``offen``/``moegliche_doh``). Reine Domaene -- nur stdlib,
keine Fremd-Domaene, kein Framework, kein infrastructure/modules-Import.
"""

from domain.dns_watch.logic import (
    CATEGORY_EXPECTED,
    CATEGORY_OPEN,
    CATEGORY_POSSIBLE_DOH,
    classify,
    is_dns_relevant,
)
from domain.dns_watch.models import (
    HOST_SCOPE_LOCAL,
    DnsContact,
    DnsWatchOverview,
    RawDnsConnection,
)

__all__ = [
    "CATEGORY_EXPECTED",
    "CATEGORY_OPEN",
    "CATEGORY_POSSIBLE_DOH",
    "HOST_SCOPE_LOCAL",
    "DnsContact",
    "DnsWatchOverview",
    "RawDnsConnection",
    "classify",
    "is_dns_relevant",
]
