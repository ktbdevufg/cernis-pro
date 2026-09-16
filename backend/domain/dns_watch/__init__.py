"""Die dns_watch-Domaene: Modelle + reine Klassifikations-Logik (Block 2, Etappe 2d).

Host-lokaler DNS-Waechter (Variante A): entscheidet je ausgehender Verbindung DIESES
Hosts, ob sie DNS-relevant ist und in welche von drei Kategorien sie faellt
(``erwartungsgemaess``/``offen``/``moegliche_doh``). Reine Domaene -- nur stdlib,
keine Fremd-Domaene, kein Framework, kein infrastructure/modules-Import.
"""

from domain.dns_watch.defaults import (
    DEFAULT_DOH_PROVIDER_IPS,
    doh_providers_or_default,
)
from domain.dns_watch.logic import (
    ACKNOWLEDGED_COUNT_KEYS,
    CATEGORY_EXPECTED,
    CATEGORY_OPEN,
    CATEGORY_POSSIBLE_DOH,
    acknowledged_count_key,
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
    "ACKNOWLEDGED_COUNT_KEYS",
    "CATEGORY_EXPECTED",
    "CATEGORY_OPEN",
    "CATEGORY_POSSIBLE_DOH",
    "DEFAULT_DOH_PROVIDER_IPS",
    "HOST_SCOPE_LOCAL",
    "DnsContact",
    "DnsWatchOverview",
    "RawDnsConnection",
    "acknowledged_count_key",
    "classify",
    "doh_providers_or_default",
    "is_dns_relevant",
]
