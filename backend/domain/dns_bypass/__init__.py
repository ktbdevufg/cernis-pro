"""Die dns_bypass-Domaene: Modelle + reine Umgehungs-Klassifikation (ADR 0042).

Netzweiter DNS-Umgehungs-Waechter: entscheidet je vom Sniffer erkannter DNS-Anfrage, ob
ihr Ziel-Resolver eine Umgehung ist (nicht in der erwarteten Menge), und aggregiert die
Umgehungen je (Quell-Geraet, Ziel-Resolver). Reine Domaene -- nur stdlib, KEINE
Fremd-Domaene (kein ``dns_watch``/``devices``/``blocklist``, independence-Contract), kein
Framework, kein infrastructure/modules-Import.
"""

from domain.dns_bypass.logic import (
    is_bypass,
)
from domain.dns_bypass.models import (
    DnsBypassFinding,
    DnsBypassOverview,
    RawDnsQuery,
)
from domain.dns_bypass.recording import (
    MAX_SAMPLE_QNAMES,
    AggregatedBypass,
    BypassDelta,
    DnsBypassDetailRow,
    DnsBypassRecording,
    DnsBypassRecordingState,
    InvalidDnsBypassRecordingTransition,
    edit,
    merge_bypass,
    start,
    stop,
)

__all__ = [
    "MAX_SAMPLE_QNAMES",
    "AggregatedBypass",
    "BypassDelta",
    "DnsBypassDetailRow",
    "DnsBypassFinding",
    "DnsBypassOverview",
    "DnsBypassRecording",
    "DnsBypassRecordingState",
    "InvalidDnsBypassRecordingTransition",
    "RawDnsQuery",
    "edit",
    "is_bypass",
    "merge_bypass",
    "start",
    "stop",
]
