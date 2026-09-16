"""Domaenenmodell der maintenance-Domaene: das Vokabular der granularen Loeschung.

Reine Domaenenlogik (stdlib, ADR 0002) -- kein Wissen ueber Persistenz oder HTTP.
Der einzige Inhalt ist der ``str``-Enum ``ScanSelection``: die waehlbaren Posten des
Wartungs-Baukastens (Stufe 1). Muster ``StrEnum`` wie ``domain/outbound_log.py`` --
der Wire-Wert ist der jeweilige String.
"""

from enum import StrEnum


class ScanSelection(StrEnum):
    """Posten der granularen Wartungs-Loeschung (Stufe 1 Baukasten).

    Vier Gruppen -- Scan&Analyse (``scan_history``, ``cve``, ``arp_guard``,
    ``analysis_acknowledgements``, ``known_hosts``), Monitoring (``rtt``, ``sla``,
    ``logging``), Aussenkontakte (``outbound_recordings``), DNS
    (``dns_bypass_recordings``, ``dns_trust_servers``). Die Wurzel-Mitnahme
    (Scan-Historie zieht die uebrigen Scan&Analyse-Posten mit) ist FRONTEND-Sperrlogik;
    das Backend loescht stur die uebergebene Menge.
    """

    SCAN_HISTORY = "scan_history"
    CVE = "cve"
    ARP_GUARD = "arp_guard"
    ANALYSIS_ACKNOWLEDGEMENTS = "analysis_acknowledgements"
    KNOWN_HOSTS = "known_hosts"
    RTT = "rtt"
    SLA = "sla"
    LOGGING = "logging"
    OUTBOUND_RECORDINGS = "outbound_recordings"
    DNS_BYPASS_RECORDINGS = "dns_bypass_recordings"
    DNS_TRUST_SERVERS = "dns_trust_servers"
