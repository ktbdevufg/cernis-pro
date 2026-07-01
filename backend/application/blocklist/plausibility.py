"""Reiner, zeitfreier Format-Plausibilitaetscheck fuer Blocklist-Quellen (Etappe 3).

Eine kleine Hilfe im Muster ``detect_license_hint``: sie gibt nur einen freundlichen
WARN-HINWEIS zurueck und VERWEIGERT NICHTS. Kennt NUR ``domain.blocklist`` (die Enums) +
stdlib -- kein Netz, keine Uhr, keine Ports.
"""

from domain.blocklist import BlocklistFormat, BlocklistGroup

__all__ = ["doh_group_format_warning"]

# Fuer die DoH-Anbieter-Gruppe plausible Formate: eine DoH-Liste ist IP- oder
# Domain-basiert. HOSTS/ADBLOCK deuten auf eine Tracker-Liste hin (falsche Gruppe).
_DOH_PLAUSIBLE_FORMATS: frozenset[BlocklistFormat] = frozenset(
    {
        BlocklistFormat.IP_LIST,
        BlocklistFormat.DOMAIN_LIST,
        BlocklistFormat.CSV_IP,
        BlocklistFormat.CSV_DOMAIN,
    }
)


def doh_group_format_warning(group: BlocklistGroup, fmt: BlocklistFormat) -> str | None:
    """WARN-Hinweis, wenn ``group==DOH``, aber ``fmt`` nicht IP-/Domain-basiert ist.

    Eine DoH-Anbieter-Liste ist IP- oder Domain-basiert (IP_LIST/DOMAIN_LIST/CSV_IP/
    CSV_DOMAIN). Ein HOSTS-/ADBLOCK-Format deutet auf eine Tracker-Liste hin -- dann
    liefert die Funktion einen Hinweis-String. Fuer alle anderen Gruppen (oder ein
    plausibles Format) ``None``. VERWEIGERT NICHTS (Muster ``detect_license_hint``) --
    reine, netzfreie Funktion.
    """
    if group is BlocklistGroup.DOH and fmt not in _DOH_PLAUSIBLE_FORMATS:
        return (
            f"Format {fmt.value!r} passt nicht zur DoH-Anbieter-Gruppe: eine DoH-Liste ist "
            "IP- oder Domain-basiert (ip_list/domain_list). HOSTS/ADBLOCK deutet auf eine "
            "Tracker-Liste hin."
        )
    return None
