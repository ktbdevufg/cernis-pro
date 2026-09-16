"""Tests des Format-Plausibilitaetschecks (Etappe 3).

``doh_group_format_warning`` warnt NUR bei group==DOH mit unpassendem Format und
verweigert NICHTS (nur Hinweis, Muster ``detect_license_hint``).
"""

from application.blocklist.plausibility import doh_group_format_warning
from domain.blocklist import BlocklistFormat, BlocklistGroup


def test_doh_mit_hosts_format_warnt() -> None:
    warning = doh_group_format_warning(BlocklistGroup.DOH, BlocklistFormat.HOSTS)
    assert isinstance(warning, str)


def test_doh_mit_ip_list_ist_none() -> None:
    assert doh_group_format_warning(BlocklistGroup.DOH, BlocklistFormat.IP_LIST) is None


def test_doh_mit_domain_list_ist_none() -> None:
    assert doh_group_format_warning(BlocklistGroup.DOH, BlocklistFormat.DOMAIN_LIST) is None


def test_nicht_doh_gruppe_wird_nicht_geprueft() -> None:
    # Nur die DoH-Gruppe wird geprueft -- eine THREAT-Liste im HOSTS-Format ist normal.
    assert doh_group_format_warning(BlocklistGroup.THREAT, BlocklistFormat.HOSTS) is None
