"""Tests der reinen Format-Parser (``application.blocklist.parsing``).

Deckt alle ``BlocklistFormat``-Familien ueber den ``parse_blocklist``-Dispatch ab:
HOSTS (Sentinel-IP verwerfen), DOMAIN_LIST (Wildcard), ADBLOCK (Domain-Extract +
Element-Hide/Exception ignorieren), IP_LIST (gueltig/ungueltig), CSV (Domain + IP,
Header tolerant), sowie Dedupe + stabile Reihenfolge. Zeitfrei/netzfrei.
"""

from application.blocklist.parsing import parse_blocklist
from domain.blocklist import BlocklistFormat


def test_hosts_verwirft_sentinel_ips_und_liefert_domains() -> None:
    raw = (
        "# Kommentar\n"
        "0.0.0.0 ads.example.com\n"
        "127.0.0.1 tracker.example.org\n"
        "\n"
        ":: ipv6.example.net\n"
    )
    domains, ip_cidrs = parse_blocklist(BlocklistFormat.HOSTS, raw)
    assert domains == ["ads.example.com", "tracker.example.org", "ipv6.example.net"]
    # Die Sentinel-IPs (0.0.0.0/127.0.0.1/::) sind KEINE Threat-IPs -> nie als IP-Eintrag.
    assert ip_cidrs == []


def test_hosts_inline_kommentar_wird_abgeschnitten() -> None:
    domains, _ = parse_blocklist(BlocklistFormat.HOSTS, "0.0.0.0 a.example.com # inline")
    assert domains == ["a.example.com"]


def test_domain_list_strippt_wildcard_und_normalisiert() -> None:
    raw = "*.ads.example.com\nwww.tracker.example.org\n! adblock-kommentar\nplain.example.net\n"
    domains, ip_cidrs = parse_blocklist(BlocklistFormat.DOMAIN_LIST, raw)
    # '*.x' -> 'x'; 'www.' wird von normalize_domain entfernt.
    assert domains == ["ads.example.com", "tracker.example.org", "plain.example.net"]
    assert ip_cidrs == []


def test_adblock_extrahiert_domain_und_ignoriert_hide_und_exception() -> None:
    raw = (
        "||ads.example.com^\n"
        "||tracker.example.org^$third-party\n"
        "@@||allowed.example.net^\n"  # Ausnahme -> ignorieren
        "example.com##.banner\n"  # Element-Hide -> ignorieren
        "example.com#@#.x\n"  # Element-Hide-Ausnahme -> ignorieren
        "||cdn.example.io/path\n"  # Pfad nach Domain -> nur Domain
        "/some/url/rule\n"  # keine ||-Regel -> ignorieren
    )
    domains, ip_cidrs = parse_blocklist(BlocklistFormat.ADBLOCK, raw)
    assert domains == ["ads.example.com", "tracker.example.org", "cdn.example.io"]
    assert ip_cidrs == []


def test_ip_list_nimmt_gueltige_und_verwirft_ungueltige() -> None:
    raw = (
        "1.2.3.4\n"
        "10.0.0.0/8\n"
        "2001:db8::1\n"
        "; kommentar-zeile\n"
        "999.999.999.999\n"  # ungueltig -> verwerfen
        "5.6.7.8 ; inline-kommentar\n"
        "nonsense\n"
    )
    domains, ip_cidrs = parse_blocklist(BlocklistFormat.IP_LIST, raw)
    assert domains == []
    assert ip_cidrs == ["1.2.3.4", "10.0.0.0/8", "2001:db8::1", "5.6.7.8"]


def test_csv_domain_ueberspringt_header_und_nimmt_erste_domain_spalte() -> None:
    raw = "name,domain,note\nEvil Tracker,ads.example.com,bad\nAnother,track.example.org,x\n"
    domains, ip_cidrs = parse_blocklist(BlocklistFormat.CSV_DOMAIN, raw)
    # Header-Zeile (keine Zelle ist gueltige Domain) faellt heraus.
    assert domains == ["ads.example.com", "track.example.org"]
    assert ip_cidrs == []


def test_csv_ip_ueberspringt_header_und_nimmt_erste_ip_spalte() -> None:
    raw = "label,ip\nbad-host,1.2.3.4\nnet,10.0.0.0/24\n"
    domains, ip_cidrs = parse_blocklist(BlocklistFormat.CSV_IP, raw)
    assert domains == []
    assert ip_cidrs == ["1.2.3.4", "10.0.0.0/24"]


def test_dedupe_haelt_stabile_reihenfolge() -> None:
    raw = "0.0.0.0 a.example.com\n0.0.0.0 b.example.com\n0.0.0.0 a.example.com\n"
    domains, _ = parse_blocklist(BlocklistFormat.HOSTS, raw)
    # Dublette 'a' faellt weg, Reihenfolge des Erstauftretens bleibt.
    assert domains == ["a.example.com", "b.example.com"]
