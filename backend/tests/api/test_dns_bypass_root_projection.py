"""Composition-Root-Anreicherung des DNS-Umgehungs-Waechters (ADR 0042, Etappe 4b).

Testet die zwei reinen Root-Nahtstellen aus ``app.py`` gegen In-Memory-Fake-Repos
(kein Sniff, kein asyncio-Loop, keine echte Persistenz):

* ``_dns_bypass_name_by_ip`` (Option 2): Quell-IP -> best-effort Anzeigename aus dem
  Bestand ueber ``Device.last_ip``; Prioritaet ``label > hostname > mac``; Geraete ohne
  ``last_ip`` fallen raus.
* ``_dns_bypass_doh_lookup`` (eigene Naht, NICHT MatchContacts): ein Ziel gilt als DoH,
  wenn ``lookup_ips``/``lookup_domains`` einen Treffer liefern, dessen ``source_id`` eine
  AKTIVE Quelle der Gruppe ``DOH`` ist (``enabled`` + ``group == DOH``). Treffer aus einer
  anderen Gruppe ODER aus einer deaktivierten DOH-Quelle zaehlen NICHT.
"""

from datetime import UTC, datetime

from app import _dns_bypass_doh_lookup, _dns_bypass_name_by_ip
from domain.blocklist import (
    BlocklistFormat,
    BlocklistGroup,
    BlocklistSource,
    BlocklistStatus,
    SourceOrigin,
)
from domain.devices import Device


def _source(
    source_id: str,
    name: str,
    group: BlocklistGroup,
    *,
    enabled: bool = True,
) -> BlocklistSource:
    """Baut eine schlanke Quellen-Definition -- nur id/name/group/enabled sind relevant."""
    return BlocklistSource(
        id=source_id,
        name=name,
        group=group,
        fmt=BlocklistFormat.IP_LIST,
        origin=SourceOrigin.BUILTIN,
        url=None,
        license="CC0",
        attribution_required=False,
        enabled=enabled,
        last_fetched_ts=None,
        status=BlocklistStatus.NEVER,
        entry_count=None,
    )


class _FakeSourceRepo:
    """``BlocklistSourceRepository``-Fake: haelt eine feste Liste von Definitionen."""

    def __init__(self, sources: list[BlocklistSource]) -> None:
        self._sources = sources

    def list_all(self) -> list[BlocklistSource]:
        return self._sources


class _FakeEntryRepo:
    """``BlocklistEntryRepository``-Fake: feste Treffer je Ziel-IP bzw. Domain-Kandidat.

    ``ip_hits`` bildet ``dst_ip -> [(source_id, matched_cidr)]`` ab, ``domain_hits`` bildet
    einen Suffix-Kandidaten -> ``[(source_id, matched_domain)]``. Nur die zwei Lookups, die
    ``_dns_bypass_doh_lookup`` nutzt.
    """

    def __init__(
        self,
        ip_hits: dict[str, list[tuple[str, str]]] | None = None,
        domain_hits: dict[str, list[tuple[str, str]]] | None = None,
    ) -> None:
        self._ip_hits = ip_hits or {}
        self._domain_hits = domain_hits or {}

    def lookup_ips(self, ip: str) -> list[tuple[str, str]]:
        return list(self._ip_hits.get(ip, []))

    def lookup_domains(self, candidates: list[str]) -> list[tuple[str, str]]:
        hits: list[tuple[str, str]] = []
        for candidate in candidates:
            hits.extend(self._domain_hits.get(candidate, []))
        return hits


def _device(mac: str, *, last_ip: str | None, label: str = "", hostname: str = "") -> Device:
    """Baut ein schlankes Geraet -- nur mac/last_ip/label/hostname sind hier relevant."""
    now = datetime(2026, 7, 1, tzinfo=UTC)
    return Device(
        mac=mac,
        first_seen=now,
        last_seen=now,
        last_ip=last_ip,
        label=label,
        hostname=hostname,
    )


# ── _dns_bypass_name_by_ip (Option 2) ──────────────────────────────────────────


def test_name_by_ip_prioritaet_label_vor_hostname_vor_mac() -> None:
    """label > hostname > mac; ohne label/hostname greift die (immer gesetzte) mac."""
    devices = [
        _device("AA:AA:AA:AA:AA:AA", last_ip="192.168.1.10", label="TV", hostname="tv.local"),
        _device("BB:BB:BB:BB:BB:BB", last_ip="192.168.1.11", hostname="drucker.local"),
        _device("CC:CC:CC:CC:CC:CC", last_ip="192.168.1.12"),
    ]
    name_by_ip = _dns_bypass_name_by_ip(devices)
    assert name_by_ip == {
        "192.168.1.10": "TV",
        "192.168.1.11": "drucker.local",
        "192.168.1.12": "CC:CC:CC:CC:CC:CC",
    }


def test_name_by_ip_ignoriert_geraete_ohne_last_ip() -> None:
    """Geraete ohne ``last_ip`` liefern keinen Eintrag (keine Zuordnung moeglich)."""
    devices = [_device("AA:AA:AA:AA:AA:AA", last_ip=None, label="Ghost")]
    assert _dns_bypass_name_by_ip(devices) == {}


def test_name_by_ip_zuordnung_und_none_ueber_get() -> None:
    """src_ip == device.last_ip -> Name; unbekannte src_ip -> None (ueber ``.get``)."""
    name_by_ip = _dns_bypass_name_by_ip(
        [_device("AA:AA:AA:AA:AA:AA", last_ip="10.0.0.5", label="PC")]
    )
    assert name_by_ip.get("10.0.0.5") == "PC"
    assert name_by_ip.get("10.0.0.9") is None


# ── _dns_bypass_doh_lookup (eigene Naht, NICHT MatchContacts) ───────────────────


def test_doh_lookup_ip_treffer_aktive_doh_quelle() -> None:
    """Ziel-IP steht in einer aktiven DOH-Quelle -> (True, Quellenname)."""
    sources = _FakeSourceRepo([_source("doh_ip", "Bekannte DoH-Anbieter (IP)", BlocklistGroup.DOH)])
    entries = _FakeEntryRepo(ip_hits={"1.1.1.1": [("doh_ip", "1.1.1.1/32")]})
    assert _dns_bypass_doh_lookup(sources, entries, "1.1.1.1", "") == (
        True,
        "Bekannte DoH-Anbieter (IP)",
    )


def test_doh_lookup_domain_treffer_ueber_suffix_kandidaten() -> None:
    """qname-Suffix steht in einer aktiven DOH-Domain-Quelle -> (True, Quellenname)."""
    sources = _FakeSourceRepo(
        [_source("doh_dom", "Bekannte DoH-Anbieter (Domain)", BlocklistGroup.DOH)]
    )
    entries = _FakeEntryRepo(
        domain_hits={"cloudflare-dns.com": [("doh_dom", "cloudflare-dns.com")]}
    )
    assert _dns_bypass_doh_lookup(sources, entries, "9.9.9.9", "cloudflare-dns.com") == (
        True,
        "Bekannte DoH-Anbieter (Domain)",
    )


def test_doh_lookup_kein_treffer() -> None:
    """Kein Treffer in Roh-Lookups -> (False, None)."""
    sources = _FakeSourceRepo([_source("doh_ip", "DoH IP", BlocklistGroup.DOH)])
    entries = _FakeEntryRepo()
    assert _dns_bypass_doh_lookup(sources, entries, "8.8.8.8", "example.com") == (False, None)


def test_doh_lookup_treffer_anderer_gruppe_zaehlt_nicht() -> None:
    """Treffer aus einer NICHT-DOH-Quelle (z. B. THREAT) ist keine DoH-Bewertung."""
    sources = _FakeSourceRepo([_source("threat", "Feodo", BlocklistGroup.THREAT)])
    entries = _FakeEntryRepo(ip_hits={"5.5.5.5": [("threat", "5.5.5.5/32")]})
    assert _dns_bypass_doh_lookup(sources, entries, "5.5.5.5", "") == (False, None)


def test_doh_lookup_deaktivierte_doh_quelle_zaehlt_nicht() -> None:
    """Treffer aus einer DEAKTIVIERTEN DOH-Quelle zaehlt nicht (nur aktive Quellen)."""
    sources = _FakeSourceRepo([_source("doh_off", "DoH aus", BlocklistGroup.DOH, enabled=False)])
    entries = _FakeEntryRepo(ip_hits={"1.1.1.1": [("doh_off", "1.1.1.1/32")]})
    assert _dns_bypass_doh_lookup(sources, entries, "1.1.1.1", "") == (False, None)
