"""Tests der blocklist-Use-Cases mit In-Memory-Fakes (kein echtes Netz, keine echte DB).

``_FakeSourceRepo``/``_FakeEntryRepo`` bilden die Port-Semantik in-memory nach;
``_FakeFetcher`` liefert deterministischen Text bzw. wirft. Gedeckt: Seed idempotent,
AddUserSource slug+license_hint, Refresh OK setzt OK+count, Refresh Fetch-Fehler setzt
BROKEN ohne Werfen, RefreshDue nur faellige, Health BROKEN+Vorschlag, Match
strictness-/group-/enabled-Filter + suffix/CIDR-Treffer, ResetToDefaults, ImportUploaded
parst sofort, strictness_from_wire 422.
"""

import pytest

from application.blocklist.errors import BlocklistError, UnknownStrictnessError
from application.blocklist.use_cases import (
    AddUserSource,
    CheckBlocklistHealth,
    ContactInput,
    ImportUploadedSource,
    MatchContacts,
    RefreshDueSources,
    RefreshSource,
    ResetSourcesToDefaults,
    SeedBuiltinDohContent,
    SeedDefaultSources,
    UpdateUserSource,
    strictness_from_wire,
)
from domain.blocklist import (
    DEFAULT_SOURCES,
    BlocklistFormat,
    BlocklistGroup,
    BlocklistSource,
    BlocklistStatus,
    MatchStrictness,
    SourceOrigin,
    ip_in_cidr,
)

# ── In-Memory-Fakes ───────────────────────────────────────────────────────────


class _FakeSourceRepo:
    """In-Memory-``BlocklistSourceRepository`` (dict ueber id)."""

    def __init__(self) -> None:
        self._store: dict[str, BlocklistSource] = {}

    def upsert(self, source: BlocklistSource) -> None:
        self._store[source.id] = source

    def get(self, source_id: str) -> BlocklistSource | None:
        return self._store.get(source_id)

    def list_all(self) -> list[BlocklistSource]:
        return sorted(self._store.values(), key=lambda s: (s.group.value, s.name))

    def delete(self, source_id: str) -> None:
        self._store.pop(source_id, None)

    def clear_all(self) -> None:
        self._store.clear()


class _FakeEntryRepo:
    """In-Memory-``BlocklistEntryRepository`` (domains/ip_cidrs je source_id)."""

    def __init__(self) -> None:
        self._domains: dict[str, list[str]] = {}
        self._ips: dict[str, list[str]] = {}

    def replace_entries(self, source_id: str, domains: list[str], ip_cidrs: list[str]) -> None:
        self._domains[source_id] = list(domains)
        self._ips[source_id] = list(ip_cidrs)

    def delete_for(self, source_id: str) -> None:
        self._domains.pop(source_id, None)
        self._ips.pop(source_id, None)

    def count_for(self, source_id: str) -> int:
        return len(self._domains.get(source_id, [])) + len(self._ips.get(source_id, []))

    def lookup_domains(self, candidates: list[str]) -> list[tuple[str, str]]:
        wanted = set(candidates)
        hits: list[tuple[str, str]] = []
        for source_id, values in self._domains.items():
            for value in values:
                if value in wanted:
                    hits.append((source_id, value))
        return hits

    def lookup_ips(self, ip: str) -> list[tuple[str, str]]:
        hits: list[tuple[str, str]] = []
        for source_id, values in self._ips.items():
            for value in values:
                if value == ip or ip_in_cidr(ip, value):
                    hits.append((source_id, value))
        return hits

    def clear_all(self) -> None:
        self._domains.clear()
        self._ips.clear()


class _FakeFetcher:
    """Fake-``BlocklistFetcher``: liefert je url Text aus einem dict, sonst wirft er."""

    def __init__(self, by_url: dict[str, str]) -> None:
        self._by_url = by_url

    def fetch(self, url: str) -> str:
        if url not in self._by_url:
            raise RuntimeError(f"kein Fake-Text fuer {url}")
        return self._by_url[url]


def _source(
    source_id: str,
    *,
    group: BlocklistGroup = BlocklistGroup.THREAT,
    fmt: BlocklistFormat = BlocklistFormat.DOMAIN_LIST,
    url: str | None = "https://example.test/list",
    enabled: bool = True,
    status: BlocklistStatus = BlocklistStatus.NEVER,
    last_fetched_ts: float | None = None,
    entry_count: int | None = None,
) -> BlocklistSource:
    return BlocklistSource(
        id=source_id,
        name=source_id,
        group=group,
        fmt=fmt,
        origin=SourceOrigin.USER_URL,
        url=url,
        license="unknown",
        attribution_required=False,
        enabled=enabled,
        last_fetched_ts=last_fetched_ts,
        status=status,
        entry_count=entry_count,
    )


# ── Seed / Reset ──────────────────────────────────────────────────────────────


def test_seed_default_sources_ist_idempotent_und_schont_aenderungen() -> None:
    sources = _FakeSourceRepo()
    SeedDefaultSources(sources)()
    assert len(sources.list_all()) == len(DEFAULT_SOURCES)

    # Eine Werksquelle deaktivieren, dann erneut seeden -> Aenderung bleibt, kein Doppel.
    first = DEFAULT_SOURCES[0]
    sources.upsert(_source(first.id, group=first.group, enabled=False))
    SeedDefaultSources(sources)()
    assert len(sources.list_all()) == len(DEFAULT_SOURCES)
    stored_first = sources.get(first.id)
    assert stored_first is not None
    assert stored_first.enabled is False


def test_reset_to_defaults_raeumt_ab_und_legt_werksliste_neu_an() -> None:
    sources = _FakeSourceRepo()
    entries = _FakeEntryRepo()
    sources.upsert(_source("user_custom"))
    entries.replace_entries("user_custom", ["x.example.com"], [])

    ResetSourcesToDefaults(sources, entries)()

    ids = {s.id for s in sources.list_all()}
    assert ids == {d.id for d in DEFAULT_SOURCES}
    assert "user_custom" not in ids
    assert entries.count_for("user_custom") == 0


def test_seed_builtin_doh_content_laedt_ok_und_ist_idempotent() -> None:
    sources = _FakeSourceRepo()
    entries = _FakeEntryRepo()
    # Erst die Werksquellen anlegen (BUILTIN, url=None, entry_count None), dann DoH laden.
    SeedDefaultSources(sources)()
    SeedBuiltinDohContent(sources, entries, now_provider=lambda: 1000.0)()

    for doh_id in ("doh_providers_ip", "doh_providers_domain"):
        stored = sources.get(doh_id)
        assert stored is not None
        assert stored.status is BlocklistStatus.OK
        assert stored.entry_count is not None and stored.entry_count > 0
        assert stored.last_fetched_ts == 1000.0
        assert entries.count_for(doh_id) == stored.entry_count

    # Idempotent: ein zweiter Lauf (andere now) schreibt NICHT neu (schon geladen).
    SeedBuiltinDohContent(sources, entries, now_provider=lambda: 2000.0)()
    reloaded = sources.get("doh_providers_ip")
    assert reloaded is not None
    assert reloaded.last_fetched_ts == 1000.0


# ── AddUserSource / ImportUploadedSource ──────────────────────────────────────


def test_add_user_source_baut_slug_und_liefert_license_hint() -> None:
    sources = _FakeSourceRepo()
    result = AddUserSource(sources)(
        name="My EasyList Mirror",
        url="https://easylist.to/easylist/easylist.txt",
        group="tracker_ads",
        fmt="adblock",
    )
    assert result.source_id == "my_easylist_mirror"
    # detect_license_hint erkennt 'easylist' im Host -> Hinweis (verweigert nichts).
    assert result.license_hint is not None
    stored = sources.get("my_easylist_mirror")
    assert stored is not None
    assert stored.origin is SourceOrigin.USER_URL
    assert stored.enabled is True
    assert stored.status is BlocklistStatus.NEVER


def test_add_user_source_kollision_haengt_suffix_an() -> None:
    sources = _FakeSourceRepo()
    AddUserSource(sources)("Liste", "https://a.test/l", "threat", "domain_list")
    result2 = AddUserSource(sources)("Liste", "https://b.test/l", "threat", "domain_list")
    assert result2.source_id == "liste_2"


def test_add_user_source_unbekannte_gruppe_wirft_blocklist_error() -> None:
    sources = _FakeSourceRepo()
    with pytest.raises(BlocklistError):
        AddUserSource(sources)("X", "https://a.test/l", "nicht_existent", "domain_list")


def test_add_user_source_doh_mit_hosts_setzt_group_warning() -> None:
    sources = _FakeSourceRepo()
    result = AddUserSource(sources)("Eigene DoH", "https://a.test/l", "doh", "hosts")
    assert result.group_warning is not None


def test_add_user_source_doh_mit_ip_list_ohne_group_warning() -> None:
    sources = _FakeSourceRepo()
    result = AddUserSource(sources)("Eigene DoH", "https://a.test/l", "doh", "ip_list")
    assert result.group_warning is None


def test_import_uploaded_source_parst_sofort_und_setzt_ok() -> None:
    sources = _FakeSourceRepo()
    entries = _FakeEntryRepo()
    result = ImportUploadedSource(sources, entries, now_provider=lambda: 1000.0)(
        name="Upload Liste",
        group="threat",
        fmt="domain_list",
        raw_text="a.example.com\nb.example.com\n",
    )
    assert result.entry_count == 2
    stored = sources.get(result.source_id)
    assert stored is not None
    assert stored.origin is SourceOrigin.UPLOAD
    assert stored.url is None
    assert stored.status is BlocklistStatus.OK
    assert stored.last_fetched_ts == 1000.0
    assert entries.count_for(result.source_id) == 2


# ── UpdateUserSource ──────────────────────────────────────────────────────────


def test_update_user_source_partiell_und_unbekannt_wirft() -> None:
    sources = _FakeSourceRepo()
    sources.upsert(_source("src", enabled=True))
    UpdateUserSource(sources)("src", enabled=False, name="Neuer Name")
    updated = sources.get("src")
    assert updated is not None
    assert updated.enabled is False
    assert updated.name == "Neuer Name"
    # url unangetastet
    assert updated.url == "https://example.test/list"

    with pytest.raises(BlocklistError):
        UpdateUserSource(sources)("gibt_es_nicht", enabled=True)


# ── RefreshSource ─────────────────────────────────────────────────────────────


def test_refresh_source_ok_setzt_ok_und_count() -> None:
    sources = _FakeSourceRepo()
    entries = _FakeEntryRepo()
    sources.upsert(_source("src", fmt=BlocklistFormat.DOMAIN_LIST, url="https://x.test/l"))
    fetcher = _FakeFetcher({"https://x.test/l": "a.example.com\nb.example.com\n"})

    result = RefreshSource(sources, entries, fetcher, now_provider=lambda: 50.0)("src")

    assert result.ok is True
    assert result.entry_count == 2
    assert result.error is None
    stored = sources.get("src")
    assert stored is not None
    assert stored.status is BlocklistStatus.OK
    assert stored.last_fetched_ts == 50.0
    assert stored.entry_count == 2


def test_refresh_source_fetch_fehler_setzt_broken_ohne_werfen() -> None:
    sources = _FakeSourceRepo()
    entries = _FakeEntryRepo()
    # Vorzustand: einmal erfolgreich geladen (ts + count vorhanden).
    sources.upsert(
        _source(
            "src",
            url="https://down.test/l",
            status=BlocklistStatus.OK,
            last_fetched_ts=10.0,
            entry_count=7,
        )
    )
    fetcher = _FakeFetcher({})  # jede url wirft

    result = RefreshSource(sources, entries, fetcher, now_provider=lambda: 999.0)("src")

    assert result.ok is False
    assert result.entry_count is None
    assert result.error is not None
    stored = sources.get("src")
    assert stored is not None
    assert stored.status is BlocklistStatus.BROKEN
    # last_fetched_ts/entry_count BLEIBEN auf dem letzten guten Stand.
    assert stored.last_fetched_ts == 10.0
    assert stored.entry_count == 7


def test_refresh_source_unbekannt_oder_upload_wirft() -> None:
    sources = _FakeSourceRepo()
    entries = _FakeEntryRepo()
    fetcher = _FakeFetcher({})
    refresh = RefreshSource(sources, entries, fetcher)
    with pytest.raises(BlocklistError):
        refresh("gibt_es_nicht")
    sources.upsert(_source("upl", url=None, status=BlocklistStatus.OK))
    with pytest.raises(BlocklistError):
        refresh("upl")


# ── RefreshDueSources ─────────────────────────────────────────────────────────


def test_refresh_due_nur_faellige_aktive_mit_url() -> None:
    sources = _FakeSourceRepo()
    entries = _FakeEntryRepo()
    now = 1_000_000.0
    # faellig: nie geladen
    sources.upsert(_source("never", url="https://a.test/l", last_fetched_ts=None))
    # faellig: alt (> 7 Tage)
    sources.upsert(_source("old", url="https://b.test/l", last_fetched_ts=now - 8 * 86400))
    # nicht faellig: frisch
    sources.upsert(_source("fresh", url="https://c.test/l", last_fetched_ts=now - 1 * 86400))
    # nicht faellig: deaktiviert
    sources.upsert(_source("off", url="https://d.test/l", enabled=False, last_fetched_ts=None))
    # nicht faellig: Upload (keine url)
    sources.upsert(_source("upl", url=None, last_fetched_ts=None))

    fetcher = _FakeFetcher(
        {"https://a.test/l": "x.example.com\n", "https://b.test/l": "y.example.com\n"}
    )
    refresh = RefreshSource(sources, entries, fetcher, now_provider=lambda: now)
    results = RefreshDueSources(sources, refresh, now_provider=lambda: now)(7)

    refreshed_ids = {r.source_id for r in results}
    assert refreshed_ids == {"never", "old"}


# ── CheckBlocklistHealth ──────────────────────────────────────────────────────


def test_health_meldet_broken_mit_ersatzvorschlag_gleicher_gruppe() -> None:
    sources = _FakeSourceRepo()
    # zwei THREAT-Quellen: eine BROKEN, eine gesund (OK) -> die gesunde wird vorgeschlagen.
    sources.upsert(
        _source("threat_broken", group=BlocklistGroup.THREAT, status=BlocklistStatus.BROKEN)
    )
    sources.upsert(_source("threat_ok", group=BlocklistGroup.THREAT, status=BlocklistStatus.OK))

    issues = CheckBlocklistHealth(sources)()
    assert len(issues) == 1
    assert issues[0].source_id == "threat_broken"
    assert issues[0].suggested_replacement_id == "threat_ok"


def test_health_leer_wenn_nichts_broken() -> None:
    sources = _FakeSourceRepo()
    sources.upsert(_source("ok", status=BlocklistStatus.OK))
    assert CheckBlocklistHealth(sources)() == []


# ── MatchContacts ─────────────────────────────────────────────────────────────


def test_match_suffix_und_cidr_treffer_mit_strictness_und_group_filter() -> None:
    sources = _FakeSourceRepo()
    entries = _FakeEntryRepo()
    # THREAT-Domainliste, TRACKER_ADS-Domainliste, THREAT-IP-Netz.
    sources.upsert(_source("threat_dom", group=BlocklistGroup.THREAT))
    sources.upsert(_source("ads_dom", group=BlocklistGroup.TRACKER_ADS))
    sources.upsert(_source("threat_ip", group=BlocklistGroup.THREAT, fmt=BlocklistFormat.IP_LIST))
    entries.replace_entries("threat_dom", ["example.com"], [])
    entries.replace_entries("ads_dom", ["ads.example.org"], [])
    entries.replace_entries("threat_ip", [], ["10.0.0.0/8"])

    match = MatchContacts(sources, entries)
    contacts = [
        ContactInput(remote_ip="10.1.2.3", hostname="sub.example.com"),
        ContactInput(remote_ip="8.8.8.8", hostname="ads.example.org"),
    ]

    # CRITICAL_ONLY -> nur THREAT zaehlt: Kontakt 1 trifft Domain-Suffix + IP-Netz,
    # Kontakt 2 (nur TRACKER_ADS) faellt unter CRITICAL_ONLY weg.
    results = match(contacts, MatchStrictness.CRITICAL_ONLY)
    matched_sources_0 = {m.source_id for m in results[0].matches}
    assert matched_sources_0 == {"threat_dom", "threat_ip"}
    assert results[1].matches == ()

    # RECOMMENDED -> THREAT + TRACKER_ADS: Kontakt 2 trifft jetzt ads_dom.
    results = match(contacts, MatchStrictness.RECOMMENDED)
    assert {m.source_id for m in results[1].matches} == {"ads_dom"}

    # group-Filter: TRACKER_ADS abgeschaltet -> Kontakt 2 wieder leer, trotz RECOMMENDED.
    results = match(contacts, MatchStrictness.RECOMMENDED, frozenset({BlocklistGroup.THREAT}))
    assert results[1].matches == ()


def test_match_filtert_deaktivierte_quellen() -> None:
    sources = _FakeSourceRepo()
    entries = _FakeEntryRepo()
    sources.upsert(_source("off_dom", group=BlocklistGroup.THREAT, enabled=False))
    entries.replace_entries("off_dom", ["example.com"], [])

    results = MatchContacts(sources, entries)(
        [ContactInput(remote_ip="1.2.3.4", hostname="example.com")],
        MatchStrictness.ALL,
    )
    assert results[0].matches == ()


# ── strictness_from_wire ──────────────────────────────────────────────────────


def test_strictness_from_wire_hebt_und_wirft_bei_fehlwert() -> None:
    assert strictness_from_wire("recommended") is MatchStrictness.RECOMMENDED
    with pytest.raises(UnknownStrictnessError):
        strictness_from_wire("gibt_es_nicht")
