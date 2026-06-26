"""Tests der blocklist-Domaene -- reine Funktionen + DEFAULT_SOURCES-Invarianten.

Belegt die zeitfreien, netzfreien Funktionen (``normalize_domain``,
``domain_suffix_candidates``, ``strictness_allows``, ``ip_in_cidr``,
``detect_license_hint``) und die Werks-Invarianten der ``DEFAULT_SOURCES``. Muster der
uebrigen domain-Tests (reine Asserts, kein I/O).
"""

from domain.blocklist import (
    DEFAULT_SOURCES,
    BlocklistFormat,
    BlocklistGroup,
    BlocklistStatus,
    MatchStrictness,
    SourceOrigin,
    detect_license_hint,
    domain_suffix_candidates,
    ip_in_cidr,
    normalize_domain,
    strictness_allows,
)

# ── normalize_domain ──────────────────────────────────────────────────────────


def test_normalize_domain_trimmt_lowercased_www_und_trailing_dot() -> None:
    assert normalize_domain("  WWW.Example.COM.  ") == "example.com"


def test_normalize_domain_behaelt_subdomain() -> None:
    assert normalize_domain("sub.Example.com") == "sub.example.com"


def test_normalize_domain_leer_ist_none() -> None:
    assert normalize_domain("   ") is None


def test_normalize_domain_ohne_punkt_ist_none() -> None:
    assert normalize_domain("localhost") is None


def test_normalize_domain_mit_slash_ist_none() -> None:
    assert normalize_domain("example.com/pfad") is None


def test_normalize_domain_nur_www_ist_none() -> None:
    # "www." -> nach www-Abschnitt leer -> None (kein Punkt).
    assert normalize_domain("www.") is None


# ── domain_suffix_candidates ──────────────────────────────────────────────────


def test_suffix_candidates_alle_eltern() -> None:
    assert domain_suffix_candidates("sub.example.com") == (
        "sub.example.com",
        "example.com",
        "com",
    )


def test_suffix_candidates_www_frei_und_lowercased() -> None:
    assert domain_suffix_candidates("WWW.Example.COM") == ("example.com", "com")


def test_suffix_candidates_leer_ist_leeres_tuple() -> None:
    assert domain_suffix_candidates("  ") == ()


def test_suffix_candidates_einzelnes_label() -> None:
    assert domain_suffix_candidates("com") == ("com",)


# ── strictness_allows (alle 3 Stufen x 2 Gruppen) ─────────────────────────────


def test_strictness_critical_only_nur_threat() -> None:
    assert strictness_allows(BlocklistGroup.THREAT, MatchStrictness.CRITICAL_ONLY) is True
    assert strictness_allows(BlocklistGroup.TRACKER_ADS, MatchStrictness.CRITICAL_ONLY) is False


def test_strictness_recommended_threat_und_tracker() -> None:
    assert strictness_allows(BlocklistGroup.THREAT, MatchStrictness.RECOMMENDED) is True
    assert strictness_allows(BlocklistGroup.TRACKER_ADS, MatchStrictness.RECOMMENDED) is True


def test_strictness_all_immer_true() -> None:
    assert strictness_allows(BlocklistGroup.THREAT, MatchStrictness.ALL) is True
    assert strictness_allows(BlocklistGroup.TRACKER_ADS, MatchStrictness.ALL) is True


# ── ip_in_cidr (in/out/ungueltig/exakt) ───────────────────────────────────────


def test_ip_in_cidr_drin() -> None:
    assert ip_in_cidr("10.0.0.5", "10.0.0.0/24") is True


def test_ip_in_cidr_draussen() -> None:
    assert ip_in_cidr("10.0.1.5", "10.0.0.0/24") is False


def test_ip_in_cidr_exakt_ohne_praefix_als_32() -> None:
    # cidr ohne "/" -> /32 (IPv4): nur die IP selbst trifft.
    assert ip_in_cidr("1.2.3.4", "1.2.3.4") is True
    assert ip_in_cidr("1.2.3.5", "1.2.3.4") is False


def test_ip_in_cidr_ipv6_exakt() -> None:
    assert ip_in_cidr("2001:db8::1", "2001:db8::1") is True
    assert ip_in_cidr("2001:db8::1", "2001:db8::/32") is True


def test_ip_in_cidr_familien_mismatch_false() -> None:
    assert ip_in_cidr("10.0.0.5", "2001:db8::/32") is False


def test_ip_in_cidr_ungueltig_false() -> None:
    assert ip_in_cidr("keine-ip", "10.0.0.0/24") is False
    assert ip_in_cidr("10.0.0.5", "muell") is False


# ── detect_license_hint (Treffer + None) ──────────────────────────────────────


def test_detect_license_hint_easylist() -> None:
    assert (
        detect_license_hint("https://easylist.to/easylist/easylist.txt")
        == "GPL-2.0-or-later / CC-BY-SA-3.0"
    )


def test_detect_license_hint_adguard() -> None:
    assert detect_license_hint("https://filters.adguard.com/list.txt") == "GPL-3.0 / CC-BY-SA"


def test_detect_license_hint_disconnect() -> None:
    assert detect_license_hint("https://services.disconnect.me/x") == "GPL-3.0"


def test_detect_license_hint_fanboy() -> None:
    assert detect_license_hint("https://fanboy.co.nz/x.txt") == "CC-BY-SA-3.0"


def test_detect_license_hint_unbekannt_none() -> None:
    assert detect_license_hint("https://raw.githubusercontent.com/StevenBlack/hosts") is None


def test_detect_license_hint_host_nicht_pfad() -> None:
    # "easylist" nur im Pfad, nicht im Host -> kein Treffer (Host-genaue Heuristik).
    assert detect_license_hint("https://example.com/easylist.txt") is None


# ── DEFAULT_SOURCES-Invarianten ───────────────────────────────────────────────


def test_default_sources_ids_eindeutig() -> None:
    ids = [src.id for src in DEFAULT_SOURCES]
    assert len(ids) == len(set(ids))


def test_default_sources_deaktivierte_sind_die_copyleft_quellen() -> None:
    deaktiviert = {src.id for src in DEFAULT_SOURCES if not src.enabled}
    assert deaktiviert == {"easylist", "easyprivacy"}


def test_default_sources_aktive_sind_lizenzrobust() -> None:
    aktiv = {src.id for src in DEFAULT_SOURCES if src.enabled}
    assert aktiv == {
        "stevenblack_hosts",
        "oisd_small",
        "urlhaus",
        "feodo_ipblocklist",
        "firehol_level1",
    }


def test_default_sources_alle_builtin_never_uninitialisiert() -> None:
    for src in DEFAULT_SOURCES:
        assert src.origin is SourceOrigin.BUILTIN
        assert src.status is BlocklistStatus.NEVER
        assert src.last_fetched_ts is None
        assert src.entry_count is None


def test_default_sources_urlhaus_ist_hosts_format() -> None:
    urlhaus = next(src for src in DEFAULT_SOURCES if src.id == "urlhaus")
    assert urlhaus.fmt is BlocklistFormat.HOSTS
    assert urlhaus.group is BlocklistGroup.THREAT
