"""Unit-Tests der devices-Domaene -- reine Logik, kein I/O.

Prueft die zentrale MAC-Normalisierung, die Device-Invarianten und die beiden
Merge-Regeln (``merge_scan`` inkl. BUG-2-FIX, ``should_append_ip``). ``now`` wird
als fixer Wert injiziert -> deterministisch, keine Uhr in der Domaene.
"""

from dataclasses import replace
from datetime import datetime, timedelta

import pytest

from domain.devices import (
    Device,
    DeviceSource,
    IpHistoryEntry,
    ScannedHost,
    TrustState,
    is_archive_candidate,
    merge_scan,
    normalize_mac,
    register_archive_prompt,
    should_append_ip,
)

NOW = datetime(2026, 5, 28, 12, 0, 0)
EARLIER = datetime(2026, 5, 1, 9, 0, 0)
MAC = "AA:BB:CC:DD:EE:01"


# ── normalize_mac ──────────────────────────────────────────────────────────


def test_normalize_mac_unifies_separators_and_case() -> None:
    assert normalize_mac("aa-bb-cc-dd-ee-01") == MAC
    assert normalize_mac("aabb.ccdd.ee01") == MAC
    assert normalize_mac("aabbccddee01") == MAC
    assert normalize_mac(MAC) == MAC


def test_normalize_mac_is_idempotent() -> None:
    once = normalize_mac("aa-bb-cc-dd-ee-01")
    assert normalize_mac(once) == once


def test_normalize_mac_without_hex_raises() -> None:
    with pytest.raises(ValueError):
        normalize_mac("")
    with pytest.raises(ValueError):
        normalize_mac(" : : ")


# ── Device.__post_init__ ─────────────────────────────────────────────────────


def test_device_normalizes_mac() -> None:
    dev = Device(mac="aa-bb-cc-dd-ee-01", first_seen=NOW, last_seen=NOW)
    assert dev.mac == MAC


def test_device_empty_mac_raises() -> None:
    with pytest.raises(ValueError):
        Device(mac="", first_seen=NOW, last_seen=NOW)


def test_device_negative_times_seen_raises() -> None:
    with pytest.raises(ValueError):
        Device(mac=MAC, first_seen=NOW, last_seen=NOW, times_seen=-1)


# ── merge_scan: Neu-Fall ─────────────────────────────────────────────────────


def test_merge_scan_new_device() -> None:
    result = merge_scan(
        None,
        ScannedHost(
            mac=MAC,
            ip="10.0.0.5",
            vendor="Acme",
            hostname="host.local",
            os_guess="Linux",
            open_ports=(22, 80),
        ),
        NOW,
    )
    assert result.mac == MAC
    assert result.times_seen == 1
    assert result.is_known is False
    assert result.first_seen == NOW
    assert result.last_seen == NOW
    assert result.last_ip == "10.0.0.5"
    assert result.vendor == "Acme"
    assert result.hostname == "host.local"
    assert result.os_guess == "Linux"
    assert result.open_ports == (22, 80)
    # Keine Kuratierung bei Neuentdeckung:
    assert result.label == ""
    assert result.tags == ()
    assert result.category == ""


# ── merge_scan: Update-Fall ──────────────────────────────────────────────────


def _curated_existing() -> Device:
    return Device(
        mac=MAC,
        first_seen=EARLIER,
        last_seen=EARLIER,
        last_ip="10.0.0.1",
        times_seen=3,
        is_known=True,
        vendor="OldVendor",
        label="Server",
        notes="Rack 3",
        category="server",
        hostname="oldhost",
        os_guess="OldOS",
        tags=("prod", "core"),
        open_ports=(22,),
    )


def test_merge_scan_update_refreshes_scan_fields_and_preserves_curation() -> None:
    scanned = ScannedHost(
        mac=MAC,
        ip="10.0.0.9",
        vendor="NewVendor",
        hostname="newhost",
        os_guess="NewOS",
        open_ports=(22, 443),
    )
    result = merge_scan(_curated_existing(), scanned, NOW)

    # Scan-getriebene Felder aktualisiert:
    assert result.times_seen == 4
    assert result.last_seen == NOW
    assert result.last_ip == "10.0.0.9"
    assert result.open_ports == (22, 443)
    assert result.vendor == "NewVendor"
    assert result.hostname == "newhost"
    assert result.os_guess == "NewOS"

    # Bewahrt:
    assert result.first_seen == EARLIER
    assert result.label == "Server"
    assert result.notes == "Rack 3"
    assert result.tags == ("prod", "core")
    assert result.category == "server"


def test_merge_scan_empty_scan_fields_keep_existing() -> None:
    # CASE-WHEN-Semantik: leerer Scan-Wert loescht vendor/hostname/os_guess NICHT;
    # last_ip/open_ports werden hingegen unbedingt uebernommen (wie im Altcode).
    scanned = ScannedHost(mac=MAC, ip="10.0.0.9", vendor="", hostname="", os_guess="")
    result = merge_scan(_curated_existing(), scanned, NOW)
    assert result.vendor == "OldVendor"
    assert result.hostname == "oldhost"
    assert result.os_guess == "OldOS"
    assert result.last_ip == "10.0.0.9"
    assert result.open_ports == ()


def test_merge_scan_bug2_fix_scan_never_resets_is_known() -> None:
    # BUG-2-FIX: ein Scan setzt is_known nie auf False zurueck.
    result = merge_scan(_curated_existing(), ScannedHost(mac=MAC, ip="10.0.0.9"), NOW)
    assert result.is_known is True


# ── trust_state: Default, Insert, Bewahrung ─────────────────────────────────


def test_device_default_trust_state_is_neutral() -> None:
    dev = Device(mac=MAC, first_seen=NOW, last_seen=NOW)
    assert dev.trust_state is TrustState.NEUTRAL


def test_merge_scan_new_device_trust_state_neutral() -> None:
    # Insert-Zweig (existing is None): trust_state wird nicht gesetzt -> Default.
    result = merge_scan(None, ScannedHost(mac=MAC, ip="10.0.0.5"), NOW)
    assert result.trust_state is TrustState.NEUTRAL


def test_merge_scan_preserves_trust_state_over_rescan() -> None:
    # Ein Re-Scan darf trust_state NIE aendern (wie is_known).
    existing = replace(_curated_existing(), trust_state=TrustState.WATCH)
    result = merge_scan(existing, ScannedHost(mac=MAC, ip="10.0.0.9"), NOW)
    assert result.trust_state is TrustState.WATCH


# ── watch_dismissed: Default, Insert, Bewahrung ─────────────────────────────


def test_device_default_watch_dismissed_is_false() -> None:
    dev = Device(mac=MAC, first_seen=NOW, last_seen=NOW)
    assert dev.watch_dismissed is False


def test_merge_scan_new_device_watch_dismissed_false() -> None:
    # Insert-Zweig (existing is None): watch_dismissed wird nicht gesetzt ->
    # Default False -> eine Neuentdeckung gehoert frisch in die Wache.
    result = merge_scan(None, ScannedHost(mac=MAC, ip="10.0.0.5"), NOW)
    assert result.watch_dismissed is False


def test_merge_scan_preserves_watch_dismissed_over_rescan() -> None:
    # Ein Re-Scan darf watch_dismissed NIE aendern (wie is_known/trust_state):
    # ein einmal Weggelegtes bleibt weggelegt.
    existing = replace(_curated_existing(), watch_dismissed=True)
    result = merge_scan(existing, ScannedHost(mac=MAC, ip="10.0.0.9"), NOW)
    assert result.watch_dismissed is True


# ── should_append_ip ─────────────────────────────────────────────────────────


def test_should_append_ip_first_ip_true() -> None:
    assert should_append_ip(None, "10.0.0.1") is True


def test_should_append_ip_same_ip_false() -> None:
    existing = Device(mac=MAC, first_seen=NOW, last_seen=NOW, last_ip="10.0.0.1")
    assert should_append_ip(existing, "10.0.0.1") is False


def test_should_append_ip_new_ip_true() -> None:
    existing = Device(mac=MAC, first_seen=NOW, last_seen=NOW, last_ip="10.0.0.1")
    assert should_append_ip(existing, "10.0.0.2") is True


def test_should_append_ip_without_ip_false() -> None:
    existing = Device(mac=MAC, first_seen=NOW, last_seen=NOW, last_ip="10.0.0.1")
    assert should_append_ip(None, None) is False
    assert should_append_ip(existing, None) is False
    assert should_append_ip(None, "") is False


# ── IpHistoryEntry ───────────────────────────────────────────────────────────


def test_ip_history_entry_normalizes_mac() -> None:
    entry = IpHistoryEntry(mac="aa-bb-cc-dd-ee-01", ip="10.0.0.1", seen_at=NOW)
    assert entry.mac == MAC
    assert entry.ip == "10.0.0.1"
    assert entry.seen_at == NOW


# ── is_archive_candidate ─────────────────────────────────────────────────────


def _lifecycle_device(**over: object) -> Device:
    """Ein Device mit last_seen=NOW; einzelne Lebenszyklus-Felder ueberschreibbar."""
    base: dict[str, object] = {"mac": MAC, "first_seen": EARLIER, "last_seen": NOW}
    base.update(over)
    return Device(**base)  # type: ignore[arg-type]


def test_is_archive_candidate_old_unarchived_undismissed_true() -> None:
    # Nicht archiviert, nicht dismissed, last_seen aelter als Schwelle -> True.
    dev = _lifecycle_device(last_seen=NOW - timedelta(days=40))
    assert is_archive_candidate(dev, NOW, threshold_days=30) is True


def test_is_archive_candidate_exactly_on_threshold_true() -> None:
    # Grenze: last_seen == now - threshold_days -> Differenz genau threshold -> >= True.
    dev = _lifecycle_device(last_seen=NOW - timedelta(days=30))
    assert is_archive_candidate(dev, NOW, threshold_days=30) is True


def test_is_archive_candidate_younger_than_threshold_false() -> None:
    # last_seen juenger als Schwelle -> noch kein Kandidat.
    dev = _lifecycle_device(last_seen=NOW - timedelta(days=29))
    assert is_archive_candidate(dev, NOW, threshold_days=30) is False


def test_is_archive_candidate_archived_always_false() -> None:
    # archived=True -> immer False, auch wenn uralt.
    dev = _lifecycle_device(last_seen=NOW - timedelta(days=999), archived=True)
    assert is_archive_candidate(dev, NOW, threshold_days=30) is False


def test_is_archive_candidate_dismissed_always_false() -> None:
    # archive_prompt_dismissed=True -> immer False, auch wenn uralt.
    dev = _lifecycle_device(last_seen=NOW - timedelta(days=999), archive_prompt_dismissed=True)
    assert is_archive_candidate(dev, NOW, threshold_days=30) is False


# ── register_archive_prompt ──────────────────────────────────────────────────


def test_register_archive_prompt_yes_archives_and_keeps_count() -> None:
    # archive=True -> archived True; count und dismissed UNVERAENDERT.
    dev = _lifecycle_device(archive_prompt_count=1, archive_prompt_dismissed=False)
    result = register_archive_prompt(dev, archive=True)
    assert result.archived is True
    assert result.archive_prompt_count == 1
    assert result.archive_prompt_dismissed is False


def test_register_archive_prompt_no_from_zero_increments_to_one() -> None:
    dev = _lifecycle_device(archive_prompt_count=0)
    result = register_archive_prompt(dev, archive=False)
    assert result.archive_prompt_count == 1
    assert result.archive_prompt_dismissed is False


def test_register_archive_prompt_no_from_one_increments_to_two() -> None:
    dev = _lifecycle_device(archive_prompt_count=1)
    result = register_archive_prompt(dev, archive=False)
    assert result.archive_prompt_count == 2
    assert result.archive_prompt_dismissed is False


def test_register_archive_prompt_no_from_two_hits_three_x_rule() -> None:
    # 3x-Regel-Grenze: ab dem 3. Nein (count >= 3) wird dismissed gesetzt.
    dev = _lifecycle_device(archive_prompt_count=2)
    result = register_archive_prompt(dev, archive=False)
    assert result.archive_prompt_count == 3
    assert result.archive_prompt_dismissed is True


def test_register_archive_prompt_no_from_three_stays_dismissed() -> None:
    # Ueber die Grenze hinaus: count zaehlt weiter hoch, dismissed bleibt True.
    dev = _lifecycle_device(archive_prompt_count=3, archive_prompt_dismissed=True)
    result = register_archive_prompt(dev, archive=False)
    assert result.archive_prompt_count == 4
    assert result.archive_prompt_dismissed is True


# ── merge_scan: Lebenszyklus-Felder ──────────────────────────────────────────


def test_merge_scan_preserves_lifecycle_fields_over_rescan() -> None:
    # Ein Scan aendert archived/source/count/dismissed NIE; last_seen/times_seen
    # werden hingegen aktualisiert.
    existing = Device(
        mac=MAC,
        first_seen=EARLIER,
        last_seen=EARLIER,
        times_seen=2,
        archived=True,
        source=DeviceSource.MANUAL,
        archive_prompt_count=2,
        archive_prompt_dismissed=True,
    )
    result = merge_scan(existing, ScannedHost(mac=MAC, ip="10.0.0.9"), NOW)
    # Lebenszyklus unveraendert:
    assert result.archived is True
    assert result.source is DeviceSource.MANUAL
    assert result.archive_prompt_count == 2
    assert result.archive_prompt_dismissed is True
    # Scan-getriebene Felder aktualisiert:
    assert result.last_seen == NOW
    assert result.times_seen == 3


def test_merge_scan_new_device_lifecycle_defaults() -> None:
    # Neuentdeckung (existing=None): source default SCAN, nicht archiviert, frisch.
    result = merge_scan(None, ScannedHost(mac=MAC, ip="10.0.0.5"), NOW)
    assert result.source is DeviceSource.SCAN
    assert result.archived is False
    assert result.archive_prompt_count == 0
    assert result.archive_prompt_dismissed is False


# ── DeviceSource + Device-Defaults ───────────────────────────────────────────


def test_device_source_string_values() -> None:
    # StrEnum-Werte: normalisierbar aus "scan"/"manual".
    assert DeviceSource("scan") is DeviceSource.SCAN
    assert DeviceSource("manual") is DeviceSource.MANUAL
    assert DeviceSource.SCAN.value == "scan"
    assert DeviceSource.MANUAL.value == "manual"


def test_device_default_source_is_scan() -> None:
    dev = Device(mac=MAC, first_seen=NOW, last_seen=NOW)
    assert dev.source is DeviceSource.SCAN


def test_device_negative_archive_prompt_count_raises() -> None:
    with pytest.raises(ValueError):
        Device(mac=MAC, first_seen=NOW, last_seen=NOW, archive_prompt_count=-1)
