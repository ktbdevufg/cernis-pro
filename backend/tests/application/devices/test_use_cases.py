"""Tests der devices-Use-Cases gegen In-Memory-Fakes beider Ports.

Kein echtes SQLite/keine Uhr noetig -- wir testen gegen die Protocols. Kern der
Behauptungen: die 24h-Grenze entsteht im Use-Case (active_24h-Fix), es gibt nur
EINEN Schreibpfad (BUG-3-Fix) und ``is_known`` ueberlebt einen Re-Scan
end-to-end (BUG-2-Fix).
"""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from application.devices import (
    AnswerArchivePrompt,
    ArchiveDevice,
    CreateDevice,
    DeleteDevice,
    DeviceAlreadyExistsError,
    DeviceBroadcastMacError,
    DeviceNotFoundError,
    DismissDeviceFromWatch,
    GetArchiveCandidates,
    GetArchivedDevices,
    GetDevice,
    GetDevices,
    GetDeviceStats,
    GetUnclassifiedDevices,
    InvalidTrustStateError,
    RecordScannedHost,
    RestoreDevice,
    UpdateDeviceMeta,
)
from domain.devices import (
    BROADCAST_MAC,
    Device,
    DeviceSource,
    DeviceStats,
    IpHistoryEntry,
    ScannedHost,
    TrustState,
    normalize_mac,
)
from ports.devices import Clock, DeviceRepository

NOW = datetime(2026, 5, 28, 12, 0, 0, tzinfo=UTC)
MAC = "AA:BB:CC:DD:EE:01"


# ── In-Memory-Fakes der Ports ───────────────────────────────────────────────


class FakeDeviceRepository:
    """In-Memory-Implementierung des ``DeviceRepository``-Protocols."""

    def __init__(self) -> None:
        self._devices: dict[str, Device] = {}
        self._history: list[IpHistoryEntry] = []
        self.save_calls = 0
        self.stats_active_since: datetime | None = None

    def get(self, mac: str) -> Device | None:
        return self._devices.get(normalize_mac(mac))

    def get_all(self, known_only: bool) -> list[Device]:
        # Archivierte Geraete sind aus der Standard-Liste raus -- spiegelt den
        # Adapter (SqliteDeviceRepository: WHERE archived = 0).
        items = [
            d for d in self._devices.values() if (d.is_known or not known_only) and not d.archived
        ]
        return sorted(items, key=lambda d: d.last_seen, reverse=True)

    def get_unclassified(self) -> list[Device]:
        # Wie der Adapter: zusaetzlich archivierte ausschliessen (archived = 0).
        items = [
            d
            for d in self._devices.values()
            if not d.is_known and not d.watch_dismissed and not d.archived
        ]
        return sorted(items, key=lambda d: d.last_seen, reverse=True)

    def get_archived(self) -> list[Device]:
        items = [d for d in self._devices.values() if d.archived]
        return sorted(items, key=lambda d: d.last_seen, reverse=True)

    def get_archive_candidates(self, not_seen_since: datetime) -> list[Device]:
        items = [
            d
            for d in self._devices.values()
            if not d.archived and not d.archive_prompt_dismissed and d.last_seen <= not_seen_since
        ]
        return sorted(items, key=lambda d: d.last_seen)

    def save(self, device: Device) -> None:
        self.save_calls += 1
        self._devices[device.mac] = device

    def delete(self, mac: str) -> None:
        norm = normalize_mac(mac)
        self._devices.pop(norm, None)
        self._history = [e for e in self._history if e.mac != norm]

    def append_ip_history(self, entry: IpHistoryEntry) -> None:
        self._history.append(entry)

    def get_ip_history(self, mac: str, limit: int = 20) -> list[IpHistoryEntry]:
        norm = normalize_mac(mac)
        items = sorted(
            (e for e in self._history if e.mac == norm),
            key=lambda e: e.seen_at,
            reverse=True,
        )
        return items[:limit]

    def stats(self, active_since: datetime) -> DeviceStats:
        # Archivierte Geraete zaehlen in KEINER Kennzahl mit -- spiegelt den
        # Adapter (SqliteDeviceRepository: jede Zaehlung auf archived = 0).
        self.stats_active_since = active_since
        live = [d for d in self._devices.values() if not d.archived]
        total = len(live)
        known = sum(1 for d in live if d.is_known)
        active = sum(1 for d in live if d.last_seen >= active_since)
        return DeviceStats(total=total, known=known, unknown=total - known, active=active)

    def clear_all(self) -> None:
        """Leert Geraete und IP-Historie."""
        self._devices.clear()
        self._history.clear()


class FakeClock:
    """Uhr mit fixem ``now`` -- deterministisch."""

    def __init__(self, now: datetime) -> None:
        self._now = now

    def now(self) -> datetime:
        return self._now


@pytest.fixture
def repo() -> FakeDeviceRepository:
    return FakeDeviceRepository()


def _device(mac: str = MAC, **over: Any) -> Device:
    base: dict[str, Any] = {
        "mac": mac,
        "first_seen": NOW,
        "last_seen": NOW,
        "last_ip": "10.0.0.5",
        "times_seen": 1,
        "is_known": False,
        "vendor": "Acme",
        "label": "",
        "notes": "",
        "category": "",
        "hostname": "host.local",
        "os_guess": "Linux",
        "tags": (),
        "open_ports": (22, 80),
    }
    base.update(over)
    return Device(**base)


# ── Struktureller Vertrag der Fakes ─────────────────────────────────────────


def test_fake_repo_conforms_to_protocol() -> None:
    _: DeviceRepository = FakeDeviceRepository()


def test_fake_clock_conforms_to_protocol() -> None:
    _: Clock = FakeClock(NOW)


# ── GetDeviceStats: 24h-Grenze entsteht im Use-Case ─────────────────────────


def test_get_device_stats_uses_now_minus_24h(repo: FakeDeviceRepository) -> None:
    repo.save(_device("AA:BB:CC:DD:EE:01", is_known=True, last_seen=NOW))
    repo.save(_device("AA:BB:CC:DD:EE:02", is_known=False, last_seen=NOW - timedelta(days=2)))
    stats = GetDeviceStats(repo, FakeClock(NOW))()
    assert repo.stats_active_since == NOW - timedelta(hours=24)
    assert stats.total == 2
    assert stats.known == 1
    assert stats.unknown == 1
    assert stats.active == 1  # nur das NOW-Geraet liegt im 24h-Fenster


# ── GetDevices ──────────────────────────────────────────────────────────────


def test_get_devices_passes_known_only_through(repo: FakeDeviceRepository) -> None:
    repo.save(_device("AA:BB:CC:DD:EE:01", is_known=True))
    repo.save(_device("AA:BB:CC:DD:EE:02", is_known=False))
    assert {d.mac for d in GetDevices(repo)(known_only=False)} == {
        "AA:BB:CC:DD:EE:01",
        "AA:BB:CC:DD:EE:02",
    }
    assert [d.mac for d in GetDevices(repo)(known_only=True)] == ["AA:BB:CC:DD:EE:01"]


# ── GetUnclassifiedDevices (Wache) ──────────────────────────────────────────


def test_get_unclassified_filters_known_and_dismissed(repo: FakeDeviceRepository) -> None:
    # In der Wache: nur is_known=False UND watch_dismissed=False.
    repo.save(_device("AA:BB:CC:DD:EE:01"))  # is_known=False, watch_dismissed=False -> in Wache
    repo.save(_device("AA:BB:CC:DD:EE:02", is_known=True))  # bekannt -> raus
    repo.save(_device("AA:BB:CC:DD:EE:03", watch_dismissed=True))  # weggelegt -> raus
    macs = {d.mac for d in GetUnclassifiedDevices(repo)()}
    assert macs == {"AA:BB:CC:DD:EE:01"}


def test_get_unclassified_empty_returns_empty_list(repo: FakeDeviceRepository) -> None:
    assert GetUnclassifiedDevices(repo)() == []


# ── GetDevice ───────────────────────────────────────────────────────────────


def test_get_device_returns_device_with_history(repo: FakeDeviceRepository) -> None:
    repo.save(_device())
    repo.append_ip_history(IpHistoryEntry(MAC, "10.0.0.5", NOW))
    result = GetDevice(repo)(MAC)
    assert result.device.mac == MAC
    assert isinstance(result.ip_history, tuple)
    assert [e.ip for e in result.ip_history] == ["10.0.0.5"]


def test_get_device_unknown_raises(repo: FakeDeviceRepository) -> None:
    with pytest.raises(DeviceNotFoundError):
        GetDevice(repo)("AA:BB:CC:DD:EE:99")


# ── UpdateDeviceMeta ────────────────────────────────────────────────────────


def test_update_device_meta_partial_only_changes_given(repo: FakeDeviceRepository) -> None:
    repo.save(_device(label="alt", notes="bleibt"))
    updated = UpdateDeviceMeta(repo)(MAC, label="neu")
    assert updated.label == "neu"
    assert updated.notes == "bleibt"  # nicht uebergeben -> unveraendert
    stored = repo.get(MAC)
    assert stored is not None
    assert stored.label == "neu"


def test_update_device_meta_tags_become_tuple(repo: FakeDeviceRepository) -> None:
    repo.save(_device())
    updated = UpdateDeviceMeta(repo)(MAC, tags=["a", "b"])
    assert updated.tags == ("a", "b")
    assert isinstance(updated.tags, tuple)


def test_update_device_meta_can_set_is_known(repo: FakeDeviceRepository) -> None:
    repo.save(_device(is_known=False))
    updated = UpdateDeviceMeta(repo)(MAC, is_known=True)
    assert updated.is_known is True


def test_update_device_meta_sets_trust_state(repo: FakeDeviceRepository) -> None:
    repo.save(_device(trust_state=TrustState.NEUTRAL))
    updated = UpdateDeviceMeta(repo)(MAC, trust_state=TrustState.WATCH)
    assert updated.trust_state is TrustState.WATCH


def test_update_device_meta_accepts_raw_str_trust_state(repo: FakeDeviceRepository) -> None:
    # Der api-Ring reicht einen rohen str durch -> Hebung im Use-Case.
    repo.save(_device())
    updated = UpdateDeviceMeta(repo)(MAC, trust_state="trusted")
    assert updated.trust_state is TrustState.TRUSTED


def test_update_device_meta_invalid_trust_state_raises(repo: FakeDeviceRepository) -> None:
    repo.save(_device())
    with pytest.raises(InvalidTrustStateError):
        UpdateDeviceMeta(repo)(MAC, trust_state="vertrauenswuerdig")


def test_update_trust_trusted_implies_is_known(repo: FakeDeviceRepository) -> None:
    # Konsistenz-Regel: trusted ordnet das Geraet ein -> is_known mitgesetzt.
    repo.save(_device(is_known=False))
    updated = UpdateDeviceMeta(repo)(MAC, trust_state=TrustState.TRUSTED)
    assert updated.is_known is True


def test_update_trust_watch_implies_is_known(repo: FakeDeviceRepository) -> None:
    repo.save(_device(is_known=False))
    updated = UpdateDeviceMeta(repo)(MAC, trust_state=TrustState.WATCH)
    assert updated.is_known is True


def test_update_trust_neutral_leaves_is_known_untouched(repo: FakeDeviceRepository) -> None:
    repo.save(_device(is_known=False))
    updated = UpdateDeviceMeta(repo)(MAC, trust_state=TrustState.NEUTRAL)
    assert updated.is_known is False  # NEUTRAL beruehrt is_known nie


def test_update_explicit_is_known_overrides_trust_implication(repo: FakeDeviceRepository) -> None:
    # Explizit uebergebenes is_known hat Vorrang vor der trusted/watch-Implikation.
    repo.save(_device(is_known=False))
    updated = UpdateDeviceMeta(repo)(MAC, trust_state=TrustState.TRUSTED, is_known=False)
    assert updated.is_known is False
    assert updated.trust_state is TrustState.TRUSTED


def test_update_device_meta_sets_watch_dismissed(repo: FakeDeviceRepository) -> None:
    # Generischer Update-Pfad fuer das Wache-Wegleg-Flag.
    repo.save(_device(watch_dismissed=False))
    updated = UpdateDeviceMeta(repo)(MAC, watch_dismissed=True)
    assert updated.watch_dismissed is True


def test_update_device_meta_watch_dismissed_none_leaves_untouched(
    repo: FakeDeviceRepository,
) -> None:
    repo.save(_device(watch_dismissed=True))
    updated = UpdateDeviceMeta(repo)(MAC, label="neu")  # watch_dismissed nicht uebergeben
    assert updated.watch_dismissed is True


# ── DismissDeviceFromWatch ──────────────────────────────────────────────────


def test_dismiss_sets_watch_dismissed_true(repo: FakeDeviceRepository) -> None:
    repo.save(_device(watch_dismissed=False))
    updated = DismissDeviceFromWatch(repo)(MAC, dismissed=True)
    assert updated.watch_dismissed is True
    stored = repo.get(MAC)
    assert stored is not None
    assert stored.watch_dismissed is True


def test_dismiss_reverts_watch_dismissed_false(repo: FakeDeviceRepository) -> None:
    # Ruecknehmbar: ein weggelegtes Geraet wieder in die Wache holen.
    repo.save(_device(watch_dismissed=True))
    updated = DismissDeviceFromWatch(repo)(MAC, dismissed=False)
    assert updated.watch_dismissed is False


def test_dismiss_single_save_path(repo: FakeDeviceRepository) -> None:
    repo.save(_device())  # save_calls == 1 (Setup)
    DismissDeviceFromWatch(repo)(MAC, dismissed=True)
    assert repo.save_calls == 2  # genau EIN zusaetzlicher Schreibpfad


def test_dismiss_unknown_mac_raises(repo: FakeDeviceRepository) -> None:
    with pytest.raises(DeviceNotFoundError):
        DismissDeviceFromWatch(repo)("AA:BB:CC:DD:EE:99", dismissed=True)


def test_update_device_meta_single_save_no_dual_write(repo: FakeDeviceRepository) -> None:
    repo.save(_device())  # save_calls == 1 (Setup)
    UpdateDeviceMeta(repo)(MAC, label="neu")
    # Genau EIN zusaetzlicher Schreibpfad (BUG-3-Fix: kein Dual-Write).
    assert repo.save_calls == 2


def test_update_device_meta_unknown_mac_raises(repo: FakeDeviceRepository) -> None:
    # Bewusste Abweichung vom Altcode-No-op: Update auf unbekannte MAC ist Fehler.
    with pytest.raises(DeviceNotFoundError):
        UpdateDeviceMeta(repo)("AA:BB:CC:DD:EE:99", label="x")


# ── DeleteDevice ────────────────────────────────────────────────────────────


def test_delete_device_removes_device_and_history(repo: FakeDeviceRepository) -> None:
    repo.save(_device())
    repo.append_ip_history(IpHistoryEntry(MAC, "10.0.0.5", NOW))
    DeleteDevice(repo)(MAC)
    assert repo.get(MAC) is None
    assert repo.get_ip_history(MAC) == []


def test_delete_device_unknown_mac_is_idempotent(repo: FakeDeviceRepository) -> None:
    DeleteDevice(repo)("AA:BB:CC:DD:EE:99")  # kein Fehler


# ── RecordScannedHost ───────────────────────────────────────────────────────


def test_record_new_host_saves_and_logs_first_ip(repo: FakeDeviceRepository) -> None:
    result = RecordScannedHost(repo, FakeClock(NOW))(
        ScannedHost(mac=MAC, ip="10.0.0.1", vendor="V", open_ports=(22,))
    )
    assert result is not None  # None hiesse "uebersprungen" (Broadcast-Adresse)
    assert result.times_seen == 1
    assert result.is_known is False
    assert result.first_seen == NOW
    assert repo.get(MAC) is not None
    history = repo.get_ip_history(MAC)
    assert [e.ip for e in history] == ["10.0.0.1"]
    assert history[0].seen_at == NOW


def test_record_rescan_same_ip_no_new_history(repo: FakeDeviceRepository) -> None:
    rec = RecordScannedHost(repo, FakeClock(NOW))
    rec(ScannedHost(mac=MAC, ip="10.0.0.1"))
    rec(ScannedHost(mac=MAC, ip="10.0.0.1"))
    dev = repo.get(MAC)
    assert dev is not None
    assert dev.times_seen == 2
    assert len(repo.get_ip_history(MAC)) == 1


def test_record_rescan_new_ip_adds_history(repo: FakeDeviceRepository) -> None:
    rec = RecordScannedHost(repo, FakeClock(NOW))
    rec(ScannedHost(mac=MAC, ip="10.0.0.1"))
    rec(ScannedHost(mac=MAC, ip="10.0.0.2"))
    history = repo.get_ip_history(MAC)
    assert len(history) == 2
    assert {e.ip for e in history} == {"10.0.0.1", "10.0.0.2"}


def test_record_preserves_is_known_bug2_end_to_end(repo: FakeDeviceRepository) -> None:
    clock = FakeClock(NOW)
    RecordScannedHost(repo, clock)(ScannedHost(mac=MAC, ip="10.0.0.1"))
    UpdateDeviceMeta(repo)(MAC, is_known=True)  # User markiert als bekannt
    # Re-Scan darf is_known nicht zuruecksetzen:
    result = RecordScannedHost(repo, clock)(ScannedHost(mac=MAC, ip="10.0.0.1"))
    assert result is not None
    assert result.is_known is True
    dev = repo.get(MAC)
    assert dev is not None
    assert dev.is_known is True


def test_record_broadcast_mac_is_skipped_without_entry(repo: FakeDeviceRepository) -> None:
    # Die Broadcast-Adresse ist kein Geraet: still uebersprungen (Rueckgabe None),
    # kein Fehler und kein Eintrag -- die gewoehnliche Zeile daneben wird normal
    # aufgenommen.
    rec = RecordScannedHost(repo, FakeClock(NOW))
    assert rec(ScannedHost(mac=BROADCAST_MAC, ip="10.0.0.255")) is None
    assert repo.get(BROADCAST_MAC) is None
    assert repo.save_calls == 0
    assert repo.get_ip_history(BROADCAST_MAC) == []

    result = rec(ScannedHost(mac=MAC, ip="10.0.0.1", vendor="V", open_ports=(22,)))
    assert result is not None
    assert result.mac == MAC
    assert repo.get(MAC) is not None
    assert repo.save_calls == 1
    assert [e.ip for e in repo.get_ip_history(MAC)] == ["10.0.0.1"]


def test_record_broadcast_mac_skipped_in_other_notation(repo: FakeDeviceRepository) -> None:
    # Kanonischer Vergleich: auch die Kleinschreibung mit Bindestrichen trifft.
    assert RecordScannedHost(repo, FakeClock(NOW))(ScannedHost(mac="ff-ff-ff-ff-ff-ff")) is None
    assert repo.save_calls == 0


# ── CreateDevice ─────────────────────────────────────────────────────────────


def test_create_device_success_sets_manual_known_zero_seen(repo: FakeDeviceRepository) -> None:
    created = CreateDevice(repo, FakeClock(NOW))(
        MAC, label="Drucker", notes="Flur", category="printer", tags=["office", "lan"]
    )
    assert created.source is DeviceSource.MANUAL
    assert created.is_known is True
    assert created.times_seen == 0
    assert created.label == "Drucker"
    assert created.notes == "Flur"
    assert created.category == "printer"
    assert created.tags == ("office", "lan")
    assert repo.save_calls == 1  # genau EIN Schreibpfad
    stored = repo.get(MAC)
    assert stored is not None
    assert stored.source is DeviceSource.MANUAL
    assert stored.is_known is True
    assert stored.times_seen == 0


def test_create_device_conflict_raises_and_no_extra_save(repo: FakeDeviceRepository) -> None:
    repo.save(_device(is_known=True))  # save_calls == 1 (Setup)
    with pytest.raises(DeviceAlreadyExistsError):
        CreateDevice(repo, FakeClock(NOW))(MAC, label="x")
    assert repo.save_calls == 1  # kein weiterer save bei Konflikt


def test_create_device_normalizes_mac(repo: FakeDeviceRepository) -> None:
    created = CreateDevice(repo, FakeClock(NOW))("aa-bb-cc-dd-ee-01")
    assert created.mac == MAC
    assert repo.get(MAC) is not None


def test_create_device_broadcast_mac_raises_and_saves_nothing(repo: FakeDeviceRepository) -> None:
    # Von Hand eingetragene Broadcast-Adresse: benannte Ablehnung, kein stiller
    # Verzicht (S3) -- und kein Schreibvorgang.
    with pytest.raises(DeviceBroadcastMacError):
        CreateDevice(repo, FakeClock(NOW))(BROADCAST_MAC, label="x")
    assert repo.save_calls == 0
    assert repo.get(BROADCAST_MAC) is None


def test_create_device_broadcast_mac_raises_in_other_notation(repo: FakeDeviceRepository) -> None:
    # Kanonischer Vergleich: die Schreibweise darf die Ablehnung nicht umgehen.
    with pytest.raises(DeviceBroadcastMacError):
        CreateDevice(repo, FakeClock(NOW))("ff-ff-ff-ff-ff-ff")
    assert repo.save_calls == 0


# ── ArchiveDevice ────────────────────────────────────────────────────────────


def test_archive_device_sets_archived(repo: FakeDeviceRepository) -> None:
    repo.save(_device(archived=False))  # save_calls == 1 (Setup)
    updated = ArchiveDevice(repo)(MAC)
    assert updated.archived is True
    assert repo.save_calls == 2  # genau EIN zusaetzlicher Schreibpfad
    stored = repo.get(MAC)
    assert stored is not None
    assert stored.archived is True


def test_archive_device_unknown_mac_raises(repo: FakeDeviceRepository) -> None:
    with pytest.raises(DeviceNotFoundError):
        ArchiveDevice(repo)("AA:BB:CC:DD:EE:99")


# ── RestoreDevice ────────────────────────────────────────────────────────────


def test_restore_device_unarchives_and_keeps_prompt_state(repo: FakeDeviceRepository) -> None:
    # Zurueckholen setzt den Nachfrage-Zustand NICHT zurueck (kein Reset).
    repo.save(_device(archived=True, archive_prompt_count=3, archive_prompt_dismissed=True))
    updated = RestoreDevice(repo)(MAC)
    assert updated.archived is False
    assert updated.archive_prompt_count == 3
    assert updated.archive_prompt_dismissed is True


def test_restore_device_unknown_mac_raises(repo: FakeDeviceRepository) -> None:
    with pytest.raises(DeviceNotFoundError):
        RestoreDevice(repo)("AA:BB:CC:DD:EE:99")


# ── GetArchivedDevices ───────────────────────────────────────────────────────


def test_get_archived_returns_only_archived_sorted_desc(repo: FakeDeviceRepository) -> None:
    # Gemischter Bestand; erwartet nur die archivierten, last_seen absteigend.
    repo.save(_device("AA:BB:CC:DD:EE:01", archived=False))
    repo.save(_device("AA:BB:CC:DD:EE:02", archived=True, last_seen=NOW - timedelta(days=1)))
    repo.save(_device("AA:BB:CC:DD:EE:03", archived=True, last_seen=NOW))
    macs = [d.mac for d in GetArchivedDevices(repo)()]
    assert macs == ["AA:BB:CC:DD:EE:03", "AA:BB:CC:DD:EE:02"]


# ── AnswerArchivePrompt ──────────────────────────────────────────────────────


def test_answer_archive_prompt_yes_archives(repo: FakeDeviceRepository) -> None:
    repo.save(_device(archived=False))  # save_calls == 1 (Setup)
    updated = AnswerArchivePrompt(repo)(MAC, archive=True)
    assert updated.archived is True
    assert repo.save_calls == 2  # genau EIN zusaetzlicher Schreibpfad


def test_answer_archive_prompt_no_three_times_dismisses_end_to_end(
    repo: FakeDeviceRepository,
) -> None:
    # 3x-Nein end-to-end ueber den Use-Case (nicht nur die Domaene).
    repo.save(_device(archive_prompt_count=0, archive_prompt_dismissed=False))
    uc = AnswerArchivePrompt(repo)
    first = uc(MAC, archive=False)
    assert first.archive_prompt_count == 1
    assert first.archive_prompt_dismissed is False
    second = uc(MAC, archive=False)
    assert second.archive_prompt_count == 2
    assert second.archive_prompt_dismissed is False
    third = uc(MAC, archive=False)
    assert third.archive_prompt_count == 3
    assert third.archive_prompt_dismissed is True


def test_answer_archive_prompt_unknown_mac_raises(repo: FakeDeviceRepository) -> None:
    with pytest.raises(DeviceNotFoundError):
        AnswerArchivePrompt(repo)("AA:BB:CC:DD:EE:99", archive=True)


# ── GetArchiveCandidates ─────────────────────────────────────────────────────


def test_get_archive_candidates_filters_and_sorts_ascending(repo: FakeDeviceRepository) -> None:
    # Erwartet: nur alt genug, nicht archiviert, nicht dismissed; last_seen aufsteigend.
    repo.save(_device("AA:BB:CC:DD:EE:01", last_seen=NOW - timedelta(days=40)))  # Kandidat
    repo.save(_device("AA:BB:CC:DD:EE:02", last_seen=NOW - timedelta(days=60)))  # Kandidat
    repo.save(_device("AA:BB:CC:DD:EE:03", last_seen=NOW - timedelta(days=5)))  # zu frisch
    repo.save(
        _device("AA:BB:CC:DD:EE:04", last_seen=NOW - timedelta(days=99), archived=True)
    )  # archiviert -> raus
    repo.save(
        _device(
            "AA:BB:CC:DD:EE:05",
            last_seen=NOW - timedelta(days=99),
            archive_prompt_dismissed=True,
        )
    )  # dismissed -> raus
    result = GetArchiveCandidates(repo, FakeClock(NOW))(threshold_days=30)
    # last_seen aufsteigend: der am laengsten verschollene (60d) zuerst.
    assert [d.mac for d in result] == ["AA:BB:CC:DD:EE:02", "AA:BB:CC:DD:EE:01"]


def test_get_archive_candidates_threshold_changes_result(repo: FakeDeviceRepository) -> None:
    # Die Zeitgrenze entsteht im Use-Case: gleicher Bestand, anderer threshold ->
    # anderes Ergebnis.
    repo.save(_device("AA:BB:CC:DD:EE:01", last_seen=NOW - timedelta(days=40)))
    repo.save(_device("AA:BB:CC:DD:EE:02", last_seen=NOW - timedelta(days=10)))
    uc = GetArchiveCandidates(repo, FakeClock(NOW))
    assert {d.mac for d in uc(threshold_days=30)} == {"AA:BB:CC:DD:EE:01"}
    assert {d.mac for d in uc(threshold_days=5)} == {
        "AA:BB:CC:DD:EE:01",
        "AA:BB:CC:DD:EE:02",
    }


# ── Regression: Fake-Korrektur spiegelt den Adapter (archived ausgeblendet) ──


def test_get_devices_excludes_archived(repo: FakeDeviceRepository) -> None:
    repo.save(_device("AA:BB:CC:DD:EE:01", is_known=True, archived=False))
    repo.save(_device("AA:BB:CC:DD:EE:02", is_known=True, archived=True))
    macs = {d.mac for d in GetDevices(repo)(known_only=False)}
    assert macs == {"AA:BB:CC:DD:EE:01"}


def test_get_device_stats_excludes_archived_from_total(repo: FakeDeviceRepository) -> None:
    repo.save(_device("AA:BB:CC:DD:EE:01", is_known=True, archived=False, last_seen=NOW))
    repo.save(_device("AA:BB:CC:DD:EE:02", is_known=True, archived=True, last_seen=NOW))
    stats = GetDeviceStats(repo, FakeClock(NOW))()
    assert stats.total == 1  # archiviertes zaehlt nicht mit
    assert stats.known == 1
    assert stats.active == 1
