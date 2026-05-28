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
    DeleteDevice,
    DeviceNotFoundError,
    GetDevice,
    GetDevices,
    GetDeviceStats,
    RecordScannedHost,
    UpdateDeviceMeta,
)
from domain.devices import Device, DeviceStats, IpHistoryEntry, ScannedHost, normalize_mac
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
        items = [d for d in self._devices.values() if d.is_known or not known_only]
        return sorted(items, key=lambda d: d.last_seen, reverse=True)

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
        self.stats_active_since = active_since
        total = len(self._devices)
        known = sum(1 for d in self._devices.values() if d.is_known)
        active = sum(1 for d in self._devices.values() if d.last_seen >= active_since)
        return DeviceStats(total=total, known=known, unknown=total - known, active=active)


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
    assert result.is_known is True
    dev = repo.get(MAC)
    assert dev is not None
    assert dev.is_known is True
