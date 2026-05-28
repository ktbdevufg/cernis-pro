"""Tests fuer den SQLite-Adapter ``SqliteDeviceRepository`` (gegen tmp_path-DB).

Haelt das GEWUENSCHTE v2-Verhalten fest -- insbesondere die korrigierten Bugs:
kein ``known_devices``, BUG-1-Fix (``delete`` raeumt beide Tabellen), kein
stiller JSON-Fallback, strukturell korrekte Zeit (tz-aware UTC) statt des
``active_24h``-Zeitzonen-Bugs.
"""

import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from domain.devices import Device, IpHistoryEntry
from infrastructure.device_repository import (
    CorruptDeviceError,
    SqliteDeviceRepository,
)
from ports.devices import DeviceRepository

NOW = datetime(2026, 5, 28, 12, 0, 0, tzinfo=UTC)
EARLIER = datetime(2026, 5, 1, 9, 0, 0, tzinfo=UTC)
MAC = "AA:BB:CC:DD:EE:01"


@pytest.fixture
def repo(tmp_path: Path) -> SqliteDeviceRepository:
    """Frisches Repository gegen eine temporaere DB."""
    return SqliteDeviceRepository(tmp_path / "cernis.db")


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


# ── Struktureller Vertrag ─────────────────────────────────────────────────


def test_conforms_to_device_repository_protocol(repo: SqliteDeviceRepository) -> None:
    _: DeviceRepository = repo


# ── Round-trip ─────────────────────────────────────────────────────────────


def test_save_then_get_roundtrips_all_fields(repo: SqliteDeviceRepository) -> None:
    dev = _device(
        tags=("prod", "core"),
        open_ports=(22, 443),
        is_known=True,
        last_ip="10.0.0.9",
        label="Server",
        notes="Rack 3",
        category="server",
    )
    repo.save(dev)
    got = repo.get(MAC)
    assert got is not None
    assert got == dev  # vollstaendige Feldgleichheit
    assert isinstance(got.tags, tuple)  # tuple bleibt tuple
    assert isinstance(got.open_ports, tuple)
    assert got.is_known is True  # bool bleibt bool
    assert got.last_seen.tzinfo is not None  # datetime tz-aware


def test_save_with_none_last_ip_roundtrips(repo: SqliteDeviceRepository) -> None:
    repo.save(_device(last_ip=None))
    got = repo.get(MAC)
    assert got is not None
    assert got.last_ip is None


def test_get_missing_returns_none(repo: SqliteDeviceRepository) -> None:
    assert repo.get("00:00:00:00:00:00") is None


# ── get_all ────────────────────────────────────────────────────────────────


def test_get_all_empty_returns_empty_list(repo: SqliteDeviceRepository) -> None:
    assert repo.get_all(known_only=False) == []


def test_get_all_known_only_filters(repo: SqliteDeviceRepository) -> None:
    repo.save(_device("AA:BB:CC:DD:EE:01", is_known=True))
    repo.save(_device("AA:BB:CC:DD:EE:02", is_known=False))
    known = repo.get_all(known_only=True)
    assert [d.mac for d in known] == ["AA:BB:CC:DD:EE:01"]
    assert len(repo.get_all(known_only=False)) == 2


def test_get_all_orders_by_last_seen_desc(repo: SqliteDeviceRepository) -> None:
    repo.save(_device("AA:BB:CC:DD:EE:01", last_seen=EARLIER))
    repo.save(_device("AA:BB:CC:DD:EE:02", last_seen=NOW))
    macs = [d.mac for d in repo.get_all(known_only=False)]
    assert macs == ["AA:BB:CC:DD:EE:02", "AA:BB:CC:DD:EE:01"]  # neuer zuerst


def test_save_upsert_overwrites_existing(repo: SqliteDeviceRepository) -> None:
    repo.save(_device(label="alt"))
    repo.save(_device(label="neu", is_known=True))
    got = repo.get(MAC)
    assert got is not None
    assert got.label == "neu"
    assert got.is_known is True
    assert len(repo.get_all(known_only=False)) == 1  # kein Duplikat


# ── IP-History ───────────────────────────────────────────────────────────────


def test_append_and_get_ip_history_order_and_limit(repo: SqliteDeviceRepository) -> None:
    repo.append_ip_history(IpHistoryEntry(MAC, "10.0.0.1", datetime(2026, 5, 1, tzinfo=UTC)))
    repo.append_ip_history(IpHistoryEntry(MAC, "10.0.0.2", datetime(2026, 5, 2, tzinfo=UTC)))
    repo.append_ip_history(IpHistoryEntry(MAC, "10.0.0.3", datetime(2026, 5, 3, tzinfo=UTC)))
    history = repo.get_ip_history(MAC, limit=2)
    assert [e.ip for e in history] == ["10.0.0.3", "10.0.0.2"]  # neueste zuerst, Limit greift


def test_get_ip_history_unknown_mac_returns_empty(repo: SqliteDeviceRepository) -> None:
    assert repo.get_ip_history("00:00:00:00:00:00") == []


# ── BUG-1-FIX: delete raeumt beide Tabellen ─────────────────────────────────


def test_delete_removes_device_and_ip_history(repo: SqliteDeviceRepository) -> None:
    repo.save(_device())
    repo.append_ip_history(IpHistoryEntry(MAC, "10.0.0.5", NOW))
    repo.delete(MAC)
    assert repo.get(MAC) is None
    assert repo.get_ip_history(MAC) == []  # keine verwaiste History (BUG-1-FIX)


def test_delete_missing_is_idempotent(repo: SqliteDeviceRepository) -> None:
    repo.delete("AA:BB:CC:DD:EE:99")  # kein Fehler


# ── stats ────────────────────────────────────────────────────────────────────


def test_stats_counts_total_known_unknown_active(repo: SqliteDeviceRepository) -> None:
    repo.save(_device("AA:BB:CC:DD:EE:01", is_known=True, last_seen=NOW))
    repo.save(_device("AA:BB:CC:DD:EE:02", is_known=False, last_seen=NOW))
    repo.save(_device("AA:BB:CC:DD:EE:03", is_known=False, last_seen=EARLIER))
    active_since = datetime(2026, 5, 15, 0, 0, 0, tzinfo=UTC)
    stats = repo.stats(active_since)
    assert stats.total == 3
    assert stats.known == 1
    assert stats.unknown == 2
    assert stats.active == 2  # nur die beiden mit last_seen=NOW (EARLIER liegt davor)


# ── Kein stiller Fallback bei kaputtem JSON ─────────────────────────────────


def _insert_corrupt(db_path: Path, mac: str, tags_raw: str) -> None:
    iso = "2026-05-28T12:00:00.000000+00:00"
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "INSERT INTO devices (mac, tags, open_ports, first_seen, last_seen)"
            " VALUES (?, ?, '[]', ?, ?)",
            (mac, tags_raw, iso, iso),
        )
        conn.commit()
    finally:
        conn.close()


def test_get_corrupt_json_raises_with_mac(repo: SqliteDeviceRepository, tmp_path: Path) -> None:
    _insert_corrupt(tmp_path / "cernis.db", MAC, "{kaputt")
    with pytest.raises(CorruptDeviceError) as exc_info:
        repo.get(MAC)
    assert exc_info.value.mac == MAC
    assert exc_info.value.column == "tags"


# ── MAC-Normalisierung ───────────────────────────────────────────────────────


def test_get_normalizes_mac(repo: SqliteDeviceRepository) -> None:
    repo.save(_device(MAC))  # gespeichert in Grossschreibung
    got = repo.get("aa:bb:cc:dd:ee:01")  # Abfrage in Kleinschreibung
    assert got is not None
    assert got.mac == MAC
