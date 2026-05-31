"""Characterization-Contract des scan_history-Round-trips (Altcode storage.py).

Gegen eine temporaere DB (Muster wie test_settings_storage/test_devices_db):
``CERNIS_DATA_DIR`` vor dem Import setzen, ``DB_PATH`` zusaetzlich umbiegen --
keine echte cernis.db. Haelt fest, was ``save_scan`` schreibt und wie
``get_scan_history``/``get_scan_by_id`` es zurueckliefern.
"""

from pathlib import Path
from typing import Any

import pytest


@pytest.fixture
def scan_storage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setenv("CERNIS_DATA_DIR", str(tmp_path))
    from modules import storage

    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "cernis.db"))
    storage.init_db()
    return storage


def test_save_scan_then_history_lists_entry_without_blob(scan_storage: Any) -> None:
    hosts = [
        {"ip": "192.168.1.2", "mac": "AA:BB:CC:DD:EE:01", "vendor": "X"},
        {"ip": "192.168.1.3", "mac": "AA:BB:CC:DD:EE:02", "vendor": "Y"},
    ]
    scan_storage.save_scan("192.168.1.0/24", hosts)

    history = scan_storage.get_scan_history()
    assert len(history) == 1
    entry = history[0]
    assert entry["cidr"] == "192.168.1.0/24"
    assert entry["host_count"] == 2  # == len(hosts)
    assert "result_json" not in entry  # Listen-View ohne den JSON-Blob


def test_get_scan_by_id_roundtrips_hosts(scan_storage: Any) -> None:
    hosts = [{"ip": "192.168.1.2", "mac": "AA:BB:CC:DD:EE:01"}]
    scan_storage.save_scan("10.0.0.0/24", hosts)

    scan_id = scan_storage.get_scan_history()[0]["id"]
    scan = scan_storage.get_scan_by_id(scan_id)
    assert scan is not None
    assert scan["cidr"] == "10.0.0.0/24"
    assert scan["hosts"] == hosts  # result_json -> hosts Round-trip


def test_get_scan_by_id_unknown_returns_none(scan_storage: Any) -> None:
    assert scan_storage.get_scan_by_id(9999) is None
