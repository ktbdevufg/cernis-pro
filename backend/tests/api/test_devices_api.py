"""End-to-end-Tests der devices-API (v2) gegen app.py via TestClient.

Echte Adapter auf Test-Backends via ``dependency_overrides``:
``SqliteDeviceRepository`` auf einer tmp_path-DB, ``SystemClock``. Kein echtes
cernis.db. Belegt das v2-Verhalten ueber HTTP: PUT auf unbekannte MAC -> 404
(bewusste Abweichung vom Altcode-No-op), idempotentes DELETE, korrekte
JSON-Serialisierung (Listen statt tuples, bool) und dass der devices-Router VOR
dem Frontend-Catch-all matcht.
"""

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.devices import (
    provide_delete_device,
    provide_get_device,
    provide_get_device_stats,
    provide_get_devices,
    provide_update_device_meta,
)
from app import create_app
from application.devices import (
    DeleteDevice,
    GetDevice,
    GetDevices,
    GetDeviceStats,
    UpdateDeviceMeta,
)
from domain.devices import Device, IpHistoryEntry
from infrastructure.clock import SystemClock
from infrastructure.config import AppConfig
from infrastructure.device_repository import SqliteDeviceRepository

MAC = "AA:BB:CC:DD:EE:01"


@pytest.fixture
def repo(tmp_path: Path) -> SqliteDeviceRepository:
    return SqliteDeviceRepository(tmp_path / "cernis.db")


def _device(mac: str = MAC, **over: Any) -> Device:
    now = datetime.now(UTC)
    base: dict[str, Any] = {
        "mac": mac,
        "first_seen": now,
        "last_seen": now,
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


def _wired_app(repo: SqliteDeviceRepository) -> FastAPI:
    clock = SystemClock()
    app = create_app(AppConfig())
    app.dependency_overrides[provide_get_device_stats] = lambda: GetDeviceStats(repo, clock)
    app.dependency_overrides[provide_get_devices] = lambda: GetDevices(repo)
    app.dependency_overrides[provide_get_device] = lambda: GetDevice(repo)
    app.dependency_overrides[provide_update_device_meta] = lambda: UpdateDeviceMeta(repo)
    app.dependency_overrides[provide_delete_device] = lambda: DeleteDevice(repo)
    return app


@pytest.fixture
def client(repo: SqliteDeviceRepository) -> Iterator[TestClient]:
    with TestClient(_wired_app(repo)) as test_client:
        yield test_client


# ── GET-Liste + known_only ──────────────────────────────────────────────────


def test_list_devices_and_known_only(client: TestClient, repo: SqliteDeviceRepository) -> None:
    repo.save(_device("AA:BB:CC:DD:EE:01", is_known=True))
    repo.save(_device("AA:BB:CC:DD:EE:02", is_known=False))
    all_body = client.get("/api/devices").json()
    assert {d["mac"] for d in all_body} == {"AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"}
    known_body = client.get("/api/devices", params={"known_only": True}).json()
    assert [d["mac"] for d in known_body] == ["AA:BB:CC:DD:EE:01"]


# ── GET einzeln + History + 404 ─────────────────────────────────────────────


def test_get_device_with_history(client: TestClient, repo: SqliteDeviceRepository) -> None:
    repo.save(_device())
    repo.append_ip_history(IpHistoryEntry(MAC, "10.0.0.5", datetime.now(UTC)))
    body = client.get(f"/api/devices/{MAC}").json()
    assert body["mac"] == MAC
    assert isinstance(body["ip_history"], list)
    assert body["ip_history"][0]["ip"] == "10.0.0.5"


def test_get_unknown_device_404(client: TestClient) -> None:
    assert client.get("/api/devices/AA:BB:CC:DD:EE:99").status_code == 404


# ── PUT (partiell) + 404 ────────────────────────────────────────────────────


def test_put_updates_meta(client: TestClient, repo: SqliteDeviceRepository) -> None:
    repo.save(_device(label="alt", is_known=False))
    resp = client.put(f"/api/devices/{MAC}", json={"label": "neu", "is_known": True})
    assert resp.status_code == 200
    assert resp.json()["label"] == "neu"
    body = client.get(f"/api/devices/{MAC}").json()
    assert body["label"] == "neu"
    assert body["is_known"] is True


def test_put_unknown_device_404(client: TestClient) -> None:
    # Bewusste Abweichung vom Altcode-No-op: Update auf unbekannte MAC ist Fehler.
    resp = client.put("/api/devices/AA:BB:CC:DD:EE:99", json={"label": "x"})
    assert resp.status_code == 404


# ── trust_state: PUT, 422, Spiegelung in GET/Liste ──────────────────────────


def test_put_sets_trust_state_and_reflects(
    client: TestClient, repo: SqliteDeviceRepository
) -> None:
    repo.save(_device(is_known=False))
    resp = client.put(f"/api/devices/{MAC}", json={"trust_state": "watch"})
    assert resp.status_code == 200
    assert resp.json()["trust_state"] == "watch"
    # Konsistenz-Regel ueber HTTP: watch ordnet ein -> is_known mitgesetzt.
    assert resp.json()["is_known"] is True


def test_put_invalid_trust_state_422(client: TestClient, repo: SqliteDeviceRepository) -> None:
    repo.save(_device())
    resp = client.put(f"/api/devices/{MAC}", json={"trust_state": "kaputt"})
    assert resp.status_code == 422


def test_trust_state_appears_in_get_and_list(
    client: TestClient, repo: SqliteDeviceRepository
) -> None:
    repo.save(_device())
    client.put(f"/api/devices/{MAC}", json={"trust_state": "trusted"})
    single = client.get(f"/api/devices/{MAC}").json()
    assert single["trust_state"] == "trusted"
    listed = client.get("/api/devices").json()
    assert listed[0]["trust_state"] == "trusted"


def test_default_trust_state_neutral_in_response(
    client: TestClient, repo: SqliteDeviceRepository
) -> None:
    repo.save(_device())
    body = client.get(f"/api/devices/{MAC}").json()
    assert body["trust_state"] == "neutral"


# ── DELETE idempotent ───────────────────────────────────────────────────────


def test_delete_then_404_and_idempotent(client: TestClient, repo: SqliteDeviceRepository) -> None:
    repo.save(_device())
    assert client.delete(f"/api/devices/{MAC}").status_code == 200
    assert client.get(f"/api/devices/{MAC}").status_code == 404
    # Nochmaliges DELETE: kein Fehler (idempotent, kein 404).
    assert client.delete(f"/api/devices/{MAC}").status_code == 200


# ── stats ────────────────────────────────────────────────────────────────────


def test_stats_shape(client: TestClient, repo: SqliteDeviceRepository) -> None:
    repo.save(_device("AA:BB:CC:DD:EE:01", is_known=True))
    repo.save(_device("AA:BB:CC:DD:EE:02", is_known=False))
    body = client.get("/api/devices/stats").json()
    assert body["total"] == 2
    assert body["known"] == 1
    assert body["unknown"] == 1
    assert body["active_24h"] == 2  # beide frisch -> im 24h-Fenster


# ── Serialisierung: Listen + bool ───────────────────────────────────────────


def test_serialization_lists_and_bool(client: TestClient, repo: SqliteDeviceRepository) -> None:
    repo.save(_device(tags=("prod",), open_ports=(22, 443), is_known=True))
    body = client.get(f"/api/devices/{MAC}").json()
    assert body["tags"] == ["prod"]
    assert isinstance(body["tags"], list)
    assert body["open_ports"] == [22, 443]
    assert isinstance(body["open_ports"], list)
    assert body["is_known"] is True


# ── Reihenfolge-Regression: Router vor Frontend-Catch-all ───────────────────


def test_devices_route_not_swallowed_by_frontend(client: TestClient) -> None:
    resp = client.get("/api/devices/stats")
    assert resp.status_code == 200
    assert "total" in resp.json()  # echtes JSON aus dem Router, kein index.html
