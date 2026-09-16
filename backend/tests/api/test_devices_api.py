"""End-to-end-Tests der devices-API (v2) gegen app.py via TestClient.

Echte Adapter auf Test-Backends via ``dependency_overrides``:
``SqliteDeviceRepository`` auf einer tmp_path-DB, ``SystemClock``. Kein echtes
cernis.db. Belegt das v2-Verhalten ueber HTTP: PUT auf unbekannte MAC -> 404
(bewusste Abweichung vom Altcode-No-op), idempotentes DELETE, korrekte
JSON-Serialisierung (Listen statt tuples, bool) und dass der devices-Router VOR
dem Frontend-Catch-all matcht.
"""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.devices import (
    provide_answer_archive_prompt,
    provide_archive_device,
    provide_create_device,
    provide_delete_device,
    provide_dismiss_device_from_watch,
    provide_get_archive_candidates,
    provide_get_archived_devices,
    provide_get_device,
    provide_get_device_stats,
    provide_get_devices,
    provide_get_unclassified_devices,
    provide_restore_device,
    provide_update_device_meta,
)
from app import create_app
from application.devices import (
    AnswerArchivePrompt,
    ArchiveDevice,
    CreateDevice,
    DeleteDevice,
    DismissDeviceFromWatch,
    GetArchiveCandidates,
    GetArchivedDevices,
    GetDevice,
    GetDevices,
    GetDeviceStats,
    GetUnclassifiedDevices,
    RestoreDevice,
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
    app.dependency_overrides[provide_get_unclassified_devices] = lambda: GetUnclassifiedDevices(
        repo
    )
    app.dependency_overrides[provide_get_device] = lambda: GetDevice(repo)
    app.dependency_overrides[provide_update_device_meta] = lambda: UpdateDeviceMeta(repo)
    app.dependency_overrides[provide_dismiss_device_from_watch] = lambda: DismissDeviceFromWatch(
        repo
    )
    app.dependency_overrides[provide_delete_device] = lambda: DeleteDevice(repo)
    # Geraete-Lebenszyklus (A3): Anlegen/Archivieren/Wiederherstellen + Nachfrage.
    app.dependency_overrides[provide_create_device] = lambda: CreateDevice(repo, clock)
    app.dependency_overrides[provide_archive_device] = lambda: ArchiveDevice(repo)
    app.dependency_overrides[provide_restore_device] = lambda: RestoreDevice(repo)
    app.dependency_overrides[provide_get_archived_devices] = lambda: GetArchivedDevices(repo)
    app.dependency_overrides[provide_answer_archive_prompt] = lambda: AnswerArchivePrompt(repo)
    # Kandidaten-Provider liefert ein fertig parametriertes Callable (wie der
    # Composition Root): feste 30-Tage-Schwelle gegen die echte SystemClock --
    # die Tests setzen das Test-Geraet daher mit einem WEIT alten last_seen an.
    candidates = GetArchiveCandidates(repo, clock)
    app.dependency_overrides[provide_get_archive_candidates] = lambda: (
        lambda: candidates(threshold_days=30)
    )
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


# ── Wache: GET /unclassified ────────────────────────────────────────────────


def test_unclassified_lists_only_watch_devices(
    client: TestClient, repo: SqliteDeviceRepository
) -> None:
    repo.save(_device("AA:BB:CC:DD:EE:01", is_known=False, watch_dismissed=False))  # in Wache
    repo.save(_device("AA:BB:CC:DD:EE:02", is_known=True))  # bekannt -> raus
    repo.save(_device("AA:BB:CC:DD:EE:03", is_known=False, watch_dismissed=True))  # weggelegt
    body = client.get("/api/devices/unclassified").json()
    assert [d["mac"] for d in body] == ["AA:BB:CC:DD:EE:01"]
    assert body[0]["watch_dismissed"] is False


def test_unclassified_not_swallowed_by_mac_route(
    client: TestClient, repo: SqliteDeviceRepository
) -> None:
    # /unclassified VOR /{mac}: der Pfad darf NICHT als MAC "unclassified" enden
    # (das gaebe einen 404 ueber GetDevice). Leerer Bestand -> [] mit 200.
    resp = client.get("/api/devices/unclassified")
    assert resp.status_code == 200
    assert resp.json() == []


# ── Wache: POST /{mac}/dismiss ──────────────────────────────────────────────


def test_dismiss_removes_device_from_watch(
    client: TestClient, repo: SqliteDeviceRepository
) -> None:
    repo.save(_device(is_known=False, watch_dismissed=False))
    resp = client.post(f"/api/devices/{MAC}/dismiss", json={"dismissed": True})
    assert resp.status_code == 200
    assert resp.json()["watch_dismissed"] is True
    # Aus der Wache verschwunden, aber weiter im Bestand.
    assert client.get("/api/devices/unclassified").json() == []
    assert client.get(f"/api/devices/{MAC}").status_code == 200


def test_dismiss_revert_brings_device_back(
    client: TestClient, repo: SqliteDeviceRepository
) -> None:
    repo.save(_device(is_known=False, watch_dismissed=True))
    resp = client.post(f"/api/devices/{MAC}/dismiss", json={"dismissed": False})
    assert resp.status_code == 200
    assert resp.json()["watch_dismissed"] is False
    assert [d["mac"] for d in client.get("/api/devices/unclassified").json()] == [MAC]


def test_dismiss_unknown_device_404(client: TestClient) -> None:
    resp = client.post("/api/devices/AA:BB:CC:DD:EE:99/dismiss", json={"dismissed": True})
    assert resp.status_code == 404


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


# ── POST "" (manuell anlegen): 200 / 409 / 422 ──────────────────────────────


def test_create_device_returns_manual_known(client: TestClient) -> None:
    resp = client.post("/api/devices", json={"mac": MAC, "label": "Drucker"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["mac"] == MAC
    assert body["is_known"] is True
    # source wird im Response NICHT serialisiert -> ueber GET pruefen waere noetig;
    # hier zeigt is_known/label, dass das manuelle Geraet angelegt wurde.
    assert body["label"] == "Drucker"


def test_create_device_duplicate_409(client: TestClient, repo: SqliteDeviceRepository) -> None:
    repo.save(_device(is_known=True))
    resp = client.post("/api/devices", json={"mac": MAC})
    assert resp.status_code == 409


def test_create_device_invalid_mac_422(client: TestClient) -> None:
    resp = client.post("/api/devices", json={"mac": ""})
    assert resp.status_code == 422


# ── Archivieren / Wiederherstellen: Liste vs. /archived ─────────────────────


def test_archive_moves_device_out_of_list_into_archived(
    client: TestClient, repo: SqliteDeviceRepository
) -> None:
    repo.save(_device(is_known=True))
    # Frisch angelegt: in der Standard-Liste, nicht im Archiv.
    assert [d["mac"] for d in client.get("/api/devices").json()] == [MAC]
    assert client.get("/api/devices/archived").json() == []
    # Archivieren -> verschwindet aus der Liste, taucht im Archiv auf.
    assert client.post(f"/api/devices/{MAC}/archive").status_code == 200
    assert client.get("/api/devices").json() == []
    assert [d["mac"] for d in client.get("/api/devices/archived").json()] == [MAC]
    # Wiederherstellen -> zurueck in der Liste, raus aus dem Archiv.
    assert client.post(f"/api/devices/{MAC}/restore").status_code == 200
    assert [d["mac"] for d in client.get("/api/devices").json()] == [MAC]
    assert client.get("/api/devices/archived").json() == []


def test_archive_unknown_device_404(client: TestClient) -> None:
    assert client.post("/api/devices/AA:BB:CC:DD:EE:99/archive").status_code == 404


def test_restore_unknown_device_404(client: TestClient) -> None:
    assert client.post("/api/devices/AA:BB:CC:DD:EE:99/restore").status_code == 404


def test_archive_prompt_unknown_device_404(client: TestClient) -> None:
    resp = client.post("/api/devices/AA:BB:CC:DD:EE:99/archive-prompt", json={"archive": False})
    assert resp.status_code == 404


# ── Archiv-Nachfrage 3x-Regel end-to-end ueber HTTP ─────────────────────────


def test_archive_prompt_three_no_removes_from_candidates(
    client: TestClient, repo: SqliteDeviceRepository
) -> None:
    # Zeitfalle: die Kandidaten-Schwelle (30 Tage) misst gegen die echte
    # SystemClock. Daher das Test-Geraet ueber die repo-Fixture mit einem WEIT
    # alten last_seen vorab anlegen -- so ist es ueberhaupt Kandidat.
    old = datetime.now(UTC) - timedelta(days=365)
    repo.save(_device(is_known=False, first_seen=old, last_seen=old))
    # Vor der Nachfrage: Kandidat.
    before = [d["mac"] for d in client.get("/api/devices/archive-candidates").json()]
    assert MAC in before
    # Dreimal "Nein" -> ab dem 3. Nein dauerhaft nicht mehr fragen.
    for _ in range(3):
        resp = client.post(f"/api/devices/{MAC}/archive-prompt", json={"archive": False})
        assert resp.status_code == 200
    # Danach kein Kandidat mehr (archive_prompt_dismissed=True), obwohl alt genug.
    after = [d["mac"] for d in client.get("/api/devices/archive-candidates").json()]
    assert MAC not in after
