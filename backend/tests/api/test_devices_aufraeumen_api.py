"""End-to-end-Tests der zwei Aufraeumen-Endpunkte (S88-P3) gegen app.py via TestClient.

``GET  /api/devices/netz-gruppen`` -- die Netzgruppen des aktiven Bestands.
``POST /api/devices/remove-many``  -- die Mengen-Loeschung.

Echte Adapter auf einer ``tmp_path``-DB (Muster ``test_devices_api.py``): beide
Endpunkte laufen hier ueber die ECHTEN Use-Cases und den ECHTEN SQLite-Loeschweg,
nur der DB-Pfad ist ein anderer. Damit deckt diese Datei ab, was Fakes nicht
koennen -- dass die Route ueberhaupt matcht (der Pfad-Parameter ``/{mac}`` faengt
sonst ``netz-gruppen``) und dass die Serialisierung stimmt.
"""

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.devices import (
    provide_archive_device,
    provide_entferne_geraete_menge,
    provide_get_archived_devices,
    provide_get_devices,
    provide_gruppiere_nach_netz,
)
from app import create_app
from application.devices import ArchiveDevice, GetArchivedDevices, GetDevices
from application.maintenance import (
    OHNE_IP,
    EntferneGeraeteMenge,
    GruppiereGeraeteNachNetz,
)
from domain.devices import Device
from infrastructure.config import AppConfig
from infrastructure.device_purge import SqliteDevicePurgeRepository
from infrastructure.device_repository import SqliteDeviceRepository


@pytest.fixture
def db(tmp_path: Path) -> Path:
    return tmp_path / "cernis.db"


@pytest.fixture
def repo(db: Path) -> SqliteDeviceRepository:
    return SqliteDeviceRepository(db)


def _device(mac: str, last_ip: str, **over: Any) -> Device:
    now = datetime.now(UTC)
    base: dict[str, Any] = {
        "mac": mac,
        "first_seen": now,
        "last_seen": now,
        "last_ip": last_ip,
        "times_seen": 1,
        "is_known": False,
    }
    base.update(over)
    return Device(**base)


@pytest.fixture
def client(db: Path, repo: SqliteDeviceRepository) -> Iterator[TestClient]:
    app: FastAPI = create_app(AppConfig())
    app.dependency_overrides[provide_gruppiere_nach_netz] = lambda: GruppiereGeraeteNachNetz(repo)
    app.dependency_overrides[provide_entferne_geraete_menge] = lambda: EntferneGeraeteMenge(
        SqliteDevicePurgeRepository(db)
    )
    # Fuer die Nachher-Kontrolle ueber die normale Liste.
    app.dependency_overrides[provide_get_devices] = lambda: GetDevices(repo)
    app.dependency_overrides[provide_archive_device] = lambda: ArchiveDevice(repo)
    app.dependency_overrides[provide_get_archived_devices] = lambda: GetArchivedDevices(repo)
    with TestClient(app) as test_client:
        yield test_client


# ── GET /api/devices/netz-gruppen ────────────────────────────────────────────


def test_netz_gruppen_liefert_netz_anzahl_und_macs(
    client: TestClient, repo: SqliteDeviceRepository
) -> None:
    """Der Endpunkt liefert je Gruppe genau die drei Angaben aus Auftrag 2.3."""
    repo.save(_device("AA:BB:CC:00:00:01", "192.168.1.5"))
    repo.save(_device("AA:BB:CC:00:00:02", "192.168.1.6"))
    repo.save(_device("AA:BB:CC:00:00:03", "10.0.0.1"))
    repo.save(_device("AA:BB:CC:00:00:04", ""))

    antwort = client.get("/api/devices/netz-gruppen")

    assert antwort.status_code == 200
    assert antwort.json() == [
        {"netz": "10.0.0.0/24", "anzahl": 1, "macs": ["AA:BB:CC:00:00:03"]},
        {
            "netz": "192.168.1.0/24",
            "anzahl": 2,
            "macs": ["AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02"],
        },
        {"netz": OHNE_IP, "anzahl": 1, "macs": ["AA:BB:CC:00:00:04"]},
    ]


def test_netz_gruppen_matcht_vor_dem_mac_pfad_parameter(client: TestClient) -> None:
    """ "netz-gruppen" darf NICHT als MAC in ``GET /{mac}`` landen.

    Stuende die Route hinter ``/{mac}``, lieferte sie 404 (Geraet nicht gefunden)
    statt der Gruppenliste -- der klassische Reihenfolge-Fehler, den der Bestand
    mit ``/stats``/``/archived`` schon einmal hatte.
    """
    antwort = client.get("/api/devices/netz-gruppen")

    assert antwort.status_code == 200
    assert isinstance(antwort.json(), list)


def test_netz_gruppen_bei_leerem_bestand(client: TestClient) -> None:
    """Leerer Bestand -> leere Liste, kein Fehler und kein erfundener Posten."""
    assert client.get("/api/devices/netz-gruppen").json() == []


def test_archivierte_geraete_zaehlen_nicht_mit(
    client: TestClient, repo: SqliteDeviceRepository
) -> None:
    """2.3: Die Gruppierung folgt der aktiven Liste -- Archiviertes bleibt aussen vor.

    Sonst raeumte der Anwender Geraete mit ab, die er gar nicht vor sich sieht.
    """
    repo.save(_device("AA:BB:CC:00:00:01", "192.168.1.5"))
    repo.save(_device("AA:BB:CC:00:00:02", "192.168.1.6"))
    client.post("/api/devices/AA:BB:CC:00:00:02/archive")

    gruppen = client.get("/api/devices/netz-gruppen").json()

    assert gruppen == [{"netz": "192.168.1.0/24", "anzahl": 1, "macs": ["AA:BB:CC:00:00:01"]}]


# ── POST /api/devices/remove-many ────────────────────────────────────────────


def test_remove_many_entfernt_die_uebergebenen_geraete(
    client: TestClient, repo: SqliteDeviceRepository
) -> None:
    """Der Weg von der Auswahl bis zum leeren Bestand, ueber HTTP."""
    repo.save(_device("AA:BB:CC:00:00:01", "192.168.1.5"))
    repo.save(_device("AA:BB:CC:00:00:02", "192.168.1.6"))
    repo.save(_device("AA:BB:CC:00:00:03", "10.0.0.1"))

    antwort = client.post(
        "/api/devices/remove-many",
        json={"macs": ["AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02"]},
    )

    assert antwort.status_code == 200
    assert antwort.json() == {"ok": True, "entfernt": 2}
    assert [d["mac"] for d in client.get("/api/devices").json()] == ["AA:BB:CC:00:00:03"]


def test_remove_many_mit_leerer_liste_ist_kein_fehler(
    client: TestClient, repo: SqliteDeviceRepository
) -> None:
    """4.5 ueber HTTP: leere Auswahl -> 200, nichts geloescht."""
    repo.save(_device("AA:BB:CC:00:00:01", "192.168.1.5"))

    antwort = client.post("/api/devices/remove-many", json={"macs": []})

    assert antwort.status_code == 200
    assert antwort.json() == {"ok": True, "entfernt": 0}
    assert len(client.get("/api/devices").json()) == 1


def test_remove_many_mit_unbekannter_mac_ist_kein_fehler(client: TestClient) -> None:
    """1.4: dem gemessenen Verhalten von ``DELETE /{mac}`` folgen -- idempotent, kein 404."""
    antwort = client.post("/api/devices/remove-many", json={"macs": ["00:11:22:33:44:55"]})

    assert antwort.status_code == 200
    assert antwort.json() == {"ok": True, "entfernt": 0}


def test_remove_many_mit_ungueltiger_mac_ist_kein_fehler(client: TestClient) -> None:
    """Ungueltige MACs werfen nicht -- sie raeumen nur nichts ab.

    Bewusste Wahl (1.4), begruendet am Bestand: ``DELETE /{mac}`` ist ausdruecklich
    idempotent. In einer MENGE waere ein harter Fehler zudem schaedlich -- eine
    zwischen Anzeige und Klick veraltete Liste duerfte nicht die Loeschung der
    uebrigen Geraete verhindern.
    """
    antwort = client.post("/api/devices/remove-many", json={"macs": ["keine-mac", ""]})

    assert antwort.status_code == 200
    assert antwort.json() == {"ok": True, "entfernt": 0}


def test_remove_many_ohne_macs_feld_ist_422(client: TestClient) -> None:
    """Ein fehlendes Pflichtfeld bleibt ein Eingabefehler (Pydantic, Bestandsmuster)."""
    assert client.post("/api/devices/remove-many", json={}).status_code == 422


def test_remove_many_raeumt_auch_die_ip_historie(
    client: TestClient, repo: SqliteDeviceRepository, db: Path
) -> None:
    """Ueber HTTP belegt: nicht nur die devices-Zeile geht, auch der IP-Verlauf.

    Die vollstaendige Neun-Tabellen-Messung steht im tragenden Test
    (``tests/infrastructure/test_device_purge.py``); hier geht es darum, dass der
    Endpunkt wirklich den Vollloeschweg ruft und nicht ein schlichtes DELETE.
    """
    import sqlite3

    from domain.devices import IpHistoryEntry

    repo.save(_device("AA:BB:CC:00:00:01", "192.168.1.5"))
    repo.append_ip_history(
        IpHistoryEntry(mac="AA:BB:CC:00:00:01", ip="192.168.1.5", seen_at=datetime.now(UTC))
    )
    conn = sqlite3.connect(db)
    vorher = conn.execute("SELECT count(*) FROM device_ip_history").fetchone()[0]
    conn.close()
    assert vorher == 1

    client.post("/api/devices/remove-many", json={"macs": ["AA:BB:CC:00:00:01"]})

    conn = sqlite3.connect(db)
    try:
        assert conn.execute("SELECT count(*) FROM device_ip_history").fetchone()[0] == 0
    finally:
        conn.close()
