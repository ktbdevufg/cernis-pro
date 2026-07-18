"""Tests fuer ``SqliteScanHistoryRepository`` -- gegen tmp_path-DB.

Haelt den S.1-Round-trip-Contract fest (``save`` + ``list`` ohne Blob + ``get``
mit Hosts, unbekannte ID -> ``None``) UND die v2-Schnitte: verlustfreie
``EnrichedHost``-Serialisierung (verschachtelte ``PortInfo`` / ``MdnsService`` /
``SsdpService`` und ``tuple``-Felder) sowie ``CorruptScanError`` statt eines
stillen ``or "[]"``-Rueckfalls bei kaputtem ``result_json``.
"""

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from domain.scanning import EnrichedHost, MdnsService, PortInfo, SsdpService
from infrastructure.scanning._serialization import dict_to_host
from infrastructure.scanning.scan_history import (
    CorruptScanError,
    SqliteScanHistoryRepository,
)
from ports.scanning import ScanHistoryRepository


class FakeClock:
    """Erfuellt das ``Clock``-Protocol strukturell; liefert einen festen Zeitpunkt.

    Timezone-aware UTC -- wie ``SystemClock``, damit ``.isoformat()`` einen Offset
    (``+00:00``) traegt und der Test deterministisch gegen den Erwartungswert prueft.
    """

    FIXED = datetime(2026, 7, 18, 13, 23, 45, 123456, tzinfo=UTC)

    def now(self) -> datetime:
        return self.FIXED


@pytest.fixture
def repo(tmp_path: Path) -> SqliteScanHistoryRepository:
    return SqliteScanHistoryRepository(tmp_path / "cernis.db", FakeClock())


# ── Struktureller Vertrag ─────────────────────────────────────────────────


def test_conforms_to_scan_history_protocol(repo: SqliteScanHistoryRepository) -> None:
    _: ScanHistoryRepository = repo


# ── Round-trip ─────────────────────────────────────────────────────────────


def test_save_then_list_summarizes_without_blob(repo: SqliteScanHistoryRepository) -> None:
    hosts = (
        EnrichedHost(ip="192.168.1.2", mac="AA:BB:CC:DD:EE:01", vendor="X"),
        EnrichedHost(ip="192.168.1.3", mac="AA:BB:CC:DD:EE:02", vendor="Y"),
    )
    repo.save("192.168.1.0/24", hosts)

    summaries = repo.list(20)
    assert len(summaries) == 1
    assert summaries[0].cidr == "192.168.1.0/24"
    assert summaries[0].host_count == 2  # == len(hosts)
    assert summaries[0].scan_id > 0
    # scanned_at: ISO-Zeitstempel aus der Clock (timezone-aware UTC), nicht leer.
    assert summaries[0].scanned_at != ""


def test_save_sets_scanned_at_from_clock_with_tz_offset(
    repo: SqliteScanHistoryRepository,
) -> None:
    """``scanned_at`` kommt aus der Clock: nicht leer, mit Zonen-Offset, exakter Wert.

    Belegt die A10-Etappe: der Zeitstempel wird explizit ueber den Clock-Port gesetzt
    (timezone-aware UTC, ISO-8601 mit +00:00) statt ueber den Schema-Default
    ``datetime('now')`` (UTC ohne Zonen-Kennzeichnung).
    """
    repo.save("192.168.1.0/24", ())

    scanned_at = repo.list(20)[0].scanned_at
    assert scanned_at != ""  # nicht leer
    assert scanned_at.endswith("+00:00")  # traegt eine Zeitzonen-Kennzeichnung
    assert scanned_at == FakeClock.FIXED.isoformat()  # exakt der Clock-Wert


def test_get_roundtrips_rich_host_lossless(repo: SqliteScanHistoryRepository) -> None:
    host = EnrichedHost(
        ip="10.0.0.5",
        mac="AA:BB:CC:DD:EE:01",
        vendor="Acme",
        rtt_ms=1.25,
        hostname="nas.local",
        smb_name="NAS",
        smb_domain="WORKGROUP",
        ipv6="2001:db8::5",
        ipv6_all=("2001:db8::5", "fe80::1", "fd00::5"),
        os_guess="Linux",
        os_accuracy=92,
        scan_method="nmap",
        ports=(PortInfo(port=22, state="open", service="ssh"), PortInfo(port=445, state="open")),
        mdns_services=(
            MdnsService(
                name="_smb._tcp",
                type="_smb._tcp.local.",
                port=445,
                hostname="nas.local",
                is_ndi=False,
                properties=(("model", "NAS"), ("vendor", "Acme")),
                ip="10.0.0.5",
            ),
        ),
        ssdp_services=(
            SsdpService(server="Linux/1.0 UPnP/1.0", st="upnp:rootdevice", ip="10.0.0.5"),
        ),
        is_ndi=False,
        is_unknown=True,
        category="nas",
        label="Lager-NAS",
        tags=("prod", "storage"),
        notes="Rack 3",
        source="arp",  # nicht-Default -> beweist source-Round-trip eines gemergten Hosts
    )
    repo.save("10.0.0.0/24", (host,))
    scan_id = repo.list(20)[0].scan_id

    record = repo.get(scan_id)
    assert record is not None
    assert record.cidr == "10.0.0.0/24"
    assert len(record.hosts) == 1
    got = record.hosts[0]
    assert got == host  # vollstaendige, verlustfreie Feldgleichheit
    assert got.source == "arp"  # source round-trippt (S.7f-Vorbau)
    # tuples bleiben tuples (nicht zu Listen degeneriert):
    assert isinstance(got.ports, tuple)
    assert isinstance(got.tags, tuple)
    assert isinstance(got.ipv6_all, tuple)  # JSON-Liste -> tuple, nicht degeneriert
    assert got.ipv6 == "2001:db8::5"
    assert isinstance(got.mdns_services[0].properties, tuple)
    assert isinstance(got.mdns_services[0].properties[0], tuple)
    # ip der verschachtelten Services round-trippt (S.5-Vorbau):
    assert got.mdns_services[0].ip == "10.0.0.5"
    assert got.ssdp_services[0].ip == "10.0.0.5"
    # host_count + scanned_at am Record (S.6-Vorbau, REST-Contract):
    assert record.host_count == 1
    assert record.scanned_at != ""


def test_legacy_blob_without_source_defaults_to_ping() -> None:
    """Alter DB-Blob (vor S.7f) ohne source-Feld -> EnrichedHost.source == "ping".

    Rueckwaertskompatibilitaet: ein damals gespeicherter Host war ein Ping-Host.
    """
    legacy = {"ip": "10.0.0.9", "mac": "AA:BB:CC:DD:EE:09"}  # kein "source"-Schluessel
    host = dict_to_host(scan_id=1, data=legacy)
    assert host.source == "ping"


def test_korrekte_paare_bleiben_erhalten() -> None:
    """Korrekt geformte ``properties`` ([[k, v], ...]) -> verlustfreies tuple.

    Regression gegen Ueberkorrektur: die Formpruefung in ``_str_pairs`` darf
    gueltige Paare NICHT verwerfen.
    """
    data = {
        "ip": "10.0.0.5",
        "mac": "AA:BB:CC:DD:EE:01",
        "mdns_services": [
            {"name": "_smb._tcp", "properties": [["k", "v"], ["a", "b"]]},
        ],
    }
    host = dict_to_host(scan_id=7, data=data)
    assert host.mdns_services[0].properties == (("k", "v"), ("a", "b"))


def test_flache_properties_liste_wird_corrupt_scan_error() -> None:
    """Formfremdes ``properties`` (flache String-Liste statt [key, value]-Paaren)
    -> benannter ``CorruptScanError`` MIT scan_id-Bezug, NICHT nackter ValueError.

    MUTATIONSPROBE (durchgefuehrt, ROT bestaetigt, zurueckgesetzt): wird die
    Laengen-Pruefung in ``_str_pairs`` auf ``!= 2`` verfaelscht, faellt der
    Schwester-Test ``test_korrekte_paare_bleiben_erhalten``; wird die
    ``isinstance``-Pruefung gelockert (Strings durchlassen), faellt
    ``test_zwei_zeichen_string_ist_kein_paar``. Vor dem Fix lieferte dieser Pfad
    einen nackten ``ValueError`` "too many values to unpack" ohne scan_id-Bezug.
    """
    data = {
        "ip": "10.0.0.5",
        "mac": "AA:BB:CC:DD:EE:01",
        "mdns_services": [
            {"name": "_smb._tcp", "properties": ["gcgl", "model", "at"]},
        ],
    }
    with pytest.raises(CorruptScanError) as exc:
        dict_to_host(scan_id=10, data=data)
    assert exc.value.scan_id == 10  # Fehler MIT scan_id-Bezug


def test_zwei_zeichen_string_ist_kein_paar() -> None:
    """Ein 2-Zeichen-String wie "ab" darf NICHT als Paar (a, b) durchgehen.

    Schaerft die isinstance-(list, tuple)-Pruefung ab: ``len("ab") == 2`` allein
    wuerde den String sonst still als Paar entpacken. MUTATIONSPROBE: faellt die
    ``isinstance``-Pruefung weg, laeuft dieser Test entweder still durch (falsches
    Paar) oder kracht roh -- statt sauberem ``CorruptScanError``.
    """
    data = {
        "ip": "10.0.0.5",
        "mac": "AA:BB:CC:DD:EE:01",
        "mdns_services": [{"name": "_smb._tcp", "properties": ["ab", "cd"]}],
    }
    with pytest.raises(CorruptScanError):
        dict_to_host(scan_id=11, data=data)


def test_save_empty_hosts_roundtrips(repo: SqliteScanHistoryRepository) -> None:
    repo.save("10.0.0.0/30", ())
    scan_id = repo.list(20)[0].scan_id
    record = repo.get(scan_id)
    assert record is not None
    assert record.hosts == ()


# ── Listen-Verhalten ────────────────────────────────────────────────────────


def test_list_empty_returns_empty_list(repo: SqliteScanHistoryRepository) -> None:
    assert repo.list(20) == []


def test_list_newest_first_and_respects_limit(repo: SqliteScanHistoryRepository) -> None:
    repo.save("10.0.0.0/24", ())
    repo.save("10.0.1.0/24", ())
    repo.save("10.0.2.0/24", ())

    summaries = repo.list(2)
    assert len(summaries) == 2  # limit greift
    assert summaries[0].cidr == "10.0.2.0/24"  # neuester zuerst (id DESC)
    assert summaries[1].cidr == "10.0.1.0/24"


# ── 404-Fall ─────────────────────────────────────────────────────────────────


def test_get_unknown_id_returns_none(repo: SqliteScanHistoryRepository) -> None:
    assert repo.get(9999) is None


# ── Kein stiller Fallback (CorruptScanError) ────────────────────────────────


def test_get_corrupt_json_raises_not_silent(
    repo: SqliteScanHistoryRepository, tmp_path: Path
) -> None:
    repo.save("10.0.0.0/24", (EnrichedHost(ip="10.0.0.5", mac="AA:BB:CC:DD:EE:01"),))
    scan_id = repo.list(20)[0].scan_id

    # result_json direkt korrumpieren (Bytes, die kein JSON sind)
    conn = sqlite3.connect(tmp_path / "cernis.db")
    conn.execute("UPDATE scan_history SET result_json = ? WHERE id = ?", ("{kaputt", scan_id))
    conn.commit()
    conn.close()

    with pytest.raises(CorruptScanError) as exc:
        repo.get(scan_id)
    assert exc.value.scan_id == scan_id  # Fehler MIT scan_id-Bezug


def test_get_non_array_json_raises(repo: SqliteScanHistoryRepository, tmp_path: Path) -> None:
    repo.save("10.0.0.0/24", ())
    scan_id = repo.list(20)[0].scan_id

    conn = sqlite3.connect(tmp_path / "cernis.db")
    conn.execute(
        "UPDATE scan_history SET result_json = ? WHERE id = ?",
        ('{"not": "a list"}', scan_id),
    )
    conn.commit()
    conn.close()

    with pytest.raises(CorruptScanError):
        repo.get(scan_id)
