"""Characterization-Tests fuer das Ist-Verhalten der devices-Domaene.

Halten das AKTUELLE Verhalten des Altcodes fest -- nicht das gewuenschte. Die
drei bekannten Bugs (Phase-0-/Ist-Analyse-Befund) werden hier charakterisiert,
WIE SIE SIND, nicht korrigiert: Diese Tests sind das Sicherheitsnetz, gegen das
die devices-Migration (Strangler Fig) antritt. Die bewusste Abweichung in v2
wird so belegbar.

Betroffener Altcode: ``modules/devices_db.py`` (Tabellen ``devices`` +
``device_ip_history``) und der ``known_devices``-Teil von ``modules/storage.py``.
Beide Tabellengruppen leben real in derselben ``cernis.db`` -- die Tests fahren
darum gegen EINE gemeinsame temporaere DB.
"""

import re
import sqlite3
from pathlib import Path
from typing import Any, NamedTuple

import pytest


class DevicesEnv(NamedTuple):
    """Beide Altcode-Module gegen dieselbe temporaere DB plus der DB-Pfad."""

    devices: Any
    storage: Any
    db_file: Path


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> DevicesEnv:
    """``devices_db`` UND ``storage`` gegen DIESELBE frische temporaere DB.

    Beide Module lesen ``DB_PATH`` zur Laufzeit ueber den Modul-Namen, darum wird
    er per ``setattr`` auf die tmp-DB umgebogen (gleiches Muster wie
    ``test_settings_storage``). ``CERNIS_DATA_DIR`` wird zusaetzlich vor dem
    Import gesetzt, damit ``db_path`` keine echten Nutzerverzeichnisse anlegt.
    """
    monkeypatch.setenv("CERNIS_DATA_DIR", str(tmp_path))
    from modules import devices_db, storage

    db_file = tmp_path / "cernis.db"
    monkeypatch.setattr(devices_db, "DB_PATH", str(db_file))
    monkeypatch.setattr(storage, "DB_PATH", str(db_file))
    devices_db.init_devices_db()  # devices + device_ip_history
    storage.init_db()  # settings + known_devices + scan_history
    return DevicesEnv(devices=devices_db, storage=storage, db_file=db_file)


def _scan(mac: str, ip: str, **extra: Any) -> dict[str, Any]:
    """Baut ein host-Dict, wie es die scanning-WS an update_device_from_scan gibt."""
    host: dict[str, Any] = {"mac": mac, "ip": ip}
    host.update(extra)
    return host


# ── A) devices_db-Funktionsvertrag ─────────────────────────────────────────


def test_update_device_from_scan_first_insert(env: DevicesEnv) -> None:
    env.devices.update_device_from_scan(
        _scan(
            "AA:BB:CC:00:00:50",
            "10.0.0.50",
            vendor="TestVendor",
            hostname="host.local",
            os_guess="Linux",
            ports=[
                {"port": 22, "state": "open", "service": "SSH"},
                {"port": 80, "state": "open", "service": "HTTP"},
            ],
        )
    )
    dev = env.devices.get_device("AA:BB:CC:00:00:50")
    assert dev is not None
    assert dev["times_seen"] == 1
    assert dev["is_known"] == 0  # Erst-Insert immer unknown (vgl. BUG 2)
    assert dev["last_ip"] == "10.0.0.50"
    assert dev["vendor"] == "TestVendor"
    assert dev["hostname"] == "host.local"
    assert dev["os_guess"] == "Linux"
    assert dev["open_ports"] == [22, 80]  # JSON -> Liste von Port-Ints
    assert dev["tags"] == []
    assert len(dev["ip_history"]) == 1
    assert dev["ip_history"][0]["ip"] == "10.0.0.50"


def test_update_device_from_scan_rescan_same_ip_increments_no_new_history(
    env: DevicesEnv,
) -> None:
    env.devices.update_device_from_scan(_scan("AA:BB:CC:00:00:51", "10.0.0.51"))
    env.devices.update_device_from_scan(_scan("AA:BB:CC:00:00:51", "10.0.0.51"))
    dev = env.devices.get_device("AA:BB:CC:00:00:51")
    assert dev["times_seen"] == 2
    assert len(dev["ip_history"]) == 1  # gleiche IP -> kein neuer History-Eintrag


def test_update_device_from_scan_new_ip_adds_history(env: DevicesEnv) -> None:
    env.devices.update_device_from_scan(_scan("AA:BB:CC:00:00:52", "10.0.0.10"))
    env.devices.update_device_from_scan(_scan("AA:BB:CC:00:00:52", "10.0.0.11"))
    dev = env.devices.get_device("AA:BB:CC:00:00:52")
    assert dev["times_seen"] == 2
    assert dev["last_ip"] == "10.0.0.11"
    assert len(dev["ip_history"]) == 2
    assert dev["ip_history"][0]["ip"] == "10.0.0.11"  # neuester zuerst


def test_get_device_ip_history_capped_at_20(env: DevicesEnv) -> None:
    for i in range(1, 22):  # 21 verschiedene IPs -> 21 History-Zeilen
        env.devices.update_device_from_scan(_scan("AA:BB:CC:00:00:53", f"10.0.0.{i}"))
    dev = env.devices.get_device("AA:BB:CC:00:00:53")
    assert dev["times_seen"] == 21
    assert len(dev["ip_history"]) == 20  # get_device kappt auf 20
    assert dev["ip_history"][0]["ip"] == "10.0.0.21"  # neuester zuerst


def test_get_device_returns_none_for_missing(env: DevicesEnv) -> None:
    assert env.devices.get_device("00:00:00:00:00:00") is None


def test_get_all_devices_filter_known(env: DevicesEnv) -> None:
    env.devices.update_device_from_scan(_scan("AA:BB:CC:00:00:60", "10.0.0.60"))
    env.devices.update_device_from_scan(_scan("AA:BB:CC:00:00:61", "10.0.0.61"))
    env.devices.update_device_meta("AA:BB:CC:00:00:60", is_known=True)

    all_macs = {d["mac"] for d in env.devices.get_all_devices(filter_known=False)}
    assert all_macs == {"AA:BB:CC:00:00:60", "AA:BB:CC:00:00:61"}

    known = env.devices.get_all_devices(filter_known=True)
    assert [d["mac"] for d in known] == ["AA:BB:CC:00:00:60"]


def test_get_all_devices_parses_json_fields(env: DevicesEnv) -> None:
    env.devices.update_device_from_scan(
        _scan(
            "AA:BB:CC:00:00:62",
            "10.0.0.62",
            ports=[{"port": 443, "state": "open", "service": "HTTPS"}],
        )
    )
    env.devices.update_device_meta("AA:BB:CC:00:00:62", tags=["server", "dmz"])
    dev = env.devices.get_all_devices()[0]
    assert dev["open_ports"] == [443]
    assert dev["tags"] == ["server", "dmz"]


def test_get_all_devices_orders_by_last_seen_desc(env: DevicesEnv) -> None:
    env.devices.update_device_from_scan(_scan("AA:BB:CC:00:00:70", "10.0.0.70"))
    env.devices.update_device_from_scan(_scan("AA:BB:CC:00:00:71", "10.0.0.71"))
    # last_seen deterministisch setzen (sonst ggf. gleiche Sekunde -> flaky):
    with sqlite3.connect(str(env.db_file)) as conn:
        conn.execute(
            "UPDATE devices SET last_seen=? WHERE mac=?",
            ("2020-01-01 00:00:00", "AA:BB:CC:00:00:70"),
        )
        conn.execute(
            "UPDATE devices SET last_seen=? WHERE mac=?",
            ("2025-01-01 00:00:00", "AA:BB:CC:00:00:71"),
        )
    macs = [d["mac"] for d in env.devices.get_all_devices()]
    assert macs == ["AA:BB:CC:00:00:71", "AA:BB:CC:00:00:70"]  # neuer zuerst


def test_update_device_meta_partial_update(env: DevicesEnv) -> None:
    env.devices.update_device_from_scan(_scan("AA:BB:CC:00:00:80", "10.0.0.80"))
    env.devices.update_device_meta("AA:BB:CC:00:00:80", label="Drucker")
    env.devices.update_device_meta("AA:BB:CC:00:00:80", notes="im Flur")
    dev = env.devices.get_device("AA:BB:CC:00:00:80")
    assert dev["label"] == "Drucker"  # bleibt erhalten
    assert dev["notes"] == "im Flur"


def test_update_device_meta_is_noop_on_unknown_mac(env: DevicesEnv) -> None:
    # update_device_meta ist reines UPDATE (kein Insert): auf einen nie
    # gescannten MAC wirkt es nicht -> kein devices-Eintrag entsteht.
    env.devices.update_device_meta("AA:BB:CC:00:00:81", label="Phantom")
    assert env.devices.get_device("AA:BB:CC:00:00:81") is None


def test_get_device_stats(env: DevicesEnv) -> None:
    env.devices.update_device_from_scan(_scan("AA:BB:CC:00:00:90", "10.0.0.90"))
    env.devices.update_device_from_scan(_scan("AA:BB:CC:00:00:91", "10.0.0.91"))
    env.devices.update_device_from_scan(_scan("AA:BB:CC:00:00:92", "10.0.0.92"))
    env.devices.update_device_meta("AA:BB:CC:00:00:90", is_known=True)
    stats = env.devices.get_device_stats()
    assert stats["total"] == 3
    assert stats["known"] == 1
    assert stats["unknown"] == 2
    assert stats["active_24h"] == 3  # alle frisch gescannt


# ── B) BEKANNTE BUGS (Characterization: Ist-Verhalten, Korrektur in v2) ─────


def test_bug1_delete_only_removes_known_devices_not_devices(env: DevicesEnv) -> None:
    # BUG 1 (DELETE-Halbloeschung): DELETE /api/devices/{mac} (main.py:363-366)
    # ruft storage.delete_device -> loescht NUR aus known_devices. Die
    # devices-Zeile UND device_ip_history bleiben verwaist erhalten.
    mac = "AA:BB:CC:00:00:01"
    env.devices.update_device_from_scan(_scan(mac, "10.0.0.1"))
    env.storage.upsert_device(mac=mac, label="Mein Geraet")
    # Vorbedingung: in beiden Tabellen vorhanden
    assert env.devices.get_device(mac) is not None
    assert mac in {d["mac"] for d in env.storage.get_known_devices()}

    env.storage.delete_device(mac)  # der DELETE-Pfad des Endpunkts

    # known_devices: weg
    assert mac not in {d["mac"] for d in env.storage.get_known_devices()}
    # devices: NOCH da (BUG)
    assert env.devices.get_device(mac) is not None
    # device_ip_history: verwaist NOCH da (BUG)
    with sqlite3.connect(str(env.db_file)) as conn:
        history_rows = conn.execute(
            "SELECT COUNT(*) FROM device_ip_history WHERE mac=?", (mac,)
        ).fetchone()[0]
    assert history_rows >= 1


def test_bug2_is_known_diverges_between_tables(env: DevicesEnv) -> None:
    # BUG 2 (is_known-Doppelquelle): is_known wird in devices und known_devices
    # unabhaengig gefuehrt. update_device_from_scan setzt is_known nie (Insert=0,
    # Rescan ruehrt es nicht an); update_device_meta schreibt nur devices. Wer
    # ueber eine Tabelle markiert, laesst die andere stale zurueck.
    mac = "AA:BB:CC:00:00:02"
    env.devices.update_device_from_scan(_scan(mac, "10.0.0.2"))
    assert env.devices.get_device(mac)["is_known"] == 0

    env.devices.update_device_meta(mac, is_known=True)  # nur devices
    assert env.devices.get_device(mac)["is_known"] == 1
    # known_devices weiss nichts davon (Divergenz):
    assert mac not in {d["mac"] for d in env.storage.get_known_devices()}

    # Rescan setzt is_known in devices NICHT zurueck (Spalte wird nicht angefasst):
    env.devices.update_device_from_scan(_scan(mac, "10.0.0.2"))
    assert env.devices.get_device(mac)["is_known"] == 1


def test_bug3_put_path_dual_writes_both_tables(env: DevicesEnv) -> None:
    # BUG 3 (Dual-Write): der PUT-Pfad (main.py:348-361) schreibt Metadaten in
    # BEIDE Tabellen -- update_device_meta(devices) UND upsert_device(known_devices).
    mac = "AA:BB:CC:00:00:03"
    env.devices.update_device_from_scan(_scan(mac, "10.0.0.3"))
    # exakt die zwei Aufrufe, die der Endpunkt hintereinander absetzt:
    env.devices.update_device_meta(
        mac, label="L", tags=["t1"], notes="N", category="server", is_known=True
    )
    env.storage.upsert_device(mac=mac, label="L", tags=["t1"], notes="N", is_known=True)

    dev = env.devices.get_device(mac)
    assert dev["label"] == "L"
    assert dev["tags"] == ["t1"]
    assert dev["notes"] == "N"
    assert dev["is_known"] == 1

    known = {d["mac"]: d for d in env.storage.get_known_devices()}[mac]
    assert known["label"] == "L"
    assert known["tags"] == ["t1"]
    assert known["notes"] == "N"
    assert known["is_known"] == 1


# ── C) Zeitstempel-Inkonsistenz (BUG-nah, Rationale fuer den Clock-Port) ────

_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")


def test_timestamp_format_schema_default_vs_app_write(env: DevicesEnv) -> None:
    # Beide Schreibwege liefern dasselbe TEXT-Format "%Y-%m-%d %H:%M:%S" -- das
    # ist hier stabil pruefbar. Die Inkonsistenz steckt in der ZEITZONE, NICHT
    # im Format und wird daher bewusst nicht assertiert (waere zeitzonenabhaengig
    # flaky, z. B. gruen in UTC-CI, rot lokal):
    #   - Schema-Default `datetime('now')` (devices_db.py:32/33/44) -> SQLite UTC.
    #   - update_device_from_scan schreibt `datetime.now()` (devices_db.py:60) -> LOKAL.
    # Sie stimmen nur ueberein, wenn die Maschine in UTC laeuft. Daraus folgt der
    # latente active_24h-Versatz in get_device_stats (Vergleich gegen UTC
    # `datetime('now','-1 day')`). Genau diese Vermischung loest in v2 ein
    # Clock-Port sauber auf.

    # (1) Schema-Default fuellen (kein App-Code, reines INSERT):
    with sqlite3.connect(str(env.db_file)) as conn:
        conn.execute("INSERT INTO devices (mac) VALUES (?)", ("SCHEMA:DEFAULT:01",))
        default_ls = conn.execute(
            "SELECT last_seen FROM devices WHERE mac=?", ("SCHEMA:DEFAULT:01",)
        ).fetchone()[0]
    assert _TS_RE.match(default_ls)  # UTC, aber identisches Textformat

    # (2) App-Write ueber update_device_from_scan:
    env.devices.update_device_from_scan(_scan("AA:BB:CC:00:00:F0", "10.0.0.240"))
    app_ls = env.devices.get_device("AA:BB:CC:00:00:F0")["last_seen"]
    assert _TS_RE.match(app_ls)  # LOKAL, identisches Textformat
