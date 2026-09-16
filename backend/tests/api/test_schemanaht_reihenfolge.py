"""Beweis: die Schemanaht laeuft VOR der ersten Repository-Nutzung (S88-P1a, 5.6).

Das ist die tragende Zusage der Zweiteilung aus ``create_app``: ``schema_pruefen``
steht ganz am Anfang, VOR jeder Verwendung einer Repository-Factory. Nur so kann Fall
D (zu neue Datenbank) verweigert werden, BEVOR ein Repository die Datei beruehrt --
denn sechs Repositories entstehen schon im Koerper von create_app, unabhaengig von
``bootstrap_on_startup``.

Gemessen wird an einer ECHTEN Wegwerf-Datenbank in ``tmp_path`` (also unter ``/tmp``),
nicht an einer Attrappe: geprueft wird die REIHENFOLGE echter Handlungen an einer
echten Datei.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

import app as app_module
from infrastructure.config import AppConfig
from infrastructure.db_schema import SCHEMA_VERSION, SchemaTooNewError, schema_pruefen


@pytest.fixture
def tmp_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Biegt den DB-Pfad auf eine Wegwerf-Datei unter ``/tmp`` um -- an ALLEN Stellen.

    Die v2-Repositories fragen ``get_db_path()`` bei jedem Bau frisch. Die drei
    Altcode-Initialisierer binden dagegen ``DB_PATH`` als MODULKONSTANTE an sich
    (``from modules.db_path import DB_PATH``, ausgewertet beim Import) -- sie muessen
    darum am jeweiligen Modul-Namensraum umgebogen werden, Muster wie in
    ``tests/characterization/test_devices_db.py``. Im echten Betrieb zeigen beide Wege
    ohnehin auf dieselbe Datei; nur im Test faellt der Unterschied auf.
    """
    from modules import alerting as alerting_modul
    from modules import devices_db as devices_db_modul
    from modules import storage as storage_modul

    db = tmp_path / "cernis.db"
    monkeypatch.setattr("modules.db_path.get_db_path", lambda: db)
    monkeypatch.setattr(storage_modul, "DB_PATH", str(db))
    monkeypatch.setattr(devices_db_modul, "DB_PATH", str(db))
    monkeypatch.setattr(alerting_modul, "DB_PATH", str(db))
    return db


def test_schemanaht_laeuft_vor_der_ersten_repository_nutzung(
    tmp_db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Im Protokoll der Aufrufe steht ``schema_pruefen`` VOR jedem Repository-Bau.

    Aufgezeichnet wird an zwei Stellen: an ``schema_pruefen`` (die Naht) und an
    ``sqlite3.connect`` (jede Beruehrung der Datei, egal von welchem Repository).
    """
    protokoll: list[str] = []

    # Nicht ueber ``app_module.schema_pruefen`` -- app.py importiert den Namen nur,
    # exportiert ihn aber nicht; das echte Verhalten steht im Herkunftsmodul.
    echtes_schema_pruefen = schema_pruefen

    def spy_schema_pruefen(*args: Any, **kwargs: Any) -> int:
        protokoll.append("schema_pruefen")
        return echtes_schema_pruefen(*args, **kwargs)

    echtes_connect = sqlite3.connect

    def spy_connect(*args: Any, **kwargs: Any) -> sqlite3.Connection:
        if args and str(args[0]) == str(tmp_db):
            protokoll.append("db_beruehrt")
        verbindung: sqlite3.Connection = echtes_connect(*args, **kwargs)
        return verbindung

    monkeypatch.setattr(app_module, "schema_pruefen", spy_schema_pruefen)
    monkeypatch.setattr(sqlite3, "connect", spy_connect)

    app_module.create_app(AppConfig())

    assert "schema_pruefen" in protokoll, "die Naht muss ueberhaupt laufen"
    assert "db_beruehrt" in protokoll, "Vorbedingung: es wird ueberhaupt eine DB gebaut"
    assert protokoll.index("schema_pruefen") < protokoll.index("db_beruehrt"), (
        "die Schemanaht muss VOR der ersten Datenbank-Beruehrung laufen; "
        f"Protokollanfang: {protokoll[:5]}"
    )


def test_schemanaht_verweigert_zu_neue_datenbank_beim_app_bau(tmp_db: Path) -> None:
    """Eine zu neue Datenbank laesst ``create_app`` scheitern -- ohne sie anzufassen.

    Belegt zugleich, dass die Verweigerung frueh genug greift: die Datei bleibt
    BYTEGLEICH, obwohl der App-Bau sechs Repositories im Koerper gebaut haette.
    """
    conn = sqlite3.connect(tmp_db)
    try:
        conn.execute("CREATE TABLE devices (mac TEXT PRIMARY KEY)")
        conn.execute("INSERT INTO devices (mac) VALUES ('aa:bb:cc:dd:ee:ff')")
        conn.commit()
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 98}")
    finally:
        conn.close()

    bytes_vorher = tmp_db.read_bytes()

    with pytest.raises(SchemaTooNewError) as fehler:
        app_module.create_app(AppConfig())

    assert fehler.value.gelesene_fassung == SCHEMA_VERSION + 98
    assert fehler.value.erwartete_fassung == SCHEMA_VERSION
    assert tmp_db.read_bytes() == bytes_vorher, "die zu neue Datei darf nicht angefasst werden"


def test_schemanaht_haengt_nicht_am_bootstrap_schalter(tmp_db: Path) -> None:
    """Auch ohne ``bootstrap_on_startup`` traegt die Datenbank danach ihre Fassung.

    Begruendung (Aufgabe 2.4): sechs Repositories entstehen auch ohne diesen Schalter,
    also darf die Fassungspflege nicht dahinter liegen.
    """
    app = app_module.create_app(AppConfig())
    assert app is not None

    conn = sqlite3.connect(tmp_db)
    try:
        assert int(conn.execute("PRAGMA user_version").fetchone()[0]) == SCHEMA_VERSION
    finally:
        conn.close()


def test_app_bau_legt_alle_achtunddreissig_tabellen_an(tmp_db: Path) -> None:
    """Nach dem App-Bau traegt eine frische Datenbank ALLE 38 Tabellen.

    Vor S88-P1a entstanden beim Start nur 24 -- die uebrigen 14 kamen erst, wenn ein
    Anwender die zugehoerige Funktion zum ersten Mal benutzte. Jetzt zieht die Naht
    sie alle beim Bau nach.
    """
    with TestClient(app_module.create_app(AppConfig())):
        pass

    conn = sqlite3.connect(tmp_db)
    try:
        tabellen = {
            zeile[0]
            for zeile in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
    finally:
        conn.close()

    assert len(tabellen) == 38, f"38 Tabellen erwartet, fand {len(tabellen)}: {sorted(tabellen)}"


def test_devices_behaelt_das_altcode_spaltenbild(tmp_db: Path) -> None:
    """Die Aufbaureihenfolge erhaelt das heutige devices-Spaltenbild.

    ``init_devices_db`` laeuft VOR ``device_repository`` -- auf leerer Datenbank
    gewinnt damit der Altcode-CREATE mit 14 Spalten, die sechs v2-Spalten kommen per
    additivem ALTER dahinter. Eine andere Reihenfolge erzeugte eine andere
    Spaltenfolge; dieser Test friert die heutige ein.
    """
    app_module.create_app(AppConfig())

    conn = sqlite3.connect(tmp_db)
    try:
        spalten = [zeile[1] for zeile in conn.execute("PRAGMA table_info(devices)")]
    finally:
        conn.close()

    assert spalten == [
        # 14 Spalten aus dem Altcode-CREATE (modules/devices_db.py) ...
        "mac",
        "vendor",
        "label",
        "tags",
        "notes",
        "category",
        "is_known",
        "first_seen",
        "last_seen",
        "last_ip",
        "times_seen",
        "open_ports",
        "hostname",
        "os_guess",
        # ... und sechs per ALTER nachgeruestete v2-Spalten.
        "trust_state",
        "watch_dismissed",
        "archived",
        "source",
        "archive_prompt_count",
        "archive_prompt_dismissed",
    ]
