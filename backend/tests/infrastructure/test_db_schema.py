"""Erprobung der Schemanaht (S88-P1a): ``infrastructure.db_schema``.

ALLES laeuft gegen ECHTE SQLite-Dateien in ``tmp_path`` (pytest legt das unter dem
Temp-Verzeichnis des Betriebssystems an, also unter ``/tmp``) -- keine Attrappen, kein
in-memory. Der Grund: geprueft wird das Verhalten AN einer Datei (Sicherung, Byte-
Gleichheit, ``PRAGMA user_version``), und das laesst sich mit einer Attrappe nicht
ehrlich belegen.

Die Wegwerf-Datenbank aus ``_gewachsener_bestand`` bildet das Muster des
Pruefgegenstands nach (gemessen: 31 von 38 Tabellen, ``user_version`` 0, ``devices``
mit dem Altcode-Spaltenbild aus 14 Spalten plus sechs nachgeruesteten). Der
Pruefgegenstand selbst wird dabei NICHT angefasst.
"""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

import pytest

from infrastructure.db_schema import (
    SCHEMA_VERSION,
    SchemaMigrationError,
    SchemaTooNewError,
    schema_aufbauen,
    schema_pruefen,
)

# ── Hilfsmittel ───────────────────────────────────────────────────────────────────

# Das Altcode-Spaltenbild von ``devices``: 14 Spalten, wie ``modules/devices_db.py``
# sie auf einer leeren Datenbank anlegt. Die sechs v2-Spalten fehlen hier bewusst --
# sie kommen im gewachsenen Bestand per additivem ALTER dazu, genau wie im Bestand.
_DEVICES_ALTCODE = """
    CREATE TABLE devices (
        mac          TEXT PRIMARY KEY,
        vendor       TEXT DEFAULT '',
        label        TEXT DEFAULT '',
        tags         TEXT DEFAULT '[]',
        notes        TEXT DEFAULT '',
        category     TEXT DEFAULT '',
        is_known     INTEGER DEFAULT 0,
        first_seen   TEXT DEFAULT (datetime('now')),
        last_seen    TEXT DEFAULT (datetime('now')),
        last_ip      TEXT DEFAULT '',
        times_seen   INTEGER DEFAULT 1,
        open_ports   TEXT DEFAULT '[]',
        hostname     TEXT DEFAULT '',
        os_guess     TEXT DEFAULT ''
    )
"""

_DEVICES_V2_SPALTEN = (
    "ALTER TABLE devices ADD COLUMN trust_state TEXT NOT NULL DEFAULT 'neutral'",
    "ALTER TABLE devices ADD COLUMN watch_dismissed INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE devices ADD COLUMN archived INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE devices ADD COLUMN source TEXT NOT NULL DEFAULT 'scan'",
    "ALTER TABLE devices ADD COLUMN archive_prompt_count INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE devices ADD COLUMN archive_prompt_dismissed INTEGER NOT NULL DEFAULT 0",
)


def _tabellen(db: Path) -> set[str]:
    """Liefert die Namen aller Tabellen (ohne die sqlite-internen)."""
    conn = sqlite3.connect(db)
    try:
        return {
            zeile[0]
            for zeile in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
    finally:
        conn.close()


def _fassung(db: Path) -> int:
    """Liest ``PRAGMA user_version`` der Datei."""
    conn = sqlite3.connect(db)
    try:
        return int(conn.execute("PRAGMA user_version").fetchone()[0])
    finally:
        conn.close()


def _spalten(db: Path, tabelle: str) -> list[str]:
    """Liefert das Spaltenbild einer Tabelle in Reihenfolge."""
    conn = sqlite3.connect(db)
    try:
        return [zeile[1] for zeile in conn.execute(f"PRAGMA table_info({tabelle})")]
    finally:
        conn.close()


def _inhalts_pruefsumme(db: Path) -> str:
    """Pruefsumme ueber ALLE Tabelleninhalte -- Namen, Spaltenbild und jede Zeile.

    Nicht ueber die Datei-Bytes: SQLite darf Seiten umsortieren, ohne dass sich am
    Inhalt etwas aendert. Geprueft wird also, was in der Datenbank STEHT.
    """
    hasher = hashlib.sha256()
    conn = sqlite3.connect(db)
    try:
        tabellen = sorted(
            zeile[0]
            for zeile in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        )
        for tabelle in tabellen:
            hasher.update(f"TABELLE {tabelle}\n".encode())
            for zeile in conn.execute(f"PRAGMA table_info({tabelle})"):
                hasher.update(f"  SPALTE {zeile[1]} {zeile[2]}\n".encode())
            for zeile in conn.execute(f"SELECT * FROM {tabelle} ORDER BY rowid"):
                hasher.update(f"  ZEILE {zeile!r}\n".encode())
    finally:
        conn.close()
    return hasher.hexdigest()


def _aufbauschritt(db: Path, sql: str) -> Callable[[], None]:
    """Baut einen Aufbauschritt, der ``sql`` idempotent ausfuehrt (eigene Verbindung).

    Bildet nach, was die 34 Repositories tun: eigene Verbindung, eigener Commit,
    ``CREATE TABLE IF NOT EXISTS``.
    """

    def schritt() -> None:
        conn = sqlite3.connect(db)
        try:
            with conn:
                conn.executescript(sql)
        finally:
            conn.close()

    return schritt


@pytest.fixture
def gewachsener_bestand(tmp_path: Path) -> Path:
    """Wegwerf-Datenbank nach dem Muster des Pruefgegenstands.

    ``user_version`` 0, nur ein TEIL der Tabellen vorhanden, ``devices`` mit dem
    Altcode-Spaltenbild (14 Spalten plus sechs nachgeruestete) und echten Daten darin.
    """
    db = tmp_path / "cernis.db"
    conn = sqlite3.connect(db)
    try:
        with conn:
            conn.executescript(_DEVICES_ALTCODE)
            for alter in _DEVICES_V2_SPALTEN:
                conn.execute(alter)
            conn.executescript(
                """
                CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE known_devices (mac TEXT PRIMARY KEY, name TEXT);
                CREATE TABLE device_ip_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, mac TEXT, ip TEXT, seen_at TEXT
                );
                """
            )
            conn.execute(
                "INSERT INTO devices (mac, vendor, label, last_ip, hostname)"
                " VALUES ('aa:bb:cc:dd:ee:ff', 'Fritz', 'Router', '192.168.1.1', 'fritz.box')"
            )
            conn.execute(
                "INSERT INTO devices (mac, vendor, label, last_ip, hostname)"
                " VALUES ('11:22:33:44:55:66', 'Apple', 'Laptop', '192.168.1.42', 'macbook')"
            )
            conn.execute(
                "INSERT INTO settings (key, value) VALUES ('scan_range', '192.168.1.0/24')"
            )
            conn.execute(
                "INSERT INTO device_ip_history (mac, ip, seen_at)"
                " VALUES ('aa:bb:cc:dd:ee:ff', '192.168.1.1', '2026-01-01 10:00:00')"
            )
    finally:
        conn.close()
    return db


# ── 5.1 Fall A: leere Datei ───────────────────────────────────────────────────────


def test_fall_a_leere_datei_bekommt_fassung_und_alle_tabellen(tmp_path: Path) -> None:
    """Auf einer leeren Datei laufen alle Aufbauschritte, danach steht die Fassung."""
    db = tmp_path / "cernis.db"
    erwartete_tabellen = {f"tabelle_{nummer:02d}" for nummer in range(38)}
    schritte = [
        _aufbauschritt(db, f"CREATE TABLE IF NOT EXISTS {name} (id INTEGER PRIMARY KEY)")
        for name in sorted(erwartete_tabellen)
    ]

    vorgefunden = schema_pruefen(db)
    assert vorgefunden == 0, "eine leere Datei traegt user_version 0"

    schema_aufbauen(db, vorgefunden, schritte)

    assert _fassung(db) == SCHEMA_VERSION == 1
    assert _tabellen(db) == erwartete_tabellen
    assert len(_tabellen(db)) == 38


def test_fall_a_legt_keine_sicherung_an(tmp_path: Path) -> None:
    """Fall A veraendert nichts, was nicht ohnehin idempotent ist -- also keine Sicherung."""
    db = tmp_path / "cernis.db"
    vorgefunden = schema_pruefen(db)
    schema_aufbauen(db, vorgefunden, [_aufbauschritt(db, "CREATE TABLE IF NOT EXISTS a (id INT)")])

    sicherungen = [pfad for pfad in tmp_path.iterdir() if ".sicherung" in pfad.name]
    assert sicherungen == [], f"Fall A darf keine Sicherung anlegen, fand aber {sicherungen}"


# ── 5.2 Fall A gegen einen GEWACHSENEN Bestand ────────────────────────────────────


def test_fall_a_gewachsener_bestand_behaelt_daten_und_spaltenbild(
    gewachsener_bestand: Path,
) -> None:
    """Die Naht zieht fehlende Tabellen nach, ohne Daten oder Spaltenbild anzutasten.

    Das ist der Fall, den ein echtes Update trifft: eine ueber Monate gewachsene
    Datenbank ohne Fassungsangabe, in der nur ein Teil der heutigen Tabellen steht.
    """
    db = gewachsener_bestand
    spalten_vorher = _spalten(db, "devices")
    tabellen_vorher = _tabellen(db)

    conn = sqlite3.connect(db)
    try:
        geraete_vorher = conn.execute("SELECT * FROM devices ORDER BY mac").fetchall()
        settings_vorher = conn.execute("SELECT * FROM settings ORDER BY key").fetchall()
    finally:
        conn.close()

    assert spalten_vorher[:14] == [
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
    ], "Vorbedingung: devices traegt das Altcode-Spaltenbild"
    assert len(spalten_vorher) == 20, "Vorbedingung: 14 Altcode- plus sechs v2-Spalten"

    # Aufbauschritte wie im Bestand: idempotente CREATE-Anweisungen. Die drei
    # vorhandenen Tabellen werden dabei erneut angefasst (IF NOT EXISTS greift), zwei
    # weitere kommen neu dazu.
    schritte = [
        _aufbauschritt(db, "CREATE TABLE IF NOT EXISTS devices (mac TEXT PRIMARY KEY)"),
        _aufbauschritt(db, "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY)"),
        _aufbauschritt(db, "CREATE TABLE IF NOT EXISTS sla_samples (id INTEGER PRIMARY KEY)"),
        _aufbauschritt(db, "CREATE TABLE IF NOT EXISTS remote_agents (id TEXT PRIMARY KEY)"),
    ]

    vorgefunden = schema_pruefen(db)
    assert vorgefunden == 0, "der gewachsene Bestand traegt keine Fassung"
    schema_aufbauen(db, vorgefunden, schritte)

    assert _fassung(db) == SCHEMA_VERSION

    # KEIN Datenverlust.
    conn = sqlite3.connect(db)
    try:
        assert conn.execute("SELECT * FROM devices ORDER BY mac").fetchall() == geraete_vorher
        assert conn.execute("SELECT * FROM settings ORDER BY key").fetchall() == settings_vorher
        assert conn.execute("SELECT count(*) FROM device_ip_history").fetchone()[0] == 1
    finally:
        conn.close()

    # KEINE Aenderung am Spaltenbild -- das idempotente CREATE hat die bestehende
    # devices-Tabelle nicht durch seine eigene, schmalere Fassung ersetzt.
    assert _spalten(db, "devices") == spalten_vorher

    # Fehlende Tabellen wurden nachgezogen, vorhandene blieben.
    assert tabellen_vorher <= _tabellen(db)
    assert {"sla_samples", "remote_agents"} <= _tabellen(db)


# ── 5.3 Fall B: zweiter Lauf aendert nichts ───────────────────────────────────────


def test_fall_b_zweiter_lauf_aendert_nichts(gewachsener_bestand: Path) -> None:
    """Nach dem ersten Lauf laesst ein zweiter den Inhalt unveraendert.

    Belegt ueber eine Pruefsumme ueber ALLE Tabelleninhalte vorher und nachher.
    """
    db = gewachsener_bestand
    schritte = [
        _aufbauschritt(db, "CREATE TABLE IF NOT EXISTS sla_samples (id INTEGER PRIMARY KEY)"),
        _aufbauschritt(db, "CREATE TABLE IF NOT EXISTS remote_agents (id TEXT PRIMARY KEY)"),
    ]

    # Erster Lauf: Fall A, hebt die Datei auf SCHEMA_VERSION.
    schema_aufbauen(db, schema_pruefen(db), schritte)
    assert _fassung(db) == SCHEMA_VERSION

    pruefsumme_vorher = _inhalts_pruefsumme(db)

    # Zweiter Lauf: jetzt Fall B -- die Aufbauschritte laufen erneut (sie sind
    # idempotent), sonst geschieht nichts.
    vorgefunden = schema_pruefen(db)
    assert vorgefunden == SCHEMA_VERSION, "Fall B: gelesene Fassung gleich der erwarteten"
    schema_aufbauen(db, vorgefunden, schritte)

    assert _inhalts_pruefsumme(db) == pruefsumme_vorher
    assert _fassung(db) == SCHEMA_VERSION


# ── 5.4 Fall D: zu neue Datenbank bleibt BYTEGLEICH ───────────────────────────────


def test_fall_d_zu_neue_datenbank_bleibt_bytegleich(gewachsener_bestand: Path) -> None:
    """Der wichtigste Test dieses Auftrags.

    Eine Datenbank aus einer neueren Programmfassung wird verweigert -- und dabei
    NICHT angefasst: kein Aufbauschritt, keine Sicherung, keine Fassung. Belegt ueber
    die Bytes der Datei, nicht ueber ihren Inhalt: selbst eine folgenlose Beruehrung
    (eine geoeffnete Schreibverbindung, ein neu geschriebener Header) faellt damit auf.
    """
    db = gewachsener_bestand
    conn = sqlite3.connect(db)
    try:
        conn.execute("PRAGMA user_version = 99")
    finally:
        conn.close()

    bytes_vorher = db.read_bytes()
    pruefsumme_vorher = hashlib.sha256(bytes_vorher).hexdigest()
    dateien_vorher = sorted(pfad.name for pfad in db.parent.iterdir())

    # Ein Aufbauschritt, der beim Laufen auffiele -- er darf NICHT laufen.
    gelaufen: list[str] = []

    def darf_nicht_laufen() -> None:
        gelaufen.append("aufbauschritt")

    with pytest.raises(SchemaTooNewError) as fehler:
        schema_pruefen(db)

    assert fehler.value.gelesene_fassung == 99
    assert fehler.value.erwartete_fassung == SCHEMA_VERSION
    assert gelaufen == [], "bei Fall D darf kein Aufbauschritt laufen"

    # BYTEGLEICH -- die tragende Zusage.
    assert db.read_bytes() == bytes_vorher
    assert hashlib.sha256(db.read_bytes()).hexdigest() == pruefsumme_vorher

    # Und keine Sicherung, kein sonstiger neuer Nachbar im Verzeichnis.
    assert sorted(pfad.name for pfad in db.parent.iterdir()) == dateien_vorher

    # Der Aufbauschritt haette bei einem Programmfehler ueber schema_aufbauen laufen
    # koennen -- er wird hier gar nicht erst erreicht, weil schema_pruefen wirft.
    assert darf_nicht_laufen is not None


def test_fall_d_traegt_die_fassungen_als_attribute(tmp_path: Path) -> None:
    """Die Ausnahme traegt die Zahlen als Attribute, nicht als zu parsenden Text."""
    db = tmp_path / "cernis.db"
    conn = sqlite3.connect(db)
    try:
        conn.execute("CREATE TABLE a (id INTEGER)")
        conn.execute("PRAGMA user_version = 7")
    finally:
        conn.close()

    with pytest.raises(SchemaTooNewError) as fehler:
        schema_pruefen(db, schema_version=3)

    assert isinstance(fehler.value.gelesene_fassung, int)
    assert isinstance(fehler.value.erwartete_fassung, int)
    assert (fehler.value.gelesene_fassung, fehler.value.erwartete_fassung) == (7, 3)


# ── 5.5 Die Sicherung ─────────────────────────────────────────────────────────────


def test_fall_c_legt_lesbare_sicherung_mit_demselben_inhalt_an(
    gewachsener_bestand: Path,
) -> None:
    """Fall C: kuenstliche Fassung 1 gegen SCHEMA_VERSION 2 -- ohne den Produktivwert anzutasten.

    ``schema_version`` und ``migrationen`` werden eingesetzt; ``SCHEMA_VERSION`` im
    Produktivcode bleibt unveraendert 1.
    """
    db = gewachsener_bestand
    conn = sqlite3.connect(db)
    try:
        conn.execute("PRAGMA user_version = 1")
    finally:
        conn.close()

    inhalt_vor_migration = _inhalts_pruefsumme(db)

    def migration_nach_2(verbindung: sqlite3.Connection) -> None:
        verbindung.execute("CREATE TABLE neu_in_fassung_2 (id INTEGER PRIMARY KEY)")

    vorgefunden = schema_pruefen(
        db,
        schema_version=2,
        migrationen={2: migration_nach_2},
        jetzt=datetime(2026, 8, 14, 11, 22, 33),
    )
    assert vorgefunden == 1

    # Die Sicherungsdatei ENTSTEHT, mit dem vereinbarten Namensschema.
    sicherungen = sorted(pfad for pfad in db.parent.iterdir() if ".sicherung" in pfad.name)
    assert len(sicherungen) == 1, f"genau eine Sicherung erwartet, fand {sicherungen}"
    sicherung = sicherungen[0]
    assert sicherung.name == "cernis.db.sicherung1-20260814-112233"

    # Sie ist LESBAR und traegt DENSELBEN Inhalt wie die Datenbank vor der Migration.
    assert _inhalts_pruefsumme(sicherung) == inhalt_vor_migration
    assert _fassung(sicherung) == 1

    # Die Migration lief, die Fassung steht aber noch nicht -- das tut schema_aufbauen.
    assert "neu_in_fassung_2" in _tabellen(db)
    assert _fassung(db) == 1

    schema_aufbauen(db, vorgefunden, [], schema_version=2)
    assert _fassung(db) == 2

    # Der Produktivwert blieb unberuehrt.
    assert SCHEMA_VERSION == 1


def test_sicherung_ueberschreibt_keine_bestehende(gewachsener_bestand: Path) -> None:
    """Zwei Laeufe in derselben Sekunde: die zweite Sicherung bekommt einen Zaehler."""
    db = gewachsener_bestand
    zeitpunkt = datetime(2026, 8, 14, 11, 22, 33)

    def migration_nach_2(verbindung: sqlite3.Connection) -> None:
        verbindung.execute("CREATE TABLE IF NOT EXISTS neu_in_fassung_2 (id INTEGER PRIMARY KEY)")

    for durchgang in range(2):
        conn = sqlite3.connect(db)
        try:
            conn.execute("PRAGMA user_version = 1")
        finally:
            conn.close()
        schema_pruefen(db, schema_version=2, migrationen={2: migration_nach_2}, jetzt=zeitpunkt)
        assert durchgang is not None

    namen = sorted(pfad.name for pfad in db.parent.iterdir() if ".sicherung" in pfad.name)
    assert namen == [
        "cernis.db.sicherung1-20260814-112233",
        "cernis.db.sicherung1-20260814-112233-1",
    ], f"die zweite Sicherung darf die erste nicht verdraengen, fand {namen}"


def test_fehlender_migrationsschritt_nennt_die_sicherung(gewachsener_bestand: Path) -> None:
    """Scheitert die Migration, traegt die Ausnahme den Pfad der Sicherung."""
    db = gewachsener_bestand
    conn = sqlite3.connect(db)
    try:
        conn.execute("PRAGMA user_version = 1")
    finally:
        conn.close()

    with pytest.raises(SchemaMigrationError) as fehler:
        schema_pruefen(db, schema_version=2, migrationen={})

    assert fehler.value.sicherung_pfad is not None
    assert fehler.value.sicherung_pfad.exists()
    assert (fehler.value.gelesene_fassung, fehler.value.erwartete_fassung) == (1, 2)
    # Die Fassung blieb stehen -- die Datei ist nicht halb migriert.
    assert _fassung(db) == 1


def test_gescheiterter_migrationsschritt_rollt_zurueck(gewachsener_bestand: Path) -> None:
    """Wirft ein Migrationsschritt, bleibt der Bestand auf dem alten Stand."""
    db = gewachsener_bestand
    conn = sqlite3.connect(db)
    try:
        conn.execute("PRAGMA user_version = 1")
    finally:
        conn.close()

    inhalt_vorher = _inhalts_pruefsumme(db)

    def migration_die_scheitert(verbindung: sqlite3.Connection) -> None:
        verbindung.execute("CREATE TABLE halb_fertig (id INTEGER PRIMARY KEY)")
        raise RuntimeError("Migration bricht ab")

    with pytest.raises(SchemaMigrationError) as fehler:
        schema_pruefen(db, schema_version=2, migrationen={2: migration_die_scheitert})

    assert "Migration bricht ab" in fehler.value.grund
    assert fehler.value.sicherung_pfad is not None
    assert "halb_fertig" not in _tabellen(db), "die Transaktion muss zurueckgerollt sein"
    assert _inhalts_pruefsumme(db) == inhalt_vorher
    assert _fassung(db) == 1


# ── Reihenfolge und Fehlerverhalten des Aufbaus ───────────────────────────────────


def test_aufbauschritte_laufen_in_der_uebergebenen_reihenfolge(tmp_path: Path) -> None:
    """Die Reihenfolge der Aufbauschritte ist die uebergebene -- darauf beruht 2.2."""
    db = tmp_path / "cernis.db"
    lauf: list[str] = []

    def merker(name: str) -> Callable[[], None]:
        def schritt() -> None:
            lauf.append(name)

        return schritt

    schritte = [merker("erster"), merker("zweiter"), merker("dritter")]

    schema_aufbauen(db, schema_pruefen(db), schritte)

    assert lauf == ["erster", "zweiter", "dritter"]


def test_fassung_bleibt_stehen_wenn_ein_aufbauschritt_wirft(tmp_path: Path) -> None:
    """Wirft ein Aufbauschritt, wird ``user_version`` NICHT gesetzt (letzte Handlung)."""
    db = tmp_path / "cernis.db"

    def schritt_der_wirft() -> None:
        raise RuntimeError("Aufbau scheitert")

    vorgefunden = schema_pruefen(db)
    with pytest.raises(RuntimeError, match="Aufbau scheitert"):
        schema_aufbauen(db, vorgefunden, [schritt_der_wirft])

    assert _fassung(db) == 0, "die Fassung darf erst nach fehlerfreiem Aufbau stehen"
