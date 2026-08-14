"""Tests fuer ``SqliteDevicePurgeRepository`` -- die MAC-gebundene Vollloeschung (S88-P3).

DER TRAGENDE TEST dieser Etappe steht hier: ``test_raeumt_geraet_ip_verlauf_und_alle
_sieben_nebentabellen``. Er laeuft gegen eine ECHTE SQLite-Datei (``tmp_path``, Muster
``test_device_repository.py``) und fragt JEDE der neun Tabellen VORHER und NACHHER ab.
Ein Mock taugte hier nicht: geprueft wird gerade, dass die SQL-Anweisungen die Zeilen
wirklich treffen -- inklusive der Schreibweisen-Falle unten.

DIE SCHREIBWEISEN-FALLE (gemessen an einer echten DB, S88-P3): Die neun Tabellen
fuehren die MAC NICHT einheitlich.

    devices               -> 'AA:BB:CC:DD:EE:01'   (normalize_mac, kanonisch GROSS)
    analysis_known_hosts  -> 'aa:bb:cc:dd:ee:01'   (was der Scan liefert -- klein)

``devices`` und die drei ``cve_*``-Tabellen fuehren gross, die vier uebrigen fuehren
schlicht die Schreibweise ihres Aufrufers. Ein Loeschweg, der auf Gleichheit
vergliche, liesse die Nebendaten nachweislich stehen. ``test_raeumt_auch_bei
_gemischter_schreibweise_vollstaendig`` misst genau das -- ohne ihn faellt eine
spaetere Regression (jemand ersetzt ``upper(...)`` durch einen direkten Vergleich)
nicht auf, weil sie in einer DB mit rein grossgeschriebenen Testdaten unsichtbar
bliebe.
"""

import sqlite3
from pathlib import Path

import pytest

from infrastructure.device_purge import SqliteDevicePurgeRepository
from ports.maintenance import DevicePurgeRepository

# Das Geraet, das geraeumt wird -- und das, das bleiben MUSS.
ZIEL = "AA:BB:CC:DD:EE:01"
BLEIBT = "AA:BB:CC:DD:EE:99"

# Die neun Tabellen, ueber die dieser Loeschweg geht: die zwei eigenen plus die
# sieben MAC-gebundenen Nebentabellen aus dem Auftrag.
ALLE_TABELLEN = (
    "devices",
    "device_ip_history",
    "cve_findings",
    "cve_check_state",
    "cve_acknowledgements",
    "analysis_acknowledgements",
    "analysis_known_hosts",
    "arp_baseline",
    "arp_alerts",
)


def _schema_und_daten(db: Path, ziel_mac: str, bleibt_mac: str) -> None:
    """Legt die neun Tabellen an und fuellt sie mit JE EINER Zeile pro MAC.

    Die Schemata sind deckungsgleich zu denen der zustaendigen Adapter (nur die
    Spalten, die dieser Loeschweg braucht -- die uebrigen sind fuer die Frage
    ohne Belang). Bewusst per SQL statt ueber die Adapter: so haengt dieser Test
    nicht an deren Konstruktoren (Clock-Injektion, Migrationen), und die
    Ausgangslage steht sichtbar im Test.
    """
    conn = sqlite3.connect(db)
    with conn:
        conn.executescript(
            """
            CREATE TABLE devices (mac TEXT PRIMARY KEY, last_ip TEXT);
            CREATE TABLE device_ip_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT, mac TEXT, ip TEXT);
            CREATE TABLE cve_findings (
                mac TEXT, cve_id TEXT, port INTEGER, PRIMARY KEY (mac, cve_id, port));
            CREATE TABLE cve_check_state (mac TEXT PRIMARY KEY, last_checked_ts REAL);
            CREATE TABLE cve_acknowledgements (
                id INTEGER PRIMARY KEY AUTOINCREMENT, mac TEXT, cve_id TEXT, port INTEGER);
            CREATE TABLE analysis_acknowledgements (
                id INTEGER PRIMARY KEY AUTOINCREMENT, mac TEXT, port INTEGER);
            CREATE TABLE analysis_known_hosts (mac TEXT PRIMARY KEY, first_seen TEXT);
            CREATE TABLE arp_baseline (ip TEXT PRIMARY KEY, mac TEXT);
            CREATE TABLE arp_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, old_mac TEXT, new_mac TEXT);
            """
        )
        for nummer, mac in enumerate((ziel_mac, bleibt_mac), start=1):
            conn.execute("INSERT INTO devices VALUES (?, ?)", (mac, f"192.168.1.{nummer}"))
            conn.execute(
                "INSERT INTO device_ip_history (mac, ip) VALUES (?, ?)",
                (mac, f"192.168.1.{nummer}"),
            )
            conn.execute("INSERT INTO cve_findings VALUES (?, ?, ?)", (mac, "CVE-2026-1", 22))
            conn.execute("INSERT INTO cve_check_state VALUES (?, ?)", (mac, 1.0))
            conn.execute(
                "INSERT INTO cve_acknowledgements (mac, cve_id, port) VALUES (?, ?, ?)",
                (mac, "CVE-2026-1", 22),
            )
            conn.execute(
                "INSERT INTO analysis_acknowledgements (mac, port) VALUES (?, ?)", (mac, 22)
            )
            conn.execute("INSERT INTO analysis_known_hosts VALUES (?, ?)", (mac, "2026-01-01"))
            conn.execute("INSERT INTO arp_baseline VALUES (?, ?)", (f"192.168.1.{nummer}", mac))
            # Der Alarm traegt die MAC in der ALTEN Rolle ...
            conn.execute(
                "INSERT INTO arp_alerts (ip, old_mac, new_mac) VALUES (?, ?, ?)",
                (f"192.168.1.{nummer}", mac, "FF:FF:FF:FF:FF:FE"),
            )
            # ... und ein zweiter in der NEUEN. Beide muessen gehen.
            conn.execute(
                "INSERT INTO arp_alerts (ip, old_mac, new_mac) VALUES (?, ?, ?)",
                (f"192.168.1.{nummer}", "FF:FF:FF:FF:FF:FE", mac),
            )
    conn.close()


def _zeilen_je_tabelle(db: Path) -> dict[str, int]:
    """Zaehlt die Zeilen JEDER der neun Tabellen -- die Vorher-/Nachher-Messung."""
    conn = sqlite3.connect(db)
    try:
        return {
            tabelle: conn.execute(f"SELECT count(*) FROM {tabelle}").fetchone()[0]
            for tabelle in ALLE_TABELLEN
        }
    finally:
        conn.close()


def _zeilen_fuer(db: Path, mac: str) -> dict[str, int]:
    """Zaehlt die Zeilen, die zu EINER MAC gehoeren (case-insensitiv)."""
    conn = sqlite3.connect(db)
    try:
        zaehler = {}
        for tabelle in ALLE_TABELLEN:
            if tabelle == "arp_alerts":
                sql = (
                    "SELECT count(*) FROM arp_alerts WHERE upper(old_mac) = ? OR upper(new_mac) = ?"
                )
                zaehler[tabelle] = conn.execute(sql, (mac.upper(), mac.upper())).fetchone()[0]
            else:
                sql = f"SELECT count(*) FROM {tabelle} WHERE upper(mac) = ?"
                zaehler[tabelle] = conn.execute(sql, (mac.upper(),)).fetchone()[0]
        return zaehler
    finally:
        conn.close()


@pytest.fixture
def db(tmp_path: Path) -> Path:
    """Eine echte SQLite-Datei mit beiden Geraeten in allen neun Tabellen."""
    pfad = tmp_path / "cernis.db"
    _schema_und_daten(pfad, ZIEL, BLEIBT)
    return pfad


def test_conforms_to_device_purge_repository_protocol(db: Path) -> None:
    """Struktureller Vertrag (Muster ``test_device_repository.py``)."""
    _: DevicePurgeRepository = SqliteDevicePurgeRepository(db)


# ── 4.1 Der tragende Test ─────────────────────────────────────────────────────


def test_raeumt_geraet_ip_verlauf_und_alle_sieben_nebentabellen(db: Path) -> None:
    """Nach der Loeschung traegt KEINE der neun Tabellen noch eine Zeile des Geraets.

    Vorher- UND Nachher-Abfrage je Tabelle -- ohne die Vorher-Messung bewiese ein
    leeres Nachher nichts (die Zeile koennte nie existiert haben).
    """
    vorher = _zeilen_fuer(db, ZIEL)
    assert all(anzahl > 0 for anzahl in vorher.values()), (
        f"Ausgangslage unvollstaendig -- der Test misst nichts: {vorher}"
    )
    # arp_alerts traegt die MAC in beiden Rollen: zwei Zeilen.
    assert vorher["arp_alerts"] == 2

    entfernt = SqliteDevicePurgeRepository(db).purge_devices([ZIEL])

    assert entfernt == 1, "Gemeldet wird die Zahl der geloeschten GERAETE"
    nachher = _zeilen_fuer(db, ZIEL)
    assert nachher == dict.fromkeys(ALLE_TABELLEN, 0), (
        f"Diese Tabellen tragen noch Daten des geloeschten Geraets: "
        f"{ {t: n for t, n in nachher.items() if n} }"
    )


# ── 4.2 Fremde Geraete bleiben unberuehrt ────────────────────────────────────


def test_ein_nicht_gewaehltes_geraet_bleibt_samt_nebendaten_unberuehrt(db: Path) -> None:
    """Die Loeschung trifft NUR die Auswahl -- der Rest des Bestands ueberlebt.

    Ohne diesen Test bestuende der tragende Test auch dann, wenn der Adapter
    schlicht ``DELETE FROM <tabelle>`` ohne WHERE abgesetzt haette.
    """
    vorher = _zeilen_fuer(db, BLEIBT)

    SqliteDevicePurgeRepository(db).purge_devices([ZIEL])

    assert _zeilen_fuer(db, BLEIBT) == vorher, "Das nicht gewaehlte Geraet hat Nebendaten verloren"


# ── 4.3 Abbruch mittendrin: NICHTS ist geloescht ──────────────────────────────


def test_bricht_das_loeschen_ab_ist_nichts_geloescht(
    db: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ALLES ODER NICHTS -- der Abbruch wird ERZWUNGEN, nicht angenommen.

    ERZWUNGEN WIRD ER SO: ``_vorhandene_tabellen`` meldet zusaetzlich eine Tabelle,
    die es gar nicht gibt. Der Adapter haelt sie fuer vorhanden, raeumt die davor
    liegenden Tabellen NORMAL ab und laeuft dann in ein ``OperationalError`` --
    mitten im ``with conn:``-Block, genau die Lage, um die es geht (DB gesperrt,
    Platte voll, Schema unerwartet).

    Der Hebel sitzt bewusst an einer EIGENEN Naht des Adapters und nicht an
    ``sqlite3.Connection.execute``: dessen Methoden sind unveraenderlich
    (``TypeError: cannot set 'execute' attribute of immutable type``), und ein
    Patch der stdlib waere ohnehin ein Test ueber Python statt ueber diesen Code.

    Gemessen wird ueber ALLE neun Tabellen, nicht nur ueber ``devices``: die
    Geraete-Zeile wird ohnehin zuletzt geloescht, ein Test nur auf sie bestuende
    auch bei neun Einzeltransaktionen.
    """
    vorher = _zeilen_je_tabelle(db)
    repo = SqliteDevicePurgeRepository(db)

    def meldet_eine_nicht_existierende_tabelle(conn: sqlite3.Connection) -> set[str]:
        echte = {
            row["name"]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        return echte | {"cve_findings_gibt_es_nicht"}

    # Die erfundene Tabelle in die Loeschreihenfolge einschleusen, und zwar NACH
    # echten Tabellen -- sonst braeche der Lauf ab, bevor ueberhaupt etwas
    # geloescht waere, und der Test bewiese nichts ueber den Rollback.
    monkeypatch.setattr(
        "infrastructure.device_purge._TABELLEN_MIT_MAC_SPALTE",
        (
            ("cve_findings", "mac"),
            ("cve_check_state", "mac"),
            ("cve_findings_gibt_es_nicht", "mac"),
            ("analysis_known_hosts", "mac"),
            ("device_ip_history", "mac"),
        ),
    )
    monkeypatch.setattr(
        SqliteDevicePurgeRepository,
        "_vorhandene_tabellen",
        staticmethod(meldet_eine_nicht_existierende_tabelle),
    )

    with pytest.raises(sqlite3.OperationalError):
        repo.purge_devices([ZIEL])

    assert _zeilen_je_tabelle(db) == vorher, (
        "Nach dem Abbruch fehlen Zeilen -- die Loeschung lief NICHT in einer Transaktion"
    )


# ── 4.5 Leere Auswahl ─────────────────────────────────────────────────────────


def test_eine_leere_auswahl_loescht_nichts_und_ist_kein_fehler(db: Path) -> None:
    """Wer nichts waehlt, dem passiert nichts -- ohne Ausnahme, ohne Fehlermeldung."""
    vorher = _zeilen_je_tabelle(db)

    assert SqliteDevicePurgeRepository(db).purge_devices([]) == 0

    assert _zeilen_je_tabelle(db) == vorher


def test_eine_auswahl_aus_lauter_leeren_strings_raeumt_nichts_ab(db: Path) -> None:
    """Leere/Leerzeichen-MACs treffen NICHT die Zeilen mit leerer MAC-Spalte.

    Ein ungefilterter leerer String liefe in ``upper('') IN ('')`` und raeumte
    fremde Zeilen ab -- etwa die Analyse-Eintraege eines Hosts ohne stabile
    Identitaet. Darum fliegen sie im Adapter raus.
    """
    vorher = _zeilen_je_tabelle(db)

    assert SqliteDevicePurgeRepository(db).purge_devices(["", "   "]) == 0

    assert _zeilen_je_tabelle(db) == vorher


# ── Die Schreibweisen-Falle (der Befund, der den Loeschweg traegt) ────────────


def test_raeumt_auch_bei_gemischter_schreibweise_vollstaendig(tmp_path: Path) -> None:
    """GROSS in devices, klein in den Nebentabellen -- alles muss weg.

    Das ist die ECHTE Lage im Bestand (gemessen, s. Modul-Docstring): ``devices``
    fuehrt kanonisch gross ueber ``normalize_mac``, waehrend
    ``analysis_known_hosts`` und die uebrigen die Schreibweise des Scans tragen --
    und die ist klein. Faellt dieser Test, vergleicht der Loeschweg wieder auf
    Gleichheit, und der Anwender behielte nach dem Aufraeumen verwaiste Befunde,
    ohne es zu merken.
    """
    db = tmp_path / "gemischt.db"
    _schema_und_daten(db, ZIEL, BLEIBT)

    # Die vier nicht normalisierenden Tabellen auf KLEINschreibung umstellen --
    # genau so, wie der Scan-Pfad sie befuellt.
    conn = sqlite3.connect(db)
    with conn:
        for tabelle in (
            "analysis_known_hosts",
            "analysis_acknowledgements",
            "arp_baseline",
        ):
            conn.execute(f"UPDATE {tabelle} SET mac = lower(mac)")
        conn.execute("UPDATE arp_alerts SET old_mac = lower(old_mac), new_mac = lower(new_mac)")
    conn.close()

    # Die Ausgangslage ist wirklich gemischt (sonst misst der Test nichts).
    conn = sqlite3.connect(db)
    try:
        in_devices = conn.execute("SELECT mac FROM devices WHERE mac = ?", (ZIEL,)).fetchone()
        in_hosts = conn.execute(
            "SELECT mac FROM analysis_known_hosts WHERE mac = ?", (ZIEL.lower(),)
        ).fetchone()
    finally:
        conn.close()
    assert in_devices is not None, "devices fuehrt die MAC nicht gross -- Testaufbau falsch"
    assert in_hosts is not None, "Nebentabelle fuehrt die MAC nicht klein -- Testaufbau falsch"

    # Geloescht wird mit der Schreibweise, die die Geraeteliste liefert: GROSS.
    entfernt = SqliteDevicePurgeRepository(db).purge_devices([ZIEL])

    assert entfernt == 1
    nachher = _zeilen_fuer(db, ZIEL)
    assert nachher == dict.fromkeys(ALLE_TABELLEN, 0), (
        f"Bei gemischter Schreibweise blieben Zeilen stehen: "
        f"{ {t: n for t, n in nachher.items() if n} }"
    )


def test_loeschen_mit_kleiner_schreibweise_trifft_die_grosse_devices_zeile(db: Path) -> None:
    """Die Gegenrichtung: klein hereingereicht, gross gespeichert -- trifft ebenso.

    Absicherung der Symmetrie: der Vergleich hebt BEIDE Seiten, nicht nur die
    gespeicherte.
    """
    assert SqliteDevicePurgeRepository(db).purge_devices([ZIEL.lower()]) == 1
    assert _zeilen_fuer(db, ZIEL) == dict.fromkeys(ALLE_TABELLEN, 0)


# ── Idempotenz und Robustheit ────────────────────────────────────────────────


def test_eine_unbekannte_mac_ist_kein_fehler(db: Path) -> None:
    """Idempotent wie ``DeviceRepository.delete`` -- unbekannt heisst: nichts zu tun."""
    vorher = _zeilen_je_tabelle(db)

    assert SqliteDevicePurgeRepository(db).purge_devices(["00:11:22:33:44:55"]) == 0

    assert _zeilen_je_tabelle(db) == vorher


def test_zweimal_loeschen_ist_beim_zweiten_mal_ein_no_op(db: Path) -> None:
    """Der zweite Aufruf meldet 0 und aendert nichts mehr."""
    repo = SqliteDevicePurgeRepository(db)

    assert repo.purge_devices([ZIEL]) == 1
    zwischenstand = _zeilen_je_tabelle(db)
    assert repo.purge_devices([ZIEL]) == 0
    assert _zeilen_je_tabelle(db) == zwischenstand


def test_mehrere_geraete_gehen_in_einem_aufruf(db: Path) -> None:
    """Die MENGE ist der Normalfall -- beide Geraete in EINEM Aufruf."""
    assert SqliteDevicePurgeRepository(db).purge_devices([ZIEL, BLEIBT]) == 2

    assert _zeilen_je_tabelle(db) == dict.fromkeys(ALLE_TABELLEN, 0)


def test_doppelte_macs_in_der_eingabe_zaehlen_einmal(db: Path) -> None:
    """Dieselbe MAC mehrfach uebergeben loescht ein Geraet, nicht zwei."""
    assert SqliteDevicePurgeRepository(db).purge_devices([ZIEL, ZIEL.lower(), ZIEL]) == 1


def test_eine_fehlende_nebentabelle_bricht_die_loeschung_nicht(tmp_path: Path) -> None:
    """Frische DB, in der ein zustaendiger Adapter noch nie lief.

    Der Loeschweg legt KEINE Tabelle an (das ist Sache der zustaendigen Adapter) --
    er ueberspringt, was es nicht gibt, und raeumt den Rest.
    """
    db = tmp_path / "unvollstaendig.db"
    conn = sqlite3.connect(db)
    with conn:
        conn.executescript(
            """
            CREATE TABLE devices (mac TEXT PRIMARY KEY, last_ip TEXT);
            CREATE TABLE device_ip_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT, mac TEXT, ip TEXT);
            """
        )
        conn.execute("INSERT INTO devices VALUES (?, ?)", (ZIEL, "192.168.1.1"))
        conn.execute("INSERT INTO device_ip_history (mac, ip) VALUES (?, ?)", (ZIEL, "192.168.1.1"))
    conn.close()

    assert SqliteDevicePurgeRepository(db).purge_devices([ZIEL]) == 1

    conn = sqlite3.connect(db)
    try:
        assert conn.execute("SELECT count(*) FROM devices").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM device_ip_history").fetchone()[0] == 0
    finally:
        conn.close()
