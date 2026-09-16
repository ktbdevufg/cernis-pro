"""Schemanaht: die Datenbank traegt ihre Fassung (S88-P1a).

Bis 2.1.1 trug die Datenbank KEINE Fassungsangabe -- ``PRAGMA user_version`` stand
in jedem Bestand auf 0, und jedes der 34 Repositories legte sein Stueck Schema beim
eigenen Bau idempotent selbst an. Damit war weder erkennbar, aus welcher
Programmfassung eine Datei stammt, noch gab es einen Ort, an dem eine kuenftige,
NICHT idempotente Schema-Aenderung (Spalte umbenennen, Tabelle umbauen) einmalig und
nachvollziehbar haette stattfinden koennen.

Dieses Modul ist dieser Ort. Es ist bewusst ZWEIGETEILT:

* ``schema_pruefen`` -- die ENTSCHEIDUNG ueber die Datenbank. Liest ``user_version``,
  verweigert eine zu neue Datei (Fall D) ohne jede Schreibhandlung und erledigt eine
  echte Migration (Fall C) vollstaendig, samt vorheriger Sicherung.
* ``schema_aufbauen`` -- die HANDLUNG an ihr. Fuehrt die Aufbauschritte aus und setzt
  ``user_version`` als allerletzte Handlung.

Die Trennung ist sachlich, nicht bloss technisch: die Entscheidung muss frueh fallen
(bevor irgendein Repository die Datei beruehrt), der Aufbau kann erst spaet laufen
(wenn alle Aufbauschritte bekannt sind). Eine Migration darf ausserdem nicht zwischen
halb gebauten Repositories liegen -- darum steckt sie ganz in der Pruefung.

Abgrenzung zur Datei ``.version`` (siehe ``app._check_version_upgrade``): jene traegt
die PROGRAMM-Fassung, dieses Modul den SCHEMA-Stand. Zwei verschiedene Dinge, zwei
getrennte Spuren.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Sequence
from datetime import datetime
from pathlib import Path

import structlog

_logger = structlog.get_logger(__name__)

# Der Schema-Stand, den die Fassung 2.1.2 einfuehrt. 1 ist der ERSTE gezaehlte Stand;
# alles davor liegt als 0 vor (der Vor-2.1.2-Bestand kennt user_version nicht).
SCHEMA_VERSION = 1

# Die Fassung, die ein Bestand vor 2.1.2 traegt -- ``PRAGMA user_version`` liefert auf
# einer nie gesetzten Datenbank 0, auf einer frisch angelegten ebenso.
_FASSUNG_VOR_ZAEHLUNG = 0


class SchemaTooNewError(Exception):
    """Die Datenbank stammt aus einer NEUEREN Programmfassung als dieser Prozess.

    Es wird nichts geschrieben: ein aelteres Programm kennt das neuere Schema nicht
    und wuerde beim Schreiben Daten beschaedigen. Die beiden Fassungsnummern haengen
    als Attribute an der Ausnahme (nicht als zu parsender Text), damit der Aufrufer
    sie ohne Textzerlegung anzeigen oder protokollieren kann.
    """

    def __init__(self, gelesene_fassung: int, erwartete_fassung: int) -> None:
        self.gelesene_fassung = gelesene_fassung
        self.erwartete_fassung = erwartete_fassung
        super().__init__(
            f"Datenbank-Schemastand {gelesene_fassung} ist neuer als der von diesem"
            f" Programm unterstuetzte Stand {erwartete_fassung}."
        )


class SchemaMigrationError(Exception):
    """Die Migration selbst ist gescheitert.

    Traegt zusaetzlich zu den beiden Fassungsnummern den Pfad der VOR der Migration
    angelegten Sicherung, damit der Aufrufer ihn nennen kann (Attribut, kein Text).
    ``sicherung_pfad`` ist ``None``, falls die Sicherung selbst scheiterte.
    """

    def __init__(
        self,
        gelesene_fassung: int,
        erwartete_fassung: int,
        sicherung_pfad: Path | None,
        grund: str,
    ) -> None:
        self.gelesene_fassung = gelesene_fassung
        self.erwartete_fassung = erwartete_fassung
        self.sicherung_pfad = sicherung_pfad
        self.grund = grund
        super().__init__(
            f"Migration von Schemastand {gelesene_fassung} auf {erwartete_fassung}"
            f" gescheitert: {grund}"
        )


# Zuordnung Zielfassung -> Migrationsschritt. Ein Schritt bekommt eine OFFENE
# Verbindung (die Naht haelt Verbindung und Transaktion) und fuehrt genau die
# Aenderungen aus, die von der Vorgaengerfassung auf die Zielfassung fuehren.
#
# Heute LEER, und das ist kein Versehen: SCHEMA_VERSION 1 ist der erste gezaehlte
# Stand. Es gibt keinen Weg "nach 1", weil es keinen gezaehlten Stand 0 gibt, von dem
# aus migriert wuerde -- ein Bestand mit user_version 0 ist ein Vor-2.1.2-Bestand und
# wird ueber Fall A (Aufbauschritte, die idempotent nachziehen) auf Stand 1 gehoben,
# nicht ueber eine Migration. Der erste echte Eintrag entsteht mit SCHEMA_VERSION 2.
MIGRATIONEN: dict[int, Callable[[sqlite3.Connection], None]] = {}


def _fassung_lesen(conn: sqlite3.Connection) -> int:
    """Liest ``PRAGMA user_version``. Eine nie gesetzte Datenbank liefert 0."""
    zeile = conn.execute("PRAGMA user_version").fetchone()
    return int(zeile[0]) if zeile is not None else _FASSUNG_VOR_ZAEHLUNG


def _fassung_setzen(conn: sqlite3.Connection, fassung: int) -> None:
    """Setzt ``PRAGMA user_version``.

    PRAGMA-Anweisungen nehmen keine Platzhalter; ``fassung`` ist ein ``int`` aus dem
    Programm (nie aus einer Eingabe), die Einsetzung ist damit unbedenklich.
    """
    conn.execute(f"PRAGMA user_version = {int(fassung)}")


def _sicherung_anlegen(db_pfad: Path, alte_fassung: int, jetzt: datetime) -> Path:
    """Legt ueber ``VACUUM INTO`` eine Sicherung NEBEN der Datenbank an.

    Namensschema: Datenbankname, Punkt, das Wort ``sicherung``, die alte
    Fassungsnummer, ein Zeitstempel ``JJJJMMTT-HHMMSS``. Existiert die Zieldatei
    bereits (zwei Laeufe in derselben Sekunde), wird NICHT ueberschrieben, sondern ein
    Zaehler angehaengt -- eine Sicherung darf nie eine aeltere Sicherung verdraengen.

    ``VACUUM INTO`` schreibt eine vollstaendige, in sich konsistente Kopie und
    scheitert von sich aus, wenn das Ziel schon existiert; der Zaehler laeuft dem
    zuvor.
    """
    stempel = jetzt.strftime("%Y%m%d-%H%M%S")
    grundname = f"{db_pfad.name}.sicherung{alte_fassung}-{stempel}"
    ziel = db_pfad.with_name(grundname)
    zaehler = 1
    while ziel.exists():
        ziel = db_pfad.with_name(f"{grundname}-{zaehler}")
        zaehler += 1

    # Eigene Verbindung: VACUUM INTO laeuft nicht innerhalb einer offenen Transaktion.
    conn = sqlite3.connect(db_pfad)
    try:
        conn.execute("VACUUM INTO ?", (str(ziel),))
    finally:
        conn.close()

    _logger.info("schema_sicherung_angelegt", pfad=str(ziel), alte_fassung=alte_fassung)
    return ziel


def schema_pruefen(
    db_pfad: Path,
    *,
    schema_version: int = SCHEMA_VERSION,
    migrationen: dict[int, Callable[[sqlite3.Connection], None]] | None = None,
    jetzt: datetime | None = None,
) -> int:
    """Entscheidet ueber die Datenbank und liefert den VORGEFUNDENEN Stand.

    Erste Haelfte der Zweiteilung (zweite: ``schema_aufbauen``). Diese Funktion faellt
    die Entscheidung und erledigt alles, was VOR dem Bau der Repositories geschehen
    muss; sie setzt ``user_version`` NICHT -- das tut ``schema_aufbauen`` als letzte
    Handlung, wenn die Aufbauschritte durch sind.

    Vier Faelle, entschieden am gelesenen ``PRAGMA user_version``:

    * **A -- gelesen 0**: Bestand vor 2.1.2 oder neue Datei. Hier ist nichts zu
      entscheiden; die Aufbauschritte ziehen alles nach. KEINE Sicherung: sie sind
      idempotent und aendern nichts, was nicht ohnehin bei jedem bisherigen Start
      passiert waere.
    * **B -- gelesen gleich ``schema_version``**: nichts zu migrieren.
    * **C -- gelesen zwischen 0 und ``schema_version``**: ZUERST eine Sicherung, DANN
      die Migrationsschritte in aufsteigender Folge -- beides VOLLSTAENDIG hier, denn
      eine Migration darf nicht zwischen halb gebauten Repositories liegen. Scheitert
      ein Schritt, wird ``SchemaMigrationError`` mit dem Pfad der Sicherung geworfen.
    * **D -- gelesen groesser ``schema_version``**: ``SchemaTooNewError``. Es wird
      NICHTS geschrieben -- keine Sicherung, keine Migration, keine Fassung. Dies ist
      die EINZIGE Stelle, die Fall D behandelt, und sie liegt bewusst vor jeder
      Beruehrung durch ein Repository.

    ``schema_version``, ``migrationen`` und ``jetzt`` sind einsetzbar, damit die
    Erprobung kuenftige Staende durchspielen kann, ohne den Produktivwert zu aendern.

    :returns: der vorgefundene Stand -- als Argument fuer ``schema_aufbauen`` gedacht.
    :raises SchemaTooNewError: die Datei stammt aus einer neueren Programmfassung.
    :raises SchemaMigrationError: ein Migrationsschritt ist gescheitert.
    """
    db_pfad = Path(db_pfad)
    db_pfad.parent.mkdir(parents=True, exist_ok=True)
    schritte = MIGRATIONEN if migrationen is None else migrationen

    conn = sqlite3.connect(db_pfad)
    try:
        gelesen = _fassung_lesen(conn)
    finally:
        conn.close()

    # Fall D zuerst: eine zu neue Datei wird NICHT angefasst -- keine Sicherung, keine
    # Migration. Darum steht diese Pruefung vor jeder schreibenden Handlung.
    if gelesen > schema_version:
        _logger.error("schema_zu_neu", gelesene_fassung=gelesen, erwartete_fassung=schema_version)
        raise SchemaTooNewError(gelesen, schema_version)

    if not _FASSUNG_VOR_ZAEHLUNG < gelesen < schema_version:
        # Fall A und Fall B: nichts zu entscheiden, nichts zu sichern.
        return gelesen

    # Fall C: echte Migration. Die Sicherung entsteht VOR jeder Aenderung -- sie ist der
    # Rueckweg, falls ein Migrationsschritt auf halber Strecke scheitert. Scheitert
    # schon die Sicherung, wird ebenfalls abgebrochen (keine stillen Fallbacks,
    # Finding S3): lieber kein Start als eine Migration ohne Rueckweg.
    try:
        sicherung = _sicherung_anlegen(db_pfad, gelesen, jetzt or datetime.now())
    except (sqlite3.Error, OSError) as fehler:
        _logger.error("schema_sicherung_gescheitert", grund=str(fehler))
        raise SchemaMigrationError(gelesen, schema_version, None, str(fehler)) from fehler

    # EINE Verbindung, EINE explizite Transaktion fuer alle Migrationsschritte: entweder
    # der Bestand steht vollstaendig auf dem neuen Stand, oder er steht unveraendert auf
    # dem alten.
    conn = sqlite3.connect(db_pfad)
    try:
        conn.execute("BEGIN")
        try:
            for ziel in range(gelesen + 1, schema_version + 1):
                schritt = schritte.get(ziel)
                if schritt is None:
                    raise SchemaMigrationError(
                        gelesen,
                        schema_version,
                        sicherung,
                        f"Kein Migrationsschritt fuer Zielfassung {ziel} hinterlegt.",
                    )
                _logger.info("schema_migration_schritt", zielfassung=ziel)
                schritt(conn)
            conn.execute("COMMIT")
        except BaseException as fehler:
            conn.execute("ROLLBACK")
            _logger.error(
                "schema_migration_gescheitert",
                gelesene_fassung=gelesen,
                erwartete_fassung=schema_version,
                sicherung=str(sicherung),
                grund=str(fehler),
            )
            if isinstance(fehler, SchemaMigrationError):
                raise
            raise SchemaMigrationError(gelesen, schema_version, sicherung, str(fehler)) from fehler
    finally:
        conn.close()

    return gelesen


def schema_aufbauen(
    db_pfad: Path,
    vorgefundene_fassung: int,
    aufbauschritte: Sequence[Callable[[], None]],
    *,
    schema_version: int = SCHEMA_VERSION,
) -> int:
    """Fuehrt die Aufbauschritte aus und setzt ``user_version`` als LETZTE Handlung.

    Zweite Haelfte der Zweiteilung (erste: ``schema_pruefen``, die den Stand
    ermittelt hat, der hier als ``vorgefundene_fassung`` hereinkommt). Fall D und
    Fall C sind dort bereits erledigt -- kommt der Aufruf hier an, ist die Datenbank
    entweder auf dem Stand oder alt genug, dass die idempotenten Aufbauschritte
    genuegen.

    Die Aufbauschritte laufen in ALLEN Faellen (A, B und C): sie sind idempotent
    (``CREATE TABLE IF NOT EXISTS`` plus additive ALTER-Guards) und ziehen Tabellen
    nach, die eine spaeter dazugekommene Domaene braucht -- auch nach einer Migration.

    Jeder Schritt oeffnet seine EIGENE Verbindung und committet selbst: die 34
    Repositories legen ihr Schema im Konstruktor an (``_ensure_schema``), die drei
    Altcode-Initialisierer ebenso. Sie werden bewusst NICHT umgebaut (S88-P1a,
    Aufgabe 2.1) -- sie sind idempotent und funktionieren. Die EINE Verbindung mit
    expliziter Transaktion, die dieses Modul haelt, gilt darum fuer die Handlungen der
    NAHT selbst (Fassung lesen, migrieren, Fassung setzen), nicht fuer die Schritte.

    Wirft ein Aufbauschritt, bleibt ``user_version`` stehen und die Ausnahme geht nach
    oben: der naechste Start nimmt denselben Weg erneut (die Schritte vertragen das).

    :returns: der nun geltende Schema-Stand.
    """
    for schritt in aufbauschritte:
        schritt()

    # Die Fassung wird als LETZTE Handlung gesetzt, erst nachdem alle Aufbauschritte
    # fehlerfrei durchgelaufen sind.
    if vorgefundene_fassung != schema_version:
        conn = sqlite3.connect(db_pfad)
        try:
            conn.execute("BEGIN")
            _fassung_setzen(conn, schema_version)
            conn.execute("COMMIT")
        finally:
            conn.close()
        _logger.info(
            "schema_fassung_gesetzt",
            alte_fassung=vorgefundene_fassung,
            neue_fassung=schema_version,
        )

    return schema_version
