"""SQLite-Adapter fuer den Port ``DevicePurgeRepository`` -- MAC-gebundene Vollloeschung.

Raeumt eine MENGE von Geraeten samt ALLER MAC-gebundenen Nebendaten in EINER
Transaktion ab. Das ist der einzige Grund, warum dieser Adapter existiert und die
Arbeit nicht auf die vorhandenen Repos verteilt ist:

* Die bestehenden Repos koennen nur ``clear_all()`` -- tabellenweit, ohne
  MAC-Filter (Messung S88-P3, 1.1: der Werkszustands-Loeschweg bietet KEINE
  MAC-gebundenen Bausteine).
* Jeder Adapter oeffnet seine EIGENE Connection. Selbst mit acht neuen
  ``delete_for_macs``-Methoden waeren es acht Transaktionen -- und ein Abbruch
  nach der dritten liesse einen halben Bestand zurueck.

Darum: EINE Connection, EIN ``with conn:``-Block ueber alle acht Tabellen. Bricht
ein Schritt ab, rollt sqlite3 den GANZEN Block zurueck.

KEIN Schema-Aufbau (bewusst, anders als die uebrigen Adapter): dieser Adapter legt
keine Tabelle an und ruft kein ``_ensure_schema``. Er raeumt nur, was da ist -- die
acht Tabellen gehoeren anderen Adaptern, die sie anlegen und deren Vertrag sie
fuehren. Ein ``CREATE TABLE`` hier waere eine zweite, konkurrierende Wahrheit ueber
ihr Schema. Fehlt eine Tabelle (frische DB, in der der zustaendige Adapter noch nie
lief), wird ihr Loeschschritt uebersprungen -- gemessen ueber ``sqlite_master``,
nicht ueber einen gefangenen Fehler (ein gefangenes ``OperationalError`` koennte
auch eine gesperrte DB verschlucken, und das waere der stille Fallback aus S3).

SCHREIBWEISE DER MAC (gemessen an einer echten DB, S88-P3):

    devices               -> 'AA:BB:CC:DD:EE:01'   (normalize_mac, kanonisch GROSS)
    analysis_known_hosts  -> 'aa:bb:cc:dd:ee:01'   (was der Scan liefert -- klein)

``devices`` und die drei ``cve_*``-Tabellen fuehren die MAC kanonisch gross
(``domain.devices.normalize_mac`` bzw. ``infrastructure/_cve_mac.py``). Die vier
uebrigen -- ``analysis_known_hosts``, ``analysis_acknowledgements``,
``arp_baseline``, ``arp_alerts`` -- normalisieren gar nicht, sie speichern die
Schreibweise des Aufrufers, und der Scan-Pfad (``ws_scan.record_seen_best_effort``
-> ``EnrichedHost.mac``) liefert klein. Ein Vergleich auf Gleichheit liesse ihre
Zeilen also stehen. Darum vergleicht JEDER Schritt case-insensitiv ueber
``upper(spalte)``.

DIE ZWEI arp-TABELLEN sind der Sonderfall: ``arp_baseline`` hat die IP als
PRIMARY KEY und die MAC nur als Datenspalte; ``arp_alerts`` traegt ZWEI
MAC-Spalten (``old_mac``/``new_mac``, der Kern eines ARP-Alarms ist ja der
Wechsel). Geloescht wird dort jede Zeile, in der die MAC in EINER der Rollen
vorkommt -- ein Alarm ueber ein Geraet, das es nicht mehr gibt, ist ohne seinen
Bezug nicht mehr deutbar.
"""

import sqlite3
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path

__all__ = ["SqliteDevicePurgeRepository"]

# Die sieben MAC-gebundenen Nebentabellen mit EINER MAC-Spalte, plus die beiden
# eigenen Geraete-Tabellen. Reihenfolge: erst die Nebendaten, zuletzt die
# ``devices``-Zeile selbst -- so ist der Bestand zu keinem Zeitpunkt INNERHALB der
# Transaktion in der Lage "Geraet weg, Befunde da" (nach aussen sichtbar wird
# ohnehin nur das Ergebnis, aber die Reihenfolge macht die Absicht lesbar).
_TABELLEN_MIT_MAC_SPALTE: tuple[tuple[str, str], ...] = (
    ("cve_findings", "mac"),
    ("cve_check_state", "mac"),
    ("cve_acknowledgements", "mac"),
    ("analysis_acknowledgements", "mac"),
    ("analysis_known_hosts", "mac"),
    ("arp_baseline", "mac"),
    ("device_ip_history", "mac"),
)

# ``arp_alerts`` traegt die MAC in ZWEI Rollen -- eigener Schritt (s. Docstring).
_ARP_ALERTS_SPALTEN: tuple[str, ...] = ("old_mac", "new_mac")


class SqliteDevicePurgeRepository:
    """Erfuellt das ``DevicePurgeRepository``-Protocol strukturell (SQLite)."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Connection mit Transaktion (commit/rollback) und garantiertem close.

        Muster wie ``SqliteDeviceRepository._connect``. Der ``with conn:``-Block ist
        hier das Tragende: er umschliesst ALLE Loeschschritte, sodass ein Fehler
        mittendrin den gesamten Block zurueckrollt.
        """
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    @staticmethod
    def _vorhandene_tabellen(conn: sqlite3.Connection) -> set[str]:
        """Die real vorhandenen Tabellennamen der DB.

        Gemessen statt geraten: ein Loeschschritt auf eine nicht existierende
        Tabelle wuerfe ``OperationalError``. Den zu fangen waere bequem, verschluckte
        aber auch eine gesperrte oder kaputte DB -- der stille Fallback, den S3
        verbietet. Darum die Frage vorher stellen.
        """
        rows = conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
        return {row["name"] for row in rows}

    def purge_devices(self, macs: Iterable[str]) -> int:
        """Loescht die Geraete samt aller Nebendaten in EINER Transaktion.

        Siehe ``ports/maintenance.py`` fuer den vollen Vertrag. Leere Menge -> 0,
        ohne dass eine Connection geoeffnet wird.
        """
        # Vereinheitlicht auf GROSS, weil jeder Vergleich unten ``upper(spalte)``
        # gegenueberstellt. Leere/nur-Leerzeichen-Eintraege fliegen raus: sie
        # traefen sonst Zeilen mit leerer MAC-Spalte in den Nebentabellen und
        # raeumten fremde Daten ab.
        gesucht = sorted({mac.strip().upper() for mac in macs if mac.strip()})
        if not gesucht:
            return 0

        platzhalter = ",".join("?" for _ in gesucht)
        with self._connect() as conn:
            vorhanden = self._vorhandene_tabellen(conn)

            for tabelle, spalte in _TABELLEN_MIT_MAC_SPALTE:
                if tabelle not in vorhanden:
                    continue
                # upper(spalte): die Nebentabellen fuehren die Schreibweise des
                # Scans (klein), devices fuehrt kanonisch gross -- s. Modul-Docstring.
                conn.execute(
                    f"DELETE FROM {tabelle} WHERE upper({spalte}) IN ({platzhalter})",
                    gesucht,
                )

            if "arp_alerts" in vorhanden:
                # Beide MAC-Rollen eines Alarms treffen (alt UND neu).
                bedingung = " OR ".join(
                    f"upper({spalte}) IN ({platzhalter})" for spalte in _ARP_ALERTS_SPALTEN
                )
                conn.execute(
                    f"DELETE FROM arp_alerts WHERE {bedingung}",
                    gesucht * len(_ARP_ALERTS_SPALTEN),
                )

            # ZULETZT die Geraete selbst -- ihr rowcount ist der Rueckgabewert
            # (die Zahl der wirklich entfernten Geraete, nicht der Nebenzeilen).
            if "devices" not in vorhanden:
                return 0
            cursor = conn.execute(
                f"DELETE FROM devices WHERE upper(mac) IN ({platzhalter})",
                gesucht,
            )
            return int(cursor.rowcount)
