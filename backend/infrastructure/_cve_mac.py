"""Geteilte MAC-Vereinheitlichung + Bestands-Migration der drei cve-Adapter.

URSACHE, die hier beseitigt wird (Finding 8): Die drei cve-Adapter reichten die MAC
UNVERAENDERT durch. Geschrieben wurden sie vom Drip-Worker aus dem Scan-Bestand
(``_ScanHistoryInventory`` -> ``ScanRecord.hosts[].mac``, KLEINgeschrieben), gelesen
wurden sie ueber ``list_for_host``/``get`` aber auch mit der Schreibweise des
GERAETEbestands (``devices``, dort konsequent GROSS -- ``modules/devices_db.py``
normalisiert beim Schreiben UND beim Lesen). Beide Seiten trafen sich nie: derselbe
Host lieferte ueber ``GET /api/cve/host/<MAC-GROSS>`` eine LEERE Liste, ueber
``<mac-klein>`` seine Befunde. Ein echter Funktionsfehler, kein Schoenheitsfehler.

LOESUNG: Die drei Adapter vereinheitlichen jede MAC auf GROSSSCHREIBUNG -- beim
Schreiben UND beim Lesen (auch in den Parametern von ``get``/``list_for_host``).
Danach ist ein Abgleich mit dem Geraetebestand ohne weitere Vereinheitlichung korrekt,
weil beide Seiten dieselbe kanonische Form fuehren.

NUR GROSS-/KLEINSCHREIBUNG, keine Trennzeichen-Normalisierung: ``domain.devices.
normalize_mac`` waere die kanonische Voll-Normalisierung (Trennzeichen + Gross), wirft
aber bei leerer MAC ``ValueError``. Die cve-Adapter behandeln eine leere MAC bewusst
als legitimen Datenrand (``get("")`` -> ``None``, ``list_for_host("")`` -> ``[]``), und
S3 verbietet das stille Umdeuten: eine leere MAC bleibt leer, keine ValueError-Kaskade
und keine erfundene Ersatz-Identitaet. Darum hier die schmale, verlustfreie Regel --
``upper()`` und sonst nichts. Sie ist idempotent.

MIGRATIONS-GUARD (Muster ``monitoring/rtt_history.py``, ``device_repository.py``):
Eine DB, in der die Adapter schon liefen, traegt den Altbestand in gemischter
Schreibweise. ``CREATE TABLE IF NOT EXISTS`` ist dort ein No-Op -- die alten Zeilen
blieben klein und waeren nach der Umstellung UNERREICHBAR (der Lesepfad sucht dann
gross). Darum hebt ``migrate_macs_to_upper`` den Bestand EINMALIG hoch. Der Guard ist
die Datenfrage selbst: ``WHERE mac <> upper(mac)`` findet beim zweiten Start nichts
mehr -> No-op, ohne zusaetzliche Versions-Spalte.

KOLLISIONSSICHER: In einer fremden DB kann dieselbe Adresse in BEIDEN Schreibweisen
vorliegen. Blindes ``UPDATE ... SET mac = upper(mac)`` liefe dort in einen
UNIQUE-Konflikt und riesse den Start ab. Die Zusammenfuehrungs-Regeln je Tabelle
stehen an den drei Funktionen unten. Verlustfrei: keine Zeile verschwindet, ausser sie
wird bewusst mit ihrer Gegenzeile verschmolzen.
"""

import sqlite3

__all__ = ["migrate_macs_to_upper", "normalize_mac_case"]


def normalize_mac_case(mac: str) -> str:
    """MAC auf die kanonische GROSSschreibung heben. Leer bleibt leer (S3).

    Idempotent. Bewusst NUR die Schreibweise -- Trennzeichen bleiben unangetastet
    (siehe Modul-Docstring). Eine leere MAC wird NICHT in etwas anderes umgedeutet,
    sie bleibt der leere String und laeuft in die vorhandenen Leer-Pfade der Adapter.
    """
    return mac.upper()


def _migrate_check_state(conn: sqlite3.Connection) -> int:
    """``cve_check_state`` hochschreiben. Kollision -> juengster ``last_checked_ts`` gewinnt.

    ``mac`` ist PRIMARY KEY: liegt dieselbe Adresse gross UND klein vor, darf am Ende
    nur EINE Zeile stehen. Behalten wird die mit dem JUENGSTEN ``last_checked_ts``
    SAMT deren ``ports`` (beide Felder gehoeren zusammen -- das gepruefte Port-Set ist
    der Stand ZU diesem Zeitpunkt; sie zu mischen erzeugte einen Stand, den es nie gab).
    Die Verlierer-Zeilen werden geloescht, danach bleibt das reine Hochschreiben.
    """
    # Verlierer entfernen: jede Zeile, fuer die es unter derselben kanonischen Adresse
    # eine juengere gibt. Gleichstand -> rowid als deterministischer Stichentscheid,
    # damit genau eine Zeile ueberlebt (nie null, nie zwei).
    conn.execute(
        """
        DELETE FROM cve_check_state
        WHERE EXISTS (
            SELECT 1 FROM cve_check_state AS other
            WHERE upper(other.mac) = upper(cve_check_state.mac)
              AND (
                    other.last_checked_ts > cve_check_state.last_checked_ts
                 OR (other.last_checked_ts = cve_check_state.last_checked_ts
                     AND other.rowid > cve_check_state.rowid)
              )
        )
        """
    )
    cursor = conn.execute("UPDATE cve_check_state SET mac = upper(mac) WHERE mac <> upper(mac)")
    return cursor.rowcount


def _migrate_findings(conn: sqlite3.Connection) -> int:
    """``cve_findings`` hochschreiben. Kollision -> aeltestes first_seen, juengstes last_seen.

    PRIMARY KEY ist ``(mac, cve_id, port)``. Bei Kollision wird je Schluessel EINE Zeile
    behalten, und zwar die mit dem JUENGSTEN ``last_seen_ts`` samt der dazugehoerigen
    NVD-Felder (severity/score/description/url/published/ip/service -- der frischeste
    Kenntnisstand). Ihr ``first_seen_ts`` wird anschliessend auf das AELTESTE der
    Gruppe gesetzt: daran haengt die NEU-Kennzeichnung (``domain.cve.policy.is_new``),
    sie darf durch die Migration NICHT juenger werden -- sonst floppte ein laengst
    bekannter Befund wieder als "neu" auf.
    """
    # Schritt 1: das aelteste first_seen_ts je kanonischer Identitaet auf ALLE Zeilen
    # der Gruppe ziehen -- VOR dem Loeschen, damit der Gewinner es sicher traegt.
    conn.execute(
        """
        UPDATE cve_findings
        SET first_seen_ts = (
            SELECT min(other.first_seen_ts) FROM cve_findings AS other
            WHERE upper(other.mac) = upper(cve_findings.mac)
              AND other.cve_id = cve_findings.cve_id
              AND other.port = cve_findings.port
        )
        """
    )
    # Schritt 2: Verlierer entfernen -- jede Zeile, fuer die es unter derselben
    # kanonischen Identitaet eine juengere (last_seen_ts) gibt. Gleichstand -> rowid.
    conn.execute(
        """
        DELETE FROM cve_findings
        WHERE EXISTS (
            SELECT 1 FROM cve_findings AS other
            WHERE upper(other.mac) = upper(cve_findings.mac)
              AND other.cve_id = cve_findings.cve_id
              AND other.port = cve_findings.port
              AND (
                    other.last_seen_ts > cve_findings.last_seen_ts
                 OR (other.last_seen_ts = cve_findings.last_seen_ts
                     AND other.rowid > cve_findings.rowid)
              )
        )
        """
    )
    cursor = conn.execute("UPDATE cve_findings SET mac = upper(mac) WHERE mac <> upper(mac)")
    return cursor.rowcount


def _migrate_acknowledgements(conn: sqlite3.Connection) -> int:
    """``cve_acknowledgements`` hochschreiben -- reines UPDATE, keine Zusammenfuehrung.

    ``mac`` ist hier KEIN Schluessel (die Tabelle traegt eine eigene AUTOINCREMENT-id
    und ist append-only). Zwei Zeilen derselben Adresse in verschiedener Schreibweise
    sind damit unschaedlich: der effektive Status ist ohnehin die Ableitung ueber
    ``max(id)`` je (mac, cve_id, port) -- nach dem Hochschreiben landen beide in
    DERSELBEN Gruppe, und die juengste gewinnt. Genau das ist fachlich richtig: die
    zeitlich letzte Entscheidung des Nutzers zaehlt.
    """
    cursor = conn.execute(
        "UPDATE cve_acknowledgements SET mac = upper(mac) WHERE mac <> upper(mac)"
    )
    return cursor.rowcount


def migrate_macs_to_upper(conn: sqlite3.Connection, table: str) -> int:
    """Hebt den Altbestand EINER cve-Tabelle einmalig auf Grossschreibung.

    Gibt die Zahl der hochgeschriebenen Zeilen zurueck (0 = nichts zu tun, der
    No-op-Fall beim zweiten und jedem weiteren Start). Der Aufrufer ist
    ``_ensure_schema`` des jeweiligen Adapters, der den Fehlschlag faengt und laut
    loggt -- eine misslungene Migration darf den Backend-Start NICHT verhindern.

    Die Tabelle muss existieren (der Aufruf steht NACH ``CREATE TABLE IF NOT EXISTS``).
    Ein unbekannter Tabellenname ist ein Programmierfehler und bricht laut (kein
    stiller Fallback, S3).
    """
    if table == "cve_check_state":
        return _migrate_check_state(conn)
    if table == "cve_findings":
        return _migrate_findings(conn)
    if table == "cve_acknowledgements":
        return _migrate_acknowledgements(conn)
    raise ValueError(f"Unbekannte cve-Tabelle fuer die MAC-Migration: {table}")
