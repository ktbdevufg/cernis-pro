"""Einmal-Migration des entfallenen Settings-Schluessels ``dns_expected_servers`` (S62 L7a).

URSACHE, die hier aufgeraeumt wird: Der host-lokale DNS-Waechter bezog seine erwartete
Server-Menge frueher aus einem EIGENEN Einstellungs-Schluessel (``dns_expected_servers``,
eine JSON-Liste von IP-Strings, gepflegt ueber eine separate Bedienstelle in den
Einstellungen). Der netzweite Waechter bezog dieselbe fachliche Menge dagegen aus dem
Vertrauensmodell (``dns_trust_servers``, ``trust_state == trusted``). Zwei Quellen fuer
eine Frage -- die beiden Sichten konnten verschiedene Mengen zeigen.

Seit S62 L7a gilt fuer BEIDE Waechter das Vertrauensmodell. Der alte Schluessel entfaellt
samt Bedienstelle. Eine Bestands-DB, in der der Nutzer die Liste gepflegt hat, traegt ihn
aber noch -- ihn einfach zu ignorieren waere stiller Datenverlust: die Adressen blieben in
der DB liegen und wuerden nie wieder gelesen, der Waechter faende sie ploetzlich "offen".
Darum uebernimmt ``migrate_expected_servers_to_trust`` den Altbestand EINMALIG in die
Vertrauens-Tabelle.

MUSTER: die erprobte Einmal-Migration ``infrastructure/_cve_mac.py`` (Commit 0bf95e9) --
reine SQL-Mechanik in einem eigenen ``_``-Modul, der Guard ist die Datenfrage selbst
(keine zusaetzliche Versions-Spalte), der Aufrufer faengt den Fehlschlag und loggt LAUT,
der Start laeuft trotzdem weiter. Abweichung zum CVE-Fall, bewusst: die Kategorie eines
DNS-Servers ist KEINE reine Datenfrage, sondern haengt an Lookups (Gateway? oeffentlicher
Resolver? Bedrohungsliste?), die nur der Composition Root aufloesen kann. Sie kommt darum
als injiziertes ``categorize``-Callable herein -- die vorhandene Ableitung
(``domain.dns_trust.categorize_dns_server``, verdrahtet ueber ``SyncDnsTrustServer``),
KEINE hier erfundene zweite.

FACHLICHE REGELN

* Jede Adresse des alten Schluessels wird in ``dns_trust_servers`` als ``trusted``
  hinterlegt -- sie stand in der "erwartet"-Liste, das ist genau die Aussage "vertraut".
* Ein BEREITS VORHANDENER Eintrag zu derselben Adresse behaelt seinen ``trust_state``
  unveraendert und wird NICHT ueberschrieben, auch wenn er ``neutral`` oder ``rejected``
  ist. Begruendung: eine spaetere bewusste Nutzerentscheidung in der Vertrauens-Ansicht
  wiegt schwerer als ein Altbestand aus einer entfallenen Bedienstelle. Der bestehende
  Eintrag bleibt VOLLSTAENDIG unangetastet -- auch ``last_seen`` (der regulaere
  ``SyncDnsTrustServer``-Weg pflegt ihn ohnehin bei jeder Erkennung).
* Nach erfolgreicher Uebernahme wird der alte Schluessel GELOESCHT. Damit ist die
  Migration beim zweiten Start ein Nichtvollzug (der Guard ist der fehlende Schluessel
  selbst) und der Altbestand kann nicht ein zweites Mal Vertrauen setzen, nachdem der
  Nutzer es inzwischen zurueckgenommen hat.

UNBRAUCHBARE ALTWERTE -- ENTSCHEIDUNG UND BEGRUENDUNG

Die alte Bedienstelle pruefte nur GROB (vier 0-255-Oktette ODER "enthaelt Doppelpunkt und
nur Hex-Zeichen"). Werte wie ``"1:2"``, ``"::::"`` oder ein leerer String konnten sie
passieren; ausserdem konnte der Schluessel per Settings-API mit beliebigem Inhalt
beschrieben werden. Solche Werte werden hier UEBERSPRUNGEN, nicht uebernommen und nicht
"repariert":

* Sie duerfen die Migration NICHT abbrechen -- ein einziger Muellwert wuerde sonst den
  gesamten, gueltigen Rest des Altbestands mitreissen.
* Sie duerfen NICHT uebernommen werden: ``dns_trust_servers.ip`` ist der Primaerschluessel
  und die Vergleichsgrundlage beider Waechter. Ein nicht-parsbarer Eintrag koennte dort
  nie einen echten Resolver treffen -- er waere eine tote Zeile, die in Oberflaeche,
  Bericht und PDF als "erwarteter DNS-Server" auftauchte, obwohl sie nichts erwartet.
* Sie werden NICHT still verschluckt: jeder uebersprungene Wert wird vom Aufrufer
  protokolliert (die Funktion gibt sie dafuer getrennt zurueck).

Die Pruefung ist ``ipaddress.ip_address`` (stdlib, streng) statt der groben Alt-Heuristik.
Sie ist bewusst STRENGER als die alte Bedienstelle: der Zielort ist ein Schluesselfeld,
keine Hinweisliste. Ein Wert, der ihr nicht standhaelt, haette auch als "erwarteter
Server" nie funktioniert.

NORMALISIERUNG: die Adresse wird getrimmt und ueber ``ipaddress`` in ihre kanonische Form
zurueckgeschrieben (``ip_address("::0001")`` -> ``"::1"``). So trifft ein Altwert seinen
bereits erfassten Gegenpart auch dann, wenn er anders geschrieben war -- sonst legte die
Migration eine zweite Zeile derselben Adresse an und ueberginge damit die
Nutzerentscheidung, die sie gerade bewahren soll.
"""

import ipaddress
import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field

__all__ = [
    "LEGACY_EXPECTED_SERVERS_KEY",
    "ExpectedServersMigrationResult",
    "migrate_expected_servers_to_trust",
]

# Der Name des entfallenen Settings-Schluessels. Er lebt NUR noch hier: die frueheren
# Heimatorte (api/dns_watch.py als Modulkonstante, SettingsView.jsx als Spiegelkonstante)
# sind mit S62 L7a entfallen. Nach der Migration existiert der Schluessel nicht mehr.
LEGACY_EXPECTED_SERVERS_KEY = "dns_expected_servers"


@dataclass(frozen=True)
class ExpectedServersMigrationResult:
    """Was die Migration getan hat -- Grundlage der Protokollzeile des Aufrufers.

    ``migrated`` sind die neu als vertraut angelegten Adressen (kanonische Form),
    ``kept`` die uebersprungenen, weil bereits vorhanden (deren Nutzerentscheidung
    bleibt unangetastet), ``skipped`` die uebersprungenen unbrauchbaren Rohwerte.
    ``ran`` ist ``False``, wenn der alte Schluessel gar nicht vorhanden war -- der
    Nichtvollzug beim zweiten (und jedem weiteren) Start.
    """

    ran: bool = False
    migrated: list[str] = field(default_factory=list)
    kept: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


def _canonical_ip(raw: object) -> str | None:
    """Rohwert -> kanonische IP-Zeichenkette, oder ``None`` wenn unbrauchbar.

    Streng ueber ``ipaddress.ip_address`` (stdlib): akzeptiert IPv4 und IPv6 und gibt
    die kanonische Form zurueck. Alles andere -- Nicht-Zeichenkette, leer, Hostname,
    halbe IPv6-Fragmente wie ``"1:2"``, Muell -- ergibt ``None``, KEIN Wurf und KEINE
    stille Ersatz-Adresse (S3). Der Aufrufer protokolliert den uebersprungenen Wert.
    """
    if not isinstance(raw, str):
        return None
    kandidat = raw.strip()
    if not kandidat:
        return None
    try:
        return str(ipaddress.ip_address(kandidat))
    except ValueError:
        return None


def migrate_expected_servers_to_trust(
    conn: sqlite3.Connection,
    categorize: Callable[[str], str],
    now: float,
) -> ExpectedServersMigrationResult:
    """Uebernimmt den Altbestand des alten Schluessels EINMALIG in ``dns_trust_servers``.

    ``conn`` muss BEIDE Tabellen sehen (``settings`` und ``dns_trust_servers``) -- sie
    liegen in derselben ``cernis.db``; beide muessen bereits angelegt sein (der Aufruf
    steht nach dem ``_ensure_schema`` der beiden Adapter).

    ``categorize`` loest je Adresse die Kategorie ueber die VORHANDENE Ableitung auf
    (``domain.dns_trust.categorize_dns_server``, gefuellt vom Composition Root) und gibt
    ihren ``str``-Wert zurueck -- hier wird KEINE Kategorie erfunden.

    ``now`` ist der Unix-Zeitstempel fuer ``first_seen``/``last_seen`` der neu angelegten
    Zeilen (die Uhr wohnt beim Aufrufer, dieses Modul bleibt uhrfrei).

    Kein Schluessel vorhanden -> ``ran=False``, es wird NICHTS geschrieben (Nichtvollzug).
    Ein Fehler wird geworfen, nicht geschluckt: der Aufrufer faengt ihn, loggt LAUT und
    laesst den Start weiterlaufen. Da die Migration in EINER Transaktion des ``conn``
    laeuft, bleibt ein Abbruch folgenlos -- entweder der Altbestand ist uebernommen UND
    der Schluessel geloescht, oder nichts von beidem.
    """
    row = conn.execute(
        "SELECT value FROM settings WHERE key = ?", (LEGACY_EXPECTED_SERVERS_KEY,)
    ).fetchone()
    if row is None:
        # Der Regelfall nach dem ersten Start (und in jeder frischen DB): nichts zu tun.
        return ExpectedServersMigrationResult(ran=False)

    # Der Wert liegt als JSON-in-TEXT (Schema der settings-Tabelle). Ist er kein gueltiges
    # JSON oder keine Liste, ist der GANZE Schluessel unbrauchbar: dann gibt es nichts zu
    # uebernehmen. Er wird trotzdem geloescht (er ist ab jetzt ohnehin tot) und der Rohwert
    # als uebersprungen gemeldet -- nichts still verschlucken.
    roh = row[0] if not isinstance(row, sqlite3.Row) else row["value"]
    try:
        entschluesselt = json.loads(roh)
    except (TypeError, json.JSONDecodeError):
        entschluesselt = None
    if not isinstance(entschluesselt, list):
        conn.execute("DELETE FROM settings WHERE key = ?", (LEGACY_EXPECTED_SERVERS_KEY,))
        return ExpectedServersMigrationResult(ran=True, skipped=[str(roh)])

    migrated: list[str] = []
    kept: list[str] = []
    skipped: list[str] = []

    for eintrag in entschluesselt:
        ip = _canonical_ip(eintrag)
        if ip is None:
            # Unbrauchbarer Altwert: ueberspringen, protokollieren, NICHT abbrechen.
            skipped.append(str(eintrag))
            continue

        vorhanden = conn.execute("SELECT 1 FROM dns_trust_servers WHERE ip = ?", (ip,)).fetchone()
        if vorhanden is not None:
            # Bestehende Nutzerentscheidung schlaegt den Altbestand -- nichts anfassen.
            kept.append(ip)
            continue

        # origin='migrated' (S63 L7d): diese Zeilen stammen WEDER aus realer Beobachtung
        # noch aus einer Von-Hand-Eingabe, sondern aus dem uebernommenen Altbestand. Ohne
        # die Angabe griffe der Spalten-Default 'observed' und behauptete eine Beobachtung,
        # die nie stattgefunden hat. Sobald der Server real gesehen wird, hebt
        # SyncDnsTrustServer die Herkunft auf 'observed'.
        conn.execute(
            """
            INSERT INTO dns_trust_servers (
                ip, category, trust_state, first_seen,
                last_seen, display_name, notes, is_platform_placeholder,
                expected_rank, origin
            ) VALUES (?, ?, 'trusted', ?, ?, '', '', 0, 0, 'migrated')
            """,
            (ip, categorize(ip), now, now),
        )
        migrated.append(ip)

    # Erst NACH der Uebernahme loeschen: schlaegt oben etwas fehl, rollt die Transaktion
    # des Aufrufers alles zurueck -- der Schluessel bleibt dann erhalten und der naechste
    # Start versucht es erneut. Kein halber Zustand.
    conn.execute("DELETE FROM settings WHERE key = ?", (LEGACY_EXPECTED_SERVERS_KEY,))

    return ExpectedServersMigrationResult(ran=True, migrated=migrated, kept=kept, skipped=skipped)
