"""Reine Aggregation des DNS-Waechter-Berichts (Etappe 1) -- fuenfter Reporting-Bericht.

Dies ist der fuenfte Reporting-Bericht (nach Sicherheits-, Bestands-, CVE- und
Aussenkontakte-Bericht). Die Architektur ist 1:1 analog zum Aussenkontakte-Bericht
(``outbound_report.py``): neutrale frozen Eingabe-Typen, eine reine ``build``-Funktion,
ein frozen Out-Report. Diese Datei verdichtet die neutralen DNS-Waechter-Zeilen
(``DnsWatchContactRow``) und die neutralen Rahmen-Angaben (``DnsWatchReportInput``) zu
den Gesamtzaehlern, der Kategorie-Verteilung, der Programm-Verteilung und der
sortierten Gesamt-Kontaktliste.

DATENQUELLE: die DNS-Waechter-Kontakte je Rechner (``domain.dns_watch.DnsContact``).
Der Composition Root (spaetere Etappe) PROJIZIERT diese echten Kontakte auf die hier
definierten NEUTRALEN Eingabe-Zeilen und reicht sie herein. Insbesondere die
Kategorie-Einordnung (``category``), der aufgeloeste Name (SNI/PTR) und der zuordenbare
Programmname (``app_name``) entstehen VOR dem Befuellen beim Aufrufer; hier wird NUR
gezaehlt, gruppiert und sortiert.

REINE RECHNUNG analog ``outbound_report.py``: KEINE Uhr, KEINE I/O, KEINE Persistenz,
KEINE Domaenen-Importe (CLAUDE.md, Importregel application -> domain/ports). Die
Kategorie-Konstanten stehen HIER lokal (wie ``SEVERITY_ORDER`` in ``cve_report.py``) --
die Strings sind zeichengleich zur Domaene, aber dieses Modul ist eigenstaendig und
importiert sie NICHT aus domain.
"""

from __future__ import annotations

from dataclasses import dataclass

# ── Kategorie-Schluessel + Rang (lokal, zeichengleich zur Domaene) ───────────
#
# ``CATEGORY_ORDER`` ist die feste Ausgabe-Reihenfolge der Kategorie-Verteilung (immer
# alle drei Kategorien). ``_CATEGORY_RANK`` ordnet jede Kategorie einem Rang zu -- er
# steuert die Sortierung der Kontaktliste (auffaellige zuerst). Beide sind HIER lokal
# definiert (wie ``SEVERITY_ORDER``/``SEVERITY_RANG`` in ``cve_report.py``); die Strings
# sind identisch zur Domaene, werden aber NICHT aus domain importiert.

CATEGORY_OPEN = "offen"
CATEGORY_POSSIBLE_DOH = "moegliche_doh"
CATEGORY_EXPECTED = "erwartungsgemaess"
CATEGORY_ORDER = (CATEGORY_OPEN, CATEGORY_POSSIBLE_DOH, CATEGORY_EXPECTED)
_CATEGORY_RANK = {CATEGORY_OPEN: 0, CATEGORY_POSSIBLE_DOH: 1, CATEGORY_EXPECTED: 2}

# Platzhalter fuer einen leeren Programmnamen in der Programm-Verteilung.
_UNKNOWN_APP = "(ohne)"


# ── Eingabe-Datentraeger (frozen, neutral) ──────────────────────────────────
#
# Der Aufrufer (spaetere Etappe) fuellt diese aus den echten ``DnsContact``-Objekten.
# Alle Anzeige-Texte (``hostname``, ``app_name``) und die Kategorie-Einordnung sind schon
# FERTIG vom Aufrufer gesetzt -- hier wird nur noch gezaehlt, gruppiert und sortiert.


@dataclass(frozen=True)
class DnsWatchContactRow:
    """Eine neutrale DNS-Waechter-Zeile des Berichts (Aufrufer befuellt).

    ``remote_ip`` der Anzeige-/Gruppier-Schluessel der Gegenstelle, ``hostname`` der schon
    aufgeloeste Name (SNI/PTR, "" moeglich), ``category`` der ROHE Kategorie-Schluessel
    (genau einer der drei ``CATEGORY_*``), ``app_name`` der zuordenbare Programmname (""
    moeglich). ``port`` der ``remote_port`` (0 = unbekannt; der Aufrufer liefert den Port
    oder 0), ``connection_count`` die Anzahl der Verbindungen dieser (IP, Kategorie),
    ``acknowledged`` der Quittiert-Marker (False = aktiver Kontakt, True = quittiert).
    """

    remote_ip: str
    hostname: str
    category: str
    app_name: str
    port: int
    connection_count: int
    acknowledged: bool


@dataclass(frozen=True)
class DnsWatchReportInput:
    """Neutrale Rahmen-Angaben des DNS-Waechter-Berichts (Aufrufer projiziert).

    ``host_scope`` der feste Marker ("local_host") des Bezugsrahmens -- ein technischer
    Schluessel, NICHT lokalisiert; der Rand setzt ihn und reicht ihn durch.
    ``expected_servers`` die erwarteten DNS-Server (Beleg der Einordnung),
    ``doh_providers`` die bekannten DoH-Anbieter (Beleg der Einordnung) -- beide vom
    Aufrufer gesetzt und UNVERAENDERT durchgereicht.
    """

    host_scope: str
    expected_servers: tuple[str, ...]
    doh_providers: tuple[str, ...]


# ── Ergebnis-Datentraeger (frozen) ──────────────────────────────────────────


@dataclass(frozen=True)
class CategoryCount:
    """Ein Eintrag der Kategorie-Verteilung (Kategorie + Anzahl), neutral.

    ``category`` die Kategorie (aus ``CATEGORY_ORDER``), ``count`` die Anzahl aktiver
    Kontakte dieser Kategorie (auch 0 moeglich -- es werden immer alle drei Kategorien
    ausgegeben).
    """

    category: str
    count: int


@dataclass(frozen=True)
class AppCount:
    """Ein Eintrag der Programm-Verteilung (Programm + Anzahl), neutral.

    ``app_name`` der Programmname (leere Werte als ``_UNKNOWN_APP``), ``count`` die Anzahl
    aktiver Zeilen mit diesem Programm.
    """

    app_name: str
    count: int


@dataclass(frozen=True)
class DnsWatchReport:
    """Das Gesamtergebnis der DNS-Waechter-Aggregation (alles fuer den api-Rand/Frontend).

    BEZUGSRAHMEN: ``host_scope``/``expected_servers``/``doh_providers`` werden aus
    ``status`` UNVERAENDERT durchgereicht (``host_scope`` bleibt der rohe technische
    Schluessel).

    KENNZAHLEN: ``contacts_total`` alle Zeilen (aktiv + quittiert), ``active_total`` die
    nicht-quittierten, ``acknowledged_total`` die quittierten. ``expected_active`` die
    aktiven Zeilen der Kategorie ``CATEGORY_EXPECTED``, ``open_active`` die der Kategorie
    ``CATEGORY_OPEN``, ``doh_active`` die der Kategorie ``CATEGORY_POSSIBLE_DOH``,
    ``flagged_active`` = ``open_active`` + ``doh_active`` (die auffaelligen).

    VERTEILUNGEN: ``category_distribution`` ueber AKTIVE Zeilen, IMMER alle drei
    Kategorien in ``CATEGORY_ORDER`` (auch count 0). ``app_distribution`` ueber AKTIVE
    Zeilen nach Programm (leere ``app_name`` als ``_UNKNOWN_APP``, count desc dann
    app_name asc).

    LISTE: ``contact_rows`` ALLE Zeilen (aktiv UND quittiert), sortiert nach Kategorie-Rang
    (offen vor moegliche_doh vor erwartungsgemaess), dann ``connection_count`` desc, dann
    ``remote_ip`` asc.
    """

    host_scope: str
    expected_servers: tuple[str, ...]
    doh_providers: tuple[str, ...]
    contacts_total: int
    active_total: int
    acknowledged_total: int
    expected_active: int
    open_active: int
    doh_active: int
    flagged_active: int
    category_distribution: list[CategoryCount]
    app_distribution: list[AppCount]
    contact_rows: list[DnsWatchContactRow]


# ── Reine Funktion (keine I/O, keine Uhr) ───────────────────────────────────


def build_dns_watch_report(
    status: DnsWatchReportInput, rows: list[DnsWatchContactRow]
) -> DnsWatchReport:
    """Baut den vollstaendigen DNS-Waechter-Bericht aus den neutralen Kontakt-Zeilen.

    Schritte (rein, deterministisch, KEINE Uhr):
      1. ``active`` = alle Zeilen mit ``acknowledged`` False.
      2. ``contacts_total`` = len(rows); ``active_total`` = len(active);
         ``acknowledged_total`` = contacts_total - active_total.
      3. ``category_zaehler`` je ``CATEGORY_ORDER`` (mit 0 vorbelegt) ueber AKTIVE Zeilen,
         deren ``category`` bekannt ist; daraus ``expected_active``/``open_active``/
         ``doh_active`` ziehen; ``flagged_active`` = open_active + doh_active.
      4. ``category_distribution`` je ``CATEGORY_ORDER`` ein ``CategoryCount`` -- IMMER
         alle drei Kategorien, auch count 0.
      5. ``app_distribution`` ueber AKTIVE Zeilen nach (app_name oder ``_UNKNOWN_APP``)
         gruppiert, sortiert nach (-count, app_name).
      6. ``contact_rows`` = ALLE Zeilen, sortiert nach (Kategorie-Rang, -connection_count,
         remote_ip).
      7. ``host_scope``/``expected_servers``/``doh_providers`` aus ``status`` durchreichen.

    Keine Uhr, keine I/O, keine Domaenen-Importe.
    """
    # Schritt 1: aktive Zeilen (nicht quittiert).
    active = [r for r in rows if not r.acknowledged]

    # Schritt 2: Grund-Kennzahlen.
    contacts_total = len(rows)
    active_total = len(active)
    acknowledged_total = contacts_total - active_total

    # Schritt 3: Kategorie-Zaehler ueber aktive Zeilen (immer alle drei Kategorien).
    category_zaehler = dict.fromkeys(CATEGORY_ORDER, 0)
    for row in active:
        if row.category in category_zaehler:
            category_zaehler[row.category] += 1
    expected_active = category_zaehler[CATEGORY_EXPECTED]
    open_active = category_zaehler[CATEGORY_OPEN]
    doh_active = category_zaehler[CATEGORY_POSSIBLE_DOH]
    flagged_active = open_active + doh_active

    # Schritt 4: Kategorie-Verteilung (immer alle drei Kategorien).
    category_distribution = [
        CategoryCount(category=kategorie, count=category_zaehler[kategorie])
        for kategorie in CATEGORY_ORDER
    ]

    # Schritt 5: Programm-Verteilung (aktive Zeilen, leerer app_name als Platzhalter).
    app_zaehler: dict[str, int] = {}
    for row in active:
        schluessel = row.app_name or _UNKNOWN_APP
        app_zaehler[schluessel] = app_zaehler.get(schluessel, 0) + 1
    app_distribution = [
        AppCount(app_name=programm, count=anzahl) for programm, anzahl in app_zaehler.items()
    ]
    app_distribution.sort(key=lambda a: (-a.count, a.app_name))

    # Schritt 6: contact_rows -- ALLE Zeilen, auffaellige Kategorien zuoberst, dann
    # connection_count desc, bei Gleichstand remote_ip asc. Unbekannte Kategorien landen
    # ueber den hohen Ersatz-Rang automatisch am Ende.
    contact_rows = sorted(
        rows,
        key=lambda r: (
            _CATEGORY_RANK.get(r.category, len(_CATEGORY_RANK)),
            -r.connection_count,
            r.remote_ip,
        ),
    )

    # Schritt 7: Durchreichen + Rueckgabe.
    return DnsWatchReport(
        host_scope=status.host_scope,
        expected_servers=status.expected_servers,
        doh_providers=status.doh_providers,
        contacts_total=contacts_total,
        active_total=active_total,
        acknowledged_total=acknowledged_total,
        expected_active=expected_active,
        open_active=open_active,
        doh_active=doh_active,
        flagged_active=flagged_active,
        category_distribution=category_distribution,
        app_distribution=app_distribution,
        contact_rows=contact_rows,
    )
