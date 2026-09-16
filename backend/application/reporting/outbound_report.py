"""Reine Aggregation des Aussenkontakte-Berichts (Etappe 1) -- vierter Reporting-Bericht.

Dies ist der vierte Reporting-Bericht (nach Sicherheits-, Bestands- und CVE-Bericht).
Die Architektur ist 1:1 analog zum CVE-Bericht (``cve_report.py``): neutrale frozen
Eingabe-Typen, eine reine ``build``-Funktion, ein frozen Out-Report. Diese Datei
verdichtet die neutralen Aussenkontakt-Zeilen (``OutboundContactRow``) und die
Bezugsrahmen-Kennzahlen (``OutboundReportInput``) zu den Gesamtzaehlern, der
Land-/Betreiber-Verteilung und der sortierten Gesamt-Kontaktliste.

DATENQUELLE: der verdichtete Aggregat-Stand je Aufzeichnung
(``domain.outbound_log.AggregatedContact``). Der Composition Root (spaetere Etappe)
PROJIZIERT diese echten Aggregate auf die hier definierten NEUTRALEN Eingabe-Zeilen
und reicht sie herein. Insbesondere die Blocklist-Bewertung (``tracker_lists``/
``threat_lists``), der ``is_local``-Marker, die aufgeloesten Anzeigenamen (SNI||PTR||"")
und die fertig formatierten Datums-Texte (``first_seen_text``/``last_seen_text``)
entstehen VOR dem Befuellen beim Aufrufer; hier liegen nur noch die rohen
``first_seen_ts``/``last_seen_ts`` als Sortier-/Alters-Schluessel, ohne jede
Formatierung.

REINE RECHNUNG analog ``cve_report.py``: KEINE Uhr, KEINE I/O, KEINE Persistenz,
KEINE Domaenen-Importe (CLAUDE.md, Importregel application -> domain/ports). Hier wird
nur gezaehlt, gruppiert und sortiert. Technische Schluessel (``recording_scope``)
bleiben ROH -- nur die Anzeige wird spaeter (am Rand) lokalisiert.
"""

from __future__ import annotations

from dataclasses import dataclass

# ── Eingabe-Datentraeger (frozen, neutral) ──────────────────────────────────
#
# Der Aufrufer (spaetere Etappe) fuellt diese aus den echten ``AggregatedContact``-
# Objekten. Alle Anzeige-Texte (``hostname``, ``operator``, ``first_seen_text`` ...) und
# die Blocklist-Bewertung sind schon FERTIG vom Aufrufer gesetzt -- hier wird nur noch
# gezaehlt, gruppiert und sortiert.


@dataclass(frozen=True)
class OutboundContactRow:
    """Eine neutrale Aussenkontakt-Zeile des Berichts (Aufrufer befuellt).

    ``remote_ip`` der Anzeige-/Gruppier-Schluessel der Gegenstelle, ``hostname`` der schon
    aufgeloeste Anzeigename (SNI||PTR||"", "" moeglich), ``country`` das Land ("" moeglich),
    ``operator`` der ASN-Klarname ("" moeglich), ``asn`` die ASN ("" moeglich),
    ``app_name`` der zuordenbare Anwendungsname ("" moeglich). ``first_seen_text``/
    ``last_seen_text`` sind die schon FERTIG formatierten Datums-Texte (keine Uhr hier),
    ``first_seen_ts``/``last_seen_ts`` die rohen Sortier-/Alters-Schluessel (keine
    Formatierung hier). ``total_count`` die aufsummierte Verbindungsanzahl, ``peak_count``
    das Maximum eines Zyklus. ``is_local`` markiert eine lokale/Infrastruktur-Gegenstelle
    (vom Aufrufer gesetzt; aus den Bedrohungs-/Bewertungszaehlern ausgenommen, konsistent
    zur ``OutboundView``). ``tracker_lists`` die Namen der Tracker/Werbung-Blocklisten, in
    denen die Domain liegt (leer = kein Treffer), ``threat_lists`` die Namen der
    Bedrohungs-Blocklisten, in denen die IP liegt (leer = kein Treffer) -- beide vom
    Aufrufer gesetzt.
    """

    remote_ip: str
    hostname: str
    country: str
    operator: str
    asn: str
    app_name: str
    first_seen_text: str
    last_seen_text: str
    first_seen_ts: float
    last_seen_ts: float
    total_count: int
    peak_count: int
    is_local: bool
    tracker_lists: tuple[str, ...]
    threat_lists: tuple[str, ...]


@dataclass(frozen=True)
class OutboundReportInput:
    """Neutrale Bezugsrahmen-Kennzahlen des Aussenkontakte-Berichts (Aufrufer projiziert).

    ``recording_label`` der Anzeigename der Aufzeichnung oder die fertige "Alle
    Aufzeichnungen"-Bezeichnung ("" moeglich). ``recording_scope`` der rohe Schluessel des
    Bezugsrahmens ("single" oder "all") -- ein technischer Schluessel, NICHT lokalisiert;
    der Rand setzt ihn und reicht ihn durch.
    """

    recording_label: str
    recording_scope: str


# ── Ergebnis-Datentraeger (frozen) ──────────────────────────────────────────


@dataclass(frozen=True)
class CountryCount:
    """Ein Eintrag der Land-Verteilung (Land + Anzahl distinct Gegenstellen), neutral.

    ``country`` das Land (leere Werte als ``EMPTY_COUNTRY_MARKER``), ``count`` die Anzahl der
    nicht-lokalen Gegenstellen-Zeilen mit diesem Land.
    """

    country: str
    count: int


@dataclass(frozen=True)
class OperatorCount:
    """Ein Eintrag der Betreiber-Verteilung (Betreiber + Anzahl distinct Gegenstellen).

    ``operator`` der Betreiber (leere Werte als ``EMPTY_OPERATOR_MARKER``), ``count`` die Anzahl
    der nicht-lokalen Gegenstellen-Zeilen mit diesem Betreiber.
    """

    operator: str
    count: int


@dataclass(frozen=True)
class OutboundReport:
    """Das Gesamtergebnis der Aussenkontakte-Aggregation (alles fuer den api-Rand/Frontend).

    BEZUGSRAHMEN: ``recording_label``/``recording_scope`` werden aus ``status``
    UNVERAENDERT durchgereicht (``recording_scope`` bleibt der rohe technische Schluessel).

    KENNZAHLEN: ``contacts_total`` die Anzahl aller Gegenstellen-Zeilen (inkl. lokale),
    ``remote_total`` die Anzahl NICHT-lokaler Gegenstellen (``is_local`` False),
    ``local_total`` die Anzahl lokaler Gegenstellen. ``connection_total`` die Summe der
    ``total_count`` ueber ALLE Zeilen. ``countries_total`` die Anzahl distinct nicht-leerer
    ``country`` ueber NICHT-lokale Zeilen, ``operators_total`` analog ueber ``operator``.
    ``tracker_contacts`` die Anzahl nicht-lokaler Zeilen mit nicht-leerem ``tracker_lists``,
    ``threat_contacts`` analog ueber ``threat_lists``, ``flagged_contacts`` die Anzahl
    nicht-lokaler Zeilen mit Tracker ODER Threat (distinct Zeilen, KEINE Summe -- eine
    Zeile mit BEIDEN Flags zaehlt nur 1x).

    VERTEILUNGEN: ``country_distribution`` ueber NICHT-lokale Zeilen (count desc, dann
    country asc; leere ``country`` als ``EMPTY_COUNTRY_MARKER``), ``operator_distribution``
    analog ueber ``operator`` (leere ``operator`` als ``EMPTY_OPERATOR_MARKER``).

    LISTE: ``contact_rows`` ALLE Zeilen, sortiert -- zuerst geflaggte (Threat vor Tracker)
    zuoberst, dann nach ``total_count`` desc, dann ``remote_ip`` asc.
    """

    recording_label: str
    recording_scope: str
    contacts_total: int
    remote_total: int
    local_total: int
    connection_total: int
    countries_total: int
    operators_total: int
    tracker_contacts: int
    threat_contacts: int
    flagged_contacts: int
    country_distribution: list[CountryCount]
    operator_distribution: list[OperatorCount]
    contact_rows: list[OutboundContactRow]


# ── Reine Funktionen (keine I/O, keine Uhr) ─────────────────────────────────

# Maschinelle Marker fuer einen leeren Gruppierungs-Schluessel der beiden Verteilungen.
# BEWUSST kein Anzeigetext. ZWEI Marker statt einem, weil Land und Betreiber
# unterschiedliche Texte brauchen (Muster inventory_report.py).
EMPTY_COUNTRY_MARKER = "__country_unknown__"
EMPTY_OPERATOR_MARKER = "__operator_unknown__"


def build_outbound_report(
    status: OutboundReportInput, rows: list[OutboundContactRow]
) -> OutboundReport:
    """Baut den vollstaendigen Aussenkontakte-Bericht aus den neutralen Kontakt-Zeilen.

    Schritte (rein, deterministisch, KEINE Uhr):
      1. ``nicht_lokal`` = Zeilen mit ``is_local`` False.
      2. ``contacts_total`` = len(rows); ``remote_total`` = len(nicht_lokal);
         ``local_total`` = contacts_total - remote_total.
      3. ``connection_total`` = Summe der ``total_count`` ueber ALLE Zeilen.
      4. ``countries_total`` = distinct nicht-leere ``country`` ueber nicht_lokal;
         ``operators_total`` = distinct nicht-leere ``operator`` ueber nicht_lokal.
      5. ``tracker_contacts``/``threat_contacts``/``flagged_contacts`` ueber nicht_lokal
         (flagged = Tracker ODER Threat, distinct Zeilen -- keine Summe).
      6. ``country_distribution`` ueber nicht_lokal nach (country oder
         ``EMPTY_COUNTRY_MARKER``) gruppiert, sortiert nach (-count, country);
         ``operator_distribution`` analog mit ``EMPTY_OPERATOR_MARKER``.
      7. ``contact_rows`` = ALLE Zeilen, sortiert nach dem Flag-Rang (0 Threat, 1 Tracker,
         2 Rest -- jeweils nur fuer nicht-lokale), dann -total_count, dann remote_ip.
      8. ``recording_label``/``recording_scope`` aus ``status`` durchreichen.

    Keine Uhr, keine I/O, keine Domaenen-Importe.
    """
    # Schritt 1: nicht-lokale Gegenstellen.
    nicht_lokal = [r for r in rows if not r.is_local]

    # Schritt 2: Grund-Kennzahlen.
    contacts_total = len(rows)
    remote_total = len(nicht_lokal)
    local_total = contacts_total - remote_total

    # Schritt 3: Summe der Verbindungen ueber ALLE Zeilen (inkl. lokale).
    connection_total = sum(r.total_count for r in rows)

    # Schritt 4: distinct Land/Betreiber ueber nicht-lokale, nicht-leere Werte.
    countries_total = len({r.country for r in nicht_lokal if r.country})
    operators_total = len({r.operator for r in nicht_lokal if r.operator})

    # Schritt 5: Bewertungs-Zaehler (nur nicht-lokale Zeilen).
    tracker_contacts = sum(1 for r in nicht_lokal if r.tracker_lists)
    threat_contacts = sum(1 for r in nicht_lokal if r.threat_lists)
    flagged_contacts = sum(1 for r in nicht_lokal if r.tracker_lists or r.threat_lists)

    # Schritt 6: Land-Verteilung (nicht-lokal, leere country als Platzhalter).
    country_zaehler: dict[str, int] = {}
    for row in nicht_lokal:
        schluessel = row.country or EMPTY_COUNTRY_MARKER
        country_zaehler[schluessel] = country_zaehler.get(schluessel, 0) + 1
    country_distribution = [
        CountryCount(country=land, count=anzahl) for land, anzahl in country_zaehler.items()
    ]
    country_distribution.sort(key=lambda c: (-c.count, c.country))

    # Schritt 6 (analog): Betreiber-Verteilung.
    operator_zaehler: dict[str, int] = {}
    for row in nicht_lokal:
        schluessel = row.operator or EMPTY_OPERATOR_MARKER
        operator_zaehler[schluessel] = operator_zaehler.get(schluessel, 0) + 1
    operator_distribution = [
        OperatorCount(operator=betreiber, count=anzahl)
        for betreiber, anzahl in operator_zaehler.items()
    ]
    operator_distribution.sort(key=lambda o: (-o.count, o.operator))

    # Schritt 7: contact_rows -- ALLE Zeilen, geflaggte (Threat vor Tracker) zuoberst,
    # dann nach Kontaktstaerke (total_count desc), dann remote_ip asc. Lokale tragen nie
    # Flags und rutschen ueber den hohen Flag-Rang automatisch nach unten.
    contact_rows = sorted(
        rows,
        key=lambda r: (
            0
            if (not r.is_local and r.threat_lists)
            else 1
            if (not r.is_local and r.tracker_lists)
            else 2,
            -r.total_count,
            r.remote_ip,
        ),
    )

    # Schritt 8: Durchreichen + Rueckgabe.
    return OutboundReport(
        recording_label=status.recording_label,
        recording_scope=status.recording_scope,
        contacts_total=contacts_total,
        remote_total=remote_total,
        local_total=local_total,
        connection_total=connection_total,
        countries_total=countries_total,
        operators_total=operators_total,
        tracker_contacts=tracker_contacts,
        threat_contacts=threat_contacts,
        flagged_contacts=flagged_contacts,
        country_distribution=country_distribution,
        operator_distribution=operator_distribution,
        contact_rows=contact_rows,
    )
