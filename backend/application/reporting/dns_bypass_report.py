"""Reine Aggregation des netzweiten DNS-Umgehungs-Berichts (Etappe 5) -- eigener Bericht.

Dies ist ein NEUER, EIGENER Reporting-Bericht NEBEN dem host-lokalen ``dns_watch_report``
(der UNANGETASTET bleibt -- ehrlich getrennt, Konzept-Entscheidung ADR 0042). Waehrend der
``dns_watch_report`` aus der host-lokalen ``dns_watch``-Quelle zieht, liest dieser Bericht
die PERSISTIERTEN netzweiten Umgehungs-Laeufe (die ``dns_bypass``-Aufzeichnungen aus
Etappe 3). Die Architektur ist 1:1 analog zum Aussenkontakte-Bericht
(``outbound_report.py``): neutrale frozen Eingabe-Typen, eine reine ``build``-Funktion, ein
frozen Out-Report -- mit BEZUGSRAHMEN-Wahl (eine Aufzeichnung ODER alle zusammengefasst).

DATENQUELLE: die verdichteten Umgehungs-Datensaetze je Aufzeichnung
(``domain.dns_bypass.AggregatedBypass``). Der Composition Root (Etappe 5, ``app.py``)
PROJIZIERT diese echten Aggregate auf die hier definierten NEUTRALEN Eingabe-Zeilen und
reicht sie herein. Insbesondere die Anreicherung -- der best-effort ``device_name`` (ueber
die ``_dns_bypass_name_by_ip``-Naht) und die DoH-Bewertung (``is_doh``/``doh_source_name``
ueber die ``_dns_bypass_doh_lookup``-Naht) -- faellt VOR dem Befuellen beim Aufrufer (Regel
5, DIESELBEN Nahtstellen wie im Live-View ``_dns_bypass_view``); hier liegen nur noch die
fertigen Felder.

REINE RECHNUNG analog ``outbound_report.py``: KEINE Uhr, KEINE I/O, KEINE Persistenz,
KEINE Domaenen-Importe (CLAUDE.md, Importregel application -> domain/ports). Hier wird nur
gezaehlt, gruppiert und sortiert. Technische Schluessel (``recording_scope``) bleiben ROH
-- nur die Anzeige wird spaeter (am Rand) lokalisiert.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ── Eingabe-Datentraeger (frozen, neutral) ──────────────────────────────────
#
# Der Aufrufer (Composition Root) fuellt diese aus den echten ``AggregatedBypass``-
# Objekten. Alle Anzeige-/Bewertungs-Felder (``device_name``, ``is_doh``,
# ``doh_source_name``) sind schon FERTIG vom Aufrufer gesetzt -- hier wird nur noch
# gezaehlt, gruppiert und sortiert.


@dataclass(frozen=True)
class DnsBypassReportRow:
    """Eine neutrale Umgehungs-Zeile des Berichts (Aufrufer befuellt).

    Spiegelt die Felder der Live-View ``DnsBypassFindingOut`` (dieselbe Sicht, nur aus dem
    persistenten Stand): ``src_ip`` ist das fragende Geraet (roher Gruppier-Schluessel),
    ``device_name`` der best-effort im Bestand aufgeloeste Anzeigename ("" moeglich -- der
    Aufrufer setzt "" statt ``None``, wenn keine IP passt), ``dst_ip`` der nicht-erwartete
    Ziel-Resolver, ``is_doh`` die DoH-Bewertung des Ziels, ``doh_source_name`` der Name der
    treffenden aktiven DOH-Quelle ("" moeglich). ``query_count`` die aufsummierte Anzahl
    Umgehungs-Anfragen dieser (Geraet, Resolver)-Gruppe, ``sample_qnames`` bis zu fuenf
    distinct qnames als Beleg (vom Aufrufer durchgereicht).
    """

    src_ip: str
    device_name: str
    dst_ip: str
    is_doh: bool
    doh_source_name: str
    query_count: int
    sample_qnames: tuple[str, ...]


@dataclass(frozen=True)
class DnsBypassReportInput:
    """Neutrale Bezugsrahmen-Kennzahlen des DNS-Umgehungs-Berichts (Aufrufer projiziert).

    ``recording_label`` der Anzeigename der Aufzeichnung oder die fertige "Alle
    Aufzeichnungen"-Bezeichnung ("" moeglich). ``recording_scope`` der rohe Schluessel des
    Bezugsrahmens ("single" oder "all") -- ein technischer Schluessel, NICHT lokalisiert;
    der Rand setzt ihn und reicht ihn durch. ``expected_servers`` ist die erwartete
    Resolver-Menge als ehrlicher Beleg, gegen die klassifiziert wurde (bei "single" die
    eingefrorene Menge der Aufzeichnung, bei "all" die aktuell erwartete Menge -- der Rand
    waehlt und dokumentiert).
    """

    recording_label: str
    recording_scope: str
    expected_servers: tuple[str, ...]


# ── Ergebnis-Datentraeger (frozen) ──────────────────────────────────────────


@dataclass(frozen=True)
class ResolverCount:
    """Ein Eintrag der Ziel-Resolver-Verteilung (Ziel-IP + Anzahl Umgehungen), neutral.

    ``dst_ip`` der Ziel-Resolver, ``count`` die Summe der ``query_count`` aller Zeilen zu
    diesem Ziel (ueber ALLE fragenden Geraete). Die anfragestaerksten Resolver zuerst.
    """

    dst_ip: str
    count: int


@dataclass(frozen=True)
class DnsBypassReport:
    """Das Gesamtergebnis der DNS-Umgehungs-Aggregation (alles fuer den api-Rand/Frontend).

    BEZUGSRAHMEN: ``recording_label``/``recording_scope``/``expected_servers`` werden aus
    ``status`` UNVERAENDERT durchgereicht (``recording_scope`` bleibt der rohe technische
    Schluessel, ``expected_servers`` der ehrliche Beleg).

    KENNZAHLEN: ``queries_total`` die Gesamtzahl aller in den gewaehlten Laeufen
    gespeicherten DETAIL-Anfragen (auch der erwarteten -- vom Aufrufer als Summe herein),
    ``bypass_total`` die Summe der ``query_count`` ueber ALLE Umgehungs-Zeilen,
    ``expected_total`` = ``max(queries_total - bypass_total, 0)`` (die erwartungsgemaessen
    Anfragen, ehrlich abgeleitet), ``bypass_devices`` die Anzahl distinct ``src_ip`` mit
    mindestens einer Umgehung.

    VERTEILUNG: ``resolver_distribution`` je Ziel-Resolver (``dst_ip``) die Summe der
    Umgehungs-Anfragen, sortiert nach count desc, dann ``dst_ip`` asc.

    LISTE: ``bypass_rows`` ALLE Umgehungs-Zeilen, deterministisch sortiert (``query_count``
    desc, dann ``src_ip`` asc, dann ``dst_ip`` asc).
    """

    recording_label: str
    recording_scope: str
    expected_servers: tuple[str, ...]
    queries_total: int
    bypass_total: int
    expected_total: int
    bypass_devices: int
    resolver_distribution: list[ResolverCount]
    bypass_rows: list[DnsBypassReportRow] = field(default_factory=list)


# ── Reine Funktion (keine I/O, keine Uhr) ───────────────────────────────────


def build_dns_bypass_report(
    status: DnsBypassReportInput,
    rows: list[DnsBypassReportRow],
    queries_total: int,
) -> DnsBypassReport:
    """Baut den vollstaendigen DNS-Umgehungs-Bericht aus den neutralen Umgehungs-Zeilen.

    Schritte (rein, deterministisch, KEINE Uhr):
      1. ``bypass_total`` = Summe der ``query_count`` ueber ALLE Zeilen.
      2. ``expected_total`` = ``max(queries_total - bypass_total, 0)`` (ehrlich aus dem vom
         Aufrufer gelieferten DETAIL-Gesamtstand abgeleitet -- nie negativ).
      3. ``bypass_devices`` = distinct ``src_ip`` ueber alle Zeilen.
      4. ``resolver_distribution`` je ``dst_ip`` die Summe der ``query_count``, sortiert
         nach (-count, dst_ip).
      5. ``bypass_rows`` = ALLE Zeilen, sortiert nach (-query_count, src_ip, dst_ip).
      6. ``recording_label``/``recording_scope``/``expected_servers`` aus ``status``
         durchreichen; ``queries_total`` unveraendert uebernehmen.

    Keine Uhr, keine I/O, keine Domaenen-Importe.
    """
    # Schritt 1: Summe der Umgehungs-Anfragen ueber ALLE Zeilen.
    bypass_total = sum(r.query_count for r in rows)

    # Schritt 2: erwartungsgemaesse Anfragen ehrlich ableiten (nie negativ).
    expected_total = max(queries_total - bypass_total, 0)

    # Schritt 3: distinct fragende Geraete.
    bypass_devices = len({r.src_ip for r in rows})

    # Schritt 4: Ziel-Resolver-Verteilung (Summe der query_count je dst_ip).
    resolver_zaehler: dict[str, int] = {}
    for row in rows:
        resolver_zaehler[row.dst_ip] = resolver_zaehler.get(row.dst_ip, 0) + row.query_count
    resolver_distribution = [
        ResolverCount(dst_ip=ziel, count=anzahl) for ziel, anzahl in resolver_zaehler.items()
    ]
    resolver_distribution.sort(key=lambda r: (-r.count, r.dst_ip))

    # Schritt 5: Umgehungs-Zeilen deterministisch sortieren (query_count desc, src_ip asc,
    # dst_ip asc) -- SPIEGELT die Sortierung des Live-Use-Case ``BuildDnsBypass``.
    bypass_rows = sorted(rows, key=lambda r: (-r.query_count, r.src_ip, r.dst_ip))

    # Schritt 6: Durchreichen + Rueckgabe.
    return DnsBypassReport(
        recording_label=status.recording_label,
        recording_scope=status.recording_scope,
        expected_servers=status.expected_servers,
        queries_total=queries_total,
        bypass_total=bypass_total,
        expected_total=expected_total,
        bypass_devices=bypass_devices,
        resolver_distribution=resolver_distribution,
        bypass_rows=bypass_rows,
    )
