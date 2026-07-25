"""Reine Aggregation des Bestandsberichts: Bestands-Kennzahlen, Hersteller-/
Kategorie-Verteilung und die nach Sichtung sortierten Geraete-Tabellen (Etappe 1).

Diese Datei verdichtet die neutralen Geraete-Zeilen (``InventoryDeviceRow``) zu den
Berichts-Kennzahlen (Vertrauens-Verteilung), den beiden Verteilungs-Tabellen
(Hersteller/Kategorie) und den nach letzter Sichtung sortierten Geraete-Listen
(aktiv vs. archiviert). Die Bestands-Grundzahlen (``total``/``known``/``unknown``/
``active_24h``) kommen schon fertig vom Aufrufer (aus ``DeviceStats``) und werden hier
UNVERAENDERT durchgereicht.

REINE RECHNUNG analog ``security_report.py`` / ``security_score.py``: KEINE Uhr,
KEINE I/O, KEINE Persistenz, KEINE Domaenen-Importe (CLAUDE.md, Importregel
application -> domain/ports). Diese Etappe importiert NICHTS aus devices/scanning --
der Aufrufer (spaetere Etappe am Composition Root) projiziert die echten
Device-Objekte auf die hier definierten NEUTRALEN Eingabe-Datentraeger und reicht sie
herein. Insbesondere die Formatierung der Datums-Texte (``first_seen_text``/
``last_seen_text``) und der Anzeigename (``device_label``) entstehen VOR dem Befuellen
beim Aufrufer; hier liegt nur noch ``last_seen_ts`` als Sortierschluessel, ohne jede
Formatierung.

Muster aus der Nachbarschaft uebernommen: frozen dataclasses als Ein-/Ausgabe-
Datentraeger, reine Funktionen mit ausfuehrlichen Docstrings, alle Kontextwerte via
Parameter, deterministisch ohne Wanduhr.
"""

from __future__ import annotations

from dataclasses import dataclass

# ── Eingabe-Datentraeger (frozen, neutral) ──────────────────────────────────
#
# Der Aufrufer (spaetere Etappe) fuellt diese aus den echten Device-Objekten. Alle
# Anzeige-Texte (``device_label``, die beiden Datums-Texte) und der ``last_ip``-
# Leerstring (statt None) sind schon FERTIG vom Aufrufer gesetzt -- hier wird nur noch
# gezaehlt, gruppiert und sortiert.


@dataclass(frozen=True)
class InventoryDeviceRow:
    """Eine neutrale Geraete-Zeile des Bestandsberichts (Aufrufer befuellt).

    ``device_label`` ist der schon gebildete Anzeigename (label||hostname||last_ip||
    mac -- die Wahl trifft der Aufrufer). ``vendor`` der Hersteller (leer moeglich),
    ``last_ip`` die letzte IP als Text (LEERER String wenn None -- der Aufrufer mappt
    das). ``first_seen_text``/``last_seen_text`` sind die schon FERTIG formatierten
    Datums-Texte (der Aufrufer formatiert -- hier keine Uhr). ``last_seen_ts`` ist die
    letzte Sichtung als Unix-Sekunden und dient AUSSCHLIESSLICH als Sortierschluessel
    (keine Formatierung hier). ``times_seen`` die Anzahl der Sichtungen, ``category``
    die Kategorie (leer moeglich), ``is_known`` der bekannt-Marker, ``trust_state``
    der ROHE Vertrauens-Wert ("neutral"/"trusted"/"watch"), ``source`` die Herkunft
    ("scan"/"manual"), ``archived`` der Archiv-Marker (trennt aktive von archivierten
    Zeilen).
    """

    device_label: str
    vendor: str
    last_ip: str
    first_seen_text: str
    last_seen_text: str
    last_seen_ts: float
    times_seen: int
    category: str
    is_known: bool
    trust_state: str
    source: str
    archived: bool


@dataclass(frozen=True)
class DistributionEntry:
    """Ein Eintrag einer Verteilungs-Tabelle (Hersteller bzw. Kategorie), neutral.

    ``label`` ist der Hersteller- bzw. Kategorie-Name, ``count`` die Anzahl der
    Geraete dazu. Ein leerer Hersteller/eine leere Kategorie wird in der Aggregation
    als maschineller Marker (``EMPTY_VENDOR_MARKER`` bzw. ``EMPTY_CATEGORY_MARKER``)
    gezaehlt (siehe ``build_inventory_report``) -- die ANZEIGE dazu entsteht erst beim
    Uebersetzen; ``label`` wird sonst UNVERAENDERT durchgereicht.
    """

    label: str
    count: int


# ── Ergebnis-Datentraeger (frozen) ──────────────────────────────────────────


@dataclass(frozen=True)
class InventoryReport:
    """Das Gesamtergebnis der Bestands-Aggregation (alles fuer den api-Rand/Frontend).

    ``total``/``known``/``unknown``/``active_24h`` sind die Bestands-Grundzahlen, die
    UNVERAENDERT vom Aufrufer (aus ``DeviceStats``) durchgereicht werden. ``trusted``/
    ``watch``/``neutral`` sind die ueber ALLE Zeilen (inkl. archivierte) gezaehlten
    Vertrauens-Stufen.

    ``vendor_distribution`` und ``category_distribution`` sind die beiden
    Verteilungs-Tabellen ueber ALLE Zeilen, jeweils absteigend nach ``count``, bei
    Gleichstand ``label`` aufsteigend.

    ``device_rows`` traegt die AKTIVEN (nicht archivierten) Zeilen, ``archived_rows``
    die archivierten -- beide sortiert nach letzter Sichtung absteigend
    (``last_seen_ts``), bei Gleichstand ``device_label`` aufsteigend.
    """

    total: int
    known: int
    unknown: int
    active_24h: int
    trusted: int
    watch: int
    neutral: int
    vendor_distribution: list[DistributionEntry]
    category_distribution: list[DistributionEntry]
    device_rows: list[InventoryDeviceRow]
    archived_rows: list[InventoryDeviceRow]


# ── Reine Funktionen (keine I/O, keine Uhr) ─────────────────────────────────

# Die drei gueltigen Vertrauens-Stufen. Ein unbekannter ``trust_state``-Wert wird
# bewusst als "neutral" gezaehlt -- ein nicht klassifizierter Wert darf keine Wertung
# (trusted/watch) erzeugen.
_TRUST_STATES = ("trusted", "watch", "neutral")

# Maschinelle Marker fuer einen leeren Hersteller bzw. eine leere Kategorie in den
# Verteilungen. BEWUSST kein Anzeigetext: die Beschriftung entsteht erst dort, wo
# uebersetzt wird (Frontend aus den Sprachdateien, PDF ueber ``_ui``). Die beiden
# Verteilungen brauchen unterschiedliche Texte ("Kein Hersteller ermittelt" vs. "Keine
# Kategorie ermittelt"), darum ZWEI Marker statt einem geteilten.
EMPTY_VENDOR_MARKER = "__vendor_unknown__"
EMPTY_CATEGORY_MARKER = "__category_unknown__"


def _distribution(values: list[str], empty_marker: str) -> list[DistributionEntry]:
    """Gruppiert eine Werteliste zu Verteilungs-Eintraegen (reine Helferfunktion).

    Leere Werte werden als ``empty_marker`` gezaehlt (maschineller Marker, KEIN
    Anzeigetext). Sortiert absteigend nach ``count``, bei Gleichstand ``label``
    aufsteigend. Deterministisch.
    """
    counts: dict[str, int] = {}
    for value in values:
        key = value if value else empty_marker
        counts[key] = counts.get(key, 0) + 1
    entries = [DistributionEntry(label=label, count=count) for label, count in counts.items()]
    return sorted(entries, key=lambda e: (-e.count, e.label))


def build_inventory_report(
    total: int,
    known: int,
    unknown: int,
    active_24h: int,
    rows: list[InventoryDeviceRow],
) -> InventoryReport:
    """Baut den vollstaendigen Bestandsbericht aus den neutralen Geraete-Zeilen.

    Schritte (rein, deterministisch):
      1. Vertrauens-Verteilung (``trusted``/``watch``/``neutral``) ueber ALLE Zeilen
         (inkl. archivierte) nach ``trust_state``; ein unbekannter ``trust_state``
         zaehlt als "neutral".
      2. ``vendor_distribution`` ueber ALLE Zeilen nach ``vendor`` (leer ->
         ``EMPTY_VENDOR_MARKER``), ``category_distribution`` ueber ALLE Zeilen nach
         ``category`` (leer -> ``EMPTY_CATEGORY_MARKER``) -- beide absteigend nach
         ``count``, bei Gleichstand ``label`` aufsteigend.
      3. ``device_rows`` = nur Zeilen mit ``archived == False``, ``archived_rows`` =
         nur Zeilen mit ``archived == True`` -- beide sortiert nach
         ``(-last_seen_ts, device_label)``.
      4. ``total``/``known``/``unknown``/``active_24h`` werden UNVERAENDERT
         durchgereicht (sie kommen schon fertig vom Aufrufer aus ``DeviceStats``).

    Keine Uhr, keine I/O, keine Domaenen-Importe.
    """
    trust_counts = dict.fromkeys(_TRUST_STATES, 0)
    for row in rows:
        state = row.trust_state if row.trust_state in trust_counts else "neutral"
        trust_counts[state] += 1

    vendor_distribution = _distribution([row.vendor for row in rows], EMPTY_VENDOR_MARKER)
    category_distribution = _distribution([row.category for row in rows], EMPTY_CATEGORY_MARKER)

    def _sort_key(row: InventoryDeviceRow) -> tuple[float, str]:
        return (-row.last_seen_ts, row.device_label)

    device_rows = sorted((r for r in rows if not r.archived), key=_sort_key)
    archived_rows = sorted((r for r in rows if r.archived), key=_sort_key)

    return InventoryReport(
        total=total,
        known=known,
        unknown=unknown,
        active_24h=active_24h,
        trusted=trust_counts["trusted"],
        watch=trust_counts["watch"],
        neutral=trust_counts["neutral"],
        vendor_distribution=vendor_distribution,
        category_distribution=category_distribution,
        device_rows=device_rows,
        archived_rows=archived_rows,
    )
