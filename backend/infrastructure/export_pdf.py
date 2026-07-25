"""Infrastruktur-Adapter der export-Domaene: das PDF-Rendern via reportlab.

Erfuellt EINEN Vertrag strukturell ueber reportlab (die Dependency steht bereits in
pyproject.toml):

* ``ReportlabRenderer`` (``ReportRenderer``) -- rendert ein reines, GENERISCHES
  ``PdfReportModel`` (Titel + ``meta``-Kopfpaare + Tabellen-Zeilen, von ``build_pdf_model``
  bzw. ``build_analysis_pdf_model`` gebaut) zu PDF-Bytes. Schlicht, robust, KEIN Logo, keine
  Spielereien: ein paar Kopf-Paragraphs (Titel + die generischen Metadaten-Paare) und eine
  Tabelle der Spalten/Zeilen. Derselbe Adapter rendert Scan- UND Analyse-Bericht (ADR 0015,
  Block 2: PdfReportModel generalisiert) -- der Renderer kennt die Quelle nicht, nur die
  reine Struktur.

KEINE Domaenen-Logik hier (ADR 0015): die Spalten/Zeilen/Kopf-Paare liegen im Modell
bereits fest -- der Adapter rendert nur die vorgegebene Struktur. Kein Netz-I/O; das Rendern
ist CPU-Arbeit (der Port ist ehrlich synchron). Das fertige PDF wird in einen ``BytesIO``
geschrieben und als ``bytes`` geliefert.

``infrastructure/`` darf ``domain``-Modelle kennen (es implementiert die Ports gegen sie) --
hier ``domain.export.PdfReportModel`` ueber den ``ports.export.ReportRenderer``-Vertrag. KEIN
``application``/``api``-Import (import-linter-Contract "infrastructure kennt nicht
application/api").
"""

import io
import os
from typing import ClassVar, Protocol, cast

from reportlab.graphics.shapes import Circle, Drawing, Rect, String, Wedge
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Flowable,
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from domain.export import PdfReportModel
from infrastructure.bundle_paths import resolve_bundle_path

# ── CERNIS-Farbpalette (Auftrag) ────────────────────────────────────────────
# Die Marken-/Severity-Farben des Sicherheitsberichts als reportlab-Farben. Zentral hier,
# damit Gauge/Donut/Balken/Tabellen dieselbe Palette teilen (Single Source im Adapter).
_ACCENT = colors.HexColor("#107E9C")  # CERNIS-Akzent (Kopf, Linien, Tabellenkopf)
_CRIT = colors.HexColor("#B91C1C")  # kritisch (CVE-crit / sev-high)
_NOTABLE = colors.HexColor("#EF9F27")  # auffaellig (sev-med)
_CLEAN = colors.HexColor("#B4B2A9")  # sauber / grau (sev-low)
_TEXT = colors.HexColor("#1a1a18")  # Textfarbe
_LINE = colors.HexColor("#d0cec8")  # dezente Linien
_ZEBRA = colors.HexColor("#f4f3ef")  # helle Zebra-Zeile

# Die Score-Level-Farbe der Gauge: "gut" -> Akzent, "maessig" -> auffaellig, sonst kritisch.
_LEVEL_COLORS = {"gut": _ACCENT, "maessig": _NOTABLE, "kritisch": _CRIT}

# ── CVE-Severity-Palette (Auftrag, exakte Hex) ──────────────────────────────
# Die fuenf NVD-Severity-Stufen des CVE-Berichts als reportlab-Farben -- die GLEICHE Achse wie
# die Live-Ansicht (Wiedererkennung). Eigene Konstanten neben der crit/notable-Achse des
# Sicherheitsberichts (das ist die ANDERE Achse). ``_SEV_COLORS`` ist der Lookup je Stufe.
_SEV_CRITICAL = colors.HexColor("#B91C1C")
_SEV_HIGH = colors.HexColor("#E24B4A")
_SEV_MEDIUM = colors.HexColor("#EF9F27")
_SEV_LOW = colors.HexColor("#B4B2A9")
_SEV_UNKNOWN = colors.HexColor("#D0CEC8")
_SEV_COLORS = {
    "CRITICAL": _SEV_CRITICAL,
    "HIGH": _SEV_HIGH,
    "MEDIUM": _SEV_MEDIUM,
    "LOW": _SEV_LOW,
    "UNKNOWN": _SEV_UNKNOWN,
}

# Stabile Farb-Palette fuer die DNS-Umgehungs-Verteilungs-Grafik (Variante C, gestapelter
# Balken + Legende). KEIN neues Farbset -- nur bestehende Renderer-Tokens, in der Ordnung
# der In-App-Sicht (staerkstes Ziel = Akzent, dann auffaellig/hoch/kritisch/neutral); laenger
# als die Palette wird zyklisch weitergefaerbt (deterministisch je Index).
_DIST_PALETTE: tuple[colors.Color, ...] = (
    _ACCENT,
    _NOTABLE,
    _SEV_HIGH,
    _CRIT,
    _CLEAN,
)

# Repo-Asset des CERNIS-Logos (Auftrag: per find ermittelt -> frontend/public/cernis-logo.png).
# Frozen-Build (PyInstaller): das Asset liegt ueber frontend/public -> frontend/dist gebundelt
# als _MEIPASS/frontend-dist/cernis-logo-pdf.png (Spec: frontend/dist -> "frontend-dist"). Dev:
# relativ zu diesem Modul (backend/infrastructure/ -> Repo-Root -> frontend/public). Die
# Fallunterscheidung kapselt der gemeinsame Helfer resolve_bundle_path. Existiert die Datei nicht,
# faellt die Kopfzeile sauber auf reinen Titel-Text zurueck -- KEIN gezeichnetes Ersatz-Logo
# (Auftrag); im Normalfall MUSS das Logo jetzt aber gefunden werden.
_LOGO_PATH = resolve_bundle_path(
    frozen_relative=os.path.join("frontend-dist", "cernis-logo-pdf.png"),
    dev_absolute=os.path.normpath(
        os.path.join(
            os.path.dirname(__file__), "..", "..", "frontend", "public", "cernis-logo-pdf.png"
        )
    ),
)


# ── Lokalisierte UI-Strings (Abschnittstitel, Beschriftungen, Leertext) ───
# Alle hardkodierten deutschen Strings des Renderers zentral hier.
# _ui(key, lang) liefert den String in der gewuenschten Sprache (Fallback "de").
# Neue Strings hier eintragen, nie im Render-Code hart kodieren.
_UI_STRINGS: dict[str, dict[str, str]] = {
    # Sicherheitsbericht
    "sec.netz_gesundheit": {"de": "Netz-Gesundheit", "en": "Network Health"},
    "sec.geraete_verteilung": {"de": "Geräte-Verteilung", "en": "Device Distribution"},
    "sec.auffaelligkeiten": {"de": "Auffälligkeiten je Gerät", "en": "Findings per Device"},
    "sec.ports": {"de": "Rechner mit auffälligen Ports", "en": "Devices with Notable Ports"},
    "sec.cve": {"de": "CVE-Befunde", "en": "CVE Findings"},
    "sec.netz_auffaell": {"de": "Netz-Auffälligkeiten", "en": "Network Findings"},
    "sec.bestaetigt": {"de": "Bereits bestätigt", "en": "Acknowledged"},
    "sec.krit": {"de": "kritisch", "en": "critical"},
    "sec.auffaell": {"de": "auffällig", "en": "notable"},
    "sec.ohne_befund": {"de": "ohne Befund", "en": "no findings"},
    # Gauge
    "gauge.von100": {"de": "von 100", "en": "out of 100"},
    # Donut (Sicherheitsbericht)
    "donut.geraete": {"de": "Geräte", "en": "Devices"},
    # Bestandsbericht
    "inv.kennzahlen": {"de": "Bestands-Kennzahlen", "en": "Inventory Metrics"},
    "inv.geraete_verteilung": {"de": "Geräte-Verteilung", "en": "Device Distribution"},
    "inv.nach_hersteller": {"de": "Verteilung nach Hersteller", "en": "Distribution by Vendor"},
    "inv.nach_kategorie": {"de": "Verteilung nach Kategorie", "en": "Distribution by Category"},
    "inv.geraete": {"de": "Geräte", "en": "Devices"},
    "inv.archiviert": {"de": "Archivierte Geräte", "en": "Archived Devices"},
    "inv.bekannt_unbekannt": {"de": "Bekannt / unbekannt", "en": "Known / Unknown"},
    "inv.vertrauen": {"de": "Vertrauensstatus", "en": "Trust Status"},
    "inv.bekannt": {"de": "Bekannt", "en": "Known"},
    "inv.unbekannt": {"de": "Unbekannt", "en": "Unknown"},
    "inv.vertraut": {"de": "Vertraut", "en": "Trusted"},
    "inv.beobachtet": {"de": "Beobachtet", "en": "Watched"},
    "inv.neutral": {"de": "Neutral", "en": "Neutral"},
    "inv.gesamt": {"de": "Gesamt", "en": "Total"},
    "inv.aktiv24h": {"de": "Aktiv (24h)", "en": "Active (24h)"},
    "inv.keine_eintraege": {"de": "Keine Einträge.", "en": "No entries."},
    # Anzeige fuer die maschinellen Leer-Marker der beiden Verteilungen. Der Marker selbst
    # (``__vendor_unknown__``/``__category_unknown__``) darf nie im PDF landen.
    "inv.ohne_hersteller": {
        "de": "Kein Hersteller ermittelt",
        "en": "No vendor identified",
    },
    "inv.ohne_kategorie": {
        "de": "Keine Kategorie ermittelt",
        "en": "No category identified",
    },
    # CVE-Bericht
    "cve.kennzahlen": {"de": "CVE-Kennzahlen", "en": "CVE Metrics"},
    "cve.schweregrad": {"de": "Schweregrad-Verteilung", "en": "Severity Distribution"},
    "cve.betroffene": {"de": "Betroffene Geräte", "en": "Affected Devices"},
    "cve.muster": {"de": "Muster nach Dienst", "en": "Patterns by Service"},
    "cve.befundliste": {"de": "Vollständige Befundliste", "en": "Full Finding List"},
    "cve.aktive": {"de": "Aktive Befunde", "en": "Active Findings"},
    "cve.neu24h": {"de": "Neu (24h)", "en": "New (24h)"},
    "cve.betroffene_geraete": {"de": "Betroffene Geräte", "en": "Affected Devices"},
    "cve.quittiert": {"de": "Quittiert", "en": "Acknowledged"},
    "cve.hoechste_sev": {"de": "Höchste Severity", "en": "Highest Severity"},
    "cve.abdeckung": {"de": "Abdeckung", "en": "Coverage"},
    "cve.aelteste": {"de": "Älteste Veröffentlichung", "en": "Oldest Published"},
    "cve.neu_hinweis": {
        "de": "Neu = erstmals innerhalb der letzten 24 Stunden gesehen.",
        "en": "New = first seen within the last 24 hours.",
    },
    "cve.befunde": {"de": "Befunde", "en": "Findings"},
    # Aussenkontakte-Bericht
    "out.kennzahlen": {"de": "Kennzahlen", "en": "Metrics"},
    "out.nach_land": {"de": "Verteilung nach Land", "en": "Distribution by Country"},
    "out.nach_betreiber": {"de": "Verteilung nach Betreiber", "en": "Distribution by Operator"},
    "out.detail": {"de": "Außenkontakte im Detail", "en": "External Contacts in Detail"},
    "out.gegenstellen": {"de": "Gegenstellen", "en": "Peers"},
    "out.verbindungen": {"de": "Verbindungen", "en": "Connections"},
    "out.laender": {"de": "Länder", "en": "Countries"},
    "out.betreiber": {"de": "Betreiber", "en": "Operators"},
    "out.auffaellig": {"de": "Auffällig", "en": "Flagged"},
    "out.tracker": {"de": "Tracker", "en": "Trackers"},
    "out.bedrohung": {"de": "Bedrohung", "en": "Threat"},
    "out.lokal": {"de": "Lokal", "en": "Local"},
    # DNS-Waechter-Bericht
    "dns.kennzahlen": {"de": "Kennzahlen", "en": "Metrics"},
    "dns.nach_kategorie": {"de": "Verteilung nach Kategorie", "en": "Distribution by Category"},
    "dns.nach_programm": {"de": "Verteilung nach Programm", "en": "Distribution by Application"},
    "dns.kontakte": {"de": "DNS-relevante Außenkontakte", "en": "DNS-relevant External Contacts"},
    "dns.gesamt": {"de": "Kontakte gesamt", "en": "Total Contacts"},
    "dns.aktiv": {"de": "Aktiv", "en": "Active"},
    "dns.quittiert": {"de": "Quittiert", "en": "Acknowledged"},
    "dns.erwartet": {"de": "Erwartungsgemäß", "en": "As Expected"},
    "dns.offen": {"de": "Offen", "en": "Open"},
    "dns.doh": {"de": "Möglicher DoH", "en": "Possible DoH"},
    "dns.flagged": {"de": "Auffällig", "en": "Flagged"},
    # DNS-Bypass-Bericht
    "bypass.kennzahlen": {"de": "Kennzahlen", "en": "Metrics"},
    "bypass.verteilung": {"de": "Verteilung nach Ziel", "en": "Distribution by Target"},
    "bypass.detail": {"de": "Umgehungen im Detail", "en": "Bypasses in Detail"},
    "bypass.anfragen": {"de": "Anfragen gesamt", "en": "Total Queries"},
    "bypass.umgehungen": {"de": "Umgehungen", "en": "Bypasses"},
    "bypass.erwartet": {"de": "Erwartungsgemäß", "en": "As Expected"},
    "bypass.geraete": {"de": "Geräte", "en": "Devices"},
    # Verhaltensprofil-Bericht
    "beh.kennzahlen": {"de": "Kennzahlen", "en": "Metrics"},
    "beh.tagesband": {"de": "Tagesverlauf", "en": "Daily Pattern"},
    "beh.heatmap": {"de": "Wochenmuster", "en": "Weekly Pattern"},
    "beh.geraete": {"de": "Geräte-Übersicht", "en": "Device Overview"},
    "beh.keine_daten": {
        "de": "Noch keine ausreichenden Daten für ein Verhaltensprofil.",
        "en": "Not enough data yet for a behavior profile.",
    },
    "beh.keine_geraete": {
        "de": "Keine wiederkehrenden Aufgaben mit Verhaltensdaten.",
        "en": "No recurring tasks with behavior data.",
    },
    # Seitenangabe (Fusszeile)
    "page.seite": {"de": "Seite", "en": "Page"},
}


def _ui(key: str, lang: str) -> str:
    entry = _UI_STRINGS.get(key)
    if entry is None:
        return key
    return entry.get(lang) or entry.get("de") or key


# Maschinelle Leer-Marker der beiden Bestands-Verteilungen. SPIEGEL von
# ``EMPTY_VENDOR_MARKER``/``EMPTY_CATEGORY_MARKER`` aus
# ``application.reporting.inventory_report`` -- der Adapter darf ``application`` aber NICHT
# importieren (import-linter), darum hier als lokale Konstanten gefuehrt (Muster
# ``PORT_COLUMNS``).
_EMPTY_VENDOR_MARKER = "__vendor_unknown__"
_EMPTY_CATEGORY_MARKER = "__category_unknown__"

# Marker -> _UI_STRINGS-Schluessel. Trennt die beiden Verteilungen, die
# unterschiedliche Texte brauchen.
_MARKER_UI_KEYS = {
    _EMPTY_VENDOR_MARKER: "inv.ohne_hersteller",
    _EMPTY_CATEGORY_MARKER: "inv.ohne_kategorie",
}


def _resolve_distribution_marker(
    rows: tuple[tuple[str, str], ...], marker: str, lang: str
) -> tuple[tuple[str, str], ...]:
    """Ersetzt den maschinellen Leer-Marker einer Verteilung durch seinen Anzeigetext.

    Nur der EINE zur Verteilung passende Marker wird aufgeloest (Hersteller bzw.
    Kategorie); alle anderen Labels bleiben unveraendert. Reihenfolge und ``count``
    werden nicht angefasst -- die Sortierung entsteht in ``application``.
    """
    ui_key = _MARKER_UI_KEYS[marker]
    return tuple((_ui(ui_key, lang) if label == marker else label, count) for label, count in rows)


# Spaltenueberschriften der vier Tabellen-Rubriken. SPIEGEL der ``*_COLUMNS`` aus
# ``application.reporting.security_pdf_model`` -- der Adapter darf ``application`` aber NICHT
# importieren (import-linter), darum hier als lokale Anzeige-Konstanten gefuehrt. Sie sind
# der Vertrag fuer die Spalten-Reihenfolge der vom Modell gelieferten Zeilen.
PORT_COLUMNS: tuple[str, ...] = ("Gerät", "Ports", "Schwere", "Grund")
CVE_COLUMNS: tuple[str, ...] = ("Gerät", "CVE", "CVSS", "Dienst", "Beschreibung")
NET_COLUMNS: tuple[str, ...] = ("Art", "Gerät", "Schwere", "Beschreibung")
ACK_COLUMNS: tuple[str, ...] = ("Art", "Gerät", "Detail")

# Spalten-Spiegel der beiden Bestandsbericht-Tabellen. SPIEGEL der ``*_COLUMNS`` aus
# ``application.reporting.inventory_pdf_model`` -- der Adapter darf ``application`` NICHT
# importieren (import-linter), darum hier als lokale Anzeige-Konstanten gefuehrt. Die
# Schreibweise ("Gerät" mit Umlaut) ist WOERTLICH aus inventory_pdf_model.py uebernommen, damit
# Modell, Renderer und die Spaltenbreiten-Heuristik denselben Vertrag teilen.
INVENTORY_COLUMNS: tuple[str, ...] = (
    "Gerät",
    "Hersteller",
    "Letzte IP",
    "Erste Sichtung",
    "Letzte Sichtung",
    "Gesehen",
    "Kategorie",
    "Status",
)
ARCHIVED_COLUMNS: tuple[str, ...] = (
    "Gerät",
    "Hersteller",
    "Letzte IP",
    "Letzte Sichtung",
    "Status",
)

# Spalten-Spiegel der drei CVE-Bericht-Tabellen. SPIEGEL der ``*_COLUMNS`` aus
# ``application.reporting.cve_pdf_model`` -- der Adapter darf ``application`` NICHT importieren
# (import-linter), darum hier als lokale Anzeige-Konstanten gefuehrt (Muster INVENTORY_COLUMNS).
# Die Schreibweise (Umlaute) ist WOERTLICH aus cve_pdf_model.py uebernommen, damit Modell,
# Renderer und die Spaltenbreiten-Heuristik denselben Vertrag teilen.
_CVE_DEVICE_COLUMNS: tuple[str, ...] = (
    "Gerät",
    "Befunde",
    "Höchste Severity",
    "Höchster CVSS",
    "Dienste",
)
_CVE_SERVICE_COLUMNS: tuple[str, ...] = (
    "Dienst",
    "Befunde",
    "Geräte",
    "Höchste Severity",
    "Höchster CVSS",
    "Älteste Veröffentlichung",
)
_CVE_FINDING_COLUMNS: tuple[str, ...] = (
    "Gerät",
    "CVE",
    "Severity",
    "CVSS",
    "Dienst",
    "Port",
    "Erstmals gesehen",
    "Status",
)
# Spalten der GRUPPIERTEN Befundliste (Sektion 4): das Geraet steht im Host-Kopf, die CVE-Zeilen
# tragen es NICHT mehr. Lokal/zeichengleich zu application FINDING_GROUP_COLUMNS (Regel: infra
# kennt application NICHT -> kein Import, Muster _CVE_FINDING_COLUMNS).
_CVE_FINDING_GROUP_COLUMNS: tuple[str, ...] = (
    "CVE",
    "Severity",
    "CVSS",
    "Dienst",
    "Port",
    "Erstmals gesehen",
    "Status",
)

# Spalten-Spiegel der drei Aussenkontakte-Bericht-Tabellen. SPIEGEL der ``*_COLUMNS`` aus
# ``application.reporting.outbound_pdf_model`` -- der Adapter darf ``application`` NICHT
# importieren (import-linter), darum hier als lokale Anzeige-Konstanten gefuehrt (Muster
# _CVE_*_COLUMNS). Die Schreibweise (Umlaute) ist WOERTLICH aus outbound_pdf_model.py
# uebernommen, damit Modell, Renderer und die Spaltenbreiten-Heuristik denselben Vertrag teilen.
_OUTBOUND_CONTACT_COLUMNS: tuple[str, ...] = (
    "Gegenstelle",
    "Name",
    "Land",
    "Betreiber",
    "Kontakte",
    "Bewertung",
)
_OUTBOUND_COUNTRY_COLUMNS: tuple[str, ...] = ("Land", "Gegenstellen")
_OUTBOUND_OPERATOR_COLUMNS: tuple[str, ...] = ("Betreiber", "Gegenstellen")

# Spalten-Spiegel der drei DNS-Waechter-Bericht-Tabellen. SPIEGEL der ``DNS_*_COLUMNS`` aus
# ``application.reporting.dns_watch_pdf_model`` -- der Adapter darf ``application`` NICHT
# importieren (import-linter), darum hier als lokale Anzeige-Konstanten gefuehrt (Muster
# _OUTBOUND_*_COLUMNS). Die Schreibweise (Umlaute) ist WOERTLICH aus dns_watch_pdf_model.py
# uebernommen, damit Modell, Renderer und die Spaltenbreiten-Heuristik denselben Vertrag teilen.
DNS_CATEGORY_COLUMNS: tuple[str, ...] = ("Kategorie", "Kontakte")
DNS_APP_COLUMNS: tuple[str, ...] = ("Programm", "Kontakte")
DNS_CONTACT_COLUMNS: tuple[str, ...] = (
    "Kategorie",
    "Gegenstelle",
    "Name",
    "Programm",
    "Kontakte",
    "Status",
)

# Spalten-Spiegel der DNS-Umgehungs-Detailtabelle. SPIEGEL von ``DNS_BYPASS_ROW_COLUMNS``
# aus ``application.reporting.dns_bypass_pdf_model`` -- der Adapter darf ``application`` NICHT
# importieren (import-linter), darum hier als lokale Anzeige-Konstante gefuehrt (Muster
# DNS_*_COLUMNS). Die Schreibweise (Umlaute) ist WOERTLICH aus dns_bypass_pdf_model.py
# uebernommen, damit Modell, Renderer und die Spaltenbreiten-Heuristik denselben Vertrag teilen.
# (Die fruehere Resolver-Verteilungs-Tabelle ist entfernt -- die Verteilung zeigt die Grafik.)
DNS_BYPASS_ROW_COLUMNS: tuple[str, ...] = (
    "Gerät",
    "Quell-IP",
    "Ziel-Resolver",
    "DoH",
    "Anfragen",
    "Abgefragte Namen",
)


class SecurityPdfModelLike(Protocol):
    """Struktureller Vertrag des Sicherheitsbericht-Modells (duck-typing, KEIN Import).

    ``infrastructure`` darf ``application`` NICHT importieren (import-linter-Contract
    "infrastructure kennt nicht application/api"). Das reiche ``SecurityPdfModel`` lebt aber
    in ``application/reporting``. Darum nimmt der Adapter es STRUKTURELL ueber dieses
    ``Protocol`` entgegen (genau die Felder, die er rendert) -- mypy prueft die Form, ohne
    dass eine Import-Kante in den application-Ring entsteht. Das echte Modell erfuellt das
    Protokoll automatisch (gleiche Feldnamen/Typen).

    Die Felder sind als READ-ONLY ``@property`` deklariert (nicht als settable Attribute):
    ``SecurityPdfModel`` ist ein FROZEN dataclass mit nur lesbaren Feldern -- ein Protocol mit
    settable Attributen waere damit unvertraeglich (mypy: "expected settable variable, got
    read-only attribute"). Read-only Properties decken die frozen-Felder strukturell ab.
    """

    @property
    def title(self) -> str: ...
    @property
    def generated_at_text(self) -> str: ...
    @property
    def footer_left(self) -> str: ...
    @property
    def achse_b_fussnote(self) -> str: ...
    @property
    def score_value(self) -> int: ...
    @property
    def score_level(self) -> str: ...
    @property
    def score_level_label(self) -> str: ...
    @property
    def score_einordnung(self) -> str: ...
    @property
    def critical_devices(self) -> int: ...
    @property
    def notable_devices(self) -> int: ...
    @property
    def clean_devices(self) -> int: ...
    @property
    def device_count(self) -> int: ...
    @property
    def total_burden(self) -> float: ...
    @property
    def einleitung(self) -> str: ...
    @property
    def rogue_hinweis(self) -> str: ...
    @property
    def contributions(self) -> tuple[tuple[str, str, str], ...]: ...
    @property
    def geraete_balken(self) -> tuple[tuple[str, int, int], ...]: ...
    @property
    def port_rows(self) -> tuple[tuple[str, ...], ...]: ...
    @property
    def cve_rows(self) -> tuple[tuple[str, ...], ...]: ...
    @property
    def net_rows(self) -> tuple[tuple[str, ...], ...]: ...
    @property
    def acknowledged_rows(self) -> tuple[tuple[str, ...], ...]: ...


class ManualPdfSectionLike(Protocol):
    """Struktureller Vertrag EINES Handbuch-Abschnitts (duck-typing, KEIN Import).

    Read-only Properties (das echte ``ManualPdfSection`` ist ein frozen dataclass -- siehe
    Begruendung bei ``SecurityPdfModelLike``). Erfasst genau die drei Felder, die der Adapter
    rendert: ``category_label`` (Kategorie-Ueberschrift), ``heading`` (Abschnitts-Titel) und
    ``paragraphs`` (die fertigen Fliesstext-Absaetze).
    """

    @property
    def category_label(self) -> str: ...
    @property
    def heading(self) -> str: ...
    @property
    def paragraphs(self) -> tuple[str, ...]: ...


class ManualPdfModelLike(Protocol):
    """Struktureller Vertrag des Handbuch-Modells (duck-typing, KEIN application-Import).

    Wie ``SecurityPdfModelLike``: ``infrastructure`` darf ``application`` NICHT importieren
    (import-linter), das reiche ``ManualPdfModel`` lebt aber in ``application/reporting``.
    Darum nimmt der Adapter es STRUKTURELL ueber dieses ``Protocol`` entgegen. Read-only
    Properties decken die frozen-Felder ab; ``sections`` ist ein Tupel von
    ``ManualPdfSectionLike`` (zweites kleines Protocol oben).
    """

    @property
    def title(self) -> str: ...
    @property
    def generated_at_text(self) -> str: ...
    @property
    def footer_left(self) -> str: ...
    @property
    def intro(self) -> str: ...
    @property
    def sections(self) -> tuple[ManualPdfSectionLike, ...]: ...


class InventoryPdfModelLike(Protocol):
    """Struktureller Vertrag des Bestandsbericht-Modells (duck-typing, KEIN application-Import).

    Wie ``SecurityPdfModelLike``: ``infrastructure`` darf ``application`` NICHT importieren
    (import-linter), das reiche ``InventoryPdfModel`` lebt aber in ``application/reporting``.
    Darum nimmt der Adapter es STRUKTURELL ueber dieses ``Protocol`` entgegen -- genau die
    Felder, die er rendert. Read-only Properties decken die frozen-Felder ab (siehe Begruendung
    bei ``SecurityPdfModelLike``). Das echte ``InventoryPdfModel`` erfuellt das Protokoll
    automatisch (gleiche Feldnamen/Typen).
    """

    @property
    def title(self) -> str: ...
    @property
    def generated_at_text(self) -> str: ...
    @property
    def footer_left(self) -> str: ...
    @property
    def achse_b_fussnote(self) -> str: ...
    @property
    def einleitung(self) -> str: ...
    @property
    def total(self) -> int: ...
    @property
    def known(self) -> int: ...
    @property
    def unknown(self) -> int: ...
    @property
    def active_24h(self) -> int: ...
    @property
    def trusted(self) -> int: ...
    @property
    def watch(self) -> int: ...
    @property
    def neutral(self) -> int: ...
    @property
    def vendor_rows(self) -> tuple[tuple[str, str], ...]: ...
    @property
    def category_rows(self) -> tuple[tuple[str, str], ...]: ...
    @property
    def device_rows(self) -> tuple[tuple[str, ...], ...]: ...
    @property
    def archived_rows(self) -> tuple[tuple[str, ...], ...]: ...


class _HostGroupBlockLike(Protocol):
    """Struktureller Vertrag eines Host-Blocks der gruppierten Befundliste (duck-typing).

    Deckt genau die zwei Felder ab, die der Render-Pfad liest: die fertige Kopfzeile und die
    CVE-Zeilen in ``_CVE_FINDING_GROUP_COLUMNS``-Reihenfolge. KEIN application-Import -- das echte
    ``HostGroupBlock`` erfuellt das Protokoll automatisch (gleiche Feldnamen/Typen).
    """

    @property
    def header(self) -> str: ...
    @property
    def rows(self) -> tuple[tuple[str, ...], ...]: ...


class CvePdfModelLike(Protocol):
    """Struktureller Vertrag des CVE-Bericht-Modells (duck-typing, KEIN application-Import).

    Wie ``InventoryPdfModelLike``: ``infrastructure`` darf ``application`` NICHT importieren
    (import-linter), das reiche ``CvePdfModel`` lebt aber in ``application/reporting``. Darum
    nimmt der Adapter es STRUKTURELL ueber dieses ``Protocol`` entgegen -- genau die Felder, die
    er rendert. Read-only Properties decken die frozen-Felder ab. Das echte ``CvePdfModel``
    erfuellt das Protokoll automatisch (gleiche Feldnamen/Typen).
    """

    @property
    def title(self) -> str: ...
    @property
    def generated_at_text(self) -> str: ...
    @property
    def footer_left(self) -> str: ...
    @property
    def achse_b_fussnote(self) -> str: ...
    @property
    def einleitung(self) -> str: ...
    @property
    def active_total(self) -> int: ...
    @property
    def acknowledged_total(self) -> int: ...
    @property
    def new_total(self) -> int: ...
    @property
    def affected_devices(self) -> int: ...
    @property
    def hosts_total(self) -> int: ...
    @property
    def hosts_checked(self) -> int: ...
    @property
    def coverage_text(self) -> str: ...
    @property
    def highest_severity(self) -> str: ...
    @property
    def oldest_published_text(self) -> str: ...
    @property
    def severity_rows(self) -> tuple[tuple[str, str], ...]: ...
    @property
    def severity_labels(self) -> tuple[tuple[str, str], ...]: ...
    @property
    def device_rows(self) -> tuple[tuple[str, ...], ...]: ...
    @property
    def service_rows(self) -> tuple[tuple[str, ...], ...]: ...
    @property
    def finding_rows(self) -> tuple[tuple[str, ...], ...]: ...
    @property
    def host_groups(self) -> tuple[_HostGroupBlockLike, ...]: ...


class OutboundPdfModelLike(Protocol):
    """Struktureller Vertrag des Aussenkontakte-Modells (duck-typing, KEIN application-Import).

    Wie ``CvePdfModelLike``: ``infrastructure`` darf ``application`` NICHT importieren
    (import-linter), das reiche ``OutboundPdfModel`` lebt aber in ``application/reporting``. Darum
    nimmt der Adapter es STRUKTURELL ueber dieses ``Protocol`` entgegen -- genau die Felder, die
    er rendert. Read-only Properties decken die frozen-Felder ab (siehe Begruendung bei
    ``SecurityPdfModelLike``). Das echte ``OutboundPdfModel`` erfuellt das Protokoll automatisch
    (gleiche Feldnamen/Typen).
    """

    @property
    def title(self) -> str: ...
    @property
    def generated_at_text(self) -> str: ...
    @property
    def footer_left(self) -> str: ...
    @property
    def achse_b_fussnote(self) -> str: ...
    @property
    def einleitung(self) -> str: ...
    @property
    def recording_label(self) -> str: ...
    @property
    def scope_text(self) -> str: ...
    @property
    def contacts_total(self) -> int: ...
    @property
    def remote_total(self) -> int: ...
    @property
    def local_total(self) -> int: ...
    @property
    def connection_total(self) -> int: ...
    @property
    def countries_total(self) -> int: ...
    @property
    def operators_total(self) -> int: ...
    @property
    def tracker_contacts(self) -> int: ...
    @property
    def threat_contacts(self) -> int: ...
    @property
    def flagged_contacts(self) -> int: ...
    @property
    def country_rows(self) -> tuple[tuple[str, ...], ...]: ...
    @property
    def operator_rows(self) -> tuple[tuple[str, ...], ...]: ...
    @property
    def contact_rows(self) -> tuple[tuple[str, ...], ...]: ...


class DnsWatchPdfModelLike(Protocol):
    """Struktureller Vertrag des DNS-Waechter-Modells (duck-typing, KEIN application-Import).

    Wie ``OutboundPdfModelLike``: ``infrastructure`` darf ``application`` NICHT importieren
    (import-linter), das reiche ``DnsWatchPdfModel`` lebt aber in ``application/reporting``. Darum
    nimmt der Adapter es STRUKTURELL ueber dieses ``Protocol`` entgegen -- genau die Felder, die
    er rendert. Read-only Properties decken die frozen-Felder ab (siehe Begruendung bei
    ``SecurityPdfModelLike``). Das echte ``DnsWatchPdfModel`` erfuellt das Protokoll automatisch
    (gleiche Feldnamen/Typen).
    """

    @property
    def title(self) -> str: ...
    @property
    def generated_at_text(self) -> str: ...
    @property
    def footer_left(self) -> str: ...
    @property
    def achse_b_fussnote(self) -> str: ...
    @property
    def einleitung(self) -> str: ...
    @property
    def scope_text(self) -> str: ...
    @property
    def expected_text(self) -> str: ...
    @property
    def doh_text(self) -> str: ...
    @property
    def contacts_total(self) -> int: ...
    @property
    def active_total(self) -> int: ...
    @property
    def acknowledged_total(self) -> int: ...
    @property
    def expected_active(self) -> int: ...
    @property
    def open_active(self) -> int: ...
    @property
    def doh_active(self) -> int: ...
    @property
    def flagged_active(self) -> int: ...
    @property
    def category_rows(self) -> tuple[tuple[str, ...], ...]: ...
    @property
    def app_rows(self) -> tuple[tuple[str, ...], ...]: ...
    @property
    def contact_rows(self) -> tuple[tuple[str, ...], ...]: ...


class DnsBypassPdfModelLike(Protocol):
    """Struktureller Vertrag des DNS-Umgehungs-Modells (duck-typing, KEIN application-Import).

    Wie ``DnsWatchPdfModelLike``: ``infrastructure`` darf ``application`` NICHT importieren
    (import-linter), das reiche ``DnsBypassPdfModel`` lebt aber in ``application/reporting``.
    Darum nimmt der Adapter es STRUKTURELL ueber dieses ``Protocol`` entgegen -- genau die
    Felder, die er rendert. Read-only Properties decken die frozen-Felder ab (siehe Begruendung
    bei ``SecurityPdfModelLike``). Das echte ``DnsBypassPdfModel`` erfuellt das Protokoll
    automatisch (gleiche Feldnamen/Typen).
    """

    @property
    def title(self) -> str: ...
    @property
    def generated_at_text(self) -> str: ...
    @property
    def footer_left(self) -> str: ...
    @property
    def achse_b_fussnote(self) -> str: ...
    @property
    def einleitung(self) -> str: ...
    @property
    def recording_label(self) -> str: ...
    @property
    def scope_text(self) -> str: ...
    @property
    def expected_text(self) -> str: ...
    @property
    def queries_total(self) -> int: ...
    @property
    def bypass_total(self) -> int: ...
    @property
    def expected_total(self) -> int: ...
    @property
    def bypass_devices(self) -> int: ...
    @property
    def resolver_distribution(self) -> tuple[tuple[str, str, int], ...]: ...
    @property
    def bypass_rows(self) -> tuple[tuple[str, ...], ...]: ...


class BehaviorPdfModelLike(Protocol):
    """Struktureller Vertrag des Verhaltensprofil-Modells (duck-typing, KEIN application-Import).

    Wie ``DnsBypassPdfModelLike``: ``infrastructure`` darf ``application`` NICHT importieren
    (import-linter), das reiche ``BehaviorPdfModel`` lebt aber in ``application/reporting``.
    Darum nimmt der Adapter es STRUKTURELL ueber dieses ``Protocol`` entgegen -- genau die
    Felder, die er rendert. Read-only Properties decken die frozen-Felder ab (siehe Begruendung
    bei ``SecurityPdfModelLike``). Das echte ``BehaviorPdfModel`` erfuellt das Protokoll
    automatisch (gleiche Feldnamen/Typen).
    """

    @property
    def title(self) -> str: ...
    @property
    def generated_at_text(self) -> str: ...
    @property
    def footer_left(self) -> str: ...
    @property
    def achse_b_fussnote(self) -> str: ...
    @property
    def einleitung(self) -> str: ...
    @property
    def scope(self) -> str: ...
    @property
    def scope_text(self) -> str: ...
    @property
    def single_kennzahlen(self) -> tuple[tuple[str, str], ...]: ...
    @property
    def day_band(self) -> tuple[tuple[int, int, bool], ...]: ...
    @property
    def week_heatmap(self) -> tuple[tuple[int, int, int, bool], ...]: ...
    @property
    def slot_minutes(self) -> int: ...
    @property
    def weekday_labels(self) -> tuple[str, ...]: ...
    @property
    def entry_rows(self) -> tuple[tuple[str, ...], ...]: ...


class ReportlabRenderer:
    """Rendert ein ``PdfReportModel`` zu PDF-Bytes (``ReportRenderer``) -- schlicht, robust.

    Zustandslos: pro Aufruf ein frischer ``BytesIO`` + ``SimpleDocTemplate``. Querformat
    (A4 landscape), damit die Kernfelder-Tabelle mit den offenen Ports nicht zu eng wird.
    KEINE Domaenen-Logik -- nur das Rendern der vorgegebenen Struktur (Kopf + Tabelle).
    """

    def render_pdf(self, model: PdfReportModel) -> bytes:
        """Rendert ``model`` (Kopf + Tabelle) zu fertigen PDF-Bytes -- synchron, kein I/O.

        Baut die Story (ein paar Kopf-Paragraphs aus Titel + den ``meta``-Paaren, dann die
        Tabelle aus ``columns``/``rows``) und laesst reportlab sie in einen in-memory
        ``BytesIO`` setzen. Ein Bericht ohne Datensaetze (leere ``rows``) ergibt eine Tabelle
        mit nur der Kopfzeile -- ein gueltiger, druckbarer Bericht (kein Sonderfall). Liefert
        die Bytes; ein valides PDF beginnt mit dem Magic-Header ``%PDF``.
        """
        buffer = io.BytesIO()
        document = SimpleDocTemplate(
            buffer,
            pagesize=landscape(A4),
            leftMargin=15 * mm,
            rightMargin=15 * mm,
            topMargin=15 * mm,
            bottomMargin=15 * mm,
            title=model.title,
        )
        styles = getSampleStyleSheet()
        story: list[object] = [Paragraph(model.title, styles["Title"])]
        # Kopf-Metadaten (ADR 0015, Block 2: generalisiert): die generischen (Label, Wert)-
        # Paare des Modells als schlichte Zeilen unter dem Titel, in der vorgegebenen
        # Reihenfolge. KEINE hartkodierten Labels mehr -- jeder Berichts-Builder liefert seine
        # eigenen Paare (Scan-Bericht: Scan-Zeitpunkt/Netz/Anzahl; Analyse: Erzeugt am/Anzahl).
        for label, value in model.meta:
            story.append(Paragraph(f"<b>{label}:</b> {value}", styles["Normal"]))
        story.append(Spacer(1, 6 * mm))
        # Die Tabelle: Kopfzeile (``columns``) + je Host eine Datenzeile (``rows``). Eine
        # leere Host-Liste ergibt eine Tabelle mit nur der Kopfzeile (gueltig, druckbar).
        table_data = [list(model.columns)] + [list(row) for row in model.rows]
        table = Table(table_data, repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [colors.white, colors.HexColor("#f2f2f2")],
                    ),
                ]
            )
        )
        story.append(table)
        document.build(story)
        return buffer.getvalue()

    # ── Sicherheitsbericht (Etappe 4a): eigener, reicherer Render-Pfad ───────
    #
    # NEUE Methode neben render_pdf -- die obige Methode + ihr PdfReportModel bleiben
    # UNANGETASTET (Scan-/Analyse-Export nutzt sie weiter). Dieser Pfad rendert das reiche
    # SecurityPdfModel (Grafiken + mehrere Tabellen + durchgaengige Kopfzeile). Zustandslos
    # wie der Bestand: ein frischer BytesIO + SimpleDocTemplate pro Aufruf.

    def render_security_report_pdf(self, model: SecurityPdfModelLike, lang: str = "de") -> bytes:
        """Rendert das ``SecurityPdfModel`` zum vollstaendigen Sicherheitsbericht-PDF (A4 hoch).

        Layout (Auftrag): durchgaengige Kopf-/Fusszeile je Seite (onFirstPage UND onLaterPages
        ueber dieselbe Funktion), dann die Story -- Einleitung, Score-Cockpit (Gauge), drei
        Kennzahlen, Donut, Geraete-Balken, danach je eigene Seite die vier Tabellen-Rubriken
        (Ports/CVE/Netz/bestaetigt), zuletzt die Achse-B-Fussnote (+ optional Rogue-Hinweis).

        Robust: leere Tabellen -> "Keine Eintraege." statt leerer ``Table``; die bestaetigt-
        Rubrik wird bei leerer Liste ganz weggelassen. KEINE Uhr, KEINE Rechnung -- alle Texte/
        Zahlen kommen fertig aus dem Modell. Liefert valide PDF-Bytes (Magic-Header ``%PDF``).
        """
        buffer = io.BytesIO()
        document = SimpleDocTemplate(
            buffer,
            pagesize=A4,  # Hochformat (Auftrag)
            leftMargin=18 * mm,
            rightMargin=18 * mm,
            topMargin=32 * mm,  # Platz fuer die durchgaengige Kopfzeile
            bottomMargin=20 * mm,  # Platz fuer die Fusszeile
            title=model.title,
        )

        story: list[Flowable] = []
        styles = self._security_styles()

        # ── Einleitung (Achse-B-Haltung, fertiger Text aus dem Modell) ──
        story.append(Paragraph(model.title, styles["h_title"]))
        story.append(Paragraph(model.generated_at_text, styles["sub"]))
        story.append(Spacer(1, 4 * mm))
        if model.einleitung:
            story.append(Paragraph(model.einleitung, styles["body"]))
            story.append(Spacer(1, 6 * mm))

        # ── Score-Cockpit: Gauge (Halbkreis) + Einordnung ──
        story.append(Paragraph(_ui("sec.netz_gesundheit", lang), styles["h_section"]))
        story.append(
            _gauge_drawing(
                model.score_value,
                model.score_level_label,
                _LEVEL_COLORS.get(model.score_level, _CRIT),
                lang=lang,
            )
        )
        if model.score_einordnung:
            story.append(Paragraph(model.score_einordnung, styles["body_center"]))
        story.append(Spacer(1, 6 * mm))

        # ── Drei Kennzahlen (kritisch / auffaellig / ohne Befund) ──
        story.append(self._kennzahlen_table(model, lang))
        story.append(Spacer(1, 6 * mm))

        # Seitenumbruch VOR der Geraete-Verteilung: Donut + Balken beginnen luftig oben auf
        # einer neuen Seite, statt unten an Seite 1 zu kleben.
        story.append(PageBreak())

        # ── Donut: Anteile critical / notable / clean, Mitte device_count ──
        # Ueberschrift UND Donut zusammenhalten (KeepTogether), damit der Seitenumbruch nicht
        # zwischen Ueberschrift und Ring faellt (analog zum Balken-Block darunter).
        donut_block: list[Flowable] = [
            Paragraph(_ui("sec.geraete_verteilung", lang), styles["h_section"]),
            _donut_drawing(
                model.critical_devices,
                model.notable_devices,
                model.clean_devices,
                model.device_count,
                lang=lang,
            ),
        ]
        story.append(KeepTogether(donut_block))
        story.append(Spacer(1, 6 * mm))

        # ── Geraete-Balken: VOLLSTAENDIGE Liste (kein Top-N) ──
        # Ueberschrift UND Balken zusammenhalten (KeepTogether), damit der Seitenumbruch nicht
        # zwischen Ueberschrift und Balken faellt (Ueberschrift sonst unten, Balken erst naechste
        # Seite).
        balken_block: list[Flowable] = [
            Paragraph(_ui("sec.auffaelligkeiten", lang), styles["h_section"])
        ]
        if model.geraete_balken:
            balken_block.append(_geraete_balken_drawing(model.geraete_balken, lang=lang))
        else:
            balken_block.append(Paragraph(_ui("inv.keine_eintraege", lang), styles["body"]))
        story.append(KeepTogether(balken_block))

        # ── Tabellen-Rubriken: je eigene Seite (PageBreak davor) ──
        story.append(PageBreak())
        self._append_table_section(
            story, styles, _ui("sec.ports", lang), PORT_COLUMNS, model.port_rows, lang
        )

        story.append(PageBreak())
        self._append_table_section(
            story, styles, _ui("sec.cve", lang), CVE_COLUMNS, model.cve_rows, lang
        )

        story.append(PageBreak())
        self._append_table_section(
            story, styles, _ui("sec.netz_auffaell", lang), NET_COLUMNS, model.net_rows, lang
        )

        # Rubrik 4 nur, wenn nicht leer (Auftrag: sonst weglassen).
        if model.acknowledged_rows:
            story.append(PageBreak())
            self._append_table_section(
                story,
                styles,
                _ui("sec.bestaetigt", lang),
                ACK_COLUMNS,
                model.acknowledged_rows,
                lang,
            )

        # ── Achse-B-Fussnote (invariant) + optionaler Rogue-Hinweis ──
        story.append(Spacer(1, 8 * mm))
        story.append(HRFlowable(width="100%", thickness=0.6, color=_LINE))
        story.append(Spacer(1, 2 * mm))
        story.append(
            Paragraph(
                model.achse_b_fussnote,
                styles["footnote"],
            )
        )
        if model.rogue_hinweis:
            story.append(Paragraph(model.rogue_hinweis, styles["footnote"]))

        document.build(
            story,
            onFirstPage=lambda canvas, doc: _draw_header_footer(canvas, doc, model, lang),
            onLaterPages=lambda canvas, doc: _draw_header_footer(canvas, doc, model, lang),
        )
        return buffer.getvalue()

    # ── Helfer des Sicherheitsbericht-Pfads ──────────────────────────────────

    @staticmethod
    def _security_styles() -> dict[str, ParagraphStyle]:
        """Baut die Absatz-Stile des Sicherheitsberichts in CERNIS-Farben -- pro Aufruf frisch.

        Eigener Satz (nicht das getSampleStyleSheet des Scan-Berichts), damit Titel/Abschnitte/
        Fliesstext/Fussnote die Marken-Typografie tragen. Zustandslos: ein neues Dict je Aufruf.
        """
        base = getSampleStyleSheet()
        normal = base["Normal"]
        return {
            "h_title": ParagraphStyle(
                "h_title",
                parent=normal,
                fontName="Helvetica-Bold",
                fontSize=18,
                textColor=_TEXT,
                spaceAfter=8,
            ),
            "sub": ParagraphStyle(
                "sub",
                parent=normal,
                fontName="Helvetica",
                fontSize=9,
                textColor=_CLEAN,
                spaceBefore=2,
            ),
            "h_section": ParagraphStyle(
                "h_section",
                parent=normal,
                fontName="Helvetica-Bold",
                fontSize=12,
                textColor=_ACCENT,
                spaceBefore=4,
                spaceAfter=4,
            ),
            "h_rubric": ParagraphStyle(
                "h_rubric",
                parent=normal,
                fontName="Helvetica-Bold",
                fontSize=14,
                textColor=_ACCENT,
                spaceAfter=2,
            ),
            "body": ParagraphStyle(
                "body",
                parent=normal,
                fontName="Helvetica",
                fontSize=10,
                textColor=_TEXT,
                leading=14,
            ),
            "body_center": ParagraphStyle(
                "body_center",
                parent=normal,
                fontName="Helvetica",
                fontSize=10,
                textColor=_TEXT,
                leading=14,
                alignment=TA_CENTER,
            ),
            "footnote": ParagraphStyle(
                "footnote",
                parent=normal,
                fontName="Helvetica-Oblique",
                fontSize=8,
                textColor=_CLEAN,
                leading=11,
            ),
            "cell": ParagraphStyle(
                "cell",
                parent=normal,
                fontName="Helvetica",
                fontSize=8,
                textColor=_TEXT,
                leading=10,
                # CJK erlaubt reportlab den Umbruch INNERHALB langer zusammenhaengender
                # Tokens (langer Geraetename, MAC-Adresse) -- sauberer Zeichenumbruch statt
                # hartem Abschneiden am Spaltenrand; normaler Text bricht weiter am Wort.
                wordWrap="CJK",
            ),
        }

    @staticmethod
    def _kennzahlen_table(model: SecurityPdfModelLike, lang: str = "de") -> Table:
        """Drei farbige Kennzahl-Boxen (kritisch / auffaellig / ohne Befund) als Tabelle.

        Eine 3-spaltige ``Table`` mit der grossen Zahl oben und dem Label darunter, jede Spalte
        in ihrer Severity-Farbe hinterlegt (kritisch rot, auffaellig orange, sauber grau). Reine
        Anzeige der drei Zaehler aus dem Modell -- keine Rechnung.
        """
        data = [
            [str(model.critical_devices), str(model.notable_devices), str(model.clean_devices)],
            [_ui("sec.krit", lang), _ui("sec.auffaell", lang), _ui("sec.ohne_befund", lang)],
        ]
        table = Table(data, colWidths=[57 * mm, 57 * mm, 57 * mm])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), _CRIT),
                    ("BACKGROUND", (1, 0), (1, -1), _NOTABLE),
                    ("BACKGROUND", (2, 0), (2, -1), _CLEAN),
                    ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 22),
                    ("FONTNAME", (0, 1), (-1, 1), "Helvetica"),
                    ("FONTSIZE", (0, 1), (-1, 1), 10),
                    ("TOPPADDING", (0, 0), (-1, 0), 8),
                    ("BOTTOMPADDING", (0, 1), (-1, 1), 8),
                ]
            )
        )
        return table

    def _append_table_section(
        self,
        story: list[Flowable],
        styles: dict[str, ParagraphStyle],
        title: str,
        columns: tuple[str, ...],
        rows: tuple[tuple[str, ...], ...],
        lang: str = "de",
    ) -> None:
        """Haengt eine Tabellen-Rubrik (nummerierter Titel + accent-Unterstrich + Tabelle) an.

        Leere ``rows`` -> "Keine Eintraege." statt einer leeren ``Table`` (Auftrag, Robustheit).
        Lange Textspalten werden als ``Paragraph`` (umbrechbar) gesetzt, damit die Zelle nicht
        ueber den Rand laeuft. Die Schwere-Spalte (sofern "Schwere" in den Spalten) wird als
        Badge eingefaerbt. repeatRows=1 -> Kopf wiederholt sich bei Seitenumbruch.

        ``lang`` steuert AUSSCHLIESSLICH den angezeigten Kopf-Text (``_header_labels``); die
        Steuer-Rolle von ``columns`` (Breiten, Leertext, Badge-Spalte) bleibt auf dem rohen Tupel.
        """
        story.append(Paragraph(title, styles["h_rubric"]))
        story.append(HRFlowable(width="100%", thickness=1.2, color=_ACCENT, spaceAfter=4))

        if not rows:
            leer_text = _empty_text(columns, lang)
            story.append(Paragraph(leer_text, styles["body"]))
            return

        severity_col = columns.index("Schwere") if "Schwere" in columns else -1
        # Die Roh-Zeilen (Strings) fuer das Badge-Einfaerben getrennt fuehren, die Render-Zeilen
        # (Paragraphs) fuer die Table -- der Badge-Helfer braucht den Klartext der Schwere-Zelle.
        badge_data: list[list[object]] = [list(columns)]
        render_data: list[list[object]] = [list[object](_header_labels(columns, lang))]
        for row in rows:
            badge_data.append(list(row))
            render_data.append([Paragraph(_esc(value), styles["cell"]) for value in row])

        table = Table(render_data, repeatRows=1, colWidths=_col_widths(columns))
        style = self._base_table_style(len(render_data))
        if severity_col >= 0:
            _apply_severity_badges(style, badge_data, severity_col=severity_col)
        table.setStyle(style)
        story.append(table)

    def _append_cve_finding_groups(
        self,
        story: list[Flowable],
        styles: dict[str, ParagraphStyle],
        title: str,
        columns: tuple[str, ...],
        groups: tuple[_HostGroupBlockLike, ...],
        lang: str = "de",
    ) -> None:
        """Haengt die nach Host GRUPPIERTE Befundliste (Sektion 4) an -- eigener Render-Pfad.

        ``_append_table_section`` kann keine Host-Trennzeilen; darum baut diese Methode EINE
        Tabelle: erste Zeile die Spaltenkoepfe (``columns`` = ``_CVE_FINDING_GROUP_COLUMNS``),
        dann je Host-Gruppe zuerst eine HOST-Trennzeile (eine Zelle ueber alle Spalten via SPAN,
        grau hinterlegt, fett = ``group.header``) und darunter die CVE-Zeilen ohne IP-Wiederholung.
        Leere ``groups`` -> Leer-Fallback wie ``_append_table_section``. ``repeatRows=1`` wiederholt
        nur den Spaltenkopf; die Host-Trennzeilen wandern mit. Die Severity-Zelle je CVE-Zeile wird
        in ihrer ``_SEV_COLORS``-Farbe eingefaerbt (lokal -- KEIN gemeinsamer Helfer beruehrt).

        ``lang`` steuert AUSSCHLIESSLICH den angezeigten Spaltenkopf (``_header_labels``); die
        Severity-Spalte wird weiter ueber das rohe ``columns`` bestimmt.
        """
        story.append(Paragraph(title, styles["h_rubric"]))
        story.append(HRFlowable(width="100%", thickness=1.2, color=_ACCENT, spaceAfter=4))

        if not groups:
            leer_text = _empty_text(columns, lang)
            story.append(Paragraph(leer_text, styles["body"]))
            return

        # Kopfzeilen-Stil fuer die Host-Trennzeile (fett, etwas groesser; umbrechbar).
        host_kopf_stil = ParagraphStyle(
            "cve_host_kopf",
            parent=styles["cell"],
            fontName="Helvetica-Bold",
            fontSize=9,
        )
        severity_col = columns.index("Severity") if "Severity" in columns else -1

        data: list[list[object]] = [list[object](_header_labels(columns, lang))]
        # Tabellen-Kommandos zusaetzlich zum Basis-Stil: je Host-Kopfzeile SPAN + grau + fett,
        # je CVE-Zeile die Severity-Zelle in ihrer Stufenfarbe.
        extra_cmds: list[tuple[object, ...]] = []
        for group in groups:
            kopf_index = len(data)
            data.append([Paragraph(_esc(group.header), host_kopf_stil)])
            extra_cmds.append(("SPAN", (0, kopf_index), (-1, kopf_index)))
            extra_cmds.append(("BACKGROUND", (0, kopf_index), (-1, kopf_index), _ZEBRA))
            for row in group.rows:
                zeilen_index = len(data)
                data.append([Paragraph(_esc(value), styles["cell"]) for value in row])
                if severity_col >= 0 and severity_col < len(row):
                    farbe = _SEV_COLORS.get(row[severity_col])
                    if farbe is not None:
                        extra_cmds.append(
                            (
                                "TEXTCOLOR",
                                (severity_col, zeilen_index),
                                (severity_col, zeilen_index),
                                farbe,
                            )
                        )

        table = Table(data, repeatRows=1, colWidths=_col_widths(columns))
        style = self._base_table_style(len(data))
        for cmd in extra_cmds:
            style.add(*cmd)
        table.setStyle(style)
        story.append(table)

    @staticmethod
    def _base_table_style(row_count: int) -> TableStyle:
        """Der gemeinsame Tabellen-Stil in CERNIS-Farben (Kopf accent, Zebra hell, dezente Linien).

        ``row_count`` ist die Gesamtzeilenzahl (inkl. Kopf) -- nur fuer die Symmetrie der
        Aufrufe mitgefuehrt; die Zebra-/Linien-Regeln greifen ohnehin ueber den ganzen Bereich.
        """
        _ = row_count
        return TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), _ACCENT),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 9),
                ("FONTSIZE", (0, 1), (-1, -1), 8),
                ("TEXTCOLOR", (0, 1), (-1, -1), _TEXT),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, _ZEBRA]),
                ("LINEBELOW", (0, 0), (-1, -1), 0.4, _LINE),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ]
        )

    # ── Bestandsbericht: eigener Render-Pfad ────────────────────────────────
    #
    # NEUE Methode neben render_security_report_pdf -- beide bleiben UNANGETASTET (der
    # Sicherheitsbericht-Pfad wird nicht angefasst). Dieser Pfad rendert das render-fertige
    # InventoryPdfModel (Kennzahlen + zwei Verteilungs-Tabellen + zwei Geraete-Tabellen) mit
    # durchgaengiger Kopf-/Fusszeile. Kopf-Titel parametrisch ueber model.title -> dafuer wird
    # _draw_manual_header_footer wiederverwendet (liest model.title/footer_left; _draw_header_
    # footer zeichnet den Sicherheitsbericht-Titel HARTKODIERT und passt darum hier nicht). Beide
    # Kopf-/Fuss-Funktionen teilen dieselbe _LOGO_PATH-Konstante (cernis-logo-pdf.png) -- der
    # Bestandsbericht erbt damit automatisch das verkleinerte PDF-Logo.

    def render_inventory_report_pdf(self, model: InventoryPdfModelLike, lang: str = "de") -> bytes:
        """Rendert das ``InventoryPdfModel`` zum vollstaendigen Bestandsbericht-PDF (A4 hoch).

        Layout (Auftrag): durchgaengige Kopf-/Fusszeile je Seite (onFirstPage UND onLaterPages
        ueber dieselbe Funktion ``_draw_manual_header_footer``), dann die Story -- Titel +
        Erzeugungsdatum + Einleitung, der Kennzahlen-Block, die beiden Verteilungs-Tabellen
        (Hersteller/Kategorie) und die beiden Geraete-Rubriken (aktiv/archiviert). Die archiviert-
        Rubrik wird bei leerer Liste ganz weggelassen.

        Robust: leere Verteilungs-Tabellen -> "Keine Eintraege." statt leerer ``Table``; die
        Geraete-Rubriken nutzen ``_append_table_section`` (eigener leer-Fallback). KEINE Uhr,
        KEINE Rechnung -- alle Texte/Zahlen kommen fertig aus dem Modell. Liefert valide
        PDF-Bytes (Magic-Header ``%PDF``).
        """
        buffer = io.BytesIO()
        document = SimpleDocTemplate(
            buffer,
            pagesize=A4,  # Hochformat (Auftrag)
            leftMargin=18 * mm,
            rightMargin=18 * mm,
            topMargin=32 * mm,  # Platz fuer die durchgaengige Kopfzeile
            bottomMargin=20 * mm,  # Platz fuer die Fusszeile
            title=model.title,
        )

        story: list[Flowable] = []
        styles = self._security_styles()

        # ── Titel + Erzeugungsdatum + Einleitung (fertige Texte aus dem Modell) ──
        story.append(Paragraph(model.title, styles["h_title"]))
        story.append(Paragraph(model.generated_at_text, styles["sub"]))
        story.append(Spacer(1, 4 * mm))
        if model.einleitung:
            story.append(Paragraph(model.einleitung, styles["body"]))
            story.append(Spacer(1, 6 * mm))

        # ── Bestands-Kennzahlen ──
        story.append(Paragraph(_ui("inv.kennzahlen", lang), styles["h_section"]))
        story.append(self._inventory_kennzahlen(model, lang))
        story.append(Spacer(1, 6 * mm))

        # ── Zwei Donuts: Bekannt/unbekannt + Vertrauensstatus (analog Sicherheitsbericht) ──
        # Ueberschrift UND Donut-Paar zusammenhalten (KeepTogether), damit der Seitenumbruch nicht
        # zwischen Ueberschrift und Donuts faellt (Muster donut_block im Sicherheitsbericht).
        donut_block: list[Flowable] = [
            Paragraph(_ui("inv.geraete_verteilung", lang), styles["h_section"]),
            self._inventory_donut_paar(model, lang),
        ]
        story.append(KeepTogether(donut_block))
        story.append(Spacer(1, 6 * mm))

        story.append(PageBreak())

        # ── Verteilung nach Hersteller / Kategorie (zwei schlanke (label, count)-Tabellen) ──
        story.append(Paragraph(_ui("inv.nach_hersteller", lang), styles["h_section"]))
        self._append_distribution_table(
            story,
            styles,
            ("Hersteller", "Anzahl"),
            _resolve_distribution_marker(model.vendor_rows, _EMPTY_VENDOR_MARKER, lang),
            lang,
        )
        story.append(Spacer(1, 6 * mm))

        story.append(Paragraph(_ui("inv.nach_kategorie", lang), styles["h_section"]))
        self._append_distribution_table(
            story,
            styles,
            ("Kategorie", "Anzahl"),
            _resolve_distribution_marker(model.category_rows, _EMPTY_CATEGORY_MARKER, lang),
            lang,
        )

        story.append(PageBreak())

        # ── Geraete-Rubriken: aktive immer, archivierte nur wenn vorhanden ──
        # _append_table_section rendert Kopf + Tabelle + leer-Fallback selbst. Die Status-Spalte
        # ist KEINE "Schwere"-Spalte -> kein Badge-Einfaerben (korrekt, der Bestand wertet nicht).
        self._append_table_section(
            story, styles, _ui("inv.geraete", lang), INVENTORY_COLUMNS, model.device_rows, lang
        )

        if model.archived_rows:
            story.append(PageBreak())
            self._append_table_section(
                story,
                styles,
                _ui("inv.archiviert", lang),
                ARCHIVED_COLUMNS,
                model.archived_rows,
                lang,
            )

        # ── Achse-B-Fussnote (invariant, wie im Sicherheitsbericht) ──
        story.append(Spacer(1, 8 * mm))
        story.append(HRFlowable(width="100%", thickness=0.6, color=_LINE))
        story.append(Spacer(1, 2 * mm))
        story.append(
            Paragraph(
                model.achse_b_fussnote,
                styles["footnote"],
            )
        )

        # _draw_manual_header_footer ist auf ManualPdfModelLike typisiert, liest zur Laufzeit
        # aber NUR model.title + model.footer_left -- beide hat InventoryPdfModelLike ebenfalls.
        # cast statt Aenderung der (unveraendert bleibenden) Kopf-/Fuss-Funktion: ehrliche
        # Strukturgleichheit fuer genau die zwei gelesenen Felder, keine Design-Entscheidung.
        header_model = cast(ManualPdfModelLike, model)
        document.build(
            story,
            onFirstPage=lambda canvas, doc: _draw_manual_header_footer(
                canvas, doc, header_model, lang
            ),
            onLaterPages=lambda canvas, doc: _draw_manual_header_footer(
                canvas, doc, header_model, lang
            ),
        )
        return buffer.getvalue()

    @staticmethod
    def _inventory_kennzahlen(model: InventoryPdfModelLike, lang: str = "de") -> Table:
        """Die Bestands-Kennzahlen als zwei Zeilen Kennzahl-Boxen (Zahl oben, Label darunter).

        Reihe 1: Gesamt/Bekannt/Unbekannt/Aktiv (24h), Reihe 2: Vertraut/Beobachtet/Neutral.
        Beide Reihen liegen in EINER 4-spaltigen ``Table`` (Reihe 2 nutzt 3 Spalten, die vierte
        bleibt leer) -- schlichte, lesbare graue Boxen mit Akzent-Zahl. Reine Anzeige der schon
        ermittelten Zaehler aus dem Modell -- keine Rechnung, keine neuen Farbkonstanten.
        """
        # Je Box ein (Zahl, Label)-Paar; die Tabelle traegt Zahlen-Zeile und Label-Zeile
        # abwechselnd, damit die grosse Zahl ueber dem Label steht (Muster _kennzahlen_table).
        data = [
            [str(model.total), str(model.known), str(model.unknown), str(model.active_24h)],
            [
                _ui("inv.gesamt", lang),
                _ui("inv.bekannt", lang),
                _ui("inv.unbekannt", lang),
                _ui("inv.aktiv24h", lang),
            ],
            [str(model.trusted), str(model.watch), str(model.neutral), ""],
            [_ui("inv.vertraut", lang), _ui("inv.beobachtet", lang), _ui("inv.neutral", lang), ""],
        ]
        col = 174.0 / 4 * mm
        table = Table(data, colWidths=[col, col, col, col])
        table.setStyle(
            TableStyle(
                [
                    # Dezent graue Boxen (kein neues Farbset): Hintergrund _ZEBRA, Zahl in _ACCENT,
                    # Label in _TEXT. Die leere vierte Box der zweiten Reihe bleibt ohne Fuellung.
                    ("BACKGROUND", (0, 0), (-1, 1), _ZEBRA),
                    ("BACKGROUND", (0, 2), (2, 3), _ZEBRA),
                    ("TEXTCOLOR", (0, 0), (-1, 0), _ACCENT),
                    ("TEXTCOLOR", (0, 2), (2, 2), _ACCENT),
                    ("TEXTCOLOR", (0, 1), (-1, 1), _TEXT),
                    ("TEXTCOLOR", (0, 3), (2, 3), _TEXT),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTNAME", (0, 2), (2, 2), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 20),
                    ("FONTSIZE", (0, 2), (2, 2), 20),
                    ("FONTNAME", (0, 1), (-1, 1), "Helvetica"),
                    ("FONTNAME", (0, 3), (2, 3), "Helvetica"),
                    ("FONTSIZE", (0, 1), (-1, 1), 9),
                    ("FONTSIZE", (0, 3), (2, 3), 9),
                    ("TOPPADDING", (0, 0), (-1, 0), 8),
                    ("TOPPADDING", (0, 2), (2, 2), 8),
                    ("BOTTOMPADDING", (0, 1), (-1, 1), 8),
                    ("BOTTOMPADDING", (0, 3), (2, 3), 8),
                ]
            )
        )
        return table

    def _inventory_donut_paar(self, model: InventoryPdfModelLike, lang: str = "de") -> Table:
        """Die zwei Bestands-Donuts nebeneinander (Bekannt/unbekannt links, Vertrauen rechts).

        Pro Spalte ein Block aus dezentem Titel, dem ``_inventory_donut_drawing`` und einer
        schlichten Legende (je Segment ein farbiges Quadrat + Label + Wert). Die Farbzuordnung ist
        BEWUSST konsistent zur In-App-Ansicht: bekannt/vertraut = ``_ACCENT``, unbekannt/beobachtet
        = ``_NOTABLE``, neutral = ``_CLEAN``. Reine Anzeige der schon ermittelten Zaehler aus dem
        Modell -- keine Rechnung ausser der Donut-Geometrie, keine neuen Farbkonstanten.

        Die deutschen Klartext-Labels (Titel/Legende) sind invariant wie die uebrigen deutschen
        PDF-Texte des Adapters (z. B. die Spaltenkoepfe) und werden hier lokal gesetzt.
        """
        styles = self._security_styles()
        # Dezenter Donut-Titel: kleiner als h_section, weiterhin Akzentfarbe.
        donut_titel = ParagraphStyle(
            "inv_donut_titel",
            parent=styles["h_section"],
            fontSize=10,
            alignment=TA_CENTER,
            spaceAfter=2,
        )

        donut_a = _inventory_donut_drawing(
            ((model.known, _ACCENT), (model.unknown, _NOTABLE)),
            model.total,
            _ui("donut.geraete", lang),
            lang=lang,
        )
        legende_a = self._inventory_donut_legende(
            (
                (_ui("inv.bekannt", lang), _ACCENT, model.known),
                (_ui("inv.unbekannt", lang), _NOTABLE, model.unknown),
            ),
        )

        vertrauen_summe = model.trusted + model.watch + model.neutral
        donut_b = _inventory_donut_drawing(
            ((model.trusted, _ACCENT), (model.watch, _NOTABLE), (model.neutral, _CLEAN)),
            vertrauen_summe,
            _ui("donut.geraete", lang),
            lang=lang,
        )
        legende_b = self._inventory_donut_legende(
            (
                (_ui("inv.vertraut", lang), _ACCENT, model.trusted),
                (_ui("inv.beobachtet", lang), _NOTABLE, model.watch),
                (_ui("inv.neutral", lang), _CLEAN, model.neutral),
            ),
        )

        # Je Spalte ein vertikaler Block (Titel / Donut / Legende) als innere 1-spaltige Table.
        spalte_a = Table(
            [[Paragraph(_ui("inv.bekannt_unbekannt", lang), donut_titel)], [donut_a], [legende_a]]
        )
        spalte_b = Table(
            [[Paragraph(_ui("inv.vertrauen", lang), donut_titel)], [donut_b], [legende_b]]
        )
        for spalte in (spalte_a, spalte_b):
            spalte.setStyle(TableStyle([("ALIGN", (0, 0), (-1, -1), "CENTER")]))

        half = _CONTENT_WIDTH_MM / 2.0 * mm
        paar = Table([[spalte_a, spalte_b]], colWidths=[half, half])
        paar.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ]
            )
        )
        return paar

    @staticmethod
    def _inventory_donut_legende(
        eintraege: tuple[tuple[str, colors.Color, int], ...],
    ) -> Table:
        """Schlichte Donut-Legende: je Segment ein farbiges Quadrat + Label + Wert (eine Zeile).

        Das Quadrat ist ein winziges ``Drawing`` mit ``Rect`` in Segmentfarbe (8x8), daneben Label
        und Wert als Klartext. Robuste innere Mini-``Table`` -- nur die uebergebenen Farben (aus
        ``_ACCENT``/``_NOTABLE``/``_CLEAN``), keine festen Farben.

        LEERFALL (Wurzel-Guard): sind ``eintraege`` leer -- etwa im CVE-Bericht bei leerer DB,
        wo alle Severity-Counts 0 sind und der count-> 0-Filter nichts uebrig laesst --, wuerde
        ``Table([])`` mit "must have at least a row and column" werfen. Statt dessen eine valide
        Table mit EINER leeren Zelle: reportlab-sicher, unsichtbar (kein Text, keine Farbe) und
        sprachneutral -- der Helfer kennt kein ``lang``, darum hier bewusst KEIN Hinweistext.
        Der Guard sitzt im Helfer, damit JEDER Aufrufer (Bestand wie CVE) abgesichert ist.
        """
        if not eintraege:
            return Table([[""]], colWidths=[14.0])

        data: list[list[object]] = []
        for label, color, value in eintraege:
            swatch = Drawing(10.0, 10.0)
            swatch.add(Rect(0.0, 1.0, 8.0, 8.0, fillColor=color, strokeColor=None))
            data.append([swatch, f"{label}: {value}"])

        table = Table(data, colWidths=[14.0, None])
        table.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("ALIGN", (0, 0), (0, -1), "CENTER"),
                    ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                    ("FONTSIZE", (1, 0), (1, -1), 9),
                    ("TEXTCOLOR", (1, 0), (1, -1), _TEXT),
                    ("TOPPADDING", (0, 0), (-1, -1), 1),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
                    ("LEFTPADDING", (0, 0), (-1, -1), 2),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 2),
                ]
            )
        )
        return table

    def _append_distribution_table(
        self,
        story: list[Flowable],
        styles: dict[str, ParagraphStyle],
        columns: tuple[str, str],
        rows: tuple[tuple[str, str], ...],
        lang: str = "de",
    ) -> None:
        """Haengt eine schlichte (label, count)-Verteilungs-Tabelle an (Hersteller bzw. Kategorie).

        Leere ``rows`` -> "Keine Eintraege." (body) statt einer leeren ``Table``. Feste
        colWidths (Label breit, Anzahl schmal) -- nicht ueber ``_col_widths``, weil die
        2-spaltigen Verteilungs-Schemata dort nicht hinterlegt sind. ``_base_table_style`` +
        ``repeatRows=1`` (Kopf wiederholt sich bei Seitenumbruch), Zellen als umbrechbare
        ``Paragraph`` (Muster ``_append_table_section``).
        """
        if not rows:
            story.append(Paragraph(_ui("inv.keine_eintraege", lang), styles["body"]))
            return

        content_pt = _CONTENT_WIDTH_MM * mm
        col_widths = [content_pt * 0.78, content_pt * 0.22]
        render_data: list[list[object]] = [list[object](_header_labels(columns, lang))]
        for label, count in rows:
            render_data.append(
                [
                    Paragraph(_esc(label), styles["cell"]),
                    Paragraph(_esc(count), styles["cell"]),
                ]
            )
        table = Table(render_data, repeatRows=1, colWidths=col_widths)
        table.setStyle(self._base_table_style(len(render_data)))
        story.append(table)

    # ── CVE-Bericht: eigener Render-Pfad ────────────────────────────────────
    #
    # NEUE Methode neben render_inventory_report_pdf -- beide bleiben UNANGETASTET. Dieser Pfad
    # rendert das render-fertige CvePdfModel (Kennzahlen + ein Severity-Donut + drei Sektions-
    # Tabellen) mit durchgaengiger Kopf-/Fusszeile. Kopf-Titel parametrisch ueber model.title ->
    # dafuer wird _draw_manual_header_footer wiederverwendet (liest model.title/footer_left).
    # Teilt dieselbe _LOGO_PATH-Konstante -- der CVE-Bericht erbt damit das verkleinerte PDF-Logo.

    def render_cve_report_pdf(self, model: CvePdfModelLike, lang: str = "de") -> bytes:
        """Rendert das ``CvePdfModel`` zum vollstaendigen CVE-Bericht-PDF (A4 hoch).

        Layout (Auftrag): durchgaengige Kopf-/Fusszeile je Seite (onFirstPage UND onLaterPages
        ueber dieselbe Funktion ``_draw_manual_header_footer``), dann die Story -- Titel +
        Erzeugungsdatum + Einleitung, der Kennzahlen-Block, der Severity-Donut und die drei
        Sektions-Rubriken (betroffene Geraete / Muster nach Dienst / vollstaendige Befundliste),
        je auf eigener Seite (PageBreak davor).

        Robust: leere Tabellen ziehen ihren eigenen Leer-Fallback ueber ``_append_table_section``.
        KEINE Uhr, KEINE Rechnung -- alle Texte/Zahlen kommen fertig aus dem Modell. Liefert
        valide PDF-Bytes (Magic-Header ``%PDF``).
        """
        buffer = io.BytesIO()
        document = SimpleDocTemplate(
            buffer,
            pagesize=A4,  # Hochformat (Auftrag)
            leftMargin=18 * mm,
            rightMargin=18 * mm,
            topMargin=32 * mm,  # Platz fuer die durchgaengige Kopfzeile
            bottomMargin=20 * mm,  # Platz fuer die Fusszeile
            title=model.title,
        )

        story: list[Flowable] = []
        styles = self._security_styles()

        # ── Titel + Erzeugungsdatum + Einleitung (fertige Texte aus dem Modell) ──
        story.append(Paragraph(model.title, styles["h_title"]))
        story.append(Paragraph(model.generated_at_text, styles["sub"]))
        story.append(Spacer(1, 4 * mm))
        if model.einleitung:
            story.append(Paragraph(model.einleitung, styles["body"]))
            story.append(Spacer(1, 6 * mm))

        # ── Sektion 1: Ueberblick (CVE-Kennzahlen) ──
        story.append(Paragraph(_ui("cve.kennzahlen", lang), styles["h_section"]))
        story.append(self._cve_kennzahlen(model, lang))
        story.append(Spacer(1, 6 * mm))

        # ── Severity-Donut (Ueberschrift + Donut zusammenhalten, Muster donut_block) ──
        story.append(
            KeepTogether(
                [
                    Paragraph(_ui("cve.schweregrad", lang), styles["h_section"]),
                    self._cve_severity_donut(model, lang),
                ]
            )
        )
        story.append(Spacer(1, 6 * mm))

        # ── Sektions-Rubriken ──
        # (R8) KEIN PageBreak nach dem Donut -- Sektion 2 folgt direkt, damit Seite 1 nicht
        # fast leer bleibt. _append_table_section rendert Kopf + Tabelle + leer-Fallback selbst.
        # Die Severity-Spalte bleibt Klartext (KEINE "Schwere"-Spalte -> kein Badge).
        self._append_table_section(
            story, styles, _ui("cve.betroffene", lang), _CVE_DEVICE_COLUMNS, model.device_rows, lang
        )

        # Sektion 3 + 4 je auf eigener Seite (grosse Tabellen) -- diese PageBreaks bleiben.
        story.append(PageBreak())
        self._append_table_section(
            story, styles, _ui("cve.muster", lang), _CVE_SERVICE_COLUMNS, model.service_rows, lang
        )

        story.append(PageBreak())
        # (R2/R3) Sektion 4 ueber den eigenen, nach Host gruppierten Render-Pfad (Host-Kopf +
        # CVE-Zeilen ohne IP-Wiederholung), NICHT mehr ueber die flache _append_table_section.
        self._append_cve_finding_groups(
            story,
            styles,
            _ui("cve.befundliste", lang),
            _CVE_FINDING_GROUP_COLUMNS,
            model.host_groups,
            lang,
        )

        # ── Achse-B-Fussnote (invariant, wie im Bestands-/Sicherheitsbericht) ──
        # (Etappe 3b) HR + beide Fussnoten als EIN KeepTogether-Block, damit sie nie getrennt
        # umbrechen (kein PageBreak davor). Verhindert primaer das Auseinanderreissen; ein
        # restlicher reportlab-Flow-Umbruch der ganzen Gruppe bleibt akzeptabel.
        story.append(Spacer(1, 8 * mm))
        story.append(
            KeepTogether(
                [
                    HRFlowable(width="100%", thickness=0.6, color=_LINE),
                    Spacer(1, 2 * mm),
                    Paragraph(
                        model.achse_b_fussnote,
                        styles["footnote"],
                    ),
                    # (R4) Erklaerung der Variante-C-Status-Kennzeichnung "NEU".
                    Paragraph(
                        _ui("cve.neu_hinweis", lang),
                        styles["footnote"],
                    ),
                ]
            )
        )

        # _draw_manual_header_footer ist auf ManualPdfModelLike typisiert, liest zur Laufzeit aber
        # NUR model.title + model.footer_left -- beide hat CvePdfModelLike ebenfalls (Muster
        # render_inventory_report_pdf): cast statt Aenderung der Kopf-/Fuss-Funktion.
        header_model = cast(ManualPdfModelLike, model)
        document.build(
            story,
            onFirstPage=lambda canvas, doc: _draw_manual_header_footer(
                canvas, doc, header_model, lang
            ),
            onLaterPages=lambda canvas, doc: _draw_manual_header_footer(
                canvas, doc, header_model, lang
            ),
        )
        return buffer.getvalue()

    @staticmethod
    def _cve_kennzahlen(model: CvePdfModelLike, lang: str = "de") -> Table:
        """Die CVE-Kennzahlen als zwei Zeilen Kennzahl-Boxen (Wert oben, Label darunter).

        Reihe 1 (Zahlen): Aktive Befunde / Neu (24h) / Betroffene Geraete / Quittiert.
        Reihe 2 (Texte): Hoechste Severity / Abdeckung / Aelteste Veroeffentlichung / "".
        Beide Reihen liegen in EINER 4-spaltigen ``Table`` -- schlichte graue Boxen mit
        Akzent-Wert (Muster ``_inventory_kennzahlen``). Reihe 2 traegt TEXT statt Zahlen; ihre
        Box-Schrift ist darum kleiner (12 statt 20), damit laengere Texte lesbar bleiben. Reine
        Anzeige der schon ermittelten Werte aus dem Modell -- keine Rechnung, keine neuen Farben.
        """
        oldest = model.oldest_published_text or "—"
        data = [
            [
                str(model.active_total),
                str(model.new_total),
                str(model.affected_devices),
                str(model.acknowledged_total),
            ],
            [
                _ui("cve.aktive", lang),
                _ui("cve.neu24h", lang),
                _ui("cve.betroffene_geraete", lang),
                _ui("cve.quittiert", lang),
            ],
            [model.highest_severity, model.coverage_text, oldest, ""],
            [
                _ui("cve.hoechste_sev", lang),
                _ui("cve.abdeckung", lang),
                _ui("cve.aelteste", lang),
                "",
            ],
        ]
        col = 174.0 / 4 * mm
        table = Table(data, colWidths=[col, col, col, col])
        table.setStyle(
            TableStyle(
                [
                    # Dezent graue Boxen (kein neues Farbset): Hintergrund _ZEBRA, Wert in _ACCENT,
                    # Label in _TEXT. Die leere vierte Box der zweiten Reihe bleibt ohne Fuellung.
                    ("BACKGROUND", (0, 0), (-1, 1), _ZEBRA),
                    ("BACKGROUND", (0, 2), (2, 3), _ZEBRA),
                    ("TEXTCOLOR", (0, 0), (-1, 0), _ACCENT),
                    ("TEXTCOLOR", (0, 2), (2, 2), _ACCENT),
                    ("TEXTCOLOR", (0, 1), (-1, 1), _TEXT),
                    ("TEXTCOLOR", (0, 3), (2, 3), _TEXT),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTNAME", (0, 2), (2, 2), "Helvetica-Bold"),
                    # Reihe 1: grosse Zahl (20). Reihe 2: Text -> kleinere Schrift (12).
                    ("FONTSIZE", (0, 0), (-1, 0), 20),
                    ("FONTSIZE", (0, 2), (2, 2), 12),
                    ("FONTNAME", (0, 1), (-1, 1), "Helvetica"),
                    ("FONTNAME", (0, 3), (2, 3), "Helvetica"),
                    ("FONTSIZE", (0, 1), (-1, 1), 9),
                    ("FONTSIZE", (0, 3), (2, 3), 9),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, 0), 8),
                    ("TOPPADDING", (0, 2), (2, 2), 8),
                    ("BOTTOMPADDING", (0, 1), (-1, 1), 8),
                    ("BOTTOMPADDING", (0, 3), (2, 3), 8),
                ]
            )
        )
        return table

    def _cve_severity_donut(self, model: CvePdfModelLike, lang: str = "de") -> Table:
        """Der Severity-Donut: ein Ring ueber alle fuenf Stufen (Muster ``_inventory_donut_paar``).

        Baut die Segmentliste aus ``model.severity_rows`` in der gelieferten Reihenfolge
        (SEVERITY_ORDER kommt schon so aus der Aggregation): je ``(count, _SEV_COLORS[stufe])``,
        ``count`` aus dem ``(stufe, count_text)``-Tupel via ``int``. Die Mitte traegt die Summe
        aller counts (aktive Befunde) + Label "Befunde". Die Legende fuehrt nur Stufen mit count
        > 0 (kein Rauschen; 0-Segmente sind im Donut ohnehin unsichtbar). Donut + Legende
        als 1-spaltige Table (Muster spalte_a/b). Reine Anzeige -- nur die Donut-Geometrie.

        (R8) KEIN eigener "Schweregrad-Verteilung"-Titel mehr im Donut-Block -- die
        ``h_section``-Sektionsueberschrift darueber genuegt (sonst stuende der Titel doppelt).
        """
        segmente: tuple[tuple[int, colors.Color], ...] = tuple(
            (int(count_text), _SEV_COLORS[severity]) for severity, count_text in model.severity_rows
        )
        summe = sum(count for count, _ in segmente)
        donut = _inventory_donut_drawing(segmente, summe, _ui("cve.befunde", lang), lang=lang)

        # Legende: nur Stufen mit count > 0. Farbe + Wert kommen aus severity_rows (roher
        # Schluessel fuer _SEV_COLORS), der ANGEZEIGTE Text aus severity_labels (deutsch, je
        # roh_key -> Text). Fehlt ein Label, faellt der Text ehrlich auf den Rohschluessel zurueck.
        sev_labels = dict(model.severity_labels)
        legende_eintraege: tuple[tuple[str, colors.Color, int], ...] = tuple(
            (sev_labels.get(severity, severity), _SEV_COLORS[severity], int(count_text))
            for severity, count_text in model.severity_rows
            if int(count_text) > 0
        )
        legende = self._inventory_donut_legende(legende_eintraege)

        spalte = Table([[donut], [legende]])
        spalte.setStyle(TableStyle([("ALIGN", (0, 0), (-1, -1), "CENTER")]))
        return spalte

    # ── Aussenkontakte-Bericht: eigener Render-Pfad ─────────────────────────
    #
    # NEUE Methode neben render_cve_report_pdf -- alle bestehenden Render-Pfade bleiben
    # UNANGETASTET. Dieser Pfad rendert das render-fertige OutboundPdfModel (Kennzahlen + drei
    # Tabellen) mit durchgaengiger Kopf-/Fusszeile. Kopf-Titel parametrisch ueber model.title ->
    # dafuer wird _draw_manual_header_footer wiederverwendet (liest model.title/footer_left).
    # ABER OHNE Donut/Severity: der Aussenkontakte-Bericht faellt kein Urteil, traegt keine
    # Schwere-Spalte und kein Badge.

    def render_outbound_report_pdf(self, model: OutboundPdfModelLike, lang: str = "de") -> bytes:
        """Rendert das ``OutboundPdfModel`` zum vollstaendigen Aussenkontakte-Bericht-PDF (A4 hoch).

        Layout (Muster render_cve_report_pdf, ABER ohne Donut/Severity): durchgaengige Kopf-/
        Fusszeile je Seite (onFirstPage UND onLaterPages ueber dieselbe Funktion
        ``_draw_manual_header_footer``), dann die Story -- Titel + Erzeugungsdatum + Einleitung,
        die fertige Bezugsrahmen-Zeile (``scope_text``), der Kennzahlen-Block (zwei Reihen
        Zahlen) und die drei Sektions-Rubriken (Verteilung nach Land / nach Betreiber /
        Aussenkontakte im Detail, letztere auf eigener Seite, da potentiell lang).

        Robust: leere Tabellen ziehen ihren eigenen Leer-Fallback ueber ``_append_table_section``.
        Die Bewertung-Spalte ist KEINE "Schwere"-Spalte -> kein Badge (korrekt, wir wollen kein
        Urteil). KEINE Uhr, KEINE Rechnung -- alle Texte/Zahlen kommen fertig aus dem Modell.
        Liefert valide PDF-Bytes (Magic-Header ``%PDF``).
        """
        buffer = io.BytesIO()
        document = SimpleDocTemplate(
            buffer,
            pagesize=A4,  # Hochformat (Muster CVE)
            leftMargin=18 * mm,
            rightMargin=18 * mm,
            topMargin=32 * mm,  # Platz fuer die durchgaengige Kopfzeile
            bottomMargin=20 * mm,  # Platz fuer die Fusszeile
            title=model.title,
        )

        story: list[Flowable] = []
        styles = self._security_styles()

        # ── Titel + Erzeugungsdatum + Einleitung (fertige Texte aus dem Modell) ──
        story.append(Paragraph(model.title, styles["h_title"]))
        story.append(Paragraph(model.generated_at_text, styles["sub"]))
        story.append(Spacer(1, 4 * mm))
        if model.einleitung:
            story.append(Paragraph(model.einleitung, styles["body"]))
            story.append(Spacer(1, 6 * mm))

        # ── Bezugsrahmen-Zeile (fertig lokalisiert vom Composition Root) ──
        story.append(Paragraph(model.scope_text, styles["sub"]))
        story.append(Spacer(1, 4 * mm))

        # ── Sektion 1: Ueberblick (Aussenkontakte-Kennzahlen, zwei Reihen Zahlen) ──
        story.append(Paragraph(_ui("out.kennzahlen", lang), styles["h_section"]))
        story.append(self._outbound_kennzahlen(model, lang))
        story.append(Spacer(1, 6 * mm))

        # ── Sektions-Rubriken ueber das BESTEHENDE _append_table_section ──
        # Die Bewertung-Spalte bleibt Klartext (KEINE "Schwere"-Spalte -> kein Badge).
        self._append_table_section(
            story,
            styles,
            _ui("out.nach_land", lang),
            _OUTBOUND_COUNTRY_COLUMNS,
            model.country_rows,
            lang,
        )
        story.append(Spacer(1, 6 * mm))
        self._append_table_section(
            story,
            styles,
            _ui("out.nach_betreiber", lang),
            _OUTBOUND_OPERATOR_COLUMNS,
            model.operator_rows,
            lang,
        )

        # Die Detail-Liste auf eigener Seite (potentiell lang) -- PageBreak davor.
        story.append(PageBreak())
        self._append_table_section(
            story,
            styles,
            _ui("out.detail", lang),
            _OUTBOUND_CONTACT_COLUMNS,
            model.contact_rows,
            lang,
        )

        # ── Achse-B-Fussnote (invariant, wie im CVE-/Bestandsbericht) ──
        # HR + der eine Achse-B-Satz als KeepTogether-Block. KEINE "Neu (24h)"-Zeile -- die gilt
        # nur fuer den CVE-Bericht.
        story.append(Spacer(1, 8 * mm))
        story.append(
            KeepTogether(
                [
                    HRFlowable(width="100%", thickness=0.6, color=_LINE),
                    Spacer(1, 2 * mm),
                    Paragraph(
                        model.achse_b_fussnote,
                        styles["footnote"],
                    ),
                ]
            )
        )

        # _draw_manual_header_footer ist auf ManualPdfModelLike typisiert, liest zur Laufzeit aber
        # NUR model.title + model.footer_left -- beide hat OutboundPdfModelLike ebenfalls (Muster
        # render_cve_report_pdf): cast statt Aenderung der Kopf-/Fuss-Funktion.
        header_model = cast(ManualPdfModelLike, model)
        document.build(
            story,
            onFirstPage=lambda canvas, doc: _draw_manual_header_footer(
                canvas, doc, header_model, lang
            ),
            onLaterPages=lambda canvas, doc: _draw_manual_header_footer(
                canvas, doc, header_model, lang
            ),
        )
        return buffer.getvalue()

    @staticmethod
    def _outbound_kennzahlen(model: OutboundPdfModelLike, lang: str = "de") -> Table:
        """Die Aussenkontakte-Kennzahlen als zwei Zeilen Kennzahl-Boxen (Zahl oben, Label darunter).

        Reihe 1: Gegenstellen/Verbindungen/Laender/Betreiber, Reihe 2: Auffaellig/Tracker/
        Bedrohung/Lokal. Beide Reihen liegen in EINER 4-spaltigen ``Table`` -- schlichte graue
        Boxen mit Akzent-Zahl (Muster ``_cve_kennzahlen``/``_inventory_kennzahlen``). Anders als
        ``_cve_kennzahlen`` traegt hier AUCH Reihe 2 ueberall Zahlen (alle acht Boxen gefuellt),
        darum FONTSIZE 20 fuer BEIDE Wert-Reihen. Reine Anzeige der schon ermittelten Zaehler aus
        dem Modell -- keine Rechnung, keine neuen Farben.
        """
        data = [
            [
                str(model.remote_total),
                str(model.connection_total),
                str(model.countries_total),
                str(model.operators_total),
            ],
            [
                _ui("out.gegenstellen", lang),
                _ui("out.verbindungen", lang),
                _ui("out.laender", lang),
                _ui("out.betreiber", lang),
            ],
            [
                str(model.flagged_contacts),
                str(model.tracker_contacts),
                str(model.threat_contacts),
                str(model.local_total),
            ],
            [
                _ui("out.auffaellig", lang),
                _ui("out.tracker", lang),
                _ui("out.bedrohung", lang),
                _ui("out.lokal", lang),
            ],
        ]
        col = 174.0 / 4 * mm
        table = Table(data, colWidths=[col, col, col, col])
        table.setStyle(
            TableStyle(
                [
                    # Dezent graue Boxen (kein neues Farbset): Hintergrund _ZEBRA, Zahl in _ACCENT,
                    # Label in _TEXT. Alle acht Boxen gefuellt (anders als _cve_kennzahlen).
                    ("BACKGROUND", (0, 0), (-1, 3), _ZEBRA),
                    ("TEXTCOLOR", (0, 0), (-1, 0), _ACCENT),
                    ("TEXTCOLOR", (0, 2), (-1, 2), _ACCENT),
                    ("TEXTCOLOR", (0, 1), (-1, 1), _TEXT),
                    ("TEXTCOLOR", (0, 3), (-1, 3), _TEXT),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTNAME", (0, 2), (-1, 2), "Helvetica-Bold"),
                    # Beide Wert-Reihen tragen Zahlen -> FONTSIZE 20 fuer beide.
                    ("FONTSIZE", (0, 0), (-1, 0), 20),
                    ("FONTSIZE", (0, 2), (-1, 2), 20),
                    ("FONTNAME", (0, 1), (-1, 1), "Helvetica"),
                    ("FONTNAME", (0, 3), (-1, 3), "Helvetica"),
                    ("FONTSIZE", (0, 1), (-1, 1), 9),
                    ("FONTSIZE", (0, 3), (-1, 3), 9),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, 0), 8),
                    ("TOPPADDING", (0, 2), (-1, 2), 8),
                    ("BOTTOMPADDING", (0, 1), (-1, 1), 8),
                    ("BOTTOMPADDING", (0, 3), (-1, 3), 8),
                ]
            )
        )
        return table

    def render_dns_watch_report_pdf(self, model: DnsWatchPdfModelLike, lang: str = "de") -> bytes:
        """Rendert das ``DnsWatchPdfModel`` zum vollstaendigen DNS-Waechter-Bericht-PDF (A4 hoch).

        Layout (Muster render_outbound_report_pdf, ABER ohne Dropdown/recording): durchgaengige
        Kopf-/Fusszeile je Seite (onFirstPage UND onLaterPages ueber dieselbe Funktion
        ``_draw_manual_header_footer``), dann die Story -- Titel + Erzeugungsdatum + Einleitung,
        die fertige Sicht-Zeile (``scope_text``) und die beiden fertigen Bezugsrahmen-Zeilen
        (``expected_text``/``doh_text``), der Kennzahlen-Block (zwei Reihen Zahlen) und die drei
        Sektions-Rubriken (Verteilung nach Kategorie / nach Programm / DNS-relevante
        Aussenkontakte, letztere auf eigener Seite, da potentiell lang).

        Robust: leere Tabellen ziehen ihren eigenen Leer-Fallback ueber ``_append_table_section``.
        KEINE Uhr, KEINE Rechnung -- alle Texte/Zahlen kommen fertig aus dem Modell. Liefert
        valide PDF-Bytes (Magic-Header ``%PDF``).
        """
        buffer = io.BytesIO()
        document = SimpleDocTemplate(
            buffer,
            pagesize=A4,  # Hochformat (Muster Aussenkontakte)
            leftMargin=18 * mm,
            rightMargin=18 * mm,
            topMargin=32 * mm,  # Platz fuer die durchgaengige Kopfzeile
            bottomMargin=20 * mm,  # Platz fuer die Fusszeile
            title=model.title,
        )

        story: list[Flowable] = []
        styles = self._security_styles()

        # ── Titel + Erzeugungsdatum + Einleitung (fertige Texte aus dem Modell) ──
        story.append(Paragraph(model.title, styles["h_title"]))
        story.append(Paragraph(model.generated_at_text, styles["sub"]))
        story.append(Spacer(1, 4 * mm))
        if model.einleitung:
            story.append(Paragraph(model.einleitung, styles["body"]))
            story.append(Spacer(1, 6 * mm))

        # ── Bezugsrahmen-Zeilen (fertig lokalisiert vom Composition Root) ──
        story.append(Paragraph(model.scope_text, styles["sub"]))
        story.append(Paragraph(model.expected_text, styles["sub"]))
        story.append(Paragraph(model.doh_text, styles["sub"]))
        story.append(Spacer(1, 4 * mm))

        # ── Sektion 1: Ueberblick (DNS-Waechter-Kennzahlen, zwei Reihen Zahlen) ──
        story.append(Paragraph(_ui("dns.kennzahlen", lang), styles["h_section"]))
        story.append(self._dns_watch_kennzahlen(model, lang))
        story.append(Spacer(1, 6 * mm))

        # ── Sektions-Rubriken ueber das BESTEHENDE _append_table_section ──
        self._append_table_section(
            story,
            styles,
            _ui("dns.nach_kategorie", lang),
            DNS_CATEGORY_COLUMNS,
            model.category_rows,
            lang,
        )
        story.append(Spacer(1, 6 * mm))
        self._append_table_section(
            story, styles, _ui("dns.nach_programm", lang), DNS_APP_COLUMNS, model.app_rows, lang
        )

        # Die Detail-Liste auf eigener Seite (potentiell lang) -- PageBreak davor.
        story.append(PageBreak())
        self._append_table_section(
            story,
            styles,
            _ui("dns.kontakte", lang),
            DNS_CONTACT_COLUMNS,
            model.contact_rows,
            lang,
        )

        # ── Achse-B-Fussnote (invariant, wie im Aussenkontakte-Bericht) ──
        story.append(Spacer(1, 8 * mm))
        story.append(
            KeepTogether(
                [
                    HRFlowable(width="100%", thickness=0.6, color=_LINE),
                    Spacer(1, 2 * mm),
                    Paragraph(
                        model.achse_b_fussnote,
                        styles["footnote"],
                    ),
                ]
            )
        )

        # _draw_manual_header_footer ist auf ManualPdfModelLike typisiert, liest zur Laufzeit aber
        # NUR model.title + model.footer_left -- beide hat DnsWatchPdfModelLike ebenfalls (Muster
        # render_outbound_report_pdf): cast statt Aenderung der Kopf-/Fuss-Funktion.
        header_model = cast(ManualPdfModelLike, model)
        document.build(
            story,
            onFirstPage=lambda canvas, doc: _draw_manual_header_footer(
                canvas, doc, header_model, lang
            ),
            onLaterPages=lambda canvas, doc: _draw_manual_header_footer(
                canvas, doc, header_model, lang
            ),
        )
        return buffer.getvalue()

    @staticmethod
    def _dns_watch_kennzahlen(model: DnsWatchPdfModelLike, lang: str = "de") -> Table:
        """Die DNS-Waechter-Kennzahlen als zwei Zeilen Kennzahl-Boxen (Zahl oben, Label darunter).

        Reihe 1: Kontakte gesamt/Aktiv/Quittiert, Reihe 2: Erwartungsgemaess/Offen/Moeglicher
        DoH/Auffaellig. Beide Reihen liegen in EINER 4-spaltigen ``Table`` -- schlichte graue Boxen
        mit Akzent-Zahl (Muster ``_outbound_kennzahlen``). Reihe 1 traegt nur drei Zahlen (vierte
        Box leer), Reihe 2 alle vier. Reine Anzeige der schon ermittelten Zaehler aus dem Modell --
        keine Rechnung, keine neuen Farben.
        """
        data = [
            [
                str(model.contacts_total),
                str(model.active_total),
                str(model.acknowledged_total),
                "",
            ],
            [_ui("dns.gesamt", lang), _ui("dns.aktiv", lang), _ui("dns.quittiert", lang), ""],
            [
                str(model.expected_active),
                str(model.open_active),
                str(model.doh_active),
                str(model.flagged_active),
            ],
            [
                _ui("dns.erwartet", lang),
                _ui("dns.offen", lang),
                _ui("dns.doh", lang),
                _ui("dns.flagged", lang),
            ],
        ]
        col = 174.0 / 4 * mm
        table = Table(data, colWidths=[col, col, col, col])
        table.setStyle(
            TableStyle(
                [
                    # Dezent graue Boxen (kein neues Farbset): Hintergrund _ZEBRA, Zahl in _ACCENT,
                    # Label in _TEXT. Muster _outbound_kennzahlen (beide Wert-Reihen FONTSIZE 20).
                    ("BACKGROUND", (0, 0), (-1, 3), _ZEBRA),
                    ("TEXTCOLOR", (0, 0), (-1, 0), _ACCENT),
                    ("TEXTCOLOR", (0, 2), (-1, 2), _ACCENT),
                    ("TEXTCOLOR", (0, 1), (-1, 1), _TEXT),
                    ("TEXTCOLOR", (0, 3), (-1, 3), _TEXT),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTNAME", (0, 2), (-1, 2), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 20),
                    ("FONTSIZE", (0, 2), (-1, 2), 20),
                    ("FONTNAME", (0, 1), (-1, 1), "Helvetica"),
                    ("FONTNAME", (0, 3), (-1, 3), "Helvetica"),
                    ("FONTSIZE", (0, 1), (-1, 1), 9),
                    ("FONTSIZE", (0, 3), (-1, 3), 9),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, 0), 8),
                    ("TOPPADDING", (0, 2), (-1, 2), 8),
                    ("BOTTOMPADDING", (0, 1), (-1, 1), 8),
                    ("BOTTOMPADDING", (0, 3), (-1, 3), 8),
                ]
            )
        )
        return table

    def render_dns_bypass_report_pdf(self, model: DnsBypassPdfModelLike, lang: str = "de") -> bytes:
        """Rendert das ``DnsBypassPdfModel`` zum vollstaendigen DNS-Umgehungs-Bericht-PDF (A4 hoch).

        Layout (Muster render_dns_watch_report_pdf, ABER netzweit statt host-lokal + mit
        Bezugsrahmen/recording): durchgaengige Kopf-/Fusszeile je Seite (onFirstPage UND
        onLaterPages ueber dieselbe Funktion ``_draw_manual_header_footer``), dann die Story --
        Titel + Erzeugungsdatum + Einleitung, die fertige Bezugsrahmen-Zeile (``scope_text``) und
        die fertige erwartete-Server-Zeile (``expected_text``), der Kennzahlen-Block (eine Reihe
        Zahlen), die Verteilungs-Grafik nach Ziel (gestapelter Balken + Legende, ALLEINIGE
        Verteilungs-Darstellung) und die Umgehungs-Detailliste auf eigener Seite (potentiell
        lang; eigener Render-Pfad, da die Geraet-Zelle beim eigenen Host zweizeilig ist).

        Robust: eine leere Detailliste zieht ihren eigenen Leer-Fallback.
        KEINE Uhr, KEINE Rechnung -- alle Texte/Zahlen kommen fertig aus dem Modell. Liefert
        valide PDF-Bytes (Magic-Header ``%PDF``).
        """
        buffer = io.BytesIO()
        document = SimpleDocTemplate(
            buffer,
            pagesize=A4,  # Hochformat (Muster DNS-Waechter)
            leftMargin=18 * mm,
            rightMargin=18 * mm,
            topMargin=32 * mm,  # Platz fuer die durchgaengige Kopfzeile
            bottomMargin=20 * mm,  # Platz fuer die Fusszeile
            title=model.title,
        )

        story: list[Flowable] = []
        styles = self._security_styles()

        # ── Titel + Erzeugungsdatum + Einleitung (fertige Texte aus dem Modell) ──
        story.append(Paragraph(model.title, styles["h_title"]))
        story.append(Paragraph(model.generated_at_text, styles["sub"]))
        story.append(Spacer(1, 4 * mm))
        if model.einleitung:
            story.append(Paragraph(model.einleitung, styles["body"]))
            story.append(Spacer(1, 6 * mm))

        # ── Bezugsrahmen-Zeilen (fertig lokalisiert vom Composition Root) ──
        story.append(Paragraph(model.scope_text, styles["sub"]))
        story.append(Paragraph(model.expected_text, styles["sub"]))
        story.append(Spacer(1, 4 * mm))

        # ── Sektion 1: Ueberblick (Umgehungs-Kennzahlen, eine Reihe Zahlen) ──
        story.append(Paragraph(_ui("bypass.kennzahlen", lang), styles["h_section"]))
        story.append(self._dns_bypass_kennzahlen(model, lang))
        story.append(Spacer(1, 6 * mm))

        # ── Verteilungs-Grafik (Variante C): gestapelter Balken + Legende ──
        # Nur bei vorhandenen Zielen; leere Verteilung -> keine Grafik (die Tabelle unten
        # zieht ihren eigenen Leer-Fallback). Titel + Grafik zusammenhalten.
        if model.resolver_distribution:
            story.append(
                KeepTogether(
                    [
                        Paragraph(_ui("bypass.verteilung", lang), styles["h_section"]),
                        Spacer(1, 3 * mm),
                        self._dns_bypass_verteilung_grafik(model, lang),
                    ]
                )
            )
            story.append(Spacer(1, 6 * mm))

        # ── Umgehungs-Detailliste ──
        # Die Verteilung nach Ziel wird ALLEIN ueber die Grafik oben gezeigt -- die frueher hier
        # stehende Tabelle "Verteilung nach Ziel-Resolver" war redundant und ist entfernt.
        # Die Detail-Liste auf eigener Seite (potentiell lang) -- PageBreak davor. Eigener
        # Render-Pfad, weil die Geraet-Zelle beim eigenen Host zweizeilig ist (Hostname +
        # dezente Kennzeichnung); _append_table_section kennt nur einzeilige Zellen.
        story.append(PageBreak())
        self._dns_bypass_detail_tabelle(story, styles, model.bypass_rows, lang)

        # ── Achse-B-Fussnote (invariant, wie im DNS-Waechter-/Aussenkontakte-Bericht) ──
        story.append(Spacer(1, 8 * mm))
        story.append(
            KeepTogether(
                [
                    HRFlowable(width="100%", thickness=0.6, color=_LINE),
                    Spacer(1, 2 * mm),
                    Paragraph(
                        model.achse_b_fussnote,
                        styles["footnote"],
                    ),
                ]
            )
        )

        # _draw_manual_header_footer ist auf ManualPdfModelLike typisiert, liest zur Laufzeit aber
        # NUR model.title + model.footer_left -- beide hat DnsBypassPdfModelLike ebenfalls (Muster
        # render_dns_watch_report_pdf): cast statt Aenderung der Kopf-/Fuss-Funktion.
        header_model = cast(ManualPdfModelLike, model)
        document.build(
            story,
            onFirstPage=lambda canvas, doc: _draw_manual_header_footer(
                canvas, doc, header_model, lang
            ),
            onLaterPages=lambda canvas, doc: _draw_manual_header_footer(
                canvas, doc, header_model, lang
            ),
        )
        return buffer.getvalue()

    def _dns_bypass_detail_tabelle(
        self,
        story: list[Flowable],
        styles: dict[str, ParagraphStyle],
        rows: tuple[tuple[str, ...], ...],
        lang: str = "de",
    ) -> None:
        """Haengt die Umgehungs-Detailliste an -- eigener Pfad wegen der zweizeiligen Geraet-Zelle.

        Wie ``_append_table_section`` (nummerierter Titel + Accent-Unterstrich + Tabelle, leerer
        Fallback, ``repeatRows=1``), ABER: die Geraet-Zelle (Spalte 0) kann beim eigenen Host ein
        einzelnes ``\\n`` tragen (Hostname + Kennzeichnung). Die erste Zeile wird als Name gesetzt,
        die zweite dezent (kleiner, gedaempfte Farbe) darunter -- als ``<br/>``-Paragraph. Zellen
        OHNE ``\\n`` bleiben einzeilig (Nicht-Self, unveraendert). Alle Werte werden maskiert
        (``_esc``), bevor das ``<br/>``/``<font>``-Markup gesetzt wird.
        """
        columns = DNS_BYPASS_ROW_COLUMNS
        story.append(Paragraph(_ui("bypass.detail", lang), styles["h_rubric"]))
        story.append(HRFlowable(width="100%", thickness=1.2, color=_ACCENT, spaceAfter=4))

        if not rows:
            leer_text = _empty_text(columns, lang)
            story.append(Paragraph(leer_text, styles["body"]))
            return

        # Dezenter Stil fuer die zweite Geraet-Zeile ("Dieser Rechner"): kleiner, gedaempft --
        # als Inline-Markup im selben Paragraph, damit Name und Kennzeichnung eine Zelle bleiben.
        # reportlab-Markup will "#RRGGBB"; hexval() liefert "0xRRGGBB" -> Praefix ersetzen.
        subtil = "#" + _CLEAN.hexval()[2:]

        render_data: list[list[object]] = [list[object](_header_labels(columns, lang))]
        for row in rows:
            geraet_roh = row[0]
            if "\n" in geraet_roh:
                name, _, kennzeichnung = geraet_roh.partition("\n")
                geraet_markup = (
                    f'{_esc(name)}<br/><font size="7" color="{subtil}">{_esc(kennzeichnung)}</font>'
                )
            else:
                geraet_markup = _esc(geraet_roh)
            zellen: list[object] = [Paragraph(geraet_markup, styles["cell"])]
            zellen.extend(Paragraph(_esc(value), styles["cell"]) for value in row[1:])
            render_data.append(zellen)

        table = Table(render_data, repeatRows=1, colWidths=_col_widths(columns))
        table.setStyle(self._base_table_style(len(render_data)))
        story.append(table)

    @staticmethod
    def _dns_bypass_kennzahlen(model: DnsBypassPdfModelLike, lang: str = "de") -> Table:
        """Die DNS-Umgehungs-Kennzahlen als eine Reihe Kennzahl-Boxen (Zahl oben, Label darunter).

        Reihe: Anfragen gesamt/Umgehungen/Erwartungsgemaess/Geraete. Eine 4-spaltige ``Table`` --
        schlichte graue Boxen mit Akzent-Zahl (Muster ``_dns_watch_kennzahlen``). Alle vier Boxen
        gefuellt. Reine Anzeige der schon ermittelten Zaehler aus dem Modell -- keine Rechnung,
        keine neuen Farben.
        """
        data = [
            [
                str(model.queries_total),
                str(model.bypass_total),
                str(model.expected_total),
                str(model.bypass_devices),
            ],
            [
                _ui("bypass.anfragen", lang),
                _ui("bypass.umgehungen", lang),
                _ui("bypass.erwartet", lang),
                _ui("bypass.geraete", lang),
            ],
        ]
        col = 174.0 / 4 * mm
        table = Table(data, colWidths=[col, col, col, col])
        table.setStyle(
            TableStyle(
                [
                    # Dezent graue Boxen (kein neues Farbset): Hintergrund _ZEBRA, Zahl in _ACCENT,
                    # Label in _TEXT. Muster _dns_watch_kennzahlen (Wert-Reihe FONTSIZE 20).
                    ("BACKGROUND", (0, 0), (-1, 1), _ZEBRA),
                    ("TEXTCOLOR", (0, 0), (-1, 0), _ACCENT),
                    ("TEXTCOLOR", (0, 1), (-1, 1), _TEXT),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 20),
                    ("FONTNAME", (0, 1), (-1, 1), "Helvetica"),
                    ("FONTSIZE", (0, 1), (-1, 1), 9),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("TOPPADDING", (0, 0), (-1, 0), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
                    ("TOPPADDING", (0, 1), (-1, 1), 4),
                    ("BOTTOMPADDING", (0, 1), (-1, 1), 8),
                ]
            )
        )
        return table

    def _dns_bypass_verteilung_grafik(
        self, model: DnsBypassPdfModelLike, lang: str = "de"
    ) -> Table:
        """Verteilung nach Ziel (Variante C): gestapelter horizontaler Balken + Legende.

        Zeichnet aus ``model.resolver_distribution`` (Tripel ``(resolver_name, dst_ip,
        count)``, anfragestaerkste zuerst) EINEN horizontalen Balken, dessen Segmente die
        Ziele nach ``count`` ANTEILIG zeigen (Segment-Breite = Anteil an der Summe). Die
        Farben stammen aus ``_DIST_PALETTE`` (bestehende Renderer-Tokens, staerkstes Ziel =
        Akzent), zyklisch je Index. Darunter eine Legende: je Ziel ein Farb-Quadrat + Name
        (falls vorhanden) + rohe IP + Anzahl. Reine Anzeige der schon ermittelten Werte --
        nur die Balken-Geometrie, keine neuen Farbkonstanten.

        Robust: leere Verteilung -> nur der ``h_section``-Titel ohne Grafik (der Aufrufer
        haengt den Titel getrennt an); die Summe 0 wuerde zu einer Division fuehren, darum
        wird sie hier abgefangen (leerer Balken).
        """
        styles = self._security_styles()
        eintraege = model.resolver_distribution
        summe = sum(count for _, _, count in eintraege) or 1

        bar_breite = _CONTENT_WIDTH_MM * mm
        bar_hoehe = 10.0 * mm
        drawing = Drawing(bar_breite, bar_hoehe)
        # Dezente Grundbahn hinter den Segmenten (falls Rundungsreste eine Luecke lassen).
        drawing.add(Rect(0.0, 0.0, bar_breite, bar_hoehe, fillColor=_ZEBRA, strokeColor=None))
        x = 0.0
        for i, (_, _, count) in enumerate(eintraege):
            seg_breite = bar_breite * (count / summe)
            farbe = _DIST_PALETTE[i % len(_DIST_PALETTE)]
            drawing.add(Rect(x, 0.0, seg_breite, bar_hoehe, fillColor=farbe, strokeColor=None))
            x += seg_breite

        # Legende: je Ziel ein Farb-Quadrat + Name (Beigabe) + rohe IP + Anzahl. Die rohe IP
        # bleibt immer sichtbar; ist ein Name da, steht er davor.
        legende_data: list[list[object]] = []
        for i, (resolver_name, dst_ip, count) in enumerate(eintraege):
            farbe = _DIST_PALETTE[i % len(_DIST_PALETTE)]
            swatch = Drawing(10.0, 10.0)
            swatch.add(Rect(0.0, 1.0, 8.0, 8.0, fillColor=farbe, strokeColor=None))
            beschriftung = f"{resolver_name} ({dst_ip})" if resolver_name else dst_ip
            legende_data.append([swatch, Paragraph(_esc(beschriftung), styles["cell"]), str(count)])

        legende = Table(legende_data, colWidths=[14.0, None, 60.0])
        legende.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("ALIGN", (0, 0), (0, -1), "CENTER"),
                    ("ALIGN", (2, 0), (2, -1), "RIGHT"),
                    ("FONTNAME", (2, 0), (2, -1), "Helvetica"),
                    ("FONTSIZE", (1, 0), (-1, -1), 9),
                    ("TEXTCOLOR", (1, 0), (-1, -1), _TEXT),
                    ("TOPPADDING", (0, 0), (-1, -1), 1),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
                    ("LEFTPADDING", (0, 0), (-1, -1), 2),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 2),
                ]
            )
        )

        block = Table([[drawing], [Spacer(1, 3 * mm)], [legende]], colWidths=[bar_breite])
        block.setStyle(TableStyle([("ALIGN", (0, 0), (-1, -1), "LEFT")]))
        return block

    # ── Verhaltensprofil-Bericht: eigener Render-Pfad ───────────────────────────
    #
    # NEUE Methoden neben render_dns_bypass_report_pdf -- alle bestehenden Pfade bleiben
    # UNANGETASTET. Rendert das render-fertige BehaviorPdfModel (Kennzahlen + Tagesband +
    # Wochen-Heatmap bei scope="single", Geraete-Uebersichtstabelle bei scope="all"). Kein
    # Import des application-Modells (import-linter); struktureller Vertrag ueber
    # BehaviorPdfModelLike. KEINE Uhr, KEINE Rechnung ausser reiner Balken-/Raster-Geometrie.

    # Spaltenkoepfe der "alle Geraete"-Tabelle -- WOERTLICHE Spiegelung von
    # BEHAVIOR_ENTRY_COLUMNS (application.reporting.behavior_pdf_model). Der Adapter darf die
    # Modell-Datei nicht importieren, also liegen die Strings hier lokal (Muster: der Adapter
    # haelt die DNS_*_COLUMNS-Spiegelung ebenfalls lokal). Reihenfolge/Schreibweise identisch.
    _BEHAVIOR_ENTRY_COLUMNS_LOCAL: tuple[str, ...] = (
        "Gerät",
        "Aufzeichnungstage",
        "Genug Daten",
        "Abweichungen",
        "Aktivste Zeit",
        "Aktivster Tag",
    )

    # Englische Anzeige-Koepfe zu _BEHAVIOR_ENTRY_COLUMNS_LOCAL. Liegt hier statt in
    # _HEADER_LABELS_EN, weil das deutsche Schluessel-Tupel eine Klassen-Konstante ist und auf
    # Modul-Ebene noch nicht existiert; Rolle und Fallback-Verhalten sind identisch.
    _BEHAVIOR_ENTRY_HEADER_LABELS_EN: ClassVar[dict[tuple[str, ...], tuple[str, ...]]] = {
        _BEHAVIOR_ENTRY_COLUMNS_LOCAL: (
            "Device",
            "Recording Days",
            "Enough Data",
            "Deviations",
            "Most Active Time",
            "Most Active Day",
        ),
    }

    def render_behavior_report_pdf(self, model: BehaviorPdfModelLike, lang: str = "de") -> bytes:
        """Rendert das ``BehaviorPdfModel`` zum Verhaltensprofil-Bericht-PDF (A4 hoch).

        Layout (Muster ``render_dns_bypass_report_pdf``): durchgaengige Kopf-/Fusszeile je Seite
        (onFirstPage UND onLaterPages ueber ``_draw_manual_header_footer``), dann die Story --
        Titel + Erzeugungsdatum + Einleitung, die fertige Bezugsrahmen-Zeile (``scope_text``) und
        eine Verzweigung nach ``scope``:

          * ``"single"`` -- Kennzahlen-Tabelle (Label/Wert) + Tagesverlauf-Grafik (Tagesband) +
            Wochenmuster-Grafik (Heatmap). Sind beide Grafik-Datensaetze leer, steht statt der
            Grafiken ein dezenter Hinweis-Absatz.
          * ``"all"`` -- eine Geraete-Uebersichtstabelle (leere Tabelle -> Leer-Fallback-Absatz).

        Robust: KEINE Uhr, KEINE Rechnung -- alle Texte/Zahlen kommen fertig aus dem Modell
        (die Grafiken tragen nur strukturierte Zahlen und rechnen reine Balken-Geometrie).
        Liefert valide PDF-Bytes (Magic-Header ``%PDF``).
        """
        buffer = io.BytesIO()
        document = SimpleDocTemplate(
            buffer,
            pagesize=A4,  # Hochformat (Muster DNS-Umgehung)
            leftMargin=18 * mm,
            rightMargin=18 * mm,
            topMargin=32 * mm,  # Platz fuer die durchgaengige Kopfzeile
            bottomMargin=20 * mm,  # Platz fuer die Fusszeile
            title=model.title,
        )

        story: list[Flowable] = []
        styles = self._security_styles()

        # ── Titel + Erzeugungsdatum + Einleitung (fertige Texte aus dem Modell) ──
        story.append(Paragraph(model.title, styles["h_title"]))
        story.append(Paragraph(model.generated_at_text, styles["sub"]))
        story.append(Spacer(1, 4 * mm))
        if model.einleitung:
            story.append(Paragraph(model.einleitung, styles["body"]))
            story.append(Spacer(1, 6 * mm))

        # ── Bezugsrahmen-Zeile (fertig lokalisiert vom Composition Root) ──
        story.append(Paragraph(model.scope_text, styles["sub"]))
        story.append(Spacer(1, 4 * mm))

        if model.scope == "single":
            # ── Kennzahlen (Label/Wert) ──
            story.append(Paragraph(_ui("beh.kennzahlen", lang), styles["h_section"]))
            story.append(self._behavior_kennzahlen(model, lang))
            story.append(Spacer(1, 6 * mm))

            if not model.day_band and not model.week_heatmap:
                # Zu wenig Daten fuer ein Profil -> dezenter Hinweis statt der Grafiken.
                story.append(
                    Paragraph(
                        _ui("beh.keine_daten", lang),
                        styles["body"],
                    )
                )
            else:
                # ── Tagesverlauf (Tagesband) ──
                story.append(
                    KeepTogether(
                        [
                            Paragraph(_ui("beh.tagesband", lang), styles["h_section"]),
                            Spacer(1, 3 * mm),
                            self._behavior_tagesband(model),
                        ]
                    )
                )
                story.append(Spacer(1, 6 * mm))
                # ── Wochenmuster (Heatmap) ──
                story.append(
                    KeepTogether(
                        [
                            Paragraph(_ui("beh.heatmap", lang), styles["h_section"]),
                            Spacer(1, 3 * mm),
                            self._behavior_heatmap(model),
                        ]
                    )
                )
        else:
            # ── scope == "all": Geraete-Uebersicht ──
            story.append(Paragraph(_ui("beh.geraete", lang), styles["h_section"]))
            if not model.entry_rows:
                story.append(
                    Paragraph(
                        _ui("beh.keine_geraete", lang),
                        styles["body"],
                    )
                )
            else:
                columns = self._BEHAVIOR_ENTRY_COLUMNS_LOCAL
                kopf = self._BEHAVIOR_ENTRY_HEADER_LABELS_EN.get(columns)
                render_data: list[list[object]] = [
                    list(kopf) if lang == "en" and kopf is not None else list(columns)
                ]
                for row in model.entry_rows:
                    render_data.append([Paragraph(_esc(value), styles["cell"]) for value in row])
                table = Table(render_data, repeatRows=1, colWidths=_col_widths(columns))
                table.setStyle(self._base_table_style(len(render_data)))
                story.append(table)

        # ── Achse-B-Fussnote (invariant, wie im DNS-Umgehungs-Bericht) ──
        story.append(Spacer(1, 8 * mm))
        story.append(
            KeepTogether(
                [
                    HRFlowable(width="100%", thickness=0.6, color=_LINE),
                    Spacer(1, 2 * mm),
                    Paragraph(
                        model.achse_b_fussnote,
                        styles["footnote"],
                    ),
                ]
            )
        )

        # _draw_manual_header_footer ist auf ManualPdfModelLike typisiert, liest zur Laufzeit aber
        # NUR model.title + model.footer_left -- beide hat BehaviorPdfModelLike ebenfalls (Muster
        # render_dns_bypass_report_pdf): cast statt Aenderung der Kopf-/Fuss-Funktion.
        header_model = cast(ManualPdfModelLike, model)
        document.build(
            story,
            onFirstPage=lambda canvas, doc: _draw_manual_header_footer(
                canvas, doc, header_model, lang
            ),
            onLaterPages=lambda canvas, doc: _draw_manual_header_footer(
                canvas, doc, header_model, lang
            ),
        )
        return buffer.getvalue()

    @staticmethod
    def _behavior_kennzahlen(model: BehaviorPdfModelLike, lang: str = "de") -> Table:
        """Die Einzelprofil-Kennzahlen als schlichte zweispaltige Label/Wert-Tabelle (dezent).

        ``model.single_kennzahlen`` ist eine Liste fertiger ``(Label, Wert)``-Paare. Eine
        schlichte 2-spaltige ``Table`` in ruhigem Stil (Label in ``_TEXT``, Wert in ``_ACCENT``,
        Zebra-Zeilen) -- keine Rechnung, keine neuen Farben. Leere Liste -> leere Tabelle mit
        einer Platzhalter-Zeile, damit reportlab keine 0-Zeilen-Tabelle rendern muss.
        """
        paare = model.single_kennzahlen or (("—", "—"),)
        data: list[list[object]] = [[label, wert] for label, wert in paare]
        table = Table(data, colWidths=[60 * mm, 40 * mm])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), _ZEBRA),
                    ("TEXTCOLOR", (0, 0), (0, -1), _TEXT),
                    ("TEXTCOLOR", (1, 0), (1, -1), _ACCENT),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica"),
                    ("FONTNAME", (1, 0), (1, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("ALIGN", (1, 0), (1, -1), "RIGHT"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("LINEBELOW", (0, 0), (-1, -1), 0.4, _LINE),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ]
            )
        )
        return table

    def _behavior_tagesband(self, model: BehaviorPdfModelLike) -> Flowable:
        """Tagesverlauf: EINE Reihe vertikaler Balken je Tages-Slot (Hoehe = relative Aktivitaet).

        Zeichnet aus ``model.day_band`` (Tripel ``(slot_start, activity_count, is_deviation)``,
        nach ``slot_start`` aufsteigend) je Slot einen vertikalen Balken; die Hoehe ist
        proportional zu ``activity_count / max(activity_count)`` (max 0 -> alle leer, kein
        Div-by-0). Abweichungs-Slots (``is_deviation``) in der Akzentfarbe ``_ACCENT``, normale
        dezent in ``_CLEAN`` -- bestehende Renderer-Tokens, KEINE neuen Farben. Unter den Balken
        sparsam Uhrzeit-Achsenmarken aus ``slot_start`` (Minuten seit Mitternacht), nur an jeder
        vollen Stunde, damit die Achse lesbar bleibt. Leeres Band -> dezente Grundbahn.
        """
        slots = sorted(model.day_band, key=lambda s: s[0])
        breite = _CONTENT_WIDTH_MM * mm
        plot_hoehe = 22.0 * mm
        achse_hoehe = 5.0 * mm
        gesamt_hoehe = plot_hoehe + achse_hoehe
        drawing = Drawing(breite, gesamt_hoehe)
        # Dezente Grundbahn (Basislinie) hinter den Balken.
        drawing.add(Rect(0.0, achse_hoehe, breite, plot_hoehe, fillColor=_ZEBRA, strokeColor=None))
        if not slots:
            return drawing

        max_count = max((count for _, count, _ in slots), default=0) or 1
        n = len(slots)
        slot_breite = breite / n
        # Schmaler Balken mittig im Slot, etwas Luft an den Seiten.
        bar_breite = slot_breite * 0.7
        bar_offset = (slot_breite - bar_breite) / 2.0
        for i, (slot_start, count, is_deviation) in enumerate(slots):
            hoehe = plot_hoehe * (count / max_count)
            x = i * slot_breite + bar_offset
            farbe = _ACCENT if is_deviation else _CLEAN
            if hoehe > 0:
                drawing.add(
                    Rect(x, achse_hoehe, bar_breite, hoehe, fillColor=farbe, strokeColor=None)
                )
            # Achsenmarke nur an voller Stunde (slot_start Minuten seit Mitternacht).
            if slot_start % 60 == 0:
                drawing.add(
                    String(
                        i * slot_breite + slot_breite / 2.0,
                        0.0,
                        f"{slot_start // 60:02d}:{slot_start % 60:02d}",
                        fontName="Helvetica",
                        fontSize=6,
                        fillColor=_TEXT,
                        textAnchor="middle",
                    )
                )
        return drawing

    def _behavior_heatmap(self, model: BehaviorPdfModelLike) -> Flowable:
        """Wochenmuster: Raster 7 Zeilen (Mo oben) x N Spalten (Slots), Intensitaet = Aktivitaet.

        Zeichnet aus ``model.week_heatmap`` (Zellen ``(weekday, slot_start, activity_count,
        is_deviation)``) ein Raster: 7 Zeilen (``weekday`` 0..6, Mo oben) x den distinct
        ``slot_start`` aufsteigend. Die Zell-Fuellung ist ``_ACCENT`` mit einer Deckkraft
        proportional zu ``activity_count / global max`` (max 0 -> leeres Raster, kein Div-by-0)
        -- bestehendes Token, nur die Alpha-Intensitaet variiert. Abweichungs-Zellen tragen
        zusaetzlich eine dezente ``_ACCENT``-Umrandung. Links beschriften ``model.weekday_labels``
        die Zeilen (leer -> Index als Fallback), unten sparsam Uhrzeit-Marken aus ``slot_start``
        (nur an voller Stunde). Reine Raster-Geometrie, KEINE neuen Farben.
        """
        zellen = model.week_heatmap
        slot_starts = sorted({slot_start for _, slot_start, _, _ in zellen})
        labels = model.weekday_labels
        label_w = 10.0 * mm
        achse_hoehe = 5.0 * mm
        zeilen_hoehe = 6.0 * mm
        raster_hoehe = zeilen_hoehe * 7
        breite = _CONTENT_WIDTH_MM * mm
        raster_breite = breite - label_w
        gesamt_hoehe = raster_hoehe + achse_hoehe
        drawing = Drawing(breite, gesamt_hoehe)

        # Leeres Raster (keine Spalten) -> nur die Zeilen-Beschriftung, kein Div-by-0.
        n_spalten = len(slot_starts)
        zell_breite = raster_breite / n_spalten if n_spalten else raster_breite
        max_count = max((count for _, _, count, _ in zellen), default=0) or 1
        # Aktivitaet je (weekday, slot_start) fuer schnellen Lookup.
        werte: dict[tuple[int, int], tuple[int, bool]] = {
            (weekday, slot_start): (count, is_deviation)
            for weekday, slot_start, count, is_deviation in zellen
        }

        for zeile in range(7):
            # weekday 0 (Mo) oben: y faellt mit steigender Zeile.
            y = achse_hoehe + raster_hoehe - (zeile + 1) * zeilen_hoehe
            beschriftung = labels[zeile] if zeile < len(labels) else str(zeile)
            drawing.add(
                String(
                    0.0,
                    y + zeilen_hoehe / 2.0 - 3.0,
                    beschriftung,
                    fontName="Helvetica",
                    fontSize=7,
                    fillColor=_TEXT,
                )
            )
            for spalte, slot_start in enumerate(slot_starts):
                x = label_w + spalte * zell_breite
                count, is_deviation = werte.get((zeile, slot_start), (0, False))
                # Intensitaet als Deckkraft des Akzents (bestehendes Token, nur Alpha variiert).
                anteil = count / max_count
                zell_farbe = colors.Color(_ACCENT.red, _ACCENT.green, _ACCENT.blue, alpha=anteil)
                rand = _ACCENT if is_deviation else _LINE
                drawing.add(
                    Rect(
                        x,
                        y,
                        zell_breite,
                        zeilen_hoehe,
                        fillColor=zell_farbe,
                        strokeColor=rand,
                        strokeWidth=1.0 if is_deviation else 0.3,
                    )
                )

        # Uhrzeit-Marken unten, nur an voller Stunde.
        for spalte, slot_start in enumerate(slot_starts):
            if slot_start % 60 == 0:
                drawing.add(
                    String(
                        label_w + spalte * zell_breite + zell_breite / 2.0,
                        0.0,
                        f"{slot_start // 60:02d}:{slot_start % 60:02d}",
                        fontName="Helvetica",
                        fontSize=6,
                        fillColor=_TEXT,
                        textAnchor="middle",
                    )
                )
        return drawing

    # ── Benutzerhandbuch: eigener Render-Pfad ───────────────────────────────
    #
    # NEUE Methode neben render_security_report_pdf -- beide bleiben UNANGETASTET (der
    # Sicherheitsbericht-Pfad wird nicht angefasst). Dieser Pfad rendert das schlanke
    # ManualPdfModel (Titel + optionale Einleitung + Kategorie-gruppierte Abschnitte) mit
    # durchgaengiger Kopf-/Fusszeile (Kopf-Titel parameterisiert ueber model.title).

    def render_manual_pdf(self, model: ManualPdfModelLike) -> bytes:
        """Rendert das ``ManualPdfModel`` zum Benutzerhandbuch-PDF (A4 hoch).

        Layout: durchgaengige Kopf-/Fusszeile je Seite (onFirstPage UND onLaterPages ueber
        EINEN gemeinsamen Callback, Kopf-Titel = ``model.title``), dann die Story -- Titel,
        Erzeugungsdatum, optionale Einleitung, danach die Abschnitte. Eine Kategorie-
        Ueberschrift erscheint nur EINMAL, solange sie sich nicht aendert (Muster
        ``_append_table_section``-Rubrik). Lange Texte brechen automatisch um (Paragraph);
        aktive XML-Zeichen werden via ``_esc`` maskiert. ``KeepTogether`` haelt eine
        Abschnitts-Ueberschrift mit ihrem ersten Absatz zusammen.

        Robust: leere ``sections`` -> nur Kopf/Titel (ehrlicher Leerfall, kein Absturz).
        Liefert valide PDF-Bytes (Magic-Header ``%PDF``).
        """
        buffer = io.BytesIO()
        document = SimpleDocTemplate(
            buffer,
            pagesize=A4,  # Hochformat (Auftrag)
            leftMargin=18 * mm,
            rightMargin=18 * mm,
            topMargin=32 * mm,  # Platz fuer die durchgaengige Kopfzeile
            bottomMargin=20 * mm,  # Platz fuer die Fusszeile
            title=model.title,
        )

        story: list[Flowable] = []
        styles = self._security_styles()

        # Eingerueckte Varianten NUR fuers Handbuch -- lokal, NICHT in _security_styles,
        # damit der geteilte Sicherheitsbericht-Stilsatz voellig unberuehrt bleibt. Die
        # Einrueckung macht die Struktur "Kategorie -> darunter die Abschnitte" sichtbar:
        # die Kategorie-Ueberschrift (h_rubric) bleibt am linken Rand, die Abschnitte
        # ruecken dezent ein.
        _INDENT = 11  # Punkt; dezent, aber sichtbar
        h_section_indent = ParagraphStyle(
            "h_section_indent", parent=styles["h_section"], leftIndent=_INDENT
        )
        body_indent = ParagraphStyle("body_indent", parent=styles["body"], leftIndent=_INDENT)

        # ── Titel + Erzeugungsdatum + optionale Einleitung ──
        story.append(Paragraph(_esc(model.title), styles["h_title"]))
        story.append(Paragraph(_esc(model.generated_at_text), styles["sub"]))
        story.append(Spacer(1, 4 * mm))
        if model.intro:
            story.append(Paragraph(_esc(model.intro), styles["body"]))
            story.append(Spacer(1, 6 * mm))

        # ── Abschnitte, nach Kategorie gruppiert ──
        # Die Kategorie-Ueberschrift wird nur ausgegeben, wenn sie sich gegenueber dem vorigen
        # Abschnitt aendert (Muster: Rubrik-Ueberschrift in _append_table_section).
        prev_category: str | None = None
        for section in model.sections:
            if section.category_label != prev_category:
                # Jede NEUE Kategorie beginnt auf einer eigenen Seite -- ausser der
                # allerersten (die folgt direkt auf Titel/Einleitung, kein PageBreak).
                if prev_category is not None:
                    story.append(PageBreak())
                story.append(Paragraph(_esc(section.category_label), styles["h_rubric"]))
                story.append(HRFlowable(width="100%", thickness=1.2, color=_ACCENT, spaceAfter=4))
                # Etwas Luft zwischen Kategorie-Ueberschrift/Trennlinie und erstem Abschnitt.
                story.append(Spacer(1, 2 * mm))
                prev_category = section.category_label

            # Ueberschrift + erster Absatz zusammenhalten, damit eine heading nicht allein
            # unten auf einer Seite landet (Muster KeepTogether im Sicherheitsbericht). Die
            # Abschnitte nutzen die eingerueckten Stile (h_section_indent/body_indent).
            head_block: list[Flowable] = [Paragraph(_esc(section.heading), h_section_indent)]
            if section.paragraphs:
                head_block.append(Paragraph(_esc(section.paragraphs[0]), body_indent))
            story.append(KeepTogether(head_block))
            # Die restlichen Absaetze einzeln (jeder umbrechbar).
            for para in section.paragraphs[1:]:
                story.append(Paragraph(_esc(para), body_indent))
            story.append(Spacer(1, 6 * mm))

        document.build(
            story,
            onFirstPage=lambda canvas, doc: _draw_manual_header_footer(canvas, doc, model),
            onLaterPages=lambda canvas, doc: _draw_manual_header_footer(canvas, doc, model),
        )
        return buffer.getvalue()


# ── Freistehende Render-Helfer des Sicherheitsbericht-Pfads ──────────────────
#
# Bewusst Modul-Funktionen (nicht Methoden): die Kopf-/Fusszeile braucht reportlab der
# onPage-Callback als einfache Funktion, und die Vektor-Grafiken (Gauge/Donut/Balken) sind
# reine (model-werte -> Drawing)-Funktionen ohne Adapter-Zustand. Alle zustandslos.

# Englische Anzeige-Koepfe je bekanntem Rubrik-Schema. Schluessel ist das ROHE deutsche
# Kopf-Tupel -- dieses bleibt unveraendert der Steuer-Schluessel (_COL_WEIGHTS,
# _EMPTY_SECTION_TEXT, columns.index("Schwere"/"Severity")); uebersetzt wird AUSSCHLIESSLICH
# der angezeigte Kopf-Text. Wie die *_COLUMNS selbst LOKAL gefuehrt: der Adapter darf
# ``application`` NICHT importieren (import-linter), es gibt hier also weder LocalizedText noch
# einen Lang-Typ -- die Sprache ist ein schlichtes Literal "de"/"en".
_HEADER_LABELS_EN: dict[tuple[str, ...], tuple[str, ...]] = {
    PORT_COLUMNS: ("Device", "Ports", "Severity", "Reason"),
    CVE_COLUMNS: ("Device", "CVE", "CVSS", "Service", "Description"),
    NET_COLUMNS: ("Type", "Device", "Severity", "Description"),
    ACK_COLUMNS: ("Type", "Device", "Detail"),
    INVENTORY_COLUMNS: (
        "Device",
        "Vendor",
        "Last IP",
        "First Seen",
        "Last Seen",
        "Seen",
        "Category",
        "Status",
    ),
    ARCHIVED_COLUMNS: ("Device", "Vendor", "Last IP", "Last Seen", "Status"),
    _CVE_DEVICE_COLUMNS: ("Device", "Findings", "Highest Severity", "Highest CVSS", "Services"),
    _CVE_SERVICE_COLUMNS: (
        "Service",
        "Findings",
        "Devices",
        "Highest Severity",
        "Highest CVSS",
        "Oldest Published",
    ),
    _CVE_FINDING_COLUMNS: (
        "Device",
        "CVE",
        "Severity",
        "CVSS",
        "Service",
        "Port",
        "First Seen",
        "Status",
    ),
    _CVE_FINDING_GROUP_COLUMNS: (
        "CVE",
        "Severity",
        "CVSS",
        "Service",
        "Port",
        "First Seen",
        "Status",
    ),
    _OUTBOUND_CONTACT_COLUMNS: ("Peer", "Name", "Country", "Operator", "Contacts", "Assessment"),
    _OUTBOUND_COUNTRY_COLUMNS: ("Country", "Peers"),
    _OUTBOUND_OPERATOR_COLUMNS: ("Operator", "Peers"),
    DNS_CATEGORY_COLUMNS: ("Category", "Contacts"),
    DNS_APP_COLUMNS: ("Application", "Contacts"),
    DNS_CONTACT_COLUMNS: ("Category", "Peer", "Name", "Application", "Contacts", "Status"),
    DNS_BYPASS_ROW_COLUMNS: (
        "Device",
        "Source IP",
        "Target Resolver",
        "DoH",
        "Queries",
        "Queried Names",
    ),
    # Inline-Schemata der beiden Verteilungs-Tabellen im Bestandsbericht (kein Modul-Konstanten-
    # Tupel, weil _append_distribution_table sie direkt am Aufrufer uebergeben bekommt).
    ("Hersteller", "Anzahl"): ("Vendor", "Count"),
    ("Kategorie", "Anzahl"): ("Category", "Count"),
}


def _header_labels(columns: tuple[str, ...], lang: str) -> list[str]:
    """Liefert die ANZEIGE-Koepfe eines Rubrik-Schemas in der gewuenschten Sprache.

    Bei ``lang == "en"`` die englischen Koepfe aus ``_HEADER_LABELS_EN``; ist das Schema dort
    nicht hinterlegt, fallen die rohen deutschen Koepfe durch (Fallback statt ``KeyError``).
    Bei ``"de"`` -- und jedem anderen Wert -- immer die rohen deutschen Koepfe. Aendert NICHTS
    an der Steuer-Rolle von ``columns``; der Aufrufer nutzt das rohe Tupel unveraendert weiter.
    """
    if lang == "en":
        english = _HEADER_LABELS_EN.get(columns)
        if english is not None:
            return list(english)
    return list(columns)


# Nutzbare Druckbreite einer A4-Hochformat-Seite bei 18 mm Seitenraendern (Single Source fuer
# die Spaltenbreiten-Berechnung). A4-Breite 210 mm - 2*18 mm = 174 mm.
_CONTENT_WIDTH_MM = 174.0

# Proportionale Spaltengewichte je bekanntem Rubrik-Schema (Summe egal -- es wird normiert).
# So fuellt jede Tabelle exakt die Druckbreite, mit sinnvoll breiten Text-/schmalen Wertspalten.
_COL_WEIGHTS: dict[tuple[str, ...], tuple[float, ...]] = {
    PORT_COLUMNS: (3.0, 2.0, 1.6, 4.0),
    CVE_COLUMNS: (3.4, 1.6, 1.0, 1.7, 4.0),
    NET_COLUMNS: (2.2, 2.6, 1.6, 5.0),
    ACK_COLUMNS: (2.4, 3.0, 5.0),
    # Bestandsbericht: Geraet-Spalte breiter, die schmalen Wert-Spalten (Gesehen) schlank --
    # damit fuellt die 8-spaltige Geraete-Tabelle die Druckbreite lesbar (Muster der Security-
    # Gewichte). Eigene Keys, die bestehenden Aufrufer (PORT/CVE/NET/ACK) bleiben unberuehrt.
    INVENTORY_COLUMNS: (2.4, 1.6, 1.5, 1.9, 1.9, 1.1, 1.7, 1.5),
    ARCHIVED_COLUMNS: (3.0, 2.2, 1.8, 2.0, 1.8),
    # CVE-Bericht: Geraet/Dienst breit, die schmalen Wert-/Severity-Spalten schlank -- damit
    # fuellen die drei CVE-Tabellen die Druckbreite lesbar (Muster der Inventory-Gewichte).
    # Eigene Keys; die bestehenden Aufrufer bleiben unberuehrt.
    _CVE_DEVICE_COLUMNS: (2.8, 1.2, 1.8, 1.6, 3.2),
    _CVE_SERVICE_COLUMNS: (2.4, 1.2, 1.2, 1.8, 1.6, 2.4),
    _CVE_FINDING_COLUMNS: (2.4, 2.0, 1.4, 1.0, 1.6, 0.9, 1.9, 1.4),
    # Gruppierte Befundliste (ohne Geraet-Spalte -- die steht im Host-Kopf).
    _CVE_FINDING_GROUP_COLUMNS: (2.0, 1.4, 1.0, 1.6, 0.9, 1.9, 1.6),
    # Aussenkontakte-Bericht: Gegenstelle/Name/Betreiber breit, die schmalen Wert-Spalten
    # (Land/Kontakte) schlank, die Bewertung wieder breiter (Listennamen). Eigene Keys; die
    # bestehenden Aufrufer bleiben unberuehrt. Die Verteilungs-Tabellen tragen das
    # Inventory-Verteilungsmuster (Label breit, Anzahl schmal).
    _OUTBOUND_CONTACT_COLUMNS: (2.4, 2.6, 1.4, 2.0, 1.0, 2.2),
    _OUTBOUND_COUNTRY_COLUMNS: (5.0, 1.8),
    _OUTBOUND_OPERATOR_COLUMNS: (5.0, 1.8),
    # DNS-Waechter-Bericht: Gegenstelle/Name/Programm breit, die schmalen Wert-Spalten
    # (Kontakte/Status) schlank, die Kategorie wieder breiter (Klartext). Eigene Keys; die
    # bestehenden Aufrufer bleiben unberuehrt. Die Verteilungs-Tabellen tragen das
    # Verteilungsmuster (Label breit, Anzahl schmal).
    DNS_CONTACT_COLUMNS: (1.8, 2.4, 2.4, 2.0, 1.0, 1.4),
    DNS_CATEGORY_COLUMNS: (5.0, 1.8),
    DNS_APP_COLUMNS: (5.0, 1.8),
    # DNS-Umgehungs-Bericht: Geraet/Quell-IP/Ziel-Resolver/Beispiel-Namen breit, die schmalen
    # Wert-Spalten (DoH/Anfragen) schlank -- ABER die DoH-Spalte breit genug fuer das einzeilige
    # "Bekannt" (sonst bricht es haesslich zu "Bekann/t"); "Abgefragte Namen" gibt dafuer etwas
    # Breite ab. Eigener Key; die bestehenden Aufrufer bleiben unberuehrt.
    DNS_BYPASS_ROW_COLUMNS: (2.0, 2.0, 2.2, 1.2, 1.0, 2.2),
}

# Rubrikspezifischer Leertext je Tabellen-Schema (statt generisch "Keine Eintraege.").
# Unbekannte Rubriken fallen auf _EMPTY_FALLBACK zurueck. ACK braucht keinen Eintrag, da der
# Aufrufer leere ACK-Rubriken gar nicht erst rendert.
_EMPTY_FALLBACK: dict[str, str] = {
    "de": "Keine Einträge in dieser Kategorie.",
    "en": "No entries in this category.",
}
_EMPTY_SECTION_TEXT: dict[tuple[str, ...], dict[str, str]] = {
    PORT_COLUMNS: {"de": "Keine auffälligen Ports festgestellt.", "en": "No notable ports found."},
    CVE_COLUMNS: {"de": "Keine CVE-Befunde vorhanden.", "en": "No CVE findings."},
    NET_COLUMNS: {"de": "Keine Netz-Auffälligkeiten festgestellt.", "en": "No network findings."},
    _CVE_DEVICE_COLUMNS: {"de": "Keine betroffenen Geräte.", "en": "No affected devices."},
    _CVE_SERVICE_COLUMNS: {"de": "Keine Dienste mit Befunden.", "en": "No services with findings."},
    _CVE_FINDING_COLUMNS: {"de": "Keine CVE-Befunde vorhanden.", "en": "No CVE findings."},
    _CVE_FINDING_GROUP_COLUMNS: {"de": "Keine CVE-Befunde vorhanden.", "en": "No CVE findings."},
    _OUTBOUND_CONTACT_COLUMNS: {
        "de": "Keine Außenkontakte aufgezeichnet.",
        "en": "No external contacts recorded.",
    },
    _OUTBOUND_COUNTRY_COLUMNS: {"de": "Keine Länderdaten.", "en": "No country data."},
    _OUTBOUND_OPERATOR_COLUMNS: {"de": "Keine Betreiberdaten.", "en": "No operator data."},
    DNS_CONTACT_COLUMNS: {
        "de": "Keine DNS-relevanten Außenkontakte aufgezeichnet.",
        "en": "No DNS-relevant external contacts recorded.",
    },
    DNS_CATEGORY_COLUMNS: {"de": "Keine Kategoriedaten.", "en": "No category data."},
    DNS_APP_COLUMNS: {"de": "Keine Programmdaten.", "en": "No application data."},
    DNS_BYPASS_ROW_COLUMNS: {
        "de": "Keine DNS-Umgehungen aufgezeichnet.",
        "en": "No DNS bypasses recorded.",
    },
}


def _empty_text(columns: tuple[str, ...], lang: str) -> str:
    entry = _EMPTY_SECTION_TEXT.get(columns, _EMPTY_FALLBACK)
    return entry.get(lang) or entry.get("de") or ""


def _col_widths(columns: tuple[str, ...]) -> list[float]:
    """Verteilt die Druckbreite proportional auf die Spalten des Rubrik-Schemas -- in Punkten.

    Greift auf die festen Gewichte je bekanntem Schema (``_COL_WEIGHTS``) zurueck und normiert
    sie auf die nutzbare Breite. Ein unbekanntes Schema (sollte nicht vorkommen) faellt auf
    gleich breite Spalten zurueck -- ein lesbarer Default statt eines Absturzes.
    """
    weights = _COL_WEIGHTS.get(columns)
    if weights is None or len(weights) != len(columns):
        weights = tuple(1.0 for _ in columns)
    total = sum(weights)
    content_pt = _CONTENT_WIDTH_MM * mm
    return [content_pt * (w / total) for w in weights]


def _esc(text: str) -> str:
    """Maskiert die fuer reportlab-Paragraphs aktiven XML-Zeichen -- rein, deterministisch.

    Tabellenzellen werden als ``Paragraph`` gesetzt (umbrechbar); reportlab interpretiert darin
    ein paar Mini-Markup-Zeichen. ``&``/``<``/``>`` werden maskiert, damit ein Geraetename wie
    "A & B <lab>" buchstaeblich erscheint und das Rendern nicht bricht.
    """
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# Klartext-Severity -> Badge-Farbe (fuer die "Schwere"-Zellen). Andere Werte bleiben ungefaerbt.
_SEVERITY_BADGE = {"kritisch": _CRIT, "auffällig": _NOTABLE}


def _apply_severity_badges(style: TableStyle, data: list[list[object]], severity_col: int) -> None:
    """Faerbt die Severity-Zellen einer Tabelle als Badge ein (Hintergrund + weisser Text).

    Geht die Datenzeilen (ab Zeile 1, Kopf ausgenommen) durch und setzt fuer jede Zelle der
    ``severity_col`` mit Klartext "kritisch"/"auffaellig" einen farbigen Hintergrund + weissen,
    fett gesetzten Text. Mutiert das uebergebene ``TableStyle`` in place (reportlab-Muster).
    """
    for row_index in range(1, len(data)):
        raw = data[row_index][severity_col]
        label = raw if isinstance(raw, str) else getattr(raw, "text", "")
        color = _SEVERITY_BADGE.get(label)
        if color is None:
            continue
        cell = (severity_col, row_index)
        style.add("BACKGROUND", cell, cell, color)
        style.add("TEXTCOLOR", cell, cell, _TEXT)
        style.add("FONTNAME", cell, cell, "Helvetica-Bold")
        style.add("ALIGN", cell, cell, "CENTER")


def _draw_header_footer(
    canvas: object, doc: object, model: SecurityPdfModelLike, lang: str = "de"
) -> None:
    """Zeichnet die durchgaengige Kopf- UND Fusszeile je Seite (onFirstPage UND onLaterPages).

    Kopf: links das CERNIS-Logo (falls das Repo-Asset existiert; sonst NUR der Titel-Text --
    kein gezeichnetes Ersatz-Logo, Auftrag), daneben der Titel aus ``model.title``, darunter
    eine duenne Trennlinie in accent-Farbe. Fuss: links die feste Produktzeile, rechts die
    Seitenzahl ("Seite X"). KEINE Uhr -- der Zeitstempel steht in der Story.

    (E0) Der Kopf-Titel ist PARAMETRISCH (``model.title``, wie ``_draw_manual_header_footer``
    es vormacht) -- vorher stand der Titel des Sicherheitsberichts hier fest verdrahtet. Damit
    ist KEIN Berichtstitel mehr im Renderer hartkodiert; die Sprache des Titels entscheidet
    allein die Projektion. Ein pytest-Waechter haelt die Datei frei von diesem Literal.

    ``canvas``/``doc`` sind die reportlab-Objekte des onPage-Callbacks (lose typisiert als
    ``object``, weil das Protokoll des Callbacks nicht oeffentlich annotiert ist; die genutzten
    Methoden existieren zur Laufzeit).
    """
    c = canvas  # reportlab.pdfgen.canvas.Canvas
    page_width, page_height = A4
    margin = 18 * mm

    # ── Kopfzeile ──
    header_baseline = page_height - 20 * mm
    text_x = margin
    if os.path.exists(_LOGO_PATH):
        # Logo quadratisch in die Kopfzeile, sauber skaliert; der Titel rueckt rechts daneben.
        logo_size = 12 * mm
        c.drawImage(  # type: ignore[attr-defined]
            _LOGO_PATH,
            margin,
            page_height - 22 * mm,
            width=logo_size,
            height=logo_size,
            preserveAspectRatio=True,
            mask="auto",
        )
        text_x = margin + logo_size + 4 * mm
    # else: KEIN Ersatz-Logo -- nur der Titel-Text (fehlt das Asset ausnahmsweise, traegt die
    # Kopfzeile bewusst nur den Titel; _LOGO_PATH loest frozen wie dev auf).
    c.setFillColor(_TEXT)  # type: ignore[attr-defined]
    c.setFont("Helvetica-Bold", 13)  # type: ignore[attr-defined]
    c.drawString(text_x, header_baseline, model.title)  # type: ignore[attr-defined]
    # Trennlinie unter der Kopfzeile in accent-Farbe.
    c.setStrokeColor(_ACCENT)  # type: ignore[attr-defined]
    c.setLineWidth(1.0)  # type: ignore[attr-defined]
    line_y = page_height - 24 * mm
    c.line(margin, line_y, page_width - margin, line_y)  # type: ignore[attr-defined]

    # ── Fusszeile ──
    footer_y = 12 * mm
    c.setStrokeColor(_LINE)  # type: ignore[attr-defined]
    c.setLineWidth(0.5)  # type: ignore[attr-defined]
    c.line(margin, footer_y + 4 * mm, page_width - margin, footer_y + 4 * mm)  # type: ignore[attr-defined]
    c.setFillColor(_CLEAN)  # type: ignore[attr-defined]
    c.setFont("Helvetica", 8)  # type: ignore[attr-defined]
    c.drawString(margin, footer_y, model.footer_left)  # type: ignore[attr-defined]
    page_no = getattr(doc, "page", 0)
    c.drawRightString(page_width - margin, footer_y, f"{_ui('page.seite', lang)} {page_no}")  # type: ignore[attr-defined]


def _draw_manual_header_footer(
    canvas: object, doc: object, model: ManualPdfModelLike, lang: str = "de"
) -> None:
    """Kopf-/Fusszeile des Handbuchs je Seite -- wie ``_draw_header_footer``, Titel parametrisch.

    EIGENE Funktion fuer den Handbuch-Pfad (eigenes Modell/Protocol). Identische Logik zu
    ``_draw_header_footer``; ``_LOGO_PATH`` wird unveraendert mitgenutzt; Fuss links
    ``model.footer_left``, rechts "Seite X".

    (E0) Der Kopf-Titel kommt in BEIDEN Funktionen aus ``model.title`` -- die urspruengliche
    Begruendung dieser Trennung ("dort fester Titel, hier parametrisch") ist damit entfallen.
    Die Funktionen bleiben getrennt, weil sie verschiedene Modelle/Protocols bedienen.

    ``canvas``/``doc`` sind die reportlab-Objekte des onPage-Callbacks (lose als ``object``
    typisiert -- die genutzten Methoden existieren zur Laufzeit).
    """
    c = canvas  # reportlab.pdfgen.canvas.Canvas
    page_width, page_height = A4
    margin = 18 * mm

    # ── Kopfzeile ──
    header_baseline = page_height - 20 * mm
    text_x = margin
    if os.path.exists(_LOGO_PATH):
        logo_size = 12 * mm
        c.drawImage(  # type: ignore[attr-defined]
            _LOGO_PATH,
            margin,
            page_height - 22 * mm,
            width=logo_size,
            height=logo_size,
            preserveAspectRatio=True,
            mask="auto",
        )
        text_x = margin + logo_size + 4 * mm
    # else: KEIN Ersatz-Logo -- nur der Titel-Text (fehlt das Asset ausnahmsweise; _LOGO_PATH
    # loest frozen wie dev auf).
    c.setFillColor(_TEXT)  # type: ignore[attr-defined]
    c.setFont("Helvetica-Bold", 13)  # type: ignore[attr-defined]
    c.drawString(text_x, header_baseline, model.title)  # type: ignore[attr-defined]
    # Trennlinie unter der Kopfzeile in accent-Farbe.
    c.setStrokeColor(_ACCENT)  # type: ignore[attr-defined]
    c.setLineWidth(1.0)  # type: ignore[attr-defined]
    line_y = page_height - 24 * mm
    c.line(margin, line_y, page_width - margin, line_y)  # type: ignore[attr-defined]

    # ── Fusszeile ──
    footer_y = 12 * mm
    c.setStrokeColor(_LINE)  # type: ignore[attr-defined]
    c.setLineWidth(0.5)  # type: ignore[attr-defined]
    c.line(margin, footer_y + 4 * mm, page_width - margin, footer_y + 4 * mm)  # type: ignore[attr-defined]
    c.setFillColor(_CLEAN)  # type: ignore[attr-defined]
    c.setFont("Helvetica", 8)  # type: ignore[attr-defined]
    c.drawString(margin, footer_y, model.footer_left)  # type: ignore[attr-defined]
    page_no = getattr(doc, "page", 0)
    c.drawRightString(page_width - margin, footer_y, f"{_ui('page.seite', lang)} {page_no}")  # type: ignore[attr-defined]


def _gauge_drawing(
    score_value: int, level_label: str, level_color: colors.Color, lang: str = "de"
) -> Drawing:
    """Score-Gauge als Vektor: Halbkreis 0..100, bis ``score_value`` in Level-Farbe, Rest grau.

    Der Halbkreis (180°..0°) wird aus ZWEI ``Wedge``-Sektoren gebaut: der gefuellte Anteil
    (Winkel proportional zu ``score_value``/100) in der Level-Farbe, der Rest grau. Ein weisser
    Innenkreis schneidet die Mitte zum schlanken Bogen frei. In der Mitte die grosse Zahl + "von
    100" + der Level-Klartext. Reine Anzeige -- ``score_value`` kommt fertig (geclamped) herein.

    ``score_value`` wird defensiv auf [0, 100] geklemmt (ein valides Modell liefert es bereits
    so; das Klemmen haelt die Grafik auch bei einem unerwarteten Wert heil -- keine Rechnung).
    """
    value = max(0, min(100, score_value))
    width, height = 150.0, 95.0
    drawing = Drawing(width, height)
    cx, cy = width / 2.0, 18.0
    outer_r = 62.0
    inner_r = 40.0

    # Der Halbkreis liegt zwischen 0° (rechts) und 180° (links). Der gefuellte Anteil waechst
    # von LINKS (180°) nach rechts; die Grenze liegt bei 180 - value/100*180 Grad. Ein Sektor
    # mit NULL Ausdehnung (value 0 -> leerer Fuellsektor; value 100 -> leerer Rest) wird
    # uebersprungen -- ein Null-Wedge teilt sonst in reportlab durch sin(0) (ZeroDivisionError).
    split = 180.0 - (value / 100.0) * 180.0
    if split < 180.0:  # gefuellter Sektor (links der Grenze, Level-Farbe) nur bei value > 0
        drawing.add(
            Wedge(
                cx,
                cy,
                outer_r,
                split,
                180.0,
                yradius=outer_r,
                fillColor=level_color,
                strokeColor=None,
            )
        )
    if split > 0.0:  # Rest-Sektor (rechts der Grenze, grau) nur bei value < 100
        drawing.add(
            Wedge(cx, cy, outer_r, 0.0, split, yradius=outer_r, fillColor=_CLEAN, strokeColor=None)
        )
    # Weisser Innenkreis -> schlanker Bogen statt voller Halbscheibe.
    drawing.add(Circle(cx, cy, inner_r, fillColor=colors.white, strokeColor=None))

    # Beschriftung in der Mitte: grosse Zahl, "von 100", Level.
    drawing.add(
        String(
            cx,
            cy + 14,
            str(value),
            fontName="Helvetica-Bold",
            fontSize=30,
            fillColor=_TEXT,
            textAnchor="middle",
        )
    )
    drawing.add(
        String(
            cx,
            cy + 2,
            _ui("gauge.von100", lang),
            fontName="Helvetica",
            fontSize=9,
            fillColor=_CLEAN,
            textAnchor="middle",
        )
    )
    drawing.add(
        String(
            cx,
            cy - 12,
            level_label,
            fontName="Helvetica-Bold",
            fontSize=11,
            fillColor=level_color,
            textAnchor="middle",
        )
    )
    return drawing


def _donut_drawing(
    critical: int, notable: int, clean: int, device_count: int, lang: str = "de"
) -> Drawing:
    """Geraete-Verteilung als Donut (Vektor): Anteile critical/notable/clean, Mitte device_count.

    Drei ``Wedge``-Sektoren (rot/orange/grau) im Verhaeltnis der drei Zaehler; ein weisser
    Innenkreis macht daraus den Donut. In der Mitte ``device_count`` + "Geräte". Sind ALLE
    Zaehler 0 (leeres Netz), wird ein voller grauer Ring gezeichnet (kein leeres/kaputtes Bild)
    -- ehrlicher Leerfall statt Division durch Null.

    Reine Anzeige der drei Zaehler -- keine Score-/Anteils-Rechnung ueber das Aufteilen der
    360° hinaus (das ist reine Geometrie, keine Domaenenlogik).
    """
    width, height = 150.0, 110.0
    drawing = Drawing(width, height)
    cx, cy = width / 2.0, 52.0
    outer_r = 46.0
    inner_r = 27.0

    total = critical + notable + clean
    if total <= 0:
        # Leeres Netz: voller grauer Ring (kein leeres Bild).
        drawing.add(Wedge(cx, cy, outer_r, 0.0, 360.0, fillColor=_CLEAN, strokeColor=None))
    else:
        start = 90.0  # oben beginnen, im Uhrzeigersinn fuehlt sich natuerlich an
        for count, color in ((critical, _CRIT), (notable, _NOTABLE), (clean, _CLEAN)):
            if count <= 0:
                continue
            sweep = (count / total) * 360.0
            end = start - sweep
            # Wedge erwartet start<end fuer einen Sektor gegen den Uhrzeigersinn; wir geben das
            # Intervall sortiert herein, die Reihenfolge der Sektoren bleibt durch start/end klar.
            lo, hi = sorted((start, end))
            drawing.add(Wedge(cx, cy, outer_r, lo, hi, fillColor=color, strokeColor=None))
            start = end

    # Weisser Innenkreis -> Donut. Darin die Geraetezahl + Label.
    drawing.add(Circle(cx, cy, inner_r, fillColor=colors.white, strokeColor=None))
    drawing.add(
        String(
            cx,
            cy + 2,
            str(device_count),
            fontName="Helvetica-Bold",
            fontSize=20,
            fillColor=_TEXT,
            textAnchor="middle",
        )
    )
    drawing.add(
        String(
            cx,
            cy - 12,
            _ui("donut.geraete", lang),
            fontName="Helvetica",
            fontSize=9,
            fillColor=_CLEAN,
            textAnchor="middle",
        )
    )
    return drawing


def _inventory_donut_drawing(
    segments: tuple[tuple[int, colors.Color], ...],
    center_value: int,
    center_label: str,
    lang: str = "de",
) -> Drawing:
    """Generischer Donut (Vektor) mit beliebigen Segmenten + frei waehlbarer Mitte-Zahl/-Label.

    Wie ``_donut_drawing``, nur mit variabler Segmentliste statt fester critical/notable/clean-
    Reihenfolge: je ``(wert, color)`` ein ``Wedge``-Sektor proportional zur Summe aller Werte; ein
    weisser Innenkreis macht daraus den Donut, in der Mitte ``center_value`` + ``center_label``.
    Sind ALLE Werte 0 (leeres Netz), wird ein voller grauer Ring (``_CLEAN``) gezeichnet --
    ehrlicher Leerfall statt Division durch Null, kein leeres/kaputtes Bild.

    Reine Anzeige der Segmentwerte -- keine Anteils-Rechnung ueber das Aufteilen der 360° hinaus
    (das ist reine Geometrie, keine Domaenenlogik). Masse identisch zu ``_donut_drawing``.
    """
    width, height = 150.0, 110.0
    drawing = Drawing(width, height)
    cx, cy = width / 2.0, 52.0
    outer_r = 46.0
    inner_r = 27.0

    total = sum(max(0, value) for value, _ in segments)
    if total <= 0:
        # Leeres Netz: voller grauer Ring (kein leeres Bild).
        drawing.add(Wedge(cx, cy, outer_r, 0.0, 360.0, fillColor=_CLEAN, strokeColor=None))
    else:
        start = 90.0  # oben beginnen, im Uhrzeigersinn fuehlt sich natuerlich an
        for value, color in segments:
            if value <= 0:
                continue
            sweep = (value / total) * 360.0
            end = start - sweep
            # Intervall sortiert herein (wie _donut_drawing); start/end haelt die Reihenfolge klar.
            lo, hi = sorted((start, end))
            drawing.add(Wedge(cx, cy, outer_r, lo, hi, fillColor=color, strokeColor=None))
            start = end

    # Weisser Innenkreis -> Donut. Darin die Zahl + Label.
    drawing.add(Circle(cx, cy, inner_r, fillColor=colors.white, strokeColor=None))
    drawing.add(
        String(
            cx,
            cy + 2,
            str(center_value),
            fontName="Helvetica-Bold",
            fontSize=20,
            fillColor=_TEXT,
            textAnchor="middle",
        )
    )
    drawing.add(
        String(
            cx,
            cy - 12,
            center_label,
            fontName="Helvetica",
            fontSize=9,
            fillColor=_CLEAN,
            textAnchor="middle",
        )
    )
    return drawing


def _geraete_balken_drawing(balken: tuple[tuple[str, int, int], ...], lang: str = "de") -> Drawing:
    """Geraete-Balken "Auffaelligkeiten je Geraet" als Vektor -- VOLLSTAENDIGE Liste, kein Top-N.

    Je Geraet ein horizontaler, gestapelter Balken: zuerst der kritische Anteil (rot), dann der
    auffaellige (orange), Laenge proportional zur jeweiligen Anzahl. Links das Geraete-Label,
    rechts neben dem Balken die Summe. Die Skala richtet sich nach dem groessten Gesamtwert
    aller Geraete (alle Balken teilen dieselbe Skala -> vergleichbar). Manuell gezeichnete
    Rechtecke (``Drawing`` + ``Wedge``-freie ``Rect``) -- robust und voll kontrollierbar.
    """
    row_h = 16.0
    top_pad = 6.0
    label_w = 165.0  # Platz fuer das Geraete-Label links
    bar_max_w = 185.0  # maximale Balkenlaenge (Gesamtbreite bleibt 380)
    count_w = 30.0  # Platz fuer die Summe rechts
    width = label_w + bar_max_w + count_w
    height = top_pad * 2 + row_h * len(balken)
    drawing = Drawing(width, height)

    max_total = max((c + n) for _, c, n in balken) if balken else 0
    if max_total <= 0:
        max_total = 1  # alle 0 -> keine sichtbaren Balken, aber Labels erscheinen (kein /0)

    # Von oben nach unten zeichnen: y faellt je Zeile.
    y = height - top_pad - row_h
    for label, critical_count, notable_count in balken:
        # Label (links, gekuerzt auf die Spaltenbreite ueber Zeichenmass -- grobe Annaeherung).
        shown = label if len(label) <= 32 else label[:31] + "…"
        drawing.add(String(0, y + 4, shown, fontName="Helvetica", fontSize=8, fillColor=_TEXT))
        bar_x = label_w
        # Kritischer Anteil (rot).
        crit_w = (critical_count / max_total) * bar_max_w
        if crit_w > 0:
            drawing.add(Rect(bar_x, y, crit_w, row_h - 5, fillColor=_CRIT, strokeColor=None))
        # Auffaelliger Anteil (orange), direkt anschliessend.
        notable_w = (notable_count / max_total) * bar_max_w
        if notable_w > 0:
            drawing.add(
                Rect(bar_x + crit_w, y, notable_w, row_h - 5, fillColor=_NOTABLE, strokeColor=None)
            )
        # Summe rechts neben dem Balken.
        total = critical_count + notable_count
        drawing.add(
            String(
                label_w + bar_max_w + 4,
                y + 4,
                str(total),
                fontName="Helvetica-Bold",
                fontSize=8,
                fillColor=_TEXT,
            )
        )
        y -= row_h
    return drawing
