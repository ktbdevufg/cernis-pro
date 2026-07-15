"""Render-fertiges PDF-Modell des Aussenkontakte-Berichts (Etappe 1) -- reiner Datentraeger.

Ein NEUTRALES, vollstaendig anzeige-fertiges Modell ``OutboundPdfModel``, das der
Composition Root (spaetere Etappe) aus ``OutboundReport`` PROJIZIERT und das der
reportlab-Adapter (``infrastructure/export_pdf.py``) ohne jede eigene Rechnung rendert.
Es steht neben ``CvePdfModel``/``InventoryPdfModel``/``SecurityPdfModel`` (gleiche
Schicht/Paket) und folgt deren Muster -- ein EIGENES Modell, der generische
``domain.export.PdfReportModel`` bleibt unangetastet.

REINE PROJEKTION, KEINE RECHNUNG (Muster ``cve_pdf_model``/``inventory_pdf_model``):
  * KEINE reportlab-Importe -- das Modell ist ein neutraler Datentraeger; das Rendern macht
    allein die Infrastruktur.
  * KEINE Domaenen-Importe -- es lebt in ``application/reporting`` und wird aus
    ``OutboundReport`` befuellt, traegt aber selbst nur Primitive/Tupel.
  * KEINE Uhr, KEINE Logik: ALLE Texte (das formatierte Erzeugungsdatum, der Erklaersatz,
    die fertige Bezugsrahmen-Zeile, die fertigen Tabellenzeilen samt fertiger
    Bewertungs-Spalte) kommen schon FERTIG vom Composition Root herein. Der Adapter setzt
    sie nur, das Modell fuehrt sie nur.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ── Spalten-Vertraege der drei Sektions-Tabellen (Auftrag) ──────────────────
#
# Die Spaltenueberschriften liegen HIER fest (nicht im Adapter), damit Modell und Renderer
# sich ueber denselben Vertrag einig sind. Der Composition Root liefert die Zeilen exakt in
# dieser Spalten-Reihenfolge; der Adapter setzt diese Tupel als Kopfzeile.

CONTACT_COLUMNS: tuple[str, ...] = (
    "Gegenstelle",
    "Name",
    "Land",
    "Betreiber",
    "Kontakte",
    "Bewertung",
)
COUNTRY_COLUMNS: tuple[str, ...] = ("Land", "Gegenstellen")
OPERATOR_COLUMNS: tuple[str, ...] = ("Betreiber", "Gegenstellen")


@dataclass(frozen=True)
class OutboundPdfModel:
    """Render-fertiges PDF-Modell des Aussenkontakte-Berichts (frozen, neutral).

    Alle Felder sind ANZEIGE-FERTIG: Texte sind fertig formatiert, Zahlen sind die schon
    ermittelten Zaehler, die Tabellenzeilen sind String-Tupel in der jeweiligen
    ``*_COLUMNS``-Reihenfolge. Der Adapter rendert ALLES daraus, ohne zu rechnen.

    KOPF/FUSS:
      ``title`` der Berichtstitel, ``generated_at_text`` das schon formatierte
      Erzeugungsdatum (vom Composition Root -- der Adapter fragt keine Uhr), ``footer_left``
      die feste Produktzeile der Fusszeile, ``einleitung`` der fertige Einleitungs-Absatz.

    BEZUGSRAHMEN:
      ``recording_label`` der Anzeigename der Aufzeichnung, ``scope_text`` die fertige
      lokalisierte Bezugsrahmen-Zeile (z. B. "Bezug: Aufzeichnung 'X'" / "Bezug: Alle
      Aufzeichnungen") -- der Composition Root baut sie (keine Uhr/Logik hier).

    KENNZAHLEN:
      ``contacts_total`` die Gegenstellen gesamt (inkl. lokale), ``remote_total`` die
      nicht-lokalen, ``local_total`` die lokalen, ``connection_total`` die Summe der
      Verbindungen. ``countries_total``/``operators_total`` die distinct Land-/Betreiber-
      Zaehler. ``tracker_contacts``/``threat_contacts``/``flagged_contacts`` die
      Bewertungs-Zaehler.

    SEKTIONS-TABELLEN (fertige String-Zeilen in der jeweiligen ``*_COLUMNS``-Reihenfolge):
      ``country_rows`` (Land-Verteilung, COUNTRY_COLUMNS), ``operator_rows`` (Betreiber-
      Verteilung, OPERATOR_COLUMNS), ``contact_rows`` (Kontaktliste, CONTACT_COLUMNS -- die
      Bewertung-Spalte schon als fertiger Text, z. B. "Bedrohung: Feodo" / "Tracker:
      StevenBlack" / "-"). Ist eine Tabelle LEER, laesst der spaetere Adapter die Rubrik weg
      (wie beim Bestands-/CVE-Bericht).
    """

    title: str
    generated_at_text: str
    footer_left: str
    einleitung: str
    recording_label: str
    scope_text: str
    achse_b_fussnote: str

    contacts_total: int
    remote_total: int
    local_total: int
    connection_total: int
    countries_total: int
    operators_total: int
    tracker_contacts: int
    threat_contacts: int
    flagged_contacts: int

    country_rows: tuple[tuple[str, ...], ...] = ()
    operator_rows: tuple[tuple[str, ...], ...] = ()
    contact_rows: tuple[tuple[str, ...], ...] = field(default_factory=tuple)
