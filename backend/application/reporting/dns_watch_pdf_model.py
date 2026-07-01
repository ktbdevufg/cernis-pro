"""Render-fertiges PDF-Modell des DNS-Waechter-Berichts (Etappe 1) -- reiner Datentraeger.

Ein NEUTRALES, vollstaendig anzeige-fertiges Modell ``DnsWatchPdfModel``, das der
Composition Root (spaetere Etappe) aus ``DnsWatchReport`` PROJIZIERT und das der
reportlab-Adapter (``infrastructure/export_pdf.py``) ohne jede eigene Rechnung rendert.
Es steht neben ``OutboundPdfModel``/``CvePdfModel``/``InventoryPdfModel`` (gleiche
Schicht/Paket) und folgt deren Muster -- ein EIGENES Modell, der generische
``domain.export.PdfReportModel`` bleibt unangetastet.

REINE PROJEKTION, KEINE RECHNUNG (Muster ``outbound_pdf_model``/``cve_pdf_model``):
  * KEINE reportlab-Importe -- das Modell ist ein neutraler Datentraeger; das Rendern macht
    allein die Infrastruktur.
  * KEINE Domaenen-Importe -- es lebt in ``application/reporting`` und wird aus
    ``DnsWatchReport`` befuellt, traegt aber selbst nur Primitive/Tupel.
  * KEINE Uhr, KEINE Logik: ALLE Texte (das formatierte Erzeugungsdatum, der Erklaersatz,
    die fertige Sicht-Zeile, die fertigen Listen erwarteter Server / DoH-Anbieter, die
    fertigen Tabellenzeilen) kommen schon FERTIG vom Composition Root herein. Der Adapter
    setzt sie nur, das Modell fuehrt sie nur.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ── Spalten-Vertraege der drei Sektions-Tabellen (Auftrag) ──────────────────
#
# Die Spaltenueberschriften liegen HIER fest (nicht im Adapter), damit Modell und Renderer
# sich ueber denselben Vertrag einig sind. Der Composition Root liefert die Zeilen exakt in
# dieser Spalten-Reihenfolge; der Adapter setzt diese Tupel als Kopfzeile. Der ``DNS_``-
# Praefix haelt sie von den bestehenden ``CONTACT_COLUMNS`` des Aussenkontakte-Berichts
# getrennt.

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


@dataclass(frozen=True)
class DnsWatchPdfModel:
    """Render-fertiges PDF-Modell des DNS-Waechter-Berichts (frozen, neutral).

    Alle Felder sind ANZEIGE-FERTIG: Texte sind fertig formatiert, Zahlen sind die schon
    ermittelten Zaehler, die Tabellenzeilen sind String-Tupel in der jeweiligen
    ``DNS_*_COLUMNS``-Reihenfolge. Der Adapter rendert ALLES daraus, ohne zu rechnen.

    KOPF/FUSS:
      ``title`` der Berichtstitel, ``generated_at_text`` das schon formatierte
      Erzeugungsdatum (vom Composition Root -- der Adapter fragt keine Uhr), ``footer_left``
      die feste Produktzeile der Fusszeile, ``einleitung`` der fertige Einleitungs-Absatz.

    BEZUGSRAHMEN:
      ``scope_text`` die fertige Sicht-Zeile (z. B. "Sicht: nur dieser Rechner (nicht
      netzweit)"), ``expected_text`` die fertige Liste erwarteter Server ("(keine)" wenn
      leer), ``doh_text`` die fertige Liste bekannter DoH-Anbieter ("(keine)" wenn leer) --
      der Composition Root baut sie (keine Uhr/Logik hier).

    KENNZAHLEN:
      ``contacts_total`` alle Kontakte (aktiv + quittiert), ``active_total`` die aktiven,
      ``acknowledged_total`` die quittierten. ``expected_active``/``open_active``/
      ``doh_active`` die aktiven Kontakte je Kategorie, ``flagged_active`` die auffaelligen
      (offen + moegliche_doh).

    SEKTIONS-TABELLEN (fertige String-Zeilen in der jeweiligen ``DNS_*_COLUMNS``-Reihenfolge):
      ``category_rows`` (Kategorie-Verteilung, DNS_CATEGORY_COLUMNS), ``app_rows``
      (Programm-Verteilung, DNS_APP_COLUMNS), ``contact_rows`` (Kontaktliste,
      DNS_CONTACT_COLUMNS). Ist eine Tabelle LEER, laesst der spaetere Adapter die Rubrik weg
      (wie beim Aussenkontakte-/CVE-Bericht).
    """

    title: str
    generated_at_text: str
    footer_left: str
    einleitung: str
    scope_text: str
    expected_text: str
    doh_text: str

    contacts_total: int
    active_total: int
    acknowledged_total: int
    expected_active: int
    open_active: int
    doh_active: int
    flagged_active: int

    category_rows: tuple[tuple[str, ...], ...] = ()
    app_rows: tuple[tuple[str, ...], ...] = ()
    contact_rows: tuple[tuple[str, ...], ...] = field(default_factory=tuple)
