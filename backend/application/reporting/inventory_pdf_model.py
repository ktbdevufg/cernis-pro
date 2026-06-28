"""Render-fertiges PDF-Modell des Bestandsberichts (Etappe 1) -- reiner Datentraeger.

Ein NEUTRALES, vollstaendig anzeige-fertiges Modell ``InventoryPdfModel``, das der
Composition Root (spaetere Etappe) aus ``InventoryReport`` PROJIZIERT und das der
reportlab-Adapter (``infrastructure/export_pdf.py``) ohne jede eigene Rechnung rendert.

ABGRENZUNG zum generischen ``domain.export.PdfReportModel``: jenes (Titel + meta-Paare +
EINE Tabelle) ist zu schlicht fuer den Bestandsbericht (Kennzahlen + zwei Verteilungs-
Tabellen + zwei Geraete-Tabellen + durchgaengige Kopfzeile). Dieses Modell ist daneben
gestellt -- ein EIGENES Modell; ``PdfReportModel`` bleibt unangetastet. Es folgt dem
Muster von ``SecurityPdfModel`` (gleiche Schicht/Paket).

REINE PROJEKTION, KEINE RECHNUNG (Muster ``security_pdf_model``/``inventory_report``):
  * KEINE reportlab-Importe -- das Modell ist ein neutraler Datentraeger; das Rendern macht
    allein die Infrastruktur.
  * KEINE Domaenen-Importe -- es lebt in ``application/reporting`` und wird aus
    ``InventoryReport`` befuellt, traegt aber selbst nur Primitive/Tupel.
  * KEINE Uhr, KEINE Formatierung: ALLE Texte (das formatierte Erzeugungsdatum, der
    Erklaersatz, die Datums-Texte je Zeile, die count-als-Text-Werte, die fertigen
    Tabellenzeilen) kommen schon FERTIG vom Composition Root herein. Der Adapter setzt sie
    nur, das Modell fuehrt sie nur.

Damit ist der Adapter zustandslos und rechenfrei: er hat in diesem Modell ALLES, um die
Kopf-/Fusszeile, die Kennzahl-Boxen, die beiden Verteilungs-Tabellen und die beiden
Geraete-Tabellen (aktiv/archiviert) zu rendern, ohne selbst zu aggregieren oder zu
formatieren.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ── Spalten-Vertraege der beiden Geraete-Tabellen (Auftrag) ─────────────────
#
# Die Spaltenueberschriften liegen HIER fest (nicht im Adapter), damit Modell und Renderer
# sich ueber denselben Vertrag einig sind. Der Composition Root liefert die Zeilen exakt in
# dieser Spalten-Reihenfolge; der Adapter setzt diese Tupel als Kopfzeile. Die Archiv-
# Tabelle ist bewusst schlanker (keine Erst-Sichtung/Gesehen/Kategorie -- fuer abgelegte
# Geraete genuegt der knappe Abriss).

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


@dataclass(frozen=True)
class InventoryPdfModel:
    """Render-fertiges PDF-Modell des Bestandsberichts (frozen, neutral).

    Alle Felder sind ANZEIGE-FERTIG: Texte sind fertig formatiert, Zahlen sind die schon
    ermittelten Zaehler, die Tabellenzeilen sind String-Tupel in der jeweiligen
    ``*_COLUMNS``-Reihenfolge. Der Adapter rendert ALLES daraus, ohne zu rechnen.

    KOPF/FUSS:
      ``title`` der Berichtstitel ("Netzwerk-Bestandsbericht"), ``generated_at_text`` das
      schon formatierte Erzeugungsdatum (vom Composition Root -- der Adapter fragt keine
      Uhr), ``footer_left`` die feste Produktzeile der Fusszeile, ``einleitung`` der
      fertige Einleitungs-Absatz.

    KENNZAHLEN:
      ``total`` der Gesamtbestand, ``known``/``unknown`` die bekannt/unbekannt-Zaehler,
      ``active_24h`` die in den letzten 24h gesehenen, ``trusted``/``watch``/``neutral``
      die drei Vertrauens-Stufen -- jeweils als Kennzahl-Boxen.

    VERTEILUNGS-TABELLEN (jeweils ``(label, count-als-Text)`` -- fertig formatiert):
      ``vendor_rows``   -- Hersteller-Verteilung (Hersteller-Name, Anzahl als Text).
      ``category_rows`` -- Kategorie-Verteilung (Kategorie-Name, Anzahl als Text).

    GERAETE-TABELLEN (jeweils fertige String-Zeilen in der ``*_COLUMNS``-Reihenfolge):
      ``device_rows``   -- aktive (nicht archivierte) Geraete in ``INVENTORY_COLUMNS``-
                           Reihenfolge.
      ``archived_rows`` -- archivierte Geraete in ``ARCHIVED_COLUMNS``-Reihenfolge; ist sie
                           LEER, laesst der Adapter die ganze Rubrik weg (kein leerer
                           Tabellenkopf).
    """

    title: str
    generated_at_text: str
    footer_left: str
    einleitung: str

    total: int
    known: int
    unknown: int
    active_24h: int
    trusted: int
    watch: int
    neutral: int

    vendor_rows: tuple[tuple[str, str], ...] = ()
    category_rows: tuple[tuple[str, str], ...] = ()

    device_rows: tuple[tuple[str, ...], ...] = ()
    archived_rows: tuple[tuple[str, ...], ...] = field(default_factory=tuple)
