"""Render-fertiges PDF-Modell des Verhaltensprofil-Berichts -- reiner Datentraeger.

Ein NEUTRALES, vollstaendig anzeige-fertiges Modell ``BehaviorPdfModel``, das der
Composition Root aus ``BehaviorReport`` PROJIZIERT und das der reportlab-Adapter
(``infrastructure/export_pdf.py``) ohne jede eigene Rechnung rendert. Es steht neben den
anderen ``*PdfModel`` (gleiche Schicht/Paket) und folgt deren Muster -- ein EIGENES
Modell, der generische ``domain.export.PdfReportModel`` bleibt unangetastet.

REINE PROJEKTION, KEINE RECHNUNG (Muster ``dns_bypass_pdf_model``):
  * KEINE reportlab-Importe -- das Modell ist ein neutraler Datentraeger; das Rendern macht
    allein die Infrastruktur.
  * KEINE Domaenen-Importe -- es lebt in ``application/reporting`` und wird aus
    ``BehaviorReport`` befuellt, traegt aber selbst nur Primitive/Tupel.
  * KEINE Uhr, KEINE Logik: ALLE Texte (das formatierte Erzeugungsdatum, der Erklaersatz,
    die fertige Bezugsrahmen-Zeile, die fertigen Kennzahlen und Tabellenzeilen) kommen schon
    FERTIG vom Composition Root herein. Der Adapter setzt sie nur, das Modell fuehrt sie nur.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ── Spalten-Vertrag der "alle Geraete"-Tabelle (Auftrag) ────────────────────
#
# Die Spaltenueberschriften liegen HIER fest (nicht im Adapter), damit Modell und Renderer
# sich ueber denselben Vertrag einig sind. Der Composition Root liefert die Zeilen exakt in
# dieser Spalten-Reihenfolge; der Adapter setzt dieses Tupel als Kopfzeile. Der
# ``BEHAVIOR_``-Praefix haelt es von den Spalten der anderen Berichte getrennt.

BEHAVIOR_ENTRY_COLUMNS: tuple[str, ...] = (
    "Gerät",
    "Aufzeichnungstage",
    "Genug Daten",
    "Abweichungen",
    "Aktivste Zeit",
    "Aktivster Tag",
)


@dataclass(frozen=True)
class BehaviorPdfModel:
    """Render-fertiges PDF-Modell des Verhaltensprofil-Berichts (frozen, neutral).

    Alle Felder sind ANZEIGE-FERTIG: Texte sind fertig formatiert, Zahlen sind die schon
    ermittelten Zaehler, die Tabellenzeilen sind String-Tupel in der
    ``BEHAVIOR_ENTRY_COLUMNS``-Reihenfolge. Der Adapter rendert ALLES daraus, ohne zu
    rechnen.

    KOPF/FUSS:
      ``title`` der Berichtstitel, ``generated_at_text`` das schon formatierte
      Erzeugungsdatum (vom Composition Root -- der Adapter fragt keine Uhr), ``footer_left``
      die feste Produktzeile der Fusszeile, ``einleitung`` der fertige Einleitungs-Absatz.

    BEZUGSRAHMEN:
      ``scope`` roh ("single" oder "all", fuer die Adapter-Verzweigung), ``scope_text`` die
      fertige lokalisierte Bezugsrahmen-Zeile (z. B. "Bezug: Aufgabe 'X'" / "Bezug: Alle
      Geräte") -- der Composition Root baut sie (keine Uhr/Logik hier).

    EINZELPROFIL (nur bei ``scope == "single"`` befuellt, sonst leer/Defaults):
      ``single_kennzahlen`` je Kennzahl ein schon lokalisiertes ``(Label, Wert)``-Paar (z. B.
      ``("Aufzeichnungstage", "21")``). ``day_band`` je Slot ein Tripel ``(slot_start,
      activity_count, is_deviation)`` -- STRUKTURIERT fuer die Adapter-Grafik (Tagesband).
      ``week_heatmap`` je Zelle ein Quadrupel ``(weekday, slot_start, activity_count,
      is_deviation)`` -- STRUKTURIERT fuer die Adapter-Heatmap. ``slot_minutes`` die
      Slot-Breite in Minuten (fuer die Achsen-Beschriftung im Adapter). ``weekday_labels``
      7 fertige, lokalisierte Wochentagskuerzel (Mo..So-Reihenfolge, Index = weekday 0..6),
      mit denen der Adapter die Heatmap-Zeilen beschriftet; leer erlaubt (Adapter faellt dann
      auf den Index zurueck).

    ALLE GERAETE (nur bei ``scope == "all"`` befuellt, sonst leer):
      ``entry_rows`` fertige String-Zeilen in der ``BEHAVIOR_ENTRY_COLUMNS``-Reihenfolge. Ist
      die Tabelle LEER, laesst der spaetere Adapter die Rubrik weg (Muster ``dns_bypass``).
    """

    title: str
    generated_at_text: str
    footer_left: str
    einleitung: str

    scope: str
    scope_text: str
    achse_b_fussnote: str

    single_kennzahlen: tuple[tuple[str, str], ...] = ()
    day_band: tuple[tuple[int, int, bool], ...] = ()
    week_heatmap: tuple[tuple[int, int, int, bool], ...] = ()
    slot_minutes: int = 60
    weekday_labels: tuple[str, ...] = ()

    entry_rows: tuple[tuple[str, ...], ...] = field(default_factory=tuple)
