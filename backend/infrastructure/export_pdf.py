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

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from domain.export import PdfReportModel


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
