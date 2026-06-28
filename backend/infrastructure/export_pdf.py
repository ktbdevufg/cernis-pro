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
from typing import Protocol, cast

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

# Repo-Asset des CERNIS-Logos (Auftrag: per find ermittelt -> frontend/public/cernis-logo.png).
# Relativ zu diesem Modul aufgeloest (backend/infrastructure/ -> Repo-Root -> frontend/public).
# Existiert die Datei nicht (z. B. im frozen-Build), faellt die Kopfzeile sauber auf reinen
# Titel-Text zurueck -- KEIN gezeichnetes Ersatz-Logo (Auftrag).
_LOGO_PATH = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "public", "cernis-logo-pdf.png")
)


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
    def score_value(self) -> int: ...
    @property
    def score_level(self) -> str: ...
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

    def render_security_report_pdf(self, model: SecurityPdfModelLike) -> bytes:
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
        story.append(Paragraph("Netz-Gesundheit", styles["h_section"]))
        story.append(
            _gauge_drawing(
                model.score_value,
                model.score_level,
                _LEVEL_COLORS.get(model.score_level, _CRIT),
            )
        )
        if model.score_einordnung:
            story.append(Paragraph(model.score_einordnung, styles["body_center"]))
        story.append(Spacer(1, 6 * mm))

        # ── Drei Kennzahlen (kritisch / auffaellig / ohne Befund) ──
        story.append(self._kennzahlen_table(model))
        story.append(Spacer(1, 6 * mm))

        # Seitenumbruch VOR der Geraete-Verteilung: Donut + Balken beginnen luftig oben auf
        # einer neuen Seite, statt unten an Seite 1 zu kleben.
        story.append(PageBreak())

        # ── Donut: Anteile critical / notable / clean, Mitte device_count ──
        # Ueberschrift UND Donut zusammenhalten (KeepTogether), damit der Seitenumbruch nicht
        # zwischen Ueberschrift und Ring faellt (analog zum Balken-Block darunter).
        donut_block: list[Flowable] = [
            Paragraph("Geräte-Verteilung", styles["h_section"]),
            _donut_drawing(
                model.critical_devices,
                model.notable_devices,
                model.clean_devices,
                model.device_count,
            ),
        ]
        story.append(KeepTogether(donut_block))
        story.append(Spacer(1, 6 * mm))

        # ── Geraete-Balken: VOLLSTAENDIGE Liste (kein Top-N) ──
        # Ueberschrift UND Balken zusammenhalten (KeepTogether), damit der Seitenumbruch nicht
        # zwischen Ueberschrift und Balken faellt (Ueberschrift sonst unten, Balken erst naechste
        # Seite).
        balken_block: list[Flowable] = [Paragraph("Auffälligkeiten je Gerät", styles["h_section"])]
        if model.geraete_balken:
            balken_block.append(_geraete_balken_drawing(model.geraete_balken))
        else:
            balken_block.append(Paragraph("Keine Einträge.", styles["body"]))
        story.append(KeepTogether(balken_block))

        # ── Tabellen-Rubriken: je eigene Seite (PageBreak davor) ──
        story.append(PageBreak())
        self._append_table_section(
            story, styles, "Rechner mit auffälligen Ports", PORT_COLUMNS, model.port_rows
        )

        story.append(PageBreak())
        self._append_table_section(story, styles, "CVE-Befunde", CVE_COLUMNS, model.cve_rows)

        story.append(PageBreak())
        self._append_table_section(
            story, styles, "Netz-Auffälligkeiten", NET_COLUMNS, model.net_rows
        )

        # Rubrik 4 nur, wenn nicht leer (Auftrag: sonst weglassen).
        if model.acknowledged_rows:
            story.append(PageBreak())
            self._append_table_section(
                story, styles, "Bereits bestätigt", ACK_COLUMNS, model.acknowledged_rows
            )

        # ── Achse-B-Fussnote (invariant) + optionaler Rogue-Hinweis ──
        story.append(Spacer(1, 8 * mm))
        story.append(HRFlowable(width="100%", thickness=0.6, color=_LINE))
        story.append(Spacer(1, 2 * mm))
        story.append(
            Paragraph(
                "Dieser Bericht beschreibt und ordnet ein — er fällt kein Urteil.",
                styles["footnote"],
            )
        )
        if model.rogue_hinweis:
            story.append(Paragraph(model.rogue_hinweis, styles["footnote"]))

        document.build(
            story,
            onFirstPage=lambda canvas, doc: _draw_header_footer(canvas, doc, model),
            onLaterPages=lambda canvas, doc: _draw_header_footer(canvas, doc, model),
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
            ),
        }

    @staticmethod
    def _kennzahlen_table(model: SecurityPdfModelLike) -> Table:
        """Drei farbige Kennzahl-Boxen (kritisch / auffaellig / ohne Befund) als Tabelle.

        Eine 3-spaltige ``Table`` mit der grossen Zahl oben und dem Label darunter, jede Spalte
        in ihrer Severity-Farbe hinterlegt (kritisch rot, auffaellig orange, sauber grau). Reine
        Anzeige der drei Zaehler aus dem Modell -- keine Rechnung.
        """
        data = [
            [str(model.critical_devices), str(model.notable_devices), str(model.clean_devices)],
            ["kritisch", "auffällig", "ohne Befund"],
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
    ) -> None:
        """Haengt eine Tabellen-Rubrik (nummerierter Titel + accent-Unterstrich + Tabelle) an.

        Leere ``rows`` -> "Keine Eintraege." statt einer leeren ``Table`` (Auftrag, Robustheit).
        Lange Textspalten werden als ``Paragraph`` (umbrechbar) gesetzt, damit die Zelle nicht
        ueber den Rand laeuft. Die Schwere-Spalte (sofern "Schwere" in den Spalten) wird als
        Badge eingefaerbt. repeatRows=1 -> Kopf wiederholt sich bei Seitenumbruch.
        """
        story.append(Paragraph(title, styles["h_rubric"]))
        story.append(HRFlowable(width="100%", thickness=1.2, color=_ACCENT, spaceAfter=4))

        if not rows:
            leer_text = _EMPTY_SECTION_TEXT.get(columns, _EMPTY_FALLBACK)
            story.append(Paragraph(leer_text, styles["body"]))
            return

        severity_col = columns.index("Schwere") if "Schwere" in columns else -1
        # Die Roh-Zeilen (Strings) fuer das Badge-Einfaerben getrennt fuehren, die Render-Zeilen
        # (Paragraphs) fuer die Table -- der Badge-Helfer braucht den Klartext der Schwere-Zelle.
        badge_data: list[list[object]] = [list(columns)]
        render_data: list[list[object]] = [list(columns)]
        for row in rows:
            badge_data.append(list(row))
            render_data.append([Paragraph(_esc(value), styles["cell"]) for value in row])

        table = Table(render_data, repeatRows=1, colWidths=_col_widths(columns))
        style = self._base_table_style(len(render_data))
        if severity_col >= 0:
            _apply_severity_badges(style, badge_data, severity_col=severity_col)
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

    def render_inventory_report_pdf(self, model: InventoryPdfModelLike) -> bytes:
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
        story.append(Paragraph("Bestands-Kennzahlen", styles["h_section"]))
        story.append(self._inventory_kennzahlen(model))
        story.append(Spacer(1, 6 * mm))

        story.append(PageBreak())

        # ── Verteilung nach Hersteller / Kategorie (zwei schlanke (label, count)-Tabellen) ──
        story.append(Paragraph("Verteilung nach Hersteller", styles["h_section"]))
        self._append_distribution_table(story, styles, ("Hersteller", "Anzahl"), model.vendor_rows)
        story.append(Spacer(1, 6 * mm))

        story.append(Paragraph("Verteilung nach Kategorie", styles["h_section"]))
        self._append_distribution_table(story, styles, ("Kategorie", "Anzahl"), model.category_rows)

        story.append(PageBreak())

        # ── Geraete-Rubriken: aktive immer, archivierte nur wenn vorhanden ──
        # _append_table_section rendert Kopf + Tabelle + leer-Fallback selbst. Die Status-Spalte
        # ist KEINE "Schwere"-Spalte -> kein Badge-Einfaerben (korrekt, der Bestand wertet nicht).
        self._append_table_section(story, styles, "Geräte", INVENTORY_COLUMNS, model.device_rows)

        if model.archived_rows:
            story.append(PageBreak())
            self._append_table_section(
                story, styles, "Archivierte Geräte", ARCHIVED_COLUMNS, model.archived_rows
            )

        # ── Achse-B-Fussnote (invariant, wie im Sicherheitsbericht) ──
        story.append(Spacer(1, 8 * mm))
        story.append(HRFlowable(width="100%", thickness=0.6, color=_LINE))
        story.append(Spacer(1, 2 * mm))
        story.append(
            Paragraph(
                "Dieser Bericht beschreibt und ordnet ein — er fällt kein Urteil.",
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
            onFirstPage=lambda canvas, doc: _draw_manual_header_footer(canvas, doc, header_model),
            onLaterPages=lambda canvas, doc: _draw_manual_header_footer(canvas, doc, header_model),
        )
        return buffer.getvalue()

    @staticmethod
    def _inventory_kennzahlen(model: InventoryPdfModelLike) -> Table:
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
            ["Gesamt", "Bekannt", "Unbekannt", "Aktiv (24h)"],
            [str(model.trusted), str(model.watch), str(model.neutral), ""],
            ["Vertraut", "Beobachtet", "Neutral", ""],
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

    def _append_distribution_table(
        self,
        story: list[Flowable],
        styles: dict[str, ParagraphStyle],
        columns: tuple[str, str],
        rows: tuple[tuple[str, str], ...],
    ) -> None:
        """Haengt eine schlichte (label, count)-Verteilungs-Tabelle an (Hersteller bzw. Kategorie).

        Leere ``rows`` -> "Keine Eintraege." (body) statt einer leeren ``Table``. Feste
        colWidths (Label breit, Anzahl schmal) -- nicht ueber ``_col_widths``, weil die
        2-spaltigen Verteilungs-Schemata dort nicht hinterlegt sind. ``_base_table_style`` +
        ``repeatRows=1`` (Kopf wiederholt sich bei Seitenumbruch), Zellen als umbrechbare
        ``Paragraph`` (Muster ``_append_table_section``).
        """
        if not rows:
            story.append(Paragraph("Keine Einträge.", styles["body"]))
            return

        content_pt = _CONTENT_WIDTH_MM * mm
        col_widths = [content_pt * 0.78, content_pt * 0.22]
        render_data: list[list[object]] = [list(columns)]
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

# Nutzbare Druckbreite einer A4-Hochformat-Seite bei 18 mm Seitenraendern (Single Source fuer
# die Spaltenbreiten-Berechnung). A4-Breite 210 mm - 2*18 mm = 174 mm.
_CONTENT_WIDTH_MM = 174.0

# Proportionale Spaltengewichte je bekanntem Rubrik-Schema (Summe egal -- es wird normiert).
# So fuellt jede Tabelle exakt die Druckbreite, mit sinnvoll breiten Text-/schmalen Wertspalten.
_COL_WEIGHTS: dict[tuple[str, ...], tuple[float, ...]] = {
    PORT_COLUMNS: (3.0, 2.0, 1.6, 4.0),
    CVE_COLUMNS: (2.6, 2.2, 1.0, 2.2, 4.0),
    NET_COLUMNS: (2.2, 2.6, 1.6, 5.0),
    ACK_COLUMNS: (2.4, 3.0, 5.0),
    # Bestandsbericht: Geraet-Spalte breiter, die schmalen Wert-Spalten (Gesehen) schlank --
    # damit fuellt die 8-spaltige Geraete-Tabelle die Druckbreite lesbar (Muster der Security-
    # Gewichte). Eigene Keys, die bestehenden Aufrufer (PORT/CVE/NET/ACK) bleiben unberuehrt.
    INVENTORY_COLUMNS: (2.6, 1.8, 1.4, 1.7, 1.7, 1.0, 1.6, 1.6),
    ARCHIVED_COLUMNS: (3.0, 2.2, 1.8, 2.0, 1.8),
}

# Rubrikspezifischer Leertext je Tabellen-Schema (statt generisch "Keine Eintraege.").
# Unbekannte Rubriken fallen auf _EMPTY_FALLBACK zurueck. ACK braucht keinen Eintrag, da der
# Aufrufer leere ACK-Rubriken gar nicht erst rendert.
_EMPTY_FALLBACK = "Keine Einträge in dieser Kategorie."
_EMPTY_SECTION_TEXT: dict[tuple[str, ...], str] = {
    PORT_COLUMNS: "Keine auffälligen Ports festgestellt.",
    CVE_COLUMNS: "Keine CVE-Befunde vorhanden.",
    NET_COLUMNS: "Keine Netz-Auffälligkeiten festgestellt.",
}


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


def _draw_header_footer(canvas: object, doc: object, model: SecurityPdfModelLike) -> None:
    """Zeichnet die durchgaengige Kopf- UND Fusszeile je Seite (onFirstPage UND onLaterPages).

    Kopf: links das CERNIS-Logo (falls das Repo-Asset existiert; sonst NUR der Titel-Text --
    kein gezeichnetes Ersatz-Logo, Auftrag), daneben der Titel "Netzwerk-Sicherheitsbericht",
    darunter eine duenne Trennlinie in accent-Farbe. Fuss: links die feste Produktzeile,
    rechts die Seitenzahl ("Seite X"). KEINE Uhr -- der Zeitstempel steht in der Story.

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
    # else: KEIN Ersatz-Logo -- nur der Titel-Text (TODO-Logo: Repo-Asset im frozen-Build
    # nicht vorhanden; dann traegt die Kopfzeile bewusst nur den Titel).
    c.setFillColor(_TEXT)  # type: ignore[attr-defined]
    c.setFont("Helvetica-Bold", 13)  # type: ignore[attr-defined]
    c.drawString(text_x, header_baseline, "Netzwerk-Sicherheitsbericht")  # type: ignore[attr-defined]
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
    c.drawRightString(page_width - margin, footer_y, f"Seite {page_no}")  # type: ignore[attr-defined]


def _draw_manual_header_footer(canvas: object, doc: object, model: ManualPdfModelLike) -> None:
    """Kopf-/Fusszeile des Handbuchs je Seite -- wie ``_draw_header_footer``, Titel parametrisch.

    EIGENE Funktion (keine Aenderung an ``_draw_header_footer``, das auf den Sicherheitsbericht
    mit festem Kopf-Titel zugeschnitten ist und unberuehrt bleibt). Identische Logik, aber der
    Kopf-Titel ist ``model.title`` statt einer festen Zeichenkette; ``_LOGO_PATH`` wird
    unveraendert mitgenutzt; Fuss links ``model.footer_left``, rechts "Seite X".

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
    # else: KEIN Ersatz-Logo -- nur der Titel-Text (Repo-Asset im frozen-Build evtl. nicht da).
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
    c.drawRightString(page_width - margin, footer_y, f"Seite {page_no}")  # type: ignore[attr-defined]


def _gauge_drawing(score_value: int, level_label: str, level_color: colors.Color) -> Drawing:
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
            "von 100",
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


def _donut_drawing(critical: int, notable: int, clean: int, device_count: int) -> Drawing:
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
            "Geräte",
            fontName="Helvetica",
            fontSize=9,
            fillColor=_CLEAN,
            textAnchor="middle",
        )
    )
    return drawing


def _geraete_balken_drawing(balken: tuple[tuple[str, int, int], ...]) -> Drawing:
    """Geraete-Balken "Auffaelligkeiten je Geraet" als Vektor -- VOLLSTAENDIGE Liste, kein Top-N.

    Je Geraet ein horizontaler, gestapelter Balken: zuerst der kritische Anteil (rot), dann der
    auffaellige (orange), Laenge proportional zur jeweiligen Anzahl. Links das Geraete-Label,
    rechts neben dem Balken die Summe. Die Skala richtet sich nach dem groessten Gesamtwert
    aller Geraete (alle Balken teilen dieselbe Skala -> vergleichbar). Manuell gezeichnete
    Rechtecke (``Drawing`` + ``Wedge``-freie ``Rect``) -- robust und voll kontrollierbar.
    """
    row_h = 16.0
    top_pad = 6.0
    label_w = 120.0  # Platz fuer das Geraete-Label links
    bar_max_w = 230.0  # maximale Balkenlaenge
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
        shown = label if len(label) <= 22 else label[:21] + "…"
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
