"""Tests des Handbuch-Render-Pfads ``render_manual_pdf``.

Wie beim Sicherheitsbericht: KEIN Layout-/Pixel-Assert (das fuehrt reportlab) -- geprueft wird
NUR, dass valide PDF-Bytes entstehen (nicht-leer, Magic-Header ``%PDF``) und der Aufruf nicht
wirft. Zwei Faelle: Modell mit zwei Sections in zwei Kategorien, und der Leerfall (keine
Sections -> nur Kopf/Titel, kein Absturz).

Das Modell wird hier DIREKT gebaut (kein Composition Root) -- die Projektion ist app.py.
"""

from application.reporting import ManualPdfModel, ManualPdfSection
from infrastructure.export_pdf import ReportlabRenderer


def _full_model() -> ManualPdfModel:
    """Zwei Sections in zwei Kategorien, mit mehreren Absaetzen und Sonderzeichen."""
    return ManualPdfModel(
        title="CERNIS PRO 2.0 - Benutzerhandbuch",
        generated_at_text="Erstellt am 25.06.2026 16:30",
        footer_left="CERNIS PRO 2.0 - Benutzerhandbuch",
        intro="Dieses Handbuch erklärt CERNIS PRO Schritt für Schritt.",
        sections=(
            ManualPdfSection(
                category_label="Grundlagen",
                heading="Was ist CERNIS PRO?",
                paragraphs=(
                    "CERNIS PRO ist ein Werkzeug, um das eigene Netzwerk zu verstehen.",
                    "Es zeigt Geräte, Ports & Auffälligkeiten <verständlich> an.",
                ),
            ),
            ManualPdfSection(
                category_label="Scan",
                heading="Einen Scan starten",
                paragraphs=("Drücken Sie auf Start, um einen Scan auszulösen.",),
            ),
        ),
    )


def test_render_volles_handbuch_ist_valides_pdf() -> None:
    data = ReportlabRenderer().render_manual_pdf(_full_model())
    assert isinstance(data, bytes)
    assert len(data) > 0
    assert data.startswith(b"%PDF")


def test_render_leere_sections_ist_valides_pdf() -> None:
    """Keine Sections -> nur Kopf/Titel, valides PDF, kein Absturz."""
    model = ManualPdfModel(
        title="CERNIS PRO 2.0 - User Manual",
        generated_at_text="Created at 25.06.2026 16:30",
        footer_left="CERNIS PRO 2.0 - User Manual",
    )
    data = ReportlabRenderer().render_manual_pdf(model)
    assert data.startswith(b"%PDF")
