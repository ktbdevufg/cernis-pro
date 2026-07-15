"""Tests des CVE-Bericht-Render-Pfads -- valides PDF, kein Layout-Assert.

Wie ``test_export_pdf_outbound.py``: kein echtes Netz, kein Datei-I/O ausser dem in-memory
``BytesIO``. Der Adapter rendert das render-fertige ``CvePdfModel`` zu Bytes; wir pruefen NUR,
dass valides PDF rauskommt (nicht-leere Bytes mit dem Magic-Header ``%PDF``) -- kein Layout-/
Pixel-Assert (das fuehrt reportlab).

Schwerpunkt ist der LEERE-DB-Fall: sind alle Severity-Counts 0, laesst der count-> 0-Filter der
Donut-Legende null Eintraege uebrig. Ohne den Wurzel-Guard in ``_inventory_donut_legende`` warf
reportlab dort "Table must have at least a row and column" -- der Endpunkt stuerzte ab, statt
einen gueltigen leeren Bericht zu liefern.
"""

from application.reporting.cve_pdf_model import CvePdfModel
from infrastructure.export_pdf import ReportlabRenderer


def _leeres_modell() -> CvePdfModel:
    """Leere DB: alle Tabellen leer, alle Zaehler 0, alle Severity-Counts 0."""
    return CvePdfModel(
        title="CVE-Bericht",
        generated_at_text="Erstellt am 28.06.2026 12:00",
        footer_left="CERNIS PRO 2.0 — CVE-Bericht",
        einleitung="Dieser Bericht fasst die bekannten Schwachstellen im Netz zusammen.",
        achse_b_fussnote="Hinweis zur Achse B.",
        active_total=0,
        acknowledged_total=0,
        new_total=0,
        affected_devices=0,
        hosts_total=0,
        hosts_checked=0,
        coverage_text="0 %",
        highest_severity="—",
        oldest_published_text="",
        severity_rows=(),
        severity_labels=(),
        device_rows=(),
        service_rows=(),
        finding_rows=(),
        host_groups=(),
    )


def test_render_cve_report_pdf_leeres_modell_ist_valide() -> None:
    """Leeres Modell (leere DB) ergibt valides PDF statt eines reportlab-Absturzes."""
    data = ReportlabRenderer().render_cve_report_pdf(_leeres_modell())
    assert isinstance(data, bytes)
    assert len(data) > 0
    assert data.startswith(b"%PDF")
