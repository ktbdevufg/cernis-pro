"""Tests des Aussenkontakte-Bericht-Render-Pfads (Etappe 2c) -- valides PDF, kein Layout-Assert.

Wie ``test_export_pdf.py``: kein echtes Netz, kein Datei-I/O ausser dem in-memory ``BytesIO``.
Der Adapter rendert das render-fertige ``OutboundPdfModel`` zu Bytes; wir pruefen NUR, dass
valides PDF rauskommt (nicht-leere Bytes mit dem Magic-Header ``%PDF``) -- kein Layout-/Pixel-
Assert (das fuehrt reportlab). Auch das LEERE Modell (leere Tabellen, alle Zaehler 0) muss ein
valides PDF ergeben (Leer-Fallback der Rubriken greift).
"""

from application.reporting.outbound_pdf_model import OutboundPdfModel
from application.reporting.report_texts import ACHSE_B_FUSSNOTE
from infrastructure.export_pdf import ReportlabRenderer


def _gefuelltes_modell() -> OutboundPdfModel:
    """Ein voll befuelltes Modell: zwei Verteilungen + zwei Kontakt-Zeilen, je mit Bewertung."""
    return OutboundPdfModel(
        title="Netzwerk-Außenkontakte-Bericht",
        generated_at_text="Erstellt am 28.06.2026 12:00",
        footer_left="CERNIS PRO 2.0 — Netzwerk-Außenkontakte-Bericht",
        achse_b_fussnote=ACHSE_B_FUSSNOTE.get("de"),
        einleitung=(
            "Dieser Bericht fasst die aufgezeichneten Außenkontakte dieses Rechners zusammen "
            "und ordnet sie gegen die aktiven Blocklisten ein."
        ),
        recording_label="Büro-Aufzeichnung",
        scope_text="Bezug: Aufzeichnung „Büro-Aufzeichnung“",
        contacts_total=3,
        remote_total=2,
        local_total=1,
        connection_total=42,
        countries_total=2,
        operators_total=2,
        tracker_contacts=1,
        threat_contacts=1,
        flagged_contacts=2,
        country_rows=(("Deutschland", "1"), ("USA", "1")),
        operator_rows=(("Cloudflare", "1"), ("Google LLC", "1")),
        contact_rows=(
            ("1.2.3.4", "tracker.example", "USA", "Google LLC", "30", "Tracker: StevenBlack"),
            ("5.6.7.8", "böse.example", "Deutschland", "Cloudflare", "12", "Bedrohung: Feodo"),
        ),
    )


def _leeres_modell() -> OutboundPdfModel:
    """Ein leeres Modell: leere Tabellen, alle Kennzahlen 0 (Leerfall -- ehrliches Datum)."""
    return OutboundPdfModel(
        title="Netzwerk-Außenkontakte-Bericht",
        generated_at_text="Erstellt am 28.06.2026 12:00",
        footer_left="CERNIS PRO 2.0 — Netzwerk-Außenkontakte-Bericht",
        achse_b_fussnote=ACHSE_B_FUSSNOTE.get("de"),
        einleitung=(
            "Dieser Bericht fasst die aufgezeichneten Außenkontakte dieses Rechners zusammen "
            "und ordnet sie gegen die aktiven Blocklisten ein."
        ),
        recording_label="Alle Aufzeichnungen",
        scope_text="Bezug: Alle Aufzeichnungen",
        contacts_total=0,
        remote_total=0,
        local_total=0,
        connection_total=0,
        countries_total=0,
        operators_total=0,
        tracker_contacts=0,
        threat_contacts=0,
        flagged_contacts=0,
        country_rows=(),
        operator_rows=(),
        contact_rows=(),
    )


def test_render_outbound_report_pdf_liefert_valide_bytes() -> None:
    """Gefuelltes Modell -> nicht-leere Bytes mit dem Magic-Header ``%PDF``."""
    data = ReportlabRenderer().render_outbound_report_pdf(_gefuelltes_modell())
    assert isinstance(data, bytes)
    assert len(data) > 0
    assert data.startswith(b"%PDF")


def test_render_outbound_report_pdf_leeres_modell_ist_valide() -> None:
    """Leeres Modell (leere Tabellen, Kennzahlen 0) ergibt trotzdem valides PDF (Leer-Fallback)."""
    data = ReportlabRenderer().render_outbound_report_pdf(_leeres_modell())
    assert data.startswith(b"%PDF")
