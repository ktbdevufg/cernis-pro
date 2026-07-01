"""Tests des DNS-Waechter-Bericht-Render-Pfads (Etappe 2) -- valides PDF, kein Layout-Assert.

Wie ``test_export_pdf_outbound.py``: kein echtes Netz, kein Datei-I/O ausser dem in-memory
``BytesIO``. Der Adapter rendert das render-fertige ``DnsWatchPdfModel`` zu Bytes; wir pruefen NUR,
dass valides PDF rauskommt (nicht-leere Bytes mit dem Magic-Header ``%PDF``) -- kein Layout-/Pixel-
Assert (das fuehrt reportlab). Auch das LEERE Modell (leere Tabellen, alle Zaehler 0) muss ein
valides PDF ergeben (Leer-Fallback der Rubriken greift).
"""

from application.reporting.dns_watch_pdf_model import DnsWatchPdfModel
from infrastructure.export_pdf import ReportlabRenderer


def _gefuelltes_modell() -> DnsWatchPdfModel:
    """Ein voll befuelltes Modell: beide Verteilungen + zwei Kontakt-Zeilen, je mit Status."""
    return DnsWatchPdfModel(
        title="DNS-Wächter-Bericht",
        generated_at_text="Erstellt am 28.06.2026 12:00",
        footer_left="CERNIS PRO 2.0 — DNS-Wächter-Bericht",
        einleitung=(
            "Dieser Bericht fasst die DNS-relevanten Außenkontakte dieses Rechners zusammen und "
            "ordnet sie gegen die erwarteten DNS-Server und die bekannten DoH-Anbieter ein."
        ),
        scope_text="Sicht: nur dieser Rechner (nicht netzweit)",
        expected_text="Erwartete DNS-Server: 192.168.1.1",
        doh_text="Bekannte DoH-Anbieter: cloudflare-dns.com, dns.google",
        contacts_total=3,
        active_total=2,
        acknowledged_total=1,
        expected_active=1,
        open_active=1,
        doh_active=0,
        flagged_active=1,
        category_rows=(
            ("Offen (fremder Resolver)", "1"),
            ("Möglicher DoH", "0"),
            ("Erwartungsgemäß", "1"),
        ),
        app_rows=(("firefox", "1"), ("systemd-resolved", "1")),
        contact_rows=(
            ("Offen (fremder Resolver)", "1.1.1.1", "one.one.one.one", "firefox", "30", "Aktiv"),
            ("Erwartungsgemäß", "192.168.1.1", "—", "systemd-resolved", "12", "Quittiert"),
        ),
    )


def _leeres_modell() -> DnsWatchPdfModel:
    """Ein leeres Modell: leere Tabellen, alle Kennzahlen 0 (Leerfall -- ehrliches Datum)."""
    return DnsWatchPdfModel(
        title="DNS-Wächter-Bericht",
        generated_at_text="Erstellt am 28.06.2026 12:00",
        footer_left="CERNIS PRO 2.0 — DNS-Wächter-Bericht",
        einleitung=(
            "Dieser Bericht fasst die DNS-relevanten Außenkontakte dieses Rechners zusammen und "
            "ordnet sie gegen die erwarteten DNS-Server und die bekannten DoH-Anbieter ein."
        ),
        scope_text="Sicht: nur dieser Rechner (nicht netzweit)",
        expected_text="Erwartete DNS-Server: (keine)",
        doh_text="Bekannte DoH-Anbieter: (keine)",
        contacts_total=0,
        active_total=0,
        acknowledged_total=0,
        expected_active=0,
        open_active=0,
        doh_active=0,
        flagged_active=0,
        category_rows=(),
        app_rows=(),
        contact_rows=(),
    )


def test_render_dns_watch_report_pdf_liefert_valide_bytes() -> None:
    """Gefuelltes Modell -> nicht-leere Bytes mit dem Magic-Header ``%PDF``."""
    data = ReportlabRenderer().render_dns_watch_report_pdf(_gefuelltes_modell())
    assert isinstance(data, bytes)
    assert len(data) > 0
    assert data.startswith(b"%PDF")


def test_render_dns_watch_report_pdf_leeres_modell_ist_valide() -> None:
    """Leeres Modell (leere Tabellen, Kennzahlen 0) ergibt trotzdem valides PDF (Leer-Fallback)."""
    data = ReportlabRenderer().render_dns_watch_report_pdf(_leeres_modell())
    assert data.startswith(b"%PDF")
