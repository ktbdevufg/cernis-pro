"""Tests des Sicherheitsbericht-Render-Pfads ``render_security_report_pdf`` (Etappe 4a).

Wie beim Block-1-Adapter: KEIN Layout-/Pixel-Assert (das fuehrt reportlab) -- geprueft wird
NUR, dass valide PDF-Bytes entstehen (nicht-leer, Magic-Header ``%PDF``) und der Aufruf nicht
wirft. Mehrere Faelle: voller Bericht (alle Tabellen + Grafiken), Leerfall (Score 100, leere
Tabellen -> "Keine Eintraege", kein Absturz), bestaetigt-Tabelle leer -> Rubrik weggelassen.

Das Modell wird hier DIREKT gebaut (kein Composition Root) -- die Projektion ist 4b.
"""

from application.reporting import ACHSE_B_FUSSNOTE, SecurityPdfModel
from infrastructure.export_pdf import ReportlabRenderer


def _full_model() -> SecurityPdfModel:
    """Voll gefuelltes Modell: alle Grafiken + alle vier Tabellen-Rubriken belegt."""
    return SecurityPdfModel(
        title="Netzwerk-Sicherheitsbericht",
        generated_at_text="Erzeugt am 23.06.2026 um 22:00 Uhr",
        footer_left="CERNIS PRO 2.0 — Professional Network Scanner & Monitor",
        achse_b_fussnote=ACHSE_B_FUSSNOTE.get("de"),
        score_value=64,
        score_level="maessig",
        score_einordnung="Das Netz zeigt einzelne offene Auffälligkeiten — bitte prüfen.",
        critical_devices=2,
        notable_devices=3,
        clean_devices=7,
        device_count=12,
        total_burden=3.0,
        einleitung="Dieser Bericht beschreibt den aktuellen Stand des Heimnetzes.",
        rogue_hinweis="Hinweis: ein zweiter DHCP-Server wurde im Netz beobachtet.",
        contributions=(
            ("router.local", "kritisch", "1,00"),
            ("kamera (192.168.1.50)", "kritisch", "1,00"),
            ("nas (192.168.1.20)", "auffällig", "0,33"),
        ),
        geraete_balken=(
            ("router.local", 1, 0),
            ("kamera (192.168.1.50)", 1, 1),
            ("nas (192.168.1.20)", 0, 2),
        ),
        port_rows=(
            ("router.local", "23, 2323", "kritisch", "Telnet ist im Klartext erreichbar."),
            ("nas (192.168.1.20)", "21", "auffällig", "FTP überträgt Zugangsdaten im Klartext."),
        ),
        cve_rows=(
            ("kamera (192.168.1.50)", "CVE-2024-1234", "9,8", "rtsp", "Kritische Lücke im Stream."),
            ("nas (192.168.1.20)", "CVE-2023-5678", "7,5", "http", "Veraltete Web-Oberfläche."),
        ),
        net_rows=(
            ("IP-Konflikt", "192.168.1.10", "auffällig", "Zwei Geräte teilen sich eine IP."),
        ),
        acknowledged_rows=(("Port", "drucker.local", "9100 als bewusst freigegeben bestätigt."),),
    )


def _empty_model() -> SecurityPdfModel:
    """Leerfall: Score 100, keine Befunde -> jede Rubrik 'Keine Einträge.', kein Absturz."""
    return SecurityPdfModel(
        title="Netzwerk-Sicherheitsbericht",
        generated_at_text="Erzeugt am 23.06.2026 um 22:00 Uhr",
        footer_left="CERNIS PRO 2.0 — Professional Network Scanner & Monitor",
        achse_b_fussnote=ACHSE_B_FUSSNOTE.get("de"),
        score_value=100,
        score_level="gut",
        score_einordnung="Keine offenen Auffälligkeiten — das Netz ist unauffällig.",
        critical_devices=0,
        notable_devices=0,
        clean_devices=0,
        device_count=0,
        total_burden=0.0,
        einleitung="Dieser Bericht beschreibt den aktuellen Stand.",
    )


def test_render_voller_bericht_ist_valides_pdf() -> None:
    data = ReportlabRenderer().render_security_report_pdf(_full_model())
    assert isinstance(data, bytes)
    assert len(data) > 0
    assert data.startswith(b"%PDF")


def test_render_leerfall_ist_valides_pdf() -> None:
    """Score 100, leere Tabellen, leeres Netz (device_count 0) -> valides PDF, kein Absturz."""
    data = ReportlabRenderer().render_security_report_pdf(_empty_model())
    assert data.startswith(b"%PDF")


def test_render_ohne_bestaetigte_rubrik() -> None:
    """Leere ``acknowledged_rows`` -> Rubrik 4 wird weggelassen, der Rest rendert sauber."""
    model = _full_model()
    ohne_ack = SecurityPdfModel(
        title=model.title,
        generated_at_text=model.generated_at_text,
        footer_left=model.footer_left,
        achse_b_fussnote=ACHSE_B_FUSSNOTE.get("de"),
        score_value=model.score_value,
        score_level=model.score_level,
        score_einordnung=model.score_einordnung,
        critical_devices=model.critical_devices,
        notable_devices=model.notable_devices,
        clean_devices=model.clean_devices,
        device_count=model.device_count,
        total_burden=model.total_burden,
        einleitung=model.einleitung,
        rogue_hinweis=model.rogue_hinweis,
        contributions=model.contributions,
        geraete_balken=model.geraete_balken,
        port_rows=model.port_rows,
        cve_rows=model.cve_rows,
        net_rows=model.net_rows,
        acknowledged_rows=(),
    )
    data = ReportlabRenderer().render_security_report_pdf(ohne_ack)
    assert data.startswith(b"%PDF")


def test_render_sonderzeichen_brechen_nicht() -> None:
    """Aktive XML-Zeichen (& < >) in Zellen werden maskiert -> valides PDF."""
    model = SecurityPdfModel(
        title="Netzwerk-Sicherheitsbericht",
        generated_at_text="Erzeugt am 23.06.2026",
        footer_left="CERNIS PRO 2.0",
        achse_b_fussnote=ACHSE_B_FUSSNOTE.get("de"),
        score_value=50,
        score_level="maessig",
        score_einordnung="Test <mit> & Sonderzeichen.",
        critical_devices=1,
        notable_devices=0,
        clean_devices=1,
        device_count=2,
        total_burden=1.0,
        einleitung="A & B <lab> Einleitung.",
        port_rows=(("A & B <lab>", "23", "kritisch", "Grund mit < und > und &."),),
        geraete_balken=(("A & B <lab>", 1, 0),),
        contributions=(("A & B <lab>", "kritisch", "1,00"),),
    )
    data = ReportlabRenderer().render_security_report_pdf(model)
    assert data.startswith(b"%PDF")


def test_bestehender_scan_export_pfad_unveraendert() -> None:
    """Der bestehende ``render_pdf``-Pfad (PdfReportModel) bleibt unberuehrt und valide."""
    from domain.export import PdfReportModel

    model = PdfReportModel(
        title="CERNIS PRO — Scan-Bericht",
        meta=(("Gescanntes Netz", "192.168.1.0/24"),),
        columns=("ip", "open_ports"),
        rows=(("192.168.1.10", "22/tcp"),),
    )
    data = ReportlabRenderer().render_pdf(model)
    assert data.startswith(b"%PDF")
