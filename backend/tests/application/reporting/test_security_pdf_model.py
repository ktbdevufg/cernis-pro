"""Tests des render-fertigen ``SecurityPdfModel`` (Etappe 4a) -- Konstruktion + Feldtreue.

Das Modell ist ein reiner, frozen Datentraeger (KEINE reportlab-/Domaenen-Importe, KEINE
Rechnung). Hier wird ein Modell DIREKT aus Beispieldaten gebaut und geprueft, dass die Felder
korrekt gefuehrt werden (anzeige-fertige Texte/Zahlen/Tabellenzeilen). Das Rendern testet
``tests/infrastructure/test_security_report_pdf.py``.
"""

from application.reporting import ACHSE_B_FUSSNOTE, SecurityPdfModel
from application.reporting.security_pdf_model import (
    ACK_COLUMNS,
    CVE_COLUMNS,
    NET_COLUMNS,
    PORT_COLUMNS,
)


def _example_model() -> SecurityPdfModel:
    """Ein voll gefuelltes Beispiel-Modell mit anzeige-fertigen Texten (kein Rendern)."""
    return SecurityPdfModel(
        title="Netzwerk-Sicherheitsbericht",
        generated_at_text="Erzeugt am 23.06.2026 um 22:00 Uhr",
        footer_left="CERNIS PRO 2.0 — Professional Network Scanner & Monitor",
        achse_b_fussnote=ACHSE_B_FUSSNOTE.get("de"),
        score_value=72,
        score_level="maessig",
        score_level_label="maessig",
        score_einordnung="Das Netz zeigt einzelne offene Auffälligkeiten.",
        critical_devices=1,
        notable_devices=2,
        clean_devices=5,
        device_count=8,
        total_burden=1.6668,
        einleitung="Dieser Bericht fasst den aktuellen Stand zusammen.",
        rogue_hinweis="Hinweis: ein zweiter DHCP-Server wurde im Netz beobachtet.",
        contributions=(
            ("router.local", "kritisch", "1,00"),
            ("nas (192.168.1.20)", "auffällig", "0,33"),
        ),
        geraete_balken=(
            ("router.local", 1, 0),
            ("nas (192.168.1.20)", 0, 2),
        ),
        port_rows=(("router.local", "23, 2323", "kritisch", "Telnet ist im Klartext erreichbar."),),
        cve_rows=(
            ("nas (192.168.1.20)", "CVE-2024-1234", "9,8", "smb", "Kritische Lücke in SMB."),
            ("nas (192.168.1.20)", "CVE-2023-5678", "7,5", "http", "Veraltete Web-Oberfläche."),
        ),
        net_rows=(
            ("IP-Konflikt", "192.168.1.10", "auffällig", "Zwei Geräte teilen sich eine IP."),
        ),
        acknowledged_rows=(("Port", "drucker.local", "9100 als bewusst freigegeben bestätigt."),),
    )


def test_model_fuehrt_kopf_und_score_felder() -> None:
    model = _example_model()
    assert model.title == "Netzwerk-Sicherheitsbericht"
    assert model.generated_at_text.startswith("Erzeugt am")
    assert model.score_value == 72
    assert model.score_level == "maessig"
    assert model.score_einordnung


def test_model_fuehrt_zaehler_und_basis() -> None:
    model = _example_model()
    assert model.critical_devices == 1
    assert model.notable_devices == 2
    assert model.clean_devices == 5
    assert model.device_count == 8
    # clean+notable+critical summiert sich auf device_count (reine Konsistenz der Beispieldaten,
    # KEINE Rechnung im Modell -- die Werte kommen fertig herein).
    assert (
        model.critical_devices + model.notable_devices + model.clean_devices == model.device_count
    )


def test_model_contributions_sind_anzeige_fertig() -> None:
    """Severity-Klartext + "0,33"-Last kommen fertig -- das Modell formatiert nichts."""
    model = _example_model()
    labels = [sev for _, sev, _ in model.contributions]
    assert labels == ["kritisch", "auffällig"]
    last_texte = [last for *_, last in model.contributions]
    assert last_texte == ["1,00", "0,33"]


def test_model_geraete_balken_vollstaendig() -> None:
    """Alle Geraete mit Befund werden gefuehrt (kein Top-N) -- als (label, crit, notable)."""
    model = _example_model()
    assert len(model.geraete_balken) == 2
    assert model.geraete_balken[0] == ("router.local", 1, 0)


def test_model_tabellenzeilen_in_spalten_reihenfolge() -> None:
    """Die Zeilen tragen genau so viele Spalten wie das jeweilige ``*_COLUMNS``-Schema."""
    model = _example_model()
    assert all(len(row) == len(PORT_COLUMNS) for row in model.port_rows)
    assert all(len(row) == len(CVE_COLUMNS) for row in model.cve_rows)
    assert all(len(row) == len(NET_COLUMNS) for row in model.net_rows)
    assert all(len(row) == len(ACK_COLUMNS) for row in model.acknowledged_rows)


def test_model_cve_rows_nach_geraet_gruppiert() -> None:
    """cve_rows ist flach MIT Geraete-Spalte; gleiche Geraete stehen untereinander (gruppiert)."""
    model = _example_model()
    geraete = [row[0] for row in model.cve_rows]
    assert geraete == ["nas (192.168.1.20)", "nas (192.168.1.20)"]


def test_model_default_leerfall() -> None:
    """Ein Minimal-Modell (Score 100, keine Befunde) ist gueltig -- leere Tupel als Default."""
    model = SecurityPdfModel(
        title="Netzwerk-Sicherheitsbericht",
        generated_at_text="Erzeugt am 23.06.2026",
        footer_left="CERNIS PRO 2.0",
        achse_b_fussnote=ACHSE_B_FUSSNOTE.get("de"),
        score_value=100,
        score_level="gut",
        score_level_label="gut",
        score_einordnung="Keine offenen Auffälligkeiten.",
        critical_devices=0,
        notable_devices=0,
        clean_devices=3,
        device_count=3,
        total_burden=0.0,
        einleitung="",
    )
    assert model.rogue_hinweis == ""
    assert model.port_rows == ()
    assert model.cve_rows == ()
    assert model.net_rows == ()
    assert model.acknowledged_rows == ()
