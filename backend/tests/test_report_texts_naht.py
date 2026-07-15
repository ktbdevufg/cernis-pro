"""Waechter der zweisprachigen Berichts-Textnaht (Etappen E0 + E2).

ZWECK: Dieses Netz haelt das Fundament der Naht fest -- die Textquelle selbst (A/B) UND die
beiden Regressions-Wachen (C/D), die beweisen, dass der Renderer KEINE Berichts-Texte mehr
hartkodiert. Die Wachen sind der eigentliche Wert: sie schlagen an, sobald jemand ein
deutsches Literal zurueck in ``export_pdf.py`` schreibt, statt es ueber ``report_texts`` +
Projektion zu fuehren.

C/D pruefen bewusst den QUELLTEXT (Datei einlesen, Abwesenheit pruefen) und nicht das
gerenderte PDF: das Ziel ist die ARCHITEKTUR-Eigenschaft "kein Text im Renderer", nicht die
Optik einer einzelnen Seite -- und ein Quelltext-Assert benennt bei Bruch sofort die Ursache.

E2 ergaenzt die Wachen um die RAHMENTEXTE (Titel/Fusszeile/Einleitung) der sieben Berichte:
E/F pruefen die Konstanten selbst, G den Durchstich durch eine echte Projektion (der Beweis,
dass ``lang`` bis in das fertige Modell durchschlaegt) und H die Fusszeilen-Vereinheitlichung.
"""

from __future__ import annotations

import pathlib
import time

from application.reporting.report_texts import (
    ACHSE_B_FUSSNOTE,
    ERSTELLT_AM_PRAEFIX,
    REPORT_FOOTER_BEHAVIOR,
    REPORT_FOOTER_CVE,
    REPORT_FOOTER_DNS_BYPASS,
    REPORT_FOOTER_DNS_WATCH,
    REPORT_FOOTER_INVENTORY,
    REPORT_FOOTER_OUTBOUND,
    REPORT_FOOTER_SECURITY,
    REPORT_INTRO_BEHAVIOR,
    REPORT_INTRO_CVE,
    REPORT_INTRO_DNS_BYPASS,
    REPORT_INTRO_DNS_WATCH,
    REPORT_INTRO_INVENTORY,
    REPORT_INTRO_OUTBOUND,
    REPORT_INTRO_SECURITY,
    REPORT_TITLE_BEHAVIOR,
    REPORT_TITLE_CVE,
    REPORT_TITLE_DNS_BYPASS,
    REPORT_TITLE_DNS_WATCH,
    REPORT_TITLE_INVENTORY,
    REPORT_TITLE_OUTBOUND,
    REPORT_TITLE_SECURITY,
    SEITE_PRAEFIX,
    LocalizedText,
    format_datum_kurz,
    format_generated_at,
)

# Fester Zeitstempel: 2026-03-06 14:05:00 LOKALZEIT. Bewusst ueber time.mktime aus den
# Kalenderfeldern gebaut statt als roher Epoch-Wert -- die Helfer formatieren mit
# time.localtime, ein fester Epoch-Wert waere sonst zonenabhaengig und der Test in anderer
# TZ rot (die CI laeuft nicht garantiert in Europe/Berlin).
_TS = time.mktime((2026, 3, 6, 14, 5, 0, 0, 0, -1))


# ── Test A: Datums-/Zahlenformat je Sprache ─────────────────────────────────


def test_format_generated_at_de_und_en_unterscheiden_sich() -> None:
    """de traegt TT.MM.JJJJ + deutsches Praefix, en ISO + englisches Praefix (24h beide)."""
    assert format_generated_at(_TS, "de") == "Erstellt am 06.03.2026 14:05"
    assert format_generated_at(_TS, "en") == "Generated on 2026-03-06 14:05"
    # Der Kern der Naht: derselbe Zeitpunkt, ZWEI verschiedene Darstellungen.
    assert format_generated_at(_TS, "de") != format_generated_at(_TS, "en")


def test_format_datum_kurz_de_und_en_unterscheiden_sich() -> None:
    """Reines Datum, ohne Uhrzeit und ohne Praefix."""
    assert format_datum_kurz(_TS, "de") == "06.03.2026"
    assert format_datum_kurz(_TS, "en") == "2026-03-06"


def test_format_generated_at_ist_24h_ohne_am_pm() -> None:
    """Nachmittags-Zeit bleibt in BEIDEN Sprachen 24h (so entschieden) -- kein AM/PM."""
    # Kein type: ignore noetig -- mypy leitet das Tupel-Literal direkt als Lang ab.
    for lang in ("de", "en"):
        text = format_generated_at(_TS, lang)
        assert "14:05" in text
        assert "PM" not in text.upper()


# ── Test B: LocalizedText.get liefert das jeweilige Feld ────────────────────


def test_localized_text_get_liefert_jeweiliges_feld() -> None:
    text = LocalizedText(de="Deutscher Text", en="English text")
    assert text.get("de") == "Deutscher Text"
    assert text.get("en") == "English text"


def test_kapitel0_konstanten_tragen_beide_sprachen() -> None:
    """Die querschnittlichen Texte sind in beiden Sprachen belegt und verschieden."""
    for konstante in (ACHSE_B_FUSSNOTE, ERSTELLT_AM_PRAEFIX, SEITE_PRAEFIX):
        assert konstante.get("de").strip()
        assert konstante.get("en").strip()
        assert konstante.get("de") != konstante.get("en")


# ── Regressionsnetz: der Renderer haelt KEINE Berichts-Texte mehr ───────────

_EXPORT_PDF = pathlib.Path(__file__).resolve().parents[1] / "infrastructure" / "export_pdf.py"


def _renderer_quelltext() -> str:
    return _EXPORT_PDF.read_text(encoding="utf-8")


def test_c_kein_hartkodierter_berichtstitel_im_renderer() -> None:
    """(C) Der Kopf-Titel kommt aus dem Modell -- der Titel steht nicht mehr in der Datei.

    Bis E0 zog ``_draw_header_footer`` den Titel des Sicherheitsberichts aus einem Literal;
    jetzt aus ``model.title``. Faellt jemand zurueck, ist dieser Test rot.
    """
    # Gestueckelt zusammengesetzt: sonst traegt DIESE Testdatei den Titel als Literal und der
    # Waechter wuerde -- liefe er je ueber sich selbst -- an sich selbst haengen.
    titel = "Netzwerk-" + "Sicherheitsbericht"
    assert titel not in _renderer_quelltext()


def test_d_keine_achse_b_fussnote_als_literal_im_renderer() -> None:
    """(D) Der Achse-B-Wortlaut steht 0x im Renderer -- alle sieben lesen ihn aus dem Modell."""
    wortlaut = ACHSE_B_FUSSNOTE.get("de")
    assert wortlaut not in _renderer_quelltext()
    # Gegenprobe: die sieben Berichte lesen das Modellfeld wirklich (sonst waere die
    # Abwesenheit oben auch dann gruen, wenn die Fussnote schlicht geloescht worden waere).
    assert _renderer_quelltext().count("model.achse_b_fussnote,") == 7


# ── E2: die Rahmentexte der sieben Berichte ─────────────────────────────────

# Je Bericht das Tripel (Titel, Fusszeile, Einleitung) -- die Wachen unten laufen ueber ALLE
# sieben, damit ein achter Bericht (oder ein vergessener Text) nicht durchrutscht.
_RAHMEN = (
    (REPORT_TITLE_SECURITY, REPORT_FOOTER_SECURITY, REPORT_INTRO_SECURITY),
    (REPORT_TITLE_INVENTORY, REPORT_FOOTER_INVENTORY, REPORT_INTRO_INVENTORY),
    (REPORT_TITLE_CVE, REPORT_FOOTER_CVE, REPORT_INTRO_CVE),
    (REPORT_TITLE_OUTBOUND, REPORT_FOOTER_OUTBOUND, REPORT_INTRO_OUTBOUND),
    (REPORT_TITLE_DNS_WATCH, REPORT_FOOTER_DNS_WATCH, REPORT_INTRO_DNS_WATCH),
    (REPORT_TITLE_DNS_BYPASS, REPORT_FOOTER_DNS_BYPASS, REPORT_INTRO_DNS_BYPASS),
    (REPORT_TITLE_BEHAVIOR, REPORT_FOOTER_BEHAVIOR, REPORT_INTRO_BEHAVIOR),
)


def test_e_alle_rahmentexte_tragen_beide_sprachen() -> None:
    """(E) Alle 21 Rahmentexte sind in beiden Sprachen belegt und wirklich uebersetzt.

    Das ``!=`` ist die eigentliche Wache: eine en-Fassung, die aus Bequemlichkeit den
    deutschen Satz kopiert, waere ein stiller Fallback (CLAUDE.md/Finding S3) -- der Typ-Zwang
    von ``LocalizedText`` erzwingt ein en-Feld, aber nicht dessen Inhalt.
    """
    for titel, footer, intro in _RAHMEN:
        for konstante in (titel, footer, intro):
            assert konstante.get("de").strip()
            assert konstante.get("en").strip()
            assert konstante.get("de") != konstante.get("en")


def test_f_alle_fusszeilen_tragen_produktname_und_denselben_trenner() -> None:
    """(F) Fusszeilen-Vereinheitlichung (E2): EIN Trenner ueber alle sieben, beide Sprachen.

    Der Sicherheitsbericht trug hier als einziger einen einfachen Bindestrich; diese Wache
    haelt die Korrektur fest und verhindert, dass ein neuer Bericht wieder ausschert.
    """
    for _titel, footer, _intro in _RAHMEN:
        for lang in ("de", "en"):
            text = footer.get(lang)
            assert text.startswith("CERNIS PRO 2.0 — "), text
            # Genau EIN Trenner: der Berichtsname selbst fuehrt keinen zweiten Gedankenstrich.
            assert text.count(" — ") == 1, text


def test_g_projektion_zieht_die_rahmentexte_sprachabhaengig() -> None:
    """(G) DER DURCHSTICH: dieselbe Projektion, zwei Sprachen, zwei Rahmen.

    Der Beweis, dass ``lang`` bis ins fertige Modell durchschlaegt -- nicht nur, dass die
    Konstanten existieren. Leerer Bericht: die Rahmentexte haengen nicht an Befunden.
    """
    # Import in der Funktion: ``app`` zieht den halben Composition Root nach; die uebrigen
    # Wachen dieser Datei pruefen reine Textquellen und sollen davon unabhaengig bleiben.
    from app import _project_security_pdf_model
    from application.reporting import SecurityReport
    from application.reporting.security_score import compute_security_score

    leer = SecurityReport(
        score=compute_security_score([]),
        port_findings=[],
        cve_findings=[],
        net_findings=[],
        acknowledged_port_findings=[],
        acknowledged_cve_findings=[],
        acknowledged_net_findings=[],
        device_labels=[],
    )

    de_model = _project_security_pdf_model(leer, False, "Erstellt am 06.03.2026 14:05", None)
    en_model = _project_security_pdf_model(
        leer, False, "Generated on 2026-03-06 14:05", None, lang="en"
    )

    # de: unveraendert der gewohnte Wortlaut (ausser dem korrigierten Fusszeilen-Trenner).
    assert de_model.title == "Netzwerk-Sicherheitsbericht"
    assert de_model.footer_left == "CERNIS PRO 2.0 — Netzwerk-Sicherheitsbericht"
    assert de_model.einleitung.startswith("Dieser Bericht fasst")

    # en: der englische Rahmen -- das Ziel der Etappe.
    assert en_model.title == "Network Security Report"
    assert en_model.footer_left == "CERNIS PRO 2.0 — Network Security Report"
    assert en_model.einleitung.startswith("This report brings together")

    # Und die Fussnote der Naht folgt derselben Sprache (E0 bleibt intakt).
    assert en_model.achse_b_fussnote == ACHSE_B_FUSSNOTE.get("en")
