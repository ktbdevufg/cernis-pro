"""Waechter der zweisprachigen Berichts-Textnaht (Etappe E0).

ZWECK: Dieses Netz haelt das Fundament der Naht fest -- die Textquelle selbst (A/B) UND die
beiden Regressions-Wachen (C/D), die beweisen, dass der Renderer KEINE Berichts-Texte mehr
hartkodiert. Die Wachen sind der eigentliche Wert: sie schlagen an, sobald jemand ein
deutsches Literal zurueck in ``export_pdf.py`` schreibt, statt es ueber ``report_texts`` +
Projektion zu fuehren.

C/D pruefen bewusst den QUELLTEXT (Datei einlesen, Abwesenheit pruefen) und nicht das
gerenderte PDF: das Ziel ist die ARCHITEKTUR-Eigenschaft "kein Text im Renderer", nicht die
Optik einer einzelnen Seite -- und ein Quelltext-Assert benennt bei Bruch sofort die Ursache.
"""

from __future__ import annotations

import pathlib
import time

from application.reporting.report_texts import (
    ACHSE_B_FUSSNOTE,
    ERSTELLT_AM_PRAEFIX,
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
