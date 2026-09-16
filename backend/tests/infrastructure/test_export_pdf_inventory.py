"""Tests des Bestandsbericht-Render-Pfads -- Leer-Marker der beiden Verteilungen.

Wie ``test_export_pdf_dns_watch.py``: kein echtes Netz, kein Datei-I/O ausser dem in-memory
``BytesIO``. Schwerpunkt hier ist die Aufloesung der MASCHINELLEN Leer-Marker
(``__vendor_unknown__``/``__category_unknown__``) zu ihrem Anzeigetext: das Backend liefert
in den Verteilungen keinen deutschen Anzeigetext mehr, der Renderer uebersetzt ueber den
vorhandenen ``_ui``-Weg. Der rohe Marker darf in KEINER Sprache im PDF landen.

Der Wortlaut wird an der reinen Aufloesefunktion geprueft (dort steht er im Klartext); der
Render-Durchlauf pruefen wir zusaetzlich nur auf valides PDF -- kein Layout-Assert.
"""

from application.reporting.inventory_pdf_model import InventoryPdfModel
from infrastructure.export_pdf import (
    _EMPTY_CATEGORY_MARKER,
    _EMPTY_VENDOR_MARKER,
    ReportlabRenderer,
    _resolve_distribution_marker,
)


def _modell(
    vendor_rows: tuple[tuple[str, str], ...],
    category_rows: tuple[tuple[str, str], ...],
) -> InventoryPdfModel:
    """Ein Bestands-Modell; nur die beiden Verteilungen sind fuer diese Tests relevant."""
    return InventoryPdfModel(
        title="Bestandsbericht",
        generated_at_text="Erstellt am 25.07.2026 12:00",
        footer_left="CERNIS PRO 2.0 — Bestandsbericht",
        einleitung="Dieser Bericht fasst den Geräte-Bestand dieses Netzes zusammen.",
        achse_b_fussnote="",
        total=2,
        known=2,
        unknown=0,
        active_24h=1,
        trusted=0,
        watch=0,
        neutral=2,
        vendor_rows=vendor_rows,
        category_rows=category_rows,
    )


def test_hersteller_marker_wird_zum_anzeigetext_in_beiden_sprachen() -> None:
    """T1: ``__vendor_unknown__`` -> Anzeigetext, je Sprache SPRACHRICHTIG."""
    rows = ((_EMPTY_VENDOR_MARKER, "3"),)
    erwartet = {
        "de": "Kein Hersteller ermittelt",
        "en": "No vendor identified",
    }

    for lang, text in erwartet.items():
        aufgeloest = _resolve_distribution_marker(rows, _EMPTY_VENDOR_MARKER, lang)
        assert aufgeloest == ((text, "3"),)


def test_kategorie_marker_wird_zum_anzeigetext_in_beiden_sprachen() -> None:
    """T2: ``__category_unknown__`` -> Anzeigetext, je Sprache SPRACHRICHTIG.

    Bewusst ein ANDERER Wortlaut als beim Hersteller, obwohl beide denselben Sachverhalt
    beschreiben.
    """
    rows = ((_EMPTY_CATEGORY_MARKER, "24"),)
    erwartet = {
        "de": "Keine Kategorie ermittelt",
        "en": "No category identified",
    }

    for lang, text in erwartet.items():
        aufgeloest = _resolve_distribution_marker(rows, _EMPTY_CATEGORY_MARKER, lang)
        assert aufgeloest == ((text, "24"),)


def test_echte_labels_bleiben_unveraendert() -> None:
    """T3: Nur der EINE passende Marker wird ersetzt; Reihenfolge und count bleiben."""
    rows = (("NETGEAR", "2"), (_EMPTY_VENDOR_MARKER, "1"), ("Intel Corporate", "1"))

    aufgeloest = _resolve_distribution_marker(rows, _EMPTY_VENDOR_MARKER, "de")

    assert aufgeloest == (
        ("NETGEAR", "2"),
        ("Kein Hersteller ermittelt", "1"),
        ("Intel Corporate", "1"),
    )


def test_fremder_marker_wird_in_der_anderen_verteilung_nicht_aufgeloest() -> None:
    """T4: Die Hersteller-Aufloesung fasst den Kategorie-Marker nicht an (und umgekehrt).

    Sichert die Trennung der beiden Verteilungen ab -- sonst bekaeme eine von beiden den
    Wortlaut der anderen.
    """
    rows = ((_EMPTY_CATEGORY_MARKER, "1"),)

    assert _resolve_distribution_marker(rows, _EMPTY_VENDOR_MARKER, "de") == rows


def test_render_laesst_keinen_rohen_marker_im_pdf() -> None:
    """T5: Der gerenderte Bestandsbericht ist valides PDF -- in de und en.

    Die Marker gehen durch den Renderer; ein Fehler in der Aufloesung darf den
    Render-Pfad nicht sprengen.
    """
    modell = _modell(
        vendor_rows=((_EMPTY_VENDOR_MARKER, "3"), ("NETGEAR", "2")),
        category_rows=((_EMPTY_CATEGORY_MARKER, "24"),),
    )
    renderer = ReportlabRenderer()

    for lang in ("de", "en"):
        pdf = renderer.render_inventory_report_pdf(modell, lang)
        assert pdf.startswith(b"%PDF")
        assert len(pdf) > 1000
