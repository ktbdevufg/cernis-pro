"""Render-fertiges PDF-Modell des Benutzerhandbuchs -- reiner Datentraeger.

Muster ``security_pdf_model.py``: ein NEUTRALES, vollstaendig anzeige-fertiges Modell
``ManualPdfModel``, das der Composition Root aus den geladenen Hilfe-Inhalten
(``frontend/src/lib/help_content.json``) PROJIZIERT und das der reportlab-Adapter
(``infrastructure/export_pdf.py``) ohne jede eigene Rechnung rendert.

REINE PROJEKTION, KEINE RECHNUNG:
  * KEINE reportlab-Importe -- das Modell ist ein neutraler Datentraeger; das Rendern macht
    allein die Infrastruktur.
  * KEINE Domaenen-Importe -- es lebt in ``application/reporting`` und wird vom Composition
    Root befuellt, traegt aber selbst nur Primitive/Tupel.
  * KEINE Uhr, KEINE Formatierung: ALLE Texte (der Titel, das Erzeugungsdatum, die
    Fusszeile, die Abschnitts-Texte) kommen schon FERTIG vom Composition Root herein. Der
    Adapter setzt sie nur, das Modell fuehrt sie nur.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ManualPdfSection:
    """Ein Handbuch-Abschnitt (frozen, neutral) -- anzeige-fertig.

    ``category_label`` die Kategorie-Ueberschrift (z. B. "Grundlagen"); der Adapter gibt sie
    nur EINMAL aus, solange sie sich gegenueber dem vorigen Abschnitt nicht aendert.
    ``heading`` der Abschnitts-Titel, ``paragraphs`` die fertigen Fliesstext-Absaetze (an
    Leerzeilen getrennt, gestrippt, nicht-leer) in Anzeige-Reihenfolge.
    """

    category_label: str
    heading: str
    paragraphs: tuple[str, ...]


@dataclass(frozen=True)
class ManualPdfModel:
    """Render-fertiges PDF-Modell des Benutzerhandbuchs (frozen, neutral).

    Alle Felder sind ANZEIGE-FERTIG. KOPF/FUSS: ``title`` der Handbuch-Titel (zugleich
    Kopf-Titel je Seite), ``generated_at_text`` das schon formatierte Erzeugungsdatum (der
    Adapter fragt keine Uhr), ``footer_left`` die Produktzeile der Fusszeile. ``intro`` ein
    optionaler Einleitungs-Absatz (leer -> weggelassen). ``sections`` die Abschnitte in
    Anzeige-Reihenfolge (= JSON-Reihenfolge).
    """

    title: str
    generated_at_text: str
    footer_left: str
    intro: str = ""
    sections: tuple[ManualPdfSection, ...] = field(default_factory=tuple)
