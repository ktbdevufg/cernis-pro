"""Zentrale, typisierte, zweisprachige Textquelle der Berichte (Etappe E0) -- Fundament.

DAS FUNDAMENT DER BERICHTS-TEXTNAHT: bis hierher trugen die sieben PDF-Berichte ihren
deutschen Text HARTKODIERT im reportlab-Adapter. Dieses Modul ist die EINE Quelle, aus der
alle Berichts-Texte kommen -- zweisprachig (de/en) und maschinell erzwungen.

DER ERZWINGENDE KERN: ``LocalizedText`` hat ZWEI PFLICHTFELDER (``de`` UND ``en``, kein
Default). Ein neuer Text ohne englische Fassung ist damit kein stiller Rueckfall auf
Deutsch, sondern ein mypy-FEHLER beim Konstruieren. Jeder kuenftige Bericht MUSS beide
Sprachen liefern -- das ist Absicht und der ganze Zweck dieses Moduls (vgl. CLAUDE.md,
"Keine stillen Fallbacks", Finding S3).

STEUER-SCHLUESSEL vs. ANZEIGE-TEXT (Vorbild: CVE-Bericht, ``cve_pdf_model``):
  Der CVE-Bericht trennt bereits sauber -- ``severity_rows`` traegt den ROHEN technischen
  Schluessel (Farb-Lookup ``_SEV_COLORS`` im Renderer), ``severity_labels`` daneben den
  uebersetzten ANZEIGE-Text. Dieses Muster gilt fuer die ganze Naht: deutsche Woerter, die
  als STEUER-SCHLUESSEL dienen (``_LEVEL_COLORS``-Keys, "Schwere" in ``columns``,
  ``kategorie_labels``-Keys), werden NIE uebersetzt -- nur ihre Anzeige. Dieses Modul
  enthaelt daher ausschliesslich ANZEIGE-Texte.

RING-LAGE (hexagonal, CLAUDE.md): ``application/reporting`` -- NICHT ``domain`` (kein
Domaenen-Begriff, sondern Darstellung) und NICHT ``infrastructure`` (der Renderer soll
gerade KEINE Text-Quelle mehr sein). Nur stdlib-Importe, keine Ring-Kanten.

AUFLOESUNG erst in der PROJEKTION: Die PDF-Modelle sind ANZEIGE-FERTIG (der Adapter rechnet
und formatiert nicht). Darum traegt KEIN Modell ein ``LocalizedText`` -- der Composition
Root (``app.py``) loest es via ``.get(lang)`` zum FERTIGEN String auf und setzt diesen ins
Modell; der Renderer liest nur noch.

STAND E0: nur die querschnittlichen Texte aus Kapitel 0 des Inventars (die 7x duplizierte
Achse-B-Fussnote + die Kopf-/Fusszeilen-Praefixe). Die Texte der sieben Berichte selbst
ziehen in E1-E3 nach.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Literal

# ── Sprachtyp ───────────────────────────────────────────────────────────────
#
# Ein geschlossener Literal-Typ statt ``str``: mypy weist einen Tippfehler ("De", "deu")
# schon beim Aufruf ab, und ``LocalizedText.get`` deckt mit genau diesen zwei Zweigen ALLE
# Faelle ab (kein Rueckfall-Zweig noetig -- s. ``get``).
Lang = Literal["de", "en"]


@dataclass(frozen=True)
class LocalizedText:
    """Ein Anzeige-Text in beiden Sprachen (frozen, beide Felder PFLICHT).

    Der Typ-Zwang der ganzen Naht steckt in der Signatur: ``de`` und ``en`` haben KEINEN
    Default. ``LocalizedText(de="...")`` ist damit ein mypy-Fehler ("Missing named argument
    'en'") -- eine neue deutsche Zeile ohne englische Fassung kommt gar nicht erst durch die
    Gates. Genau das soll dieses Modul erzwingen.

    ``frozen=True`` wie die PDF-Modelle: Texte sind Konstanten, keine Zustandstraeger.
    """

    de: str
    en: str

    def get(self, lang: Lang) -> str:
        """Liefert die Fassung fuer ``lang``.

        KEIN stiller Fallback (CLAUDE.md/Finding S3): ``Lang`` ist geschlossen, beide Zweige
        sind abgedeckt -- es gibt keinen dritten Fall, der still auf Deutsch zurueckfallen
        koennte.
        """
        if lang == "de":
            return self.de
        return self.en


# ── Kapitel 0 des Inventars: querschnittliche Texte ─────────────────────────
#
# Diese Texte gehoeren KEINEM einzelnen Bericht, sondern allen. Die en-Fassungen sind
# nuechtern-professionell gehalten (Ton wie das Handbuch), keine Werbesprache.

# Die Achse-B-Haltung des Produkts: der Bericht BESCHREIBT und ORDNET EIN -- er urteilt
# nicht. Stand bis E0 7x wortgleich im Renderer (Zeilen 784/1136/1426/1628/1780/1935/2233);
# jetzt EINE Quelle, die alle sieben Projektionen speist.
ACHSE_B_FUSSNOTE = LocalizedText(
    de="Dieser Bericht beschreibt und ordnet ein — er fällt kein Urteil.",
    en="This report describes and provides context — it does not pass judgement.",
)

# Praefix der Kopfzeilen-Datumsangabe; ``format_generated_at`` setzt es selbst davor.
ERSTELLT_AM_PRAEFIX = LocalizedText(
    de="Erstellt am ",
    en="Generated on ",
)

# Praefix der Seitenzahl in der Fusszeile ("Seite 3" / "Page 3").
SEITE_PRAEFIX = LocalizedText(
    de="Seite ",
    en="Page ",
)


# ── Datums- und Zahlenformat ────────────────────────────────────────────────
#
# REINE Helfer (Zeitstempel kommt HEREIN, keine Uhr-Abfrage): dieselbe ``ts`` ergibt immer
# denselben Text -- direkt unit-testbar, keine versteckte Zeitabhaengigkeit. Sie loesen
# spaeter die 8x duplizierte "Erstellt am"-Logik ab; in E0 werden sie nur bereitgestellt und
# getestet.
#
# FORMAT-ENTSCHEIDUNG (Auftrag): de traegt die gewohnte deutsche Schreibweise
# (TT.MM.JJJJ), en die ISO-Konvention (%Y-%m-%d) -- beide mit 24h-Uhrzeit, also KEIN
# AM/PM. ``time.localtime`` haelt beide Sprachen in derselben lokalen Zone; die Sprache
# aendert die SCHREIBWEISE, nicht den Zeitpunkt.


def format_generated_at(ts: float, lang: Lang) -> str:
    """Formatiert den Erzeugungs-Zeitstempel MIT Praefix ("Erstellt am ..."/"Generated on ...").

    de: ``Erstellt am 06.03.2026 14:05`` -- en: ``Generated on 2026-03-06 14:05``.
    """
    stamp = time.localtime(ts)
    muster = "%d.%m.%Y %H:%M" if lang == "de" else "%Y-%m-%d %H:%M"
    return ERSTELLT_AM_PRAEFIX.get(lang) + time.strftime(muster, stamp)


def format_datum_kurz(ts: float, lang: Lang) -> str:
    """Formatiert ein reines Datum OHNE Uhrzeit und OHNE Praefix.

    de: ``06.03.2026`` -- en: ``2026-03-06``. Fuer Datei-/Spaltendaten, wo der volle
    "Erstellt am"-Satz nicht passt.
    """
    stamp = time.localtime(ts)
    muster = "%d.%m.%Y" if lang == "de" else "%Y-%m-%d"
    return time.strftime(muster, stamp)
