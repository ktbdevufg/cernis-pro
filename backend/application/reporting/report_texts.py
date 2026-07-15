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

STAND E2: die querschnittlichen Texte aus Kapitel 0 (Achse-B-Fussnote, Kopf-/Fusszeilen-
Praefixe) PLUS die drei RAHMENTEXTE jedes der sieben Berichte (Titel, Fusszeile, Einleitung).
Die Satzbausteine im Rumpf der Berichte (Tabellenkoepfe, Schwere-Labels usw.) ziehen in E3
nach.
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


# ── Kapitel 1 des Inventars: die Rahmentexte der sieben Berichte (E2) ───────
#
# Je Bericht DREI Rahmentexte: Titel (Kopfzeile), Fusszeile links, Einleitung. Sie bilden den
# RAHMEN, den jeder Bericht gleich traegt -- der Rumpf (Tabellenkoepfe, Satzbausteine) folgt
# in E3. Die de-Fassungen sind die bisherigen Literale aus den Projektionen in ``app.py``,
# woertlich uebernommen; die en-Fassungen sind im nuechternen Handbuch-Ton gehalten (Achse B:
# beschreiben und einordnen, NICHT bewerten -- die Einleitungen tragen diese Haltung explizit,
# darum ist ihr Ton in beiden Sprachen bewusst zurueckhaltend).
#
# FUSSZEILEN-VEREINHEITLICHUNG (Entscheidung E2): alle de-Fusszeilen trennen Produktname und
# Berichtsname mit demselben Gedankenstrich (U+2014, "—") -- derselbe Strich, den schon die
# Achse-B-Fussnote und die uebrigen deutschen Texte dieses Moduls fuehren. Der
# Sicherheitsbericht trug hier als EINZIGER einen einfachen Bindestrich ("-"); das war ein
# Ausreisser und ist mit E2 korrigiert. Die en-Fusszeilen fuehren denselben Strich: der
# Trenner ist Typografie, keine Sprache.

# ── Sicherheitsbericht ──
REPORT_TITLE_SECURITY = LocalizedText(
    de="Netzwerk-Sicherheitsbericht",
    en="Network Security Report",
)
REPORT_FOOTER_SECURITY = LocalizedText(
    de="CERNIS PRO 2.0 — Netzwerk-Sicherheitsbericht",
    en="CERNIS PRO 2.0 — Network Security Report",
)
REPORT_INTRO_SECURITY = LocalizedText(
    de=(
        "Dieser Bericht fasst die über CERNIS verteilten Sicherheits-Beobachtungen zu "
        "einem Bild zusammen. Er beschreibt und ordnet ein - die Bewertung jeder "
        "Auffälligkeit bleibt bei Ihnen."
    ),
    en=(
        "This report brings together the security observations gathered across CERNIS. "
        "It describes and provides context — assessing each finding remains up to you."
    ),
)

# ── Bestandsbericht ──
REPORT_TITLE_INVENTORY = LocalizedText(
    de="Netzwerk-Bestandsbericht",
    en="Network Inventory Report",
)
REPORT_FOOTER_INVENTORY = LocalizedText(
    de="CERNIS PRO 2.0 — Netzwerk-Bestandsbericht",
    en="CERNIS PRO 2.0 — Network Inventory Report",
)
REPORT_INTRO_INVENTORY = LocalizedText(
    de=(
        "Dieser Bericht listet auf, welche Geräte im Netzwerk gesehen wurden. Er "
        "beschreibt den Bestand und ordnet ihn ein — er bewertet nicht."
    ),
    en=(
        "This report lists the devices that have been seen on the network. It describes "
        "the inventory and provides context — it does not assess it."
    ),
)

# ── CVE-Bericht ──
REPORT_TITLE_CVE = LocalizedText(
    de="CVE-Bericht",
    en="CVE Report",
)
REPORT_FOOTER_CVE = LocalizedText(
    de="CERNIS PRO 2.0 — CVE-Bericht",
    en="CERNIS PRO 2.0 — CVE Report",
)
REPORT_INTRO_CVE = LocalizedText(
    de=(
        "Dieser Bericht listet die gefundenen Schwachstellen (CVEs) im Netzwerk auf. "
        "Er beschreibt und ordnet ein — er bewertet nicht."
    ),
    en=(
        "This report lists the vulnerabilities (CVEs) found on the network. It describes "
        "and provides context — it does not assess."
    ),
)

# ── Aussenkontakte-Bericht ──
REPORT_TITLE_OUTBOUND = LocalizedText(
    de="Netzwerk-Außenkontakte-Bericht",
    en="Network Outbound Contacts Report",
)
REPORT_FOOTER_OUTBOUND = LocalizedText(
    de="CERNIS PRO 2.0 — Netzwerk-Außenkontakte-Bericht",
    en="CERNIS PRO 2.0 — Network Outbound Contacts Report",
)
REPORT_INTRO_OUTBOUND = LocalizedText(
    de=(
        "Dieser Bericht fasst die aufgezeichneten Außenkontakte dieses Rechners "
        "zusammen und ordnet sie gegen die aktiven Blocklisten ein."
    ),
    en=(
        "This report summarises the recorded outbound contacts of this computer and "
        "places them in context against the active block lists."
    ),
)

# ── DNS-Waechter-Bericht ──
REPORT_TITLE_DNS_WATCH = LocalizedText(
    de="DNS-Wächter-Bericht",
    en="DNS Watch Report",
)
REPORT_FOOTER_DNS_WATCH = LocalizedText(
    de="CERNIS PRO 2.0 — DNS-Wächter-Bericht",
    en="CERNIS PRO 2.0 — DNS Watch Report",
)
REPORT_INTRO_DNS_WATCH = LocalizedText(
    de=(
        "Dieser Bericht fasst die DNS-relevanten Außenkontakte dieses Rechners zusammen "
        "und ordnet sie gegen die erwarteten DNS-Server und die bekannten DoH-Anbieter "
        "ein."
    ),
    en=(
        "This report summarises the DNS-related outbound contacts of this computer and "
        "places them in context against the expected DNS servers and the known DoH "
        "providers."
    ),
)

# ── DNS-Umgehungs-Bericht ──
REPORT_TITLE_DNS_BYPASS = LocalizedText(
    de="Netzwerk-DNS-Umgehungs-Bericht",
    en="Network DNS Bypass Report",
)
REPORT_FOOTER_DNS_BYPASS = LocalizedText(
    de="CERNIS PRO 2.0 — Netzwerk-DNS-Umgehungs-Bericht",
    en="CERNIS PRO 2.0 — Network DNS Bypass Report",
)
REPORT_INTRO_DNS_BYPASS = LocalizedText(
    de=(
        "Dieser Bericht fasst die aufgezeichneten netzweiten DNS-Umgehungen zusammen — "
        "Anfragen von Geräten des Netzes an nicht-erwartete Resolver — und ordnet je Ziel "
        "eine mögliche DoH-Nutzung ein."
    ),
    en=(
        "This report summarises the recorded network-wide DNS bypasses — queries from "
        "devices on the network to resolvers that are not expected — and indicates for "
        "each destination whether DoH use is possible."
    ),
)

# ── Verhaltensprofil-Bericht ──
REPORT_TITLE_BEHAVIOR = LocalizedText(
    de="Verhaltensprofil-Bericht",
    en="Behaviour Profile Report",
)
REPORT_FOOTER_BEHAVIOR = LocalizedText(
    de="CERNIS PRO 2.0 — Verhaltensprofil-Bericht",
    en="CERNIS PRO 2.0 — Behaviour Profile Report",
)
REPORT_INTRO_BEHAVIOR = LocalizedText(
    de=(
        "Dieser Bericht zeigt die wiederkehrenden Aktivitätsmuster je Aufgabe bzw. Gerät "
        "— Tagesverlauf, Wochenmuster und die als untypisch markierten Abweichungen. Er "
        "beschreibt und ordnet ein, er fällt kein Urteil."
    ),
    en=(
        "This report shows the recurring activity patterns per task or device — daily "
        "profile, weekly pattern and the deviations marked as untypical. It describes and "
        "provides context, it does not pass judgement."
    ),
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
