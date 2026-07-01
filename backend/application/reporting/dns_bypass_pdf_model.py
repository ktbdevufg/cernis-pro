"""Render-fertiges PDF-Modell des DNS-Umgehungs-Berichts (Etappe 5) -- reiner Datentraeger.

Ein NEUTRALES, vollstaendig anzeige-fertiges Modell ``DnsBypassPdfModel``, das der
Composition Root (Etappe 5) aus ``DnsBypassReport`` PROJIZIERT und das der reportlab-
Adapter (``infrastructure/export_pdf.py``) ohne jede eigene Rechnung rendert. Es steht
neben ``OutboundPdfModel``/``DnsWatchPdfModel``/``CvePdfModel`` (gleiche Schicht/Paket) und
folgt deren Muster -- ein EIGENES Modell, der generische ``domain.export.PdfReportModel``
bleibt unangetastet. NEBEN dem host-lokalen ``dns_watch_pdf_model`` (der UNANGETASTET
bleibt): dies ist der NETZWEITE Umgehungs-Bericht, ehrlich getrennt.

REINE PROJEKTION, KEINE RECHNUNG (Muster ``outbound_pdf_model``/``dns_watch_pdf_model``):
  * KEINE reportlab-Importe -- das Modell ist ein neutraler Datentraeger; das Rendern macht
    allein die Infrastruktur.
  * KEINE Domaenen-Importe -- es lebt in ``application/reporting`` und wird aus
    ``DnsBypassReport`` befuellt, traegt aber selbst nur Primitive/Tupel.
  * KEINE Uhr, KEINE Logik: ALLE Texte (das formatierte Erzeugungsdatum, der Erklaersatz,
    die fertige Bezugsrahmen-Zeile, die fertige erwartete-Server-Zeile, die fertigen
    Tabellenzeilen) kommen schon FERTIG vom Composition Root herein. Der Adapter setzt sie
    nur, das Modell fuehrt sie nur.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ── Spalten-Vertraege der zwei Sektions-Tabellen (Auftrag) ──────────────────
#
# Die Spaltenueberschriften liegen HIER fest (nicht im Adapter), damit Modell und Renderer
# sich ueber denselben Vertrag einig sind. Der Composition Root liefert die Zeilen exakt in
# dieser Spalten-Reihenfolge; der Adapter setzt diese Tupel als Kopfzeile. Der
# ``DNS_BYPASS_``-Praefix haelt sie von den ``DNS_*_COLUMNS`` des host-lokalen
# DNS-Waechter-Berichts getrennt.

DNS_BYPASS_RESOLVER_COLUMNS: tuple[str, ...] = ("Ziel-Resolver", "Umgehungen")
DNS_BYPASS_ROW_COLUMNS: tuple[str, ...] = (
    "Gerät",
    "Quell-IP",
    "Ziel-Resolver",
    "DoH",
    "Anfragen",
    "Beispiel-Namen",
)


@dataclass(frozen=True)
class DnsBypassPdfModel:
    """Render-fertiges PDF-Modell des DNS-Umgehungs-Berichts (frozen, neutral).

    Alle Felder sind ANZEIGE-FERTIG: Texte sind fertig formatiert, Zahlen sind die schon
    ermittelten Zaehler, die Tabellenzeilen sind String-Tupel in der jeweiligen
    ``DNS_BYPASS_*_COLUMNS``-Reihenfolge. Der Adapter rendert ALLES daraus, ohne zu rechnen.

    KOPF/FUSS:
      ``title`` der Berichtstitel, ``generated_at_text`` das schon formatierte
      Erzeugungsdatum (vom Composition Root -- der Adapter fragt keine Uhr), ``footer_left``
      die feste Produktzeile der Fusszeile, ``einleitung`` der fertige Einleitungs-Absatz.

    BEZUGSRAHMEN:
      ``recording_label`` der Anzeigename der Aufzeichnung, ``scope_text`` die fertige
      lokalisierte Bezugsrahmen-Zeile (z. B. "Bezug: Aufzeichnung 'X'" / "Bezug: Alle
      Aufzeichnungen"), ``expected_text`` die fertige Liste der erwarteten Resolver
      ("(keine)" wenn leer) -- der Composition Root baut sie (keine Uhr/Logik hier).

    KENNZAHLEN:
      ``queries_total`` alle DNS-Anfragen der Laeufe, ``bypass_total`` die Umgehungs-
      Anfragen, ``expected_total`` die erwartungsgemaessen, ``bypass_devices`` die Anzahl
      distinct fragender Geraete mit Umgehung.

    SEKTIONS-TABELLEN (fertige String-Zeilen in der jeweiligen ``DNS_BYPASS_*_COLUMNS``-
    Reihenfolge):
      ``resolver_rows`` (Ziel-Resolver-Verteilung, DNS_BYPASS_RESOLVER_COLUMNS),
      ``bypass_rows`` (Umgehungs-Liste, DNS_BYPASS_ROW_COLUMNS). Ist eine Tabelle LEER,
      laesst der spaetere Adapter die Rubrik weg (wie beim Aussenkontakte-/DNS-Waechter-
      Bericht).
    """

    title: str
    generated_at_text: str
    footer_left: str
    einleitung: str
    recording_label: str
    scope_text: str
    expected_text: str

    queries_total: int
    bypass_total: int
    expected_total: int
    bypass_devices: int

    resolver_rows: tuple[tuple[str, ...], ...] = ()
    bypass_rows: tuple[tuple[str, ...], ...] = field(default_factory=tuple)
