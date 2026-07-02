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

# ── Spalten-Vertrag der Umgehungs-Detailtabelle (Auftrag) ───────────────────
#
# Die Spaltenueberschriften liegen HIER fest (nicht im Adapter), damit Modell und Renderer
# sich ueber denselben Vertrag einig sind. Der Composition Root liefert die Zeilen exakt in
# dieser Spalten-Reihenfolge; der Adapter setzt dieses Tupel als Kopfzeile. Der
# ``DNS_BYPASS_``-Praefix haelt es von den ``DNS_*_COLUMNS`` des host-lokalen
# DNS-Waechter-Berichts getrennt. (Die fruehere Resolver-Verteilungs-Tabelle ist entfernt --
# die Verteilung zeigt allein die Grafik ueber ``resolver_distribution``.)

DNS_BYPASS_ROW_COLUMNS: tuple[str, ...] = (
    "Gerät",
    "Quell-IP",
    "Ziel-Resolver",
    "DoH",
    "Anfragen",
    "Abgefragte Namen",
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

    VERTEILUNGS-GRAFIK (Variante C):
      ``resolver_distribution`` je Ziel-Resolver ein Tripel ``(resolver_name, dst_ip,
      count)`` -- STRUKTURIERT (nicht als fertige String-Zeile), die ALLEINIGE Verteilungs-
      Darstellung, damit der Adapter daraus den gestapelten horizontalen Balken
      + die Legende (Farbe + Name + rohe IP + Anzahl) zeichnen kann. ``resolver_name`` ist
      "" wenn nicht aufloesbar (die rohe ``dst_ip`` bleibt sichtbar). Anfragestaerkste
      zuerst (Reihenfolge kommt schon sortiert vom Composition Root).

    SEKTIONS-TABELLE (fertige String-Zeilen in der ``DNS_BYPASS_ROW_COLUMNS``-Reihenfolge):
      ``bypass_rows`` (Umgehungs-Liste, DNS_BYPASS_ROW_COLUMNS). Ist die Tabelle LEER, laesst
      der spaetere Adapter die Rubrik weg (wie beim Aussenkontakte-/DNS-Waechter-Bericht).
      Die Verteilung nach Ziel wird ALLEIN ueber die Grafik (``resolver_distribution``)
      gezeigt -- es gibt KEINE separate Verteilungs-Tabelle mehr (Redundanz entfernt).

      GERAET-ZELLE (Spalte 0) ist beim eigenen Host ZWEIZEILIG: der Composition Root setzt
      dann "Hostname\nKennzeichnung" (z. B. "ubultsvm\nDieser Rechner"), getrennt durch ein
      einzelnes ``\n``. Der Adapter rendert die erste Zeile als Namen und die zweite dezent
      darunter; ein Wert OHNE ``\n`` bleibt einzeilig (Nicht-Self, unveraendert). Die IP wird
      NICHT zusaetzlich in der Geraet-Zelle wiederholt -- sie steht in der Quell-IP-Spalte.
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

    resolver_distribution: tuple[tuple[str, str, int], ...] = ()
    bypass_rows: tuple[tuple[str, ...], ...] = field(default_factory=tuple)
