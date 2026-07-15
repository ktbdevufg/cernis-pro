"""Render-fertiges PDF-Modell des CVE-Berichts (Etappe 1) -- reiner Datentraeger.

Ein NEUTRALES, vollstaendig anzeige-fertiges Modell ``CvePdfModel``, das der
Composition Root (spaetere Etappe) aus ``CveReport`` PROJIZIERT und das der
reportlab-Adapter (``infrastructure/export_pdf.py``) ohne jede eigene Rechnung rendert.
Es steht neben ``InventoryPdfModel``/``SecurityPdfModel`` (gleiche Schicht/Paket) und
folgt deren Muster -- ein EIGENES Modell, der generische ``domain.export.PdfReportModel``
bleibt unangetastet.

REINE PROJEKTION, KEINE RECHNUNG (Muster ``inventory_pdf_model``/``security_pdf_model``):
  * KEINE reportlab-Importe -- das Modell ist ein neutraler Datentraeger; das Rendern macht
    allein die Infrastruktur.
  * KEINE Domaenen-Importe -- es lebt in ``application/reporting`` und wird aus ``CveReport``
    befuellt, traegt aber selbst nur Primitive/Tupel.
  * KEINE Uhr, KEINE Formatierung: ALLE Texte (das formatierte Erzeugungsdatum, der
    Erklaersatz, die fertige Prozent-Darstellung der Abdeckung, die fertig formatierten
    Veroeffentlichungs-Texte, die count-als-Text-Werte, die fertigen Tabellenzeilen) kommen
    schon FERTIG vom Composition Root herein. Der Adapter setzt sie nur, das Modell fuehrt
    sie nur.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ── Spalten-Vertraege der drei Sektions-Tabellen (Auftrag) ──────────────────
#
# Die Spaltenueberschriften liegen HIER fest (nicht im Adapter), damit Modell und Renderer
# sich ueber denselben Vertrag einig sind. Der Composition Root liefert die Zeilen exakt in
# dieser Spalten-Reihenfolge; der Adapter setzt diese Tupel als Kopfzeile.

DEVICE_COLUMNS: tuple[str, ...] = (
    "Gerät",
    "Befunde",
    "Höchste Severity",
    "Höchster CVSS",
    "Dienste",
)
SERVICE_COLUMNS: tuple[str, ...] = (
    "Dienst",
    "Befunde",
    "Geräte",
    "Höchste Severity",
    "Höchster CVSS",
    "Älteste Veröffentlichung",
)
FINDING_COLUMNS: tuple[str, ...] = (
    "Gerät",
    "CVE",
    "Severity",
    "CVSS",
    "Dienst",
    "Port",
    "Erstmals gesehen",
    "Status",
)
# Spalten der GRUPPIERTEN Befundliste (Sektion 4, neuer Render-Pfad): das Geraet steht im
# Host-Kopf, daher tragen die CVE-Zeilen KEINE Geraet-Spalte mehr. ``FINDING_COLUMNS`` bleibt
# fuer JSON/Referenz bestehen.
FINDING_GROUP_COLUMNS: tuple[str, ...] = (
    "CVE",
    "Severity",
    "CVSS",
    "Dienst",
    "Port",
    "Erstmals gesehen",
    "Status",
)


@dataclass(frozen=True)
class HostGroupBlock:
    """Ein Host-Block der gruppierten Befundliste (Sektion 4), render-fertig.

    ``header`` die FERTIGE Host-Kopfzeile (z. B. "pi.hole · 192.168.178.155 · DC:A6:... ·
    11 Befunde, höchste HOCH") -- der Composition Root baut sie (keine Uhr/Logik hier).
    ``rows`` die CVE-Zeilen dieses Hosts als String-Tupel in ``FINDING_GROUP_COLUMNS``-
    Reihenfolge (Status schon als Variante-C-Text).
    """

    header: str
    rows: tuple[tuple[str, ...], ...] = ()


@dataclass(frozen=True)
class CvePdfModel:
    """Render-fertiges PDF-Modell des CVE-Berichts (frozen, neutral).

    Alle Felder sind ANZEIGE-FERTIG: Texte sind fertig formatiert, Zahlen sind die schon
    ermittelten Zaehler, die Tabellenzeilen sind String-Tupel in der jeweiligen
    ``*_COLUMNS``-Reihenfolge. Der Adapter rendert ALLES daraus, ohne zu rechnen.

    KOPF/FUSS:
      ``title`` der Berichtstitel, ``generated_at_text`` das schon formatierte
      Erzeugungsdatum (vom Composition Root -- der Adapter fragt keine Uhr), ``footer_left``
      die feste Produktzeile der Fusszeile, ``einleitung`` der fertige Einleitungs-Absatz.

    KENNZAHLEN:
      ``active_total`` die aktiven Befunde, ``acknowledged_total`` die quittierten,
      ``new_total`` die neuen, ``affected_devices`` die betroffenen Geraete,
      ``hosts_total``/``hosts_checked`` die Host-Zaehler, ``coverage_text`` die fertige
      Prozent-Darstellung der Abdeckung (vom Composition Root), ``highest_severity`` die
      hoechste Severity, ``oldest_published_text`` der fertig formatierte aelteste
      Veroeffentlichungs-Text ("" erlaubt).

    SEVERITY-VERTEILUNG (fuer Donut + Tabelle), fertige ``(Stufe, Anzahl-als-Text)``-Tupel:
      ``severity_rows`` -- die Stufe bleibt der ROHE technische Schluessel (Farb-Lookup
      ``_SEV_COLORS`` im Renderer). ``severity_labels`` traegt je ``(roh_key, deutscher_text)``
      die lokalisierten Anzeige-Texte fuer die Donut-Legende; der Renderer nimmt Farbe/Wert
      aus ``severity_rows`` und den ANGEZEIGTEN Text aus ``severity_labels``.

    SEKTIONS-TABELLEN (fertige String-Zeilen in der jeweiligen ``*_COLUMNS``-Reihenfolge):
      ``device_rows`` (Sektion 2), ``service_rows`` (Sektion 3), ``finding_rows`` (Sektion 4
      -- die flache VOLLSTAENDIGE Befundliste, fuer JSON/Referenz erhalten). Ist eine Tabelle
      LEER, laesst der spaetere Adapter die Rubrik weg (wie beim Bestandsbericht).
      ``host_groups`` (Sektion 4 -- die nach Host GRUPPIERTE Sicht, die das PDF rendert):
      je Host ein ``HostGroupBlock`` mit fertiger Kopfzeile + CVE-Zeilen.
    """

    title: str
    generated_at_text: str
    footer_left: str
    einleitung: str
    achse_b_fussnote: str

    active_total: int
    acknowledged_total: int
    new_total: int
    affected_devices: int
    hosts_total: int
    hosts_checked: int
    coverage_text: str
    highest_severity: str
    oldest_published_text: str

    severity_rows: tuple[tuple[str, str], ...] = ()
    severity_labels: tuple[tuple[str, str], ...] = ()

    device_rows: tuple[tuple[str, ...], ...] = ()
    service_rows: tuple[tuple[str, ...], ...] = ()
    finding_rows: tuple[tuple[str, ...], ...] = field(default_factory=tuple)
    host_groups: tuple[HostGroupBlock, ...] = ()
