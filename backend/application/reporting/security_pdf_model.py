"""Render-fertiges PDF-Modell des Sicherheitsberichts (Etappe 4a) -- reiner Datentraeger.

Ein NEUTRALES, vollstaendig anzeige-fertiges Modell ``SecurityPdfModel``, das der
Composition Root (Etappe 4b) aus ``SecurityReport`` PROJIZIERT und das der reportlab-
Adapter (``infrastructure/export_pdf.py``) ohne jede eigene Rechnung rendert.

ABGRENZUNG zum generischen ``domain.export.PdfReportModel``: jenes (Titel + meta-Paare +
EINE Tabelle) ist zu schlicht fuer den Sicherheitsbericht (Grafiken + mehrere Tabellen +
durchgaengige Kopfzeile). Dieses Modell ist daneben gestellt -- ein EIGENES, reicheres
Modell; ``PdfReportModel`` bleibt unangetastet (Scan-/Analyse-Export nutzt es weiter).

REINE PROJEKTION, KEINE RECHNUNG (Muster ``security_score``/``security_report``):
  * KEINE reportlab-Importe -- das Modell ist ein neutraler Datentraeger; das Rendern macht
    allein die Infrastruktur.
  * KEINE Domaenen-Importe -- es lebt in ``application/reporting`` und wird aus
    ``SecurityReport`` befuellt, traegt aber selbst nur Primitive/Tupel.
  * KEINE Score-Neuberechnung, KEINE Uhr, KEINE Formatierung: ALLE Texte (das formatierte
    Datum, der Erklaersatz, die Severity-Klartexte, die "0,33"-Lastwerte, die fertigen
    Tabellenzeilen) kommen schon FERTIG vom Composition Root herein. Der Adapter setzt sie
    nur, das Modell fuehrt sie nur.

Damit ist der Adapter zustandslos und rechenfrei: er hat in diesem Modell ALLES, um die
Kopf-/Fusszeile, das Score-Cockpit (Gauge), den Donut, die Geraete-Balken und die vier
Tabellen-Rubriken zu rendern, ohne selbst zu aggregieren oder zu formatieren.

ENTSCHEIDUNG cve_rows (Auftrag, dokumentiert): die CVE-Befunde werden als FLACHE Tabelle
gefuehrt -- jede Zeile traegt die ``device_label``-Spalte als erste Spalte (s.
``CVE_COLUMNS``). Das ist in reportlab die robuste Variante (eine ``Table`` mit
``repeatRows=1`` statt vieler kleiner Bloecke) und liest sich gruppiert, weil der
Composition Root die Zeilen bereits nach Geraet sortiert/gruppiert liefert -- gleiche
device_label-Werte stehen untereinander. Kein verschachteltes Gruppen-Objekt im Modell.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ── Spalten-Vertraege der vier Tabellen-Rubriken (Auftrag) ──────────────────
#
# Die Spaltenueberschriften liegen HIER fest (nicht im Adapter), damit Modell und Renderer
# sich ueber denselben Vertrag einig sind. Der Composition Root liefert die Zeilen exakt in
# dieser Spalten-Reihenfolge; der Adapter setzt diese Tupel als Kopfzeile. cve_rows traegt
# bewusst ``Gerät`` als ERSTE Spalte (flache, nach Geraet gruppierte Tabelle -- s. Modul-
# Docstring).

PORT_COLUMNS: tuple[str, ...] = ("Gerät", "Ports", "Schwere", "Grund")
CVE_COLUMNS: tuple[str, ...] = ("Gerät", "CVE", "CVSS", "Dienst", "Beschreibung")
NET_COLUMNS: tuple[str, ...] = ("Art", "Gerät", "Schwere", "Beschreibung")
ACK_COLUMNS: tuple[str, ...] = ("Art", "Gerät", "Detail")


@dataclass(frozen=True)
class SecurityPdfModel:
    """Render-fertiges PDF-Modell des Sicherheitsberichts (frozen, neutral).

    Alle Felder sind ANZEIGE-FERTIG: Texte sind fertig formatiert, Zahlen sind die schon
    gerundeten Zaehler, die Tabellenzeilen sind String-Tupel in der jeweiligen
    ``*_COLUMNS``-Reihenfolge. Der Adapter rendert ALLES daraus, ohne zu rechnen.

    KOPF/FUSS:
      ``title`` der Berichtstitel ("Netzwerk-Sicherheitsbericht"), ``generated_at_text``
      das schon formatierte Erzeugungsdatum (vom Composition Root -- der Adapter fragt keine
      Uhr), ``footer_left`` die feste Produktzeile der Fusszeile, ``achse_b_fussnote`` der
      fertige Achse-B-Satz (E0: aus ``report_texts.ACHSE_B_FUSSNOTE`` in der Projektion nach
      ``lang`` aufgeloest -- PFLICHTFELD ohne Default, damit kein Bericht ihn still auf
      Deutsch zurueckfallen laesst; der Renderer haelt den Text NICHT mehr selbst).

    SCORE-COCKPIT:
      ``score_value`` der Netz-Gesundheit-Wert 0..100, ``score_level`` die Einstufung als
      Klartext ("gut"/"maessig"/"kritisch"), ``score_einordnung`` der fertige Erklaersatz
      darunter. Die Gauge faerbt bis ``score_value`` in der zum Level passenden Farbe (der
      Adapter waehlt die Farbe ueber ``score_level``).

    KENNZAHLEN/DONUT:
      ``critical_devices``/``notable_devices``/``clean_devices`` die drei Zaehler (Donut-
      Anteile + die drei Kennzahl-Boxen), ``device_count`` die Basis N (Donut-Mitte),
      ``total_burden`` die aufsummierte Last (nur informativ mitgefuehrt).

    SCORE-BEITRAGSLISTE:
      ``contributions`` je belastetem Geraet ein ANZEIGE-FERTIGES Tripel
      ``(device_label, severity_label, last_text)`` -- ``severity_label`` schon als Klartext
      ("kritisch"/"auffaellig"), ``last_text`` der Lastwert schon als Text ("0,33"). KEINE
      Zahl-Formatierung im Adapter.

    GERAETE-BALKEN:
      ``geraete_balken`` je Geraet MIT Befund ein ``(device_label, critical_count,
      notable_count)`` -- VOLLSTAENDIG (alle Geraete mit Befund, KEIN Top-N; das PDF zeigt
      alles). Die beiden Zahlen sind die gestapelten Balkenlaengen.

    TABELLEN-ROHDATEN (jeweils fertige String-Zeilen in der ``*_COLUMNS``-Reihenfolge):
      ``port_rows``    -- Rubrik 1 (Rechner mit auffaelligen Ports): Gerät/Ports/Schwere/Grund.
      ``cve_rows``     -- Rubrik 2 (CVE-Befunde): Gerät/CVE/CVSS/Dienst/Beschreibung; FLACH,
                          nach Geraet gruppiert (gleiche ``device_label`` untereinander).
      ``net_rows``     -- Rubrik 3 (Netz-Auffaelligkeiten): Art/Gerät/Schwere/Beschreibung.
      ``acknowledged_rows`` -- Rubrik 4 (Bereits bestaetigt): Art/Gerät/Detail; ist sie LEER,
                          laesst der Adapter die ganze Rubrik weg (kein leerer Tabellenkopf).

    severity_label-SPALTEN: in ``port_rows``/``net_rows`` traegt die "Schwere"-Spalte den
    Klartext "kritisch"/"auffaellig" (vom Composition Root) -- der Adapter faerbt die Zelle
    danach ein (Badge). KEIN Roh-Severity-String ("critical") im Modell.

    ACHSE-B-TEXTE (fertige Saetze, kein Adapter-Jargon):
      ``einleitung`` der Einleitungs-Absatz (Achse-B-Haltung -- beschreibt/ordnet ein),
      ``rogue_hinweis`` der fertige Rogue-DHCP-Hinweis ODER "" (leer -> Adapter laesst ihn
      weg). Die Achse-B-Fussnote kommt als ``achse_b_fussnote`` aus dem Modell (s. KOPF/FUSS).
    """

    title: str
    generated_at_text: str
    footer_left: str
    achse_b_fussnote: str

    score_value: int
    score_level: str
    score_einordnung: str

    critical_devices: int
    notable_devices: int
    clean_devices: int
    device_count: int
    total_burden: float

    einleitung: str
    rogue_hinweis: str = ""

    contributions: tuple[tuple[str, str, str], ...] = ()
    geraete_balken: tuple[tuple[str, int, int], ...] = ()

    port_rows: tuple[tuple[str, ...], ...] = ()
    cve_rows: tuple[tuple[str, ...], ...] = ()
    net_rows: tuple[tuple[str, ...], ...] = ()
    acknowledged_rows: tuple[tuple[str, ...], ...] = field(default_factory=tuple)
