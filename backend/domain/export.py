"""Domaenenmodell der export-Domaene: gespeicherter Scan UND aktuelle Analyse -> CSV/JSON/PDF.

Reine Domaenenlogik (stdlib + dataclasses, ADR 0002/0015) -- kein Datei-I/O, keine Uhr,
KEIN Import aus anderen Domaenen (independence-Contract). Insbesondere importiert
``domain.export`` NICHT ``domain.scanning`` UND NICHT ``domain.analysis``: damit es von
beiden Quell-Modellen unabhaengig bleibt, definiert es seine EIGENEN, schlanken Eingabe-Typen
(``Exportable*``), und die PROJEKTION (``scanning.ScanRecord``/``EnrichedHost`` bzw.
``analysis.ResolvedObservation``) auf diese Typen passiert im Composition Root (genau das
analysis-Muster mit seinen ``Observed*``-Typen, ADR 0015).

* **Block 1 (Scan):** ``Exportable{Port,Host,Scan}`` + ``to_json``/``to_csv``/
  ``build_pdf_model`` + Helfer ``format_ports``/``format_tags``.
* **Block 2 (Analyse-Befunde):** ``Exportable{Finding,Analysis}`` + ``analysis_to_json``/
  ``analysis_to_csv``/``build_analysis_pdf_model`` + Helfer ``_truncate``. ``severity`` als
  ``str`` (kein ``domain.analysis.Severity``-Import). ``generated_at`` als FELD (die Domaene
  fragt keine Uhr). Nutzt DASSELBE (generalisierte) ``PdfReportModel`` wie Block 1.

Was diese Domaene tut, ist deterministische Serialisierung bereits projizierter Werte:
CSV-/JSON-STRING-Erzeugung ueber die stdlib (``csv``/``json``) und der Aufbau eines reinen
PDF-MODELLS (Kopf-Felder + Tabellen-Zeilen als reine Daten) -- das tatsaechliche PDF-Rendern
macht die Infrastruktur (reportlab), damit die Domaene rein bleibt und die Layout-/Spalten-
Wahl testbar ist.

Eingabe-Typen (reine export-Domaenen-Werte, projiziert im Composition Root):

* ``ExportablePort`` -- ein offener Port (``port``/``protocol``/``service``), genug, um
  "22/tcp" + optional den Servicenamen darzustellen.
* ``ExportableHost`` -- die Kernfelder + die Listen, die JSON verlustarm braucht (Ports
  als ``ExportablePort``-Tupel, die mdns/ssdp-Dienste als schlanke String-Tupel -- bewusste
  Wahl: so viel wie JSON braucht, OHNE die volle scanning-Komplexitaet zu duplizieren).
* ``ExportableScan`` -- der gebuendelte Scan (``scan_id``/``cidr``/``host_count``/
  ``scanned_at`` + die Hosts).

Reine Serialisierungs-Funktionen (deterministisch, testbar, mutationsproben-tauglich):

* ``to_json`` -- verlustfrei strukturiert (stdlib ``json``, sortierte Keys, eingerueckt).
* ``to_csv`` -- flache Kernfelder, eine Zeile pro Host, definierte Spalten-Reihenfolge
  (stdlib ``csv``, das Escaping von Komma/Anfuehrungszeichen erledigt das Modul).
* ``build_pdf_model`` -- baut das reine ``PdfReportModel`` (Kopf + Tabellen-Zeilen als reine
  Daten); das Rendern macht die Infrastruktur.
* ``format_ports``/``format_tags`` -- reine Helfer fuer die zusammengefassten CSV-Spalten.

DARSTELLUNG (PDF-Pixel, Font, Seitenlayout) bleibt draussen -- das fuehrt die Infrastruktur.
Die Domaene fuehrt nur Werte + die Strukturwahl (welche Spalten, welche Reihenfolge).
"""

import csv
import io
import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

# Zielformat des Exports. PEP-695-Alias wie im uebrigen domain-Ring (diagnostics/process/
# traffic nutzen ``type X = Literal[...]``); ein reines Kategorie-Etikett ohne Verhalten.
type ExportFormat = Literal["csv", "json", "pdf"]


@dataclass(frozen=True)
class ExportablePort:
    """Ein offener Port als reines export-Wertobjekt (frozen).

    ``port`` die Port-Nummer, ``protocol`` das Transport-Protokoll (z. B. ``"tcp"``),
    ``service`` der optionale Servicename (``""`` wenn unbekannt). Genug, um "22/tcp" und
    optional den Servicenamen darzustellen. Die Projektion aus ``scanning.PortInfo``
    (das nur ``port``/``state``/``service`` traegt) setzt ``protocol`` im Composition Root
    sinnvoll (PortInfo hat kein Protokoll-Feld -- der Projektions-Schritt waehlt ``"tcp"``,
    der ueblichen Annahme des socket-/nmap-Scans, ADR 0015).
    """

    port: int
    protocol: str
    service: str = ""


@dataclass(frozen=True)
class ExportableHost:
    """Ein Host als reines export-Wertobjekt (frozen) -- die JSON-relevante Vollform.

    Die Kernfelder (``ip``/``mac``/``vendor``/``hostname``/``rtt_ms``/``os_guess``/
    ``os_accuracy``/``category``/``label``/``tags``/``source``) + die verschachtelten
    Listen, die JSON verlustarm braucht: ``ports`` als ``ExportablePort``-Tupel und die
    mdns/ssdp-Dienste als schlanke String-Tupel.

    BEWUSSTE WAHL (ADR 0015): mdns/ssdp werden als einfache, menschenlesbare String-Tupel
    gefuehrt (z. B. der mDNS-Diensttyp, die SSDP-``server``/``st``-Kennung) statt als volle
    ``MdnsService``/``SsdpService``-Strukturen -- so viel, wie JSON verlustarm darstellt,
    OHNE die volle scanning-Komplexitaet (mDNS-``properties``-Paare, IPv6-Listen, SMB-Felder)
    in der export-Domaene zu duplizieren. Welche Strings das genau sind, waehlt die Projektion
    im Composition Root (sie kennt das scanning-Modell); die Domaene fuehrt sie nur.
    """

    ip: str
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    rtt_ms: float | None = None
    os_guess: str = ""
    os_accuracy: int = 0
    category: str = ""
    label: str = ""
    tags: tuple[str, ...] = ()
    source: str = ""
    ports: tuple[ExportablePort, ...] = ()
    mdns_services: tuple[str, ...] = ()
    ssdp_services: tuple[str, ...] = ()


@dataclass(frozen=True)
class ExportableScan:
    """Ein gespeicherter Scan als reines export-Wertobjekt (frozen) -- die Export-Eingabe.

    ``scan_id`` die ID aus der ScanHistory, ``cidr`` das gescannte Netz, ``host_count`` die
    Geraeteanzahl, ``scanned_at`` der Scan-Zeitpunkt (ISO-String, wie ihn die DB-Spalte
    fuehrt), ``hosts`` die projizierten Hosts. Die Projektion aus ``scanning.ScanRecord``
    passiert im Composition Root (independence-Contract, ADR 0015).
    """

    scan_id: int
    cidr: str
    host_count: int
    scanned_at: str
    hosts: tuple[ExportableHost, ...] = ()


# CSV-Spalten in DEFINIERTER Reihenfolge (Auftrag/ADR 0015): flache Kernfelder, eine Zeile
# pro Host. Verschachteltes (mdns/ssdp-Detail) ist hier BEWUSST nicht abgebildet (in einer
# flachen Tabelle nicht sauber darstellbar -- das fuehrt JSON verlustfrei). Diese Tupel-
# Reihenfolge ist Vertrag: ``to_csv`` schreibt Header + Zeilen exakt in dieser Ordnung
# (eine Vertauschung ist ein Bruch -- mutationsproben-tauglich getestet).
_CSV_COLUMNS: tuple[str, ...] = (
    "ip",
    "mac",
    "vendor",
    "hostname",
    "os_guess",
    "category",
    "label",
    "open_ports",
    "tags",
    "source",
)

# PDF-Tabellen-Spalten in DEFINIERTER Reihenfolge (Auftrag/ADR 0015): die druckbaren
# Kernfelder eines lesbaren Berichts. Schlanker als CSV (kein label/tags/source -- ein
# Bericht zeigt die Identifikations-Kernfelder + die offenen Ports). Auch dies ist Vertrag
# (Spalten/Reihenfolge mutationsproben-tauglich getestet).
_PDF_COLUMNS: tuple[str, ...] = (
    "ip",
    "mac",
    "vendor",
    "hostname",
    "os_guess",
    "category",
    "open_ports",
)

# Fester Berichtstitel (Auftrag/ADR 0015) -- schlicht, kein Logo, keine Spielereien.
_PDF_TITLE = "CERNIS PRO — Scan-Bericht"


@dataclass(frozen=True)
class PdfReportModel:
    """Das reine PDF-MODELL (frozen) -- ein GENERISCHES Bericht-Modell als reine Daten.

    NICHT das PDF selbst: ``title`` der Berichtstitel, ``meta`` die Kopf-Zeilen als
    (Label, Wert)-Paare in fester Reihenfolge, ``columns`` die Spaltenueberschriften
    (deterministische Reihenfolge), ``rows`` die Tabellen-Zeilen (je Datensatz ein
    String-Tupel in der ``columns``-Reihenfolge). Das tatsaechliche Rendern (Font,
    Seitenlayout, Tabellen-Gitter) macht die Infrastruktur (reportlab) -- so bleibt die
    Domaene rein und die Layout-/Spaltenwahl testbar (ADR 0015).

    BEWUSSTE GENERALISIERUNG (ADR 0015, Block 2): in Block 1 trug der Kopf fest die
    SCAN-spezifischen Felder ``scanned_at``/``cidr``/``host_count`` -- das war ein faelschlich
    scan-spezifisches Bericht-Modell. Block 2 (Analyse-Export) nutzt DASSELBE Modell mit
    einem anderen Kopf (``generated_at``/``finding_count``); darum traegt der Kopf jetzt
    generische (Label, Wert)-Paare (``meta``). Jeder Berichts-Builder liefert seine eigenen
    Paare; der Renderer iteriert nur ueber sie (keine hartkodierten Labels mehr). Verhalten
    des Scan-Berichts bleibt identisch -- nur generisch statt fest.
    """

    title: str
    meta: tuple[tuple[str, str], ...]
    columns: tuple[str, ...]
    rows: tuple[tuple[str, ...], ...]


def format_ports(ports: Sequence[ExportablePort]) -> str:
    """Fasst offene Ports zu einem CSV-Feld zusammen -- rein, deterministisch, testbar.

    Form ``"<port>/<protocol>"`` je Port, mit Komma getrennt (z. B.
    ``"22/tcp,80/tcp,443/tcp"``). Die Reihenfolge ist die der Eingabe (die Projektion
    liefert die Ports bereits in ihrer scan-Reihenfolge) -- KEIN Umsortieren, damit der
    Export reproduzierbar die Quell-Reihenfolge spiegelt. Leere Eingabe -> ``""`` (kein
    erfundener Wert). Der Servicename geht hier BEWUSST nicht ein (die CSV-Spalte ist die
    kompakte Port-Liste; der Servicename steckt verlustfrei in der JSON-Form).

    Rein: kein I/O, keine Uhr; gleiche Eingabe -> gleiches Ergebnis.
    """
    return ",".join(f"{port.port}/{port.protocol}" for port in ports)


def format_tags(tags: Sequence[str]) -> str:
    """Fasst Tags zu einem CSV-Feld zusammen -- rein, deterministisch, testbar.

    Mit Semikolon getrennt (z. B. ``"a;b"``) -- BEWUSST das Semikolon statt des Kommas, weil
    das Komma in CSV das Spaltentrennzeichen ist; ein semikolon-getrenntes Tag-Feld bleibt
    auch beim Re-Import gut lesbar (das ``csv``-Modul wuerde ein komma-haltiges Feld zwar
    korrekt quoten, aber das Semikolon haelt die Spalte ohne Quoting menschenlesbar). Die
    Reihenfolge ist die der Eingabe (kein Umsortieren). Leere Eingabe -> ``""``.

    Rein: kein I/O, keine Uhr; gleiche Eingabe -> gleiches Ergebnis.
    """
    return ";".join(tags)


def to_json(scan: ExportableScan) -> str:
    """Serialisiert den Scan VERLUSTFREI strukturiert als JSON-String -- deterministisch.

    Der komplette ``ExportableScan`` (alle Host-Felder, verschachtelt: ``ports`` als
    Objekt-Liste, ``mdns_services``/``ssdp_services`` als String-Listen) wird ueber die
    stdlib ``json`` serialisiert. Deterministisch + reproduzierbar (ADR 0015): ``sort_keys``
    (stabile Key-Reihenfolge unabhaengig von der Feld-Definition), ``indent=2`` (lesbar) und
    ``ensure_ascii=False`` (echtes UTF-8 statt ``\\uXXXX``-Escapes -- Sonderzeichen bleiben
    lesbar). Die Host-/Port-REIHENFOLGE bleibt die der Eingabe (Listen werden NICHT sortiert,
    nur die Objekt-Keys) -- so spiegelt der Export die Scan-Reihenfolge reproduzierbar.

    Rein: kein I/O, keine Uhr; gleiche Eingabe -> gleicher String.
    """
    payload = {
        "scan_id": scan.scan_id,
        "cidr": scan.cidr,
        "host_count": scan.host_count,
        "scanned_at": scan.scanned_at,
        "hosts": [
            {
                "ip": host.ip,
                "mac": host.mac,
                "vendor": host.vendor,
                "hostname": host.hostname,
                "rtt_ms": host.rtt_ms,
                "os_guess": host.os_guess,
                "os_accuracy": host.os_accuracy,
                "category": host.category,
                "label": host.label,
                "tags": list(host.tags),
                "source": host.source,
                "ports": [
                    {"port": port.port, "protocol": port.protocol, "service": port.service}
                    for port in host.ports
                ],
                "mdns_services": list(host.mdns_services),
                "ssdp_services": list(host.ssdp_services),
            }
            for host in scan.hosts
        ],
    }
    return json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False)


def to_csv(scan: ExportableScan) -> str:
    """Serialisiert die Host-Kernfelder als CSV-String -- flach, deterministisch, testbar.

    Eine Header-Zeile (``_CSV_COLUMNS`` in DEFINIERTER Reihenfolge) + eine Zeile pro Host.
    ``open_ports`` wird ueber ``format_ports`` zusammengefasst (``"22/tcp,80/tcp"``), ``tags``
    ueber ``format_tags`` (``"a;b"``); das verschachtelte mdns/ssdp-Detail ist BEWUSST nicht
    Teil der CSV (in einer flachen Tabelle nicht sauber abbildbar -- das fuehrt JSON
    verlustfrei). Sonderzeichen/Kommata/Anfuehrungszeichen werden korrekt escaped -- das
    erledigt das stdlib ``csv``-Modul (kein Hand-Escaping). ``\\r\\n`` als Zeilenende
    (RFC-4180-konform, deterministisch unabhaengig von der Plattform).

    Rein: kein I/O (in-memory ``StringIO``), keine Uhr; gleiche Eingabe -> gleicher String.
    """
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(_CSV_COLUMNS)
    for host in scan.hosts:
        writer.writerow(
            [
                host.ip,
                host.mac,
                host.vendor,
                host.hostname,
                host.os_guess,
                host.category,
                host.label,
                format_ports(host.ports),
                format_tags(host.tags),
                host.source,
            ]
        )
    return buffer.getvalue()


def build_pdf_model(scan: ExportableScan) -> PdfReportModel:
    """Baut das reine PDF-MODELL aus dem Scan -- deterministisch, testbar (kein Rendern).

    Der Kopf traegt den festen Titel (``_PDF_TITLE``), den Scan-Zeitpunkt (``scanned_at``),
    das gescannte Netz (``cidr``) und die Geraeteanzahl (``host_count``). Die Tabelle nutzt
    ``_PDF_COLUMNS`` (die druckbaren Kernfelder in DEFINIERTER Reihenfolge); je Host eine
    Zeile als String-Tupel in genau dieser Spalten-Reihenfolge, ``open_ports`` ueber
    ``format_ports`` zusammengefasst. Die Host-Reihenfolge bleibt die der Eingabe.

    Das tatsaechliche Rendern (Font/Layout/Gitter) macht die Infrastruktur -- diese Funktion
    liefert nur die reinen Daten (Layout-/Spaltenwahl ist hier testbar, ADR 0015). Rein:
    kein I/O, keine Uhr; gleiche Eingabe -> gleiches Modell.
    """
    rows = tuple(
        (
            host.ip,
            host.mac,
            host.vendor,
            host.hostname,
            host.os_guess,
            host.category,
            format_ports(host.ports),
        )
        for host in scan.hosts
    )
    # Kopf-Zeilen als generische (Label, Wert)-Paare (ADR 0015, Block 2: PdfReportModel
    # generalisiert). Inhalt + Reihenfolge bleiben semantisch identisch zu Block 1
    # (Scan-Zeitpunkt, gescanntes Netz, Geraeteanzahl) -- nur generisch statt fest im
    # Renderer hartkodiert.
    meta = (
        ("Scan-Zeitpunkt", scan.scanned_at),
        ("Gescanntes Netz", scan.cidr),
        ("Geräteanzahl", str(scan.host_count)),
    )
    return PdfReportModel(
        title=_PDF_TITLE,
        meta=meta,
        columns=_PDF_COLUMNS,
        rows=rows,
    )


# ── Block 2: Analyse-Befunde -> CSV/JSON/PDF (ADR 0015, Block 2) ──────────────────────────
#
# Zweite Datenquelle der export-Domaene: die AKTUELLEN Analyse-Befunde. Anders als der Scan
# (mit gespeicherter ``scan_id``) hat die Analyse KEINEN gespeicherten Stand -- GET
# /api/analysis baut den Snapshot bei jedem Aufruf frisch; der Analyse-Export nutzt GENAU
# diesen Pfad ("die Analyse von jetzt"). Darum gibt es im Export-Pfad KEINE ``analysis_id``.
#
# INDEPENDENCE (independence-Contract, ADR 0015): ``domain.export`` importiert NICHT
# ``domain.analysis``. Eigene schlanke ``Exportable*``-Typen fuer Befunde + die Projektion
# ``ResolvedObservation`` -> ``ExportableFinding`` lebt im Composition Root (genau das
# Block-1-Muster mit ``ExportableScan``). ``severity`` ist hier bewusst ``str`` (Werte
# "info"/"notable") statt eines Imports von ``domain.analysis.Severity`` -- die Domaene
# bleibt analysis-frei.


@dataclass(frozen=True)
class ExportableFinding:
    """Ein Analyse-Befund als reines export-Wertobjekt (frozen) -- die Export-Eingabe.

    Traegt genau die Felder, die ``ResolvedObservation`` (eingebettete ``Observation`` +
    ``help_url``) fuer den Export liefert: ``rule_id``/``severity``/``title``/``detail``/
    ``subject``/``help_kind`` aus der Observation, ``help_url`` aus der Aufloesung.

    BEWUSSTE WAHL (ADR 0015, independence): ``severity`` ist ``str`` (Werte "info"/"notable"),
    KEIN Import von ``domain.analysis.Severity`` -- so bleibt ``domain.export`` unabhaengig
    von ``domain.analysis``. Die Projektion im Composition Root reicht den String herein.
    """

    rule_id: str
    severity: str
    title: str
    detail: str
    subject: str
    help_kind: str
    help_url: str


@dataclass(frozen=True)
class ExportableAnalysis:
    """Die gebuendelten Analyse-Befunde als reines export-Wertobjekt (frozen).

    ``generated_at`` der ISO-Zeitstempel, WANN der Export erzeugt wurde -- er kommt als FELD
    von aussen herein (der Composition Root/Use-Case fuellt ihn ueber die ``Clock``); die
    Domaene fragt KEINE Uhr (ADR 0002/0015). ``findings`` die projizierten Befunde in ihrer
    Eingabe-Reihenfolge (``AnalyzeSnapshot`` liefert bereits deterministisch sortiert --
    diese Reihenfolge wird NICHT veraendert). ``finding_count`` ist der Vollstaendigkeit
    halber die Anzahl (= ``len(findings)``); die Projektion setzt ihn passend.
    """

    generated_at: str
    findings: tuple[ExportableFinding, ...] = ()
    finding_count: int = 0


# CSV-Spalten in DEFINIERTER Reihenfolge (Auftrag/ADR 0015, Block 2). Anders als beim Scan
# ist das KEIN Identifikations-Schema, sondern die Befund-Sicht: severity zuerst (wonach man
# zuerst schaut), dann der lesbare Text (title/subject/detail), dann die technischen Schluessel
# (rule_id/help_kind/help_url). Tupel-Reihenfolge ist Vertrag (Mutationsprobe: Vertauschung
# -> rot). KEINE Sortierung erzwungen -- die Befund-Reihenfolge der Eingabe bleibt.
_ANALYSIS_CSV_COLUMNS: tuple[str, ...] = (
    "severity",
    "title",
    "subject",
    "detail",
    "rule_id",
    "help_kind",
    "help_url",
)

# PDF-Tabellen-Spalten in DEFINIERTER Reihenfolge (Auftrag/ADR 0015, Block 2): die LESBAREN
# Kernfelder eines Berichts. Schlanker als CSV -- ``rule_id``/``help_kind``/``help_url`` sind
# bewusst NICHT in der PDF-Tabelle (zu breit/technisch fuer einen lesbaren Bericht; sie bleiben
# verlustfrei in CSV/JSON). Auch dies ist Vertrag (Mutationsprobe: entfernte Spalte -> rot).
_ANALYSIS_PDF_COLUMNS: tuple[str, ...] = (
    "severity",
    "title",
    "subject",
    "detail",
)

# Fester Berichtstitel des Analyse-Berichts (Auftrag/ADR 0015, Block 2).
_ANALYSIS_PDF_TITLE = "CERNIS PRO — Analyse-Bericht"

# Maximale Zeichenlaenge der ``detail``-Zelle im PDF (lesbarer Bericht -- ein ueberlanges
# detail sprengt sonst die Tabellen-Zellenbreite). Reine Datenkonstante; das Kuerzen macht
# der reine Helfer ``_truncate``. CSV/JSON fuehren das volle ``detail`` (kein Kuerzen dort).
_PDF_DETAIL_MAX_LEN = 120


def _truncate(text: str, max_len: int) -> str:
    """Kuerzt ``text`` auf hoechstens ``max_len`` Zeichen -- rein, deterministisch, testbar.

    Ist ``text`` nicht laenger als ``max_len``, bleibt er unveraendert. Sonst wird er hart
    auf ``max_len`` Zeichen gekuerzt und mit einem Ellipsis-Zeichen (``…``) abgeschlossen,
    sodass das Ergebnis exakt ``max_len`` Zeichen lang ist (das Ellipsis ERSETZT das letzte
    Zeichen, verlaengert also nicht). Nur fuer die PDF-Zellenbreite -- CSV/JSON kuerzen nie.

    Rein: kein I/O, keine Uhr; gleiche Eingabe -> gleiches Ergebnis.
    """
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "…"


def analysis_to_json(analysis: ExportableAnalysis) -> str:
    """Serialisiert die Analyse VERLUSTFREI strukturiert als JSON-String -- deterministisch.

    Die komplette ``ExportableAnalysis`` (``generated_at``/``finding_count`` + alle Befund-
    Felder) wird ueber die stdlib ``json`` serialisiert. Deterministisch + reproduzierbar
    (ADR 0015): ``sort_keys`` (stabile Key-Reihenfolge), ``indent=2`` (lesbar) und
    ``ensure_ascii=False`` (echtes UTF-8 statt ``\\uXXXX`` -- Sonderzeichen bleiben lesbar).
    Die Befund-REIHENFOLGE bleibt die der Eingabe (die Liste wird NICHT sortiert, nur die
    Objekt-Keys) -- so spiegelt der Export die deterministische AnalyzeSnapshot-Ordnung.

    Rein: kein I/O, keine Uhr; gleiche Eingabe -> gleicher String.
    """
    payload = {
        "generated_at": analysis.generated_at,
        "finding_count": analysis.finding_count,
        "findings": [
            {
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "title": finding.title,
                "detail": finding.detail,
                "subject": finding.subject,
                "help_kind": finding.help_kind,
                "help_url": finding.help_url,
            }
            for finding in analysis.findings
        ],
    }
    return json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False)


def analysis_to_csv(analysis: ExportableAnalysis) -> str:
    """Serialisiert die Befunde als CSV-String -- flach, deterministisch, testbar.

    Eine Header-Zeile (``_ANALYSIS_CSV_COLUMNS`` in DEFINIERTER Reihenfolge) + eine Zeile pro
    Befund, Werte exakt in der Spalten-Reihenfolge. KEINE Sortierung erzwungen -- die
    Befund-Reihenfolge der Eingabe bleibt erhalten (``AnalyzeSnapshot`` liefert bereits
    deterministisch sortiert). Sonderzeichen/Kommata/Anfuehrungszeichen werden korrekt
    escaped -- das erledigt das stdlib ``csv``-Modul (kein Hand-Escaping). ``\\r\\n`` als
    Zeilenende (RFC-4180-konform, plattformunabhaengig).

    Rein: kein I/O (in-memory ``StringIO``), keine Uhr; gleiche Eingabe -> gleicher String.
    """
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(_ANALYSIS_CSV_COLUMNS)
    for finding in analysis.findings:
        writer.writerow(
            [
                finding.severity,
                finding.title,
                finding.subject,
                finding.detail,
                finding.rule_id,
                finding.help_kind,
                finding.help_url,
            ]
        )
    return buffer.getvalue()


def build_analysis_pdf_model(analysis: ExportableAnalysis) -> PdfReportModel:
    """Baut das reine (generische) ``PdfReportModel`` aus der Analyse -- testbar, kein Rendern.

    Nutzt das BESTEHENDE ``PdfReportModel`` aus Block 1 (kein zweites Modell). Der Kopf traegt
    den festen Titel (``_ANALYSIS_PDF_TITLE``) und die generischen ``meta``-Paare ("Erzeugt am"
    -> ``generated_at``, "Anzahl Befunde" -> ``finding_count``). Die Tabelle nutzt
    ``_ANALYSIS_PDF_COLUMNS`` (severity/title/subject/detail -- die LESBAREN Felder); je Befund
    eine Zeile in genau dieser Reihenfolge. ``detail`` wird fuer die Zellenbreite ueber
    ``_truncate`` gekuerzt (nur im PDF -- CSV/JSON fuehren das volle detail). ``rule_id``/
    ``help_kind``/``help_url`` sind BEWUSST nicht in der PDF-Tabelle (zu technisch/breit).
    Die Befund-Reihenfolge bleibt die der Eingabe.

    Rein: kein I/O, keine Uhr; gleiche Eingabe -> gleiches Modell.
    """
    rows = tuple(
        (
            finding.severity,
            finding.title,
            finding.subject,
            _truncate(finding.detail, _PDF_DETAIL_MAX_LEN),
        )
        for finding in analysis.findings
    )
    meta = (
        ("Erzeugt am", analysis.generated_at),
        ("Anzahl Befunde", str(analysis.finding_count)),
    )
    return PdfReportModel(
        title=_ANALYSIS_PDF_TITLE,
        meta=meta,
        columns=_ANALYSIS_PDF_COLUMNS,
        rows=rows,
    )
