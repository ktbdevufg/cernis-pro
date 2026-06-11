"""Domaenenmodell der export-Domaene (Block 1): gespeicherter Scan -> CSV/JSON/PDF.

Reine Domaenenlogik (stdlib + dataclasses, ADR 0002/0015) -- kein Datei-I/O, keine Uhr,
KEIN Import aus anderen Domaenen (independence-Contract). Insbesondere importiert
``domain.export`` NICHT ``domain.scanning``: damit es vom scanning-Modell unabhaengig
bleibt, definiert es seine EIGENEN, schlanken Eingabe-Typen (``Exportable*``), und die
PROJEKTION von ``scanning.ScanRecord``/``EnrichedHost`` auf diese Typen passiert im
Composition Root (genau das analysis-Muster mit seinen ``Observed*``-Typen, ADR 0015).

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
    """Das reine PDF-MODELL (frozen) -- Kopf-Felder + Tabellen-Zeilen als reine Daten.

    NICHT das PDF selbst: ``title``/``scanned_at``/``cidr``/``host_count`` sind der Kopf,
    ``columns`` die Spaltenueberschriften (deterministische Reihenfolge), ``rows`` die
    Tabellen-Zeilen (je Host ein String-Tupel in der ``columns``-Reihenfolge). Das
    tatsaechliche Rendern (Font, Seitenlayout, Tabellen-Gitter) macht die Infrastruktur
    (reportlab) -- so bleibt die Domaene rein und die Layout-/Spaltenwahl testbar (ADR 0015).
    """

    title: str
    scanned_at: str
    cidr: str
    host_count: int
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
    return PdfReportModel(
        title=_PDF_TITLE,
        scanned_at=scan.scanned_at,
        cidr=scan.cidr,
        host_count=scan.host_count,
        columns=_PDF_COLUMNS,
        rows=rows,
    )
