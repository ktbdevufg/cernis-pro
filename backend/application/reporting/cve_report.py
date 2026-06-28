"""Reine Aggregation des CVE-Berichts: Severity-Verteilung, betroffene Geraete,
Muster nach Dienst und die durchnormalisierte Gesamt-Befundliste (Etappe 1).

Dies ist der dritte Reporting-Bericht (nach Sicherheitsbericht + Bestandsbericht).
Die Architektur ist 1:1 analog zum Bestandsbericht (``inventory_report.py``):
neutrale frozen Eingabe-Typen, eine reine ``build``-Funktion, ein frozen Out-Report.
Diese Datei verdichtet die neutralen CVE-Befund-Zeilen (``CveFindingRow``) und die
Monitor-Kennzahlen (``CveMonitorInput``) zu der Severity-Verteilung, der Tabelle der
betroffenen Geraete (Sektion 2), dem Muster nach Dienst (Sektion 3) und der
vollstaendigen, durchnormalisierten Befundliste (Sektion 4).

SEVERITY-KONSISTENZ: Die NVD-Stufen + ihr Rang werden 1:1 aus der Live-Ansicht
(``severityKey``/``SEVERITY_RANG`` in ``CveView.jsx``) uebernommen. Ein unbekannter/
leerer Severity-Wert wird zu ``"UNKNOWN"`` normalisiert (kein Raten). KEINE crit/
notable-Abbildung -- das ist die andere Achse des Sicherheitsberichts.

REINE RECHNUNG analog ``inventory_report.py`` / ``security_report.py``: KEINE Uhr,
KEINE I/O, KEINE Persistenz, KEINE Domaenen-Importe (CLAUDE.md, Importregel
application -> domain/ports). Der Composition Root (spaetere Etappe) projiziert die
echten ``ActiveFinding``/``MonitorStatus`` auf die hier definierten NEUTRALEN
Eingabe-Datentraeger und reicht sie herein. Insbesondere die Formatierung der
Datums-Texte (``first_seen_text``) und der Anzeigename (``device_label``) entstehen
VOR dem Befuellen beim Aufrufer; hier liegt nur noch ``first_seen_ts`` als
Sortier-/Alters-Schluessel, ohne jede Formatierung.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass

# ── Severity-Stufen + Rang (1:1 aus der Live-Ansicht) ───────────────────────
#
# ``SEVERITY_ORDER`` ist die feste Ausgabe-Reihenfolge der Severity-Verteilung (immer
# alle fuenf Stufen). ``SEVERITY_RANG`` ordnet jede Stufe einem Rang zu -- exakt wie
# ``SEVERITY_RANG`` in ``CveView.jsx``; ``_norm_severity`` normalisiert wie
# ``severityKey`` (kein Raten).

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
SEVERITY_RANG: dict[str, int] = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


def _norm_severity(value: str) -> str:
    """Normalisiert eine rohe NVD-Severity auf einen bekannten Schluessel (rein).

    Liefert ``value.upper()`` wenn das in ``SEVERITY_RANG`` liegt, sonst ``"UNKNOWN"``
    -- exakt wie ``severityKey`` in ``CveView.jsx`` (kein Raten).
    """
    key = value.upper()
    return key if key in SEVERITY_RANG else "UNKNOWN"


# ── Eingabe-Datentraeger (frozen, neutral) ──────────────────────────────────
#
# Der Aufrufer (spaetere Etappe) fuellt diese aus den echten ``ActiveFinding``-/
# ``MonitorStatus``-Objekten. Alle Anzeige-Texte (``device_label``,
# ``first_seen_text``) sind schon FERTIG vom Aufrufer gesetzt -- hier wird nur noch
# normalisiert, gezaehlt, gruppiert und sortiert.


@dataclass(frozen=True)
class CveFindingRow:
    """Eine neutrale CVE-Befund-Zeile des CVE-Berichts (Aufrufer befuellt).

    ``device_label`` ist der schon gebildete Anzeigename (label||hostname||ip||mac --
    die Wahl trifft der Aufrufer), ``mac`` die MAC als Gruppier-Schluessel, ``ip`` die
    Anzeige-IP des Hosts ("" moeglich; der Aufrufer liefert die Finding-IP, ersatzweise
    die Geraete-IP). Die IP wird hier NICHT verrechnet -- sie dient nur dem Host-Kopf der
    gruppierten Befundliste (``HostFindingGroup.ip``). ``cve_id``
    die CVE-Kennung, ``severity`` die ROHE NVD-Severity (wird hier via
    ``_norm_severity`` normalisiert), ``cvss_score`` der CVSS-Wert. ``service`` der
    Dienst-/Protokoll-Bezeichner (leer moeglich), ``port`` der Port. ``first_seen_text``
    ist der schon FERTIG formatierte Datums-Text (keine Uhr hier), ``first_seen_ts`` der
    Sortier-/Alters-Schluessel (keine Formatierung hier). ``published`` das
    NVD-Veroeffentlichungsdatum als roher Text ("" moeglich). ``acknowledged`` der
    Quittiert-Marker (False = aktiver Befund, True = quittiert), ``is_new`` die vom
    Aufrufer durchgereichte Domaenen-Ableitung.
    """

    device_label: str
    mac: str
    ip: str
    cve_id: str
    severity: str
    cvss_score: float
    service: str
    port: int
    first_seen_text: str
    first_seen_ts: float
    published: str
    acknowledged: bool
    is_new: bool


@dataclass(frozen=True)
class CveMonitorInput:
    """Neutrale Monitor-Kennzahlen des CVE-Berichts (Aufrufer projiziert ``MonitorStatus``).

    ``hosts_total`` die Gesamtzahl der Hosts, ``hosts_due`` die faelligen, ``hosts_checked``
    die geprueften, ``findings_total`` die Gesamtzahl der Befunde, ``findings_active`` die
    aktiven. Werden -- soweit der Report sie traegt -- UNVERAENDERT durchgereicht.
    """

    hosts_total: int
    hosts_due: int
    hosts_checked: int
    findings_total: int
    findings_active: int


# ── Ergebnis-Datentraeger (frozen) ──────────────────────────────────────────


@dataclass(frozen=True)
class SeverityCount:
    """Ein Eintrag der Severity-Verteilung (Stufe + Anzahl), neutral.

    ``severity`` die Stufe (aus ``SEVERITY_ORDER``), ``count`` die Anzahl aktiver
    Befunde dieser Stufe (auch 0 moeglich -- es werden immer alle fuenf Stufen
    ausgegeben).
    """

    severity: str
    count: int


@dataclass(frozen=True)
class DeviceCveRow:
    """Sektion 2 -- eine Zeile je betroffenem Geraet (ueber AKTIVE Befunde).

    ``device_label`` der Anzeigename (das Label der ersten aktiven Zeile dieses ``mac``,
    stabil), ``mac`` die MAC. ``finding_count`` die Anzahl AKTIVER Befunde dieses
    Geraets, ``highest_severity`` die hoechste Severity nach Rang ("UNKNOWN" wenn keine),
    ``highest_cvss`` der hoechste CVSS dieses Geraets (0.0 wenn keine). ``services`` die
    kommaseparierte, sortierte, deduplizierte Liste nicht-leerer Dienste ("" moeglich).
    """

    device_label: str
    mac: str
    finding_count: int
    highest_severity: str
    highest_cvss: float
    services: str


@dataclass(frozen=True)
class ServiceCveRow:
    """Sektion 3 -- eine Zeile je Dienst (Muster nach Dienst, ueber AKTIVE Befunde).

    ``service`` der Dienst-Name (ein leerer Dienst wird als "(ohne)" gefuehrt),
    ``finding_count`` die Anzahl AKTIVER Befunde mit diesem Dienst, ``device_count`` die
    Anzahl betroffener Geraete (distinct ``mac``) mit diesem Dienst. ``highest_severity``
    die hoechste Severity nach Rang, ``highest_cvss`` der hoechste CVSS. ``oldest_published``
    die aelteste ``published`` je Dienst als Text ("" wenn keine/alle leer).
    """

    service: str
    finding_count: int
    device_count: int
    highest_severity: str
    highest_cvss: float
    oldest_published: str


@dataclass(frozen=True)
class HostFindingGroup:
    """Sektion 4 (gruppierte Sicht) -- ein Host-Block der vollstaendigen Befundliste.

    Gruppiert ALLE Befunde eines Hosts (aktiv UND quittiert) unter einem Host-Kopf.
    ``device_label`` der Anzeigename (das Label der ersten Zeile dieser ``mac`` in
    ``all_rows``-Reihenfolge, stabil), ``mac`` die MAC, ``ip`` die IP fuer den Host-Kopf
    (die erste nicht-leere ``ip`` der Gruppe; "" wenn alle leer). ``finding_count`` die
    Anzahl der Befunde dieses Hosts, ``highest_severity`` die hoechste Severity nach Rang
    ueber die Gruppe. ``rows`` die Befunde dieses Hosts, schon sortiert (Severity-Rang
    absteigend, dann CVSS absteigend, dann Port aufsteigend, dann cve_id).
    """

    device_label: str
    mac: str
    ip: str
    finding_count: int
    highest_severity: str
    rows: list[CveFindingRow]


@dataclass(frozen=True)
class CveReport:
    """Das Gesamtergebnis der CVE-Aggregation (alles fuer den api-Rand/Frontend).

    KENNZAHLEN: ``generated_findings_total`` (== ``status.findings_total``, durchgereicht),
    ``active_total`` die Anzahl aktiver (nicht-quittierter) Zeilen, ``acknowledged_total``
    die quittierten, ``new_total`` die aktiven Zeilen mit ``is_new == True``,
    ``affected_devices`` die distinct ``mac`` ueber AKTIVE Befunde. ``hosts_total``/
    ``hosts_checked`` kommen aus ``status``. ``coverage_text`` ist hier bewusst LEER (der
    PDF-/Frontend-Rand bildet die Prozentdarstellung -- hier NICHT rechnen-als-Text).
    ``highest_severity`` die hoechste Severity ueber AKTIVE Befunde ("UNKNOWN" wenn keine),
    ``oldest_published`` die aelteste ``published`` ueber AKTIVE Befunde ("" wenn keine).

    ``severity_counts`` die Severity-Verteilung ueber AKTIVE Befunde, in
    ``SEVERITY_ORDER``-Reihenfolge (immer alle fuenf Stufen, auch count 0).
    ``device_rows`` Sektion 2, ``service_rows`` Sektion 3, ``all_rows`` Sektion 4 (ALLE
    Zeilen, aktiv UND quittiert, mit durchnormalisierter Severity, sortiert).
    ``host_groups`` die ZUSAETZLICHE, nach Host gruppierte Sicht derselben Zeilen (fuer
    das PDF und das spaetere Frontend); ``all_rows`` bleibt fuer JSON/Frontend erhalten.
    """

    generated_findings_total: int
    active_total: int
    acknowledged_total: int
    new_total: int
    affected_devices: int
    hosts_total: int
    hosts_checked: int
    coverage_text: str
    highest_severity: str
    oldest_published: str
    severity_counts: list[SeverityCount]
    device_rows: list[DeviceCveRow]
    service_rows: list[ServiceCveRow]
    all_rows: list[CveFindingRow]
    host_groups: list[HostFindingGroup]


# ── Reine Funktionen (keine I/O, keine Uhr) ─────────────────────────────────

# Platzhalter fuer einen leeren Dienst in der Muster-nach-Dienst-Aggregation (Sektion 3).
_EMPTY_SERVICE = "(ohne)"


def _rang(sev: str) -> int:
    """Rang einer schon NORMALISIERTEN Severity (``sev`` ist immer ein gueltiger Key)."""
    return SEVERITY_RANG[sev]


def _highest_severity(rows: list[CveFindingRow]) -> str:
    """Hoechste Severity nach Rang ueber die uebergebenen Zeilen ("UNKNOWN" wenn leer)."""
    highest = "UNKNOWN"
    for row in rows:
        if _rang(row.severity) > _rang(highest):
            highest = row.severity
    return highest


def _oldest_published(rows: list[CveFindingRow]) -> str:
    """Kleinste NICHT-leere ``published`` als String-Min ("" wenn keine).

    NVD ``published`` ist ISO-8601, daher ist die String-Minimal-Auswahl korrekt
    chronologisch -- robust ohne jedes Datums-Parsing. Leere ``published`` werden
    ignoriert.
    """
    candidates = [row.published for row in rows if row.published]
    return min(candidates) if candidates else ""


def build_cve_report(status: CveMonitorInput, rows: list[CveFindingRow]) -> CveReport:
    """Baut den vollstaendigen CVE-Bericht aus den neutralen Befund-Zeilen.

    Schritte (rein, deterministisch, KEINE Uhr):
      0. Severity jeder Zeile via ``_norm_severity`` normalisieren (neue
         ``CveFindingRow``-Instanzen mit ``dataclasses.replace``, da die Eingabe frozen
         ist).
      1. AKTIVE Zeilen = nicht-quittierte; ``active_total``/``acknowledged_total``/
         ``new_total`` daraus.
      2. ``severity_counts`` ueber AKTIVE Zeilen je Stufe, IMMER alle fuenf Stufen in
         ``SEVERITY_ORDER`` (count 0 erlaubt).
      3. ``affected_devices`` = distinct ``mac`` ueber AKTIVE Zeilen.
      4. ``highest_severity`` (Report) = hoechste Stufe nach Rang ueber AKTIVE Zeilen.
      5. ``oldest_published`` (Report) = kleinste nicht-leere ``published`` (String-Min).
      6. ``device_rows`` (Sektion 2) je distinct ``mac`` ueber AKTIVE Zeilen, sortiert
         nach ``(-highest_rang, -highest_cvss, -finding_count, device_label)``.
      7. ``service_rows`` (Sektion 3) je Dienst-Schluessel (leer -> "(ohne)") ueber
         AKTIVE Zeilen, sortiert nach ``(-highest_rang, -finding_count, service)``.
      8. ``all_rows`` (Sektion 4) = ALLE normalisierten Zeilen (aktiv UND quittiert),
         sortiert nach ``(-rang(severity), -cvss_score, device_label, cve_id)``.
      8b. ``host_groups`` (Sektion 4, gruppierte Sicht) = dieselben Zeilen nach ``mac``
         gruppiert; je Gruppe ein Host-Kopf + die nach ``(-rang, -cvss, port, cve_id)``
         sortierten Zeilen. Host-Reihenfolge: gefaehrlichster zuerst, nach
         ``(-rang(highest_severity), -max_cvss, -finding_count, device_label)``.
      9. ``coverage_text`` = "" (der PDF-/Frontend-Rand bildet die Prozentdarstellung);
         ``generated_findings_total``/``hosts_total``/``hosts_checked`` aus ``status``
         durchreichen.

    Keine Uhr, keine I/O, keine Domaenen-Importe.
    """
    # Schritt 0: Severity normalisieren (frozen -> neue Instanzen).
    normalisiert = [dataclasses.replace(row, severity=_norm_severity(row.severity)) for row in rows]

    # Schritt 1: aktive Zeilen + Kennzahlen.
    aktive = [r for r in normalisiert if not r.acknowledged]
    active_total = len(aktive)
    acknowledged_total = len(normalisiert) - active_total
    new_total = sum(1 for r in aktive if r.is_new)

    # Schritt 2: Severity-Verteilung (immer alle fuenf Stufen).
    severity_zaehler = dict.fromkeys(SEVERITY_ORDER, 0)
    for row in aktive:
        severity_zaehler[row.severity] += 1
    severity_counts = [
        SeverityCount(severity=stufe, count=severity_zaehler[stufe]) for stufe in SEVERITY_ORDER
    ]

    # Schritt 3: betroffene Geraete (distinct mac ueber aktive Zeilen).
    affected_devices = len({r.mac for r in aktive})

    # Schritte 4/5: Report-Spitzenwerte ueber aktive Zeilen.
    highest_severity = _highest_severity(aktive)
    oldest_published = _oldest_published(aktive)

    # Schritt 6: device_rows (Sektion 2), je distinct mac ueber aktive Zeilen.
    device_gruppen: dict[str, list[CveFindingRow]] = {}
    for row in aktive:
        device_gruppen.setdefault(row.mac, []).append(row)
    device_rows = [
        DeviceCveRow(
            device_label=gruppe[0].device_label,
            mac=mac,
            finding_count=len(gruppe),
            highest_severity=_highest_severity(gruppe),
            highest_cvss=max(r.cvss_score for r in gruppe),
            services=", ".join(sorted({r.service for r in gruppe if r.service})),
        )
        for mac, gruppe in device_gruppen.items()
    ]
    device_rows.sort(
        key=lambda d: (
            -_rang(d.highest_severity),
            -d.highest_cvss,
            -d.finding_count,
            d.device_label,
        )
    )

    # Schritt 7: service_rows (Sektion 3), je Dienst-Schluessel ueber aktive Zeilen.
    service_gruppen: dict[str, list[CveFindingRow]] = {}
    for row in aktive:
        schluessel = row.service if row.service else _EMPTY_SERVICE
        service_gruppen.setdefault(schluessel, []).append(row)
    service_rows = [
        ServiceCveRow(
            service=service,
            finding_count=len(gruppe),
            device_count=len({r.mac for r in gruppe}),
            highest_severity=_highest_severity(gruppe),
            highest_cvss=max(r.cvss_score for r in gruppe),
            oldest_published=_oldest_published(gruppe),
        )
        for service, gruppe in service_gruppen.items()
    ]
    service_rows.sort(key=lambda s: (-_rang(s.highest_severity), -s.finding_count, s.service))

    # Schritt 8: all_rows (Sektion 4), ALLE normalisierten Zeilen.
    all_rows = sorted(
        normalisiert,
        key=lambda r: (-_rang(r.severity), -r.cvss_score, r.device_label, r.cve_id),
    )

    # Schritt 8b: host_groups (Sektion 4, gruppierte Sicht) -- ALLE Zeilen nach mac
    # gruppiert (aktiv UND quittiert, wie all_rows). Die Gruppierung laeuft ueber
    # all_rows, damit "device_label/ip der ersten Zeile" stabil aus der all_rows-
    # Reihenfolge stammt.
    host_gruppen: dict[str, list[CveFindingRow]] = {}
    for row in all_rows:
        host_gruppen.setdefault(row.mac, []).append(row)
    host_groups = [
        HostFindingGroup(
            device_label=gruppe[0].device_label,
            mac=mac,
            ip=next((r.ip for r in gruppe if r.ip), ""),
            finding_count=len(gruppe),
            highest_severity=_highest_severity(gruppe),
            rows=sorted(
                gruppe,
                key=lambda r: (-_rang(r.severity), -r.cvss_score, r.port, r.cve_id),
            ),
        )
        for mac, gruppe in host_gruppen.items()
    ]
    host_groups.sort(
        key=lambda g: (
            -_rang(g.highest_severity),
            -max(r.cvss_score for r in g.rows),
            -g.finding_count,
            g.device_label,
        )
    )

    # Schritt 9: Durchreichen + leerer coverage_text.
    return CveReport(
        generated_findings_total=status.findings_total,
        active_total=active_total,
        acknowledged_total=acknowledged_total,
        new_total=new_total,
        affected_devices=affected_devices,
        hosts_total=status.hosts_total,
        hosts_checked=status.hosts_checked,
        coverage_text="",
        highest_severity=highest_severity,
        oldest_published=oldest_published,
        severity_counts=severity_counts,
        device_rows=device_rows,
        service_rows=service_rows,
        all_rows=all_rows,
        host_groups=host_groups,
    )
