"""Reine Aggregation des Sicherheitsberichts: Quellen je Geraet zum schwersten
Vergehen + Berichts-Tabellen-Strukturen (Etappe 2).

Diese Datei verdichtet die Rohbefunde MEHRERER Quellen (Ports/CVE/Netz) je Geraet
zum schwersten OFFENEN Vergehen (``DeviceBurden.worst_severity``) und reicht die
nach Schwere/Relevanz sortierten Berichts-Tabellen heraus. Der eigentliche
Netz-Gesundheit-Score wird aus ``security_score.py`` (gleiche Schicht/Paket)
uebernommen.

REINE RECHNUNG analog ``security_score.py`` / ``behavior_profile.py``: KEINE Uhr,
KEINE I/O, KEINE Persistenz, KEINE Domaenen-Importe (CLAUDE.md, Importregel
application -> domain/ports). Diese Etappe importiert NICHTS aus CVE/security/
dns_watch -- der Aufrufer (Etappe 2b am Composition Root) projiziert die echten
Objekte (ActiveFinding/ArpAlert/DnsContact ...) auf die hier definierten
NEUTRALEN Eingabe-Datentraeger und reicht sie herein.

Die Gewichte und Schwellen (inkl. ``cvss_critical_min``) kommen als Parameter mit
Defaults herein (spaeter aus analysis-Settings), nicht hartkodiert -- dieselbe Naht
wie bei ``compute_security_score`` und bei ``behavior_profile``.

Muster aus der Nachbarschaft uebernommen: frozen dataclasses als Ein-/Ausgabe-
Datentraeger, reine Funktionen mit ausfuehrlichen Docstrings, alle Kontextwerte via
Parameter, deterministisch ohne Wanduhr.
"""

from __future__ import annotations

from dataclasses import dataclass

from application.reporting.security_score import (
    DeviceBurden,
    SecurityScore,
    compute_security_score,
)

# ── Eingabe-Datentraeger (frozen, neutral) ──────────────────────────────────
#
# Der Aufrufer (Etappe 2b) fuellt diese aus den echten Quell-Objekten. Sie tragen
# bereits ``device_label`` als Match-Schluessel und -- wo zutreffend -- eine
# ``severity`` schon als "critical"/"notable" (z. B. das ARP-Mapping
# "high"->"critical"/"medium"->"notable" macht der Aufrufer VOR dem Befuellen).


@dataclass(frozen=True)
class PortFinding:
    """Ein offener-/riskanter-Port-Befund EINES Geraets (neutral, Aufrufer befuellt).

    ``device_label`` ist der Match-Schluessel zwischen den Quellen (Anzeigename oder
    ip||mac, vom Aufrufer gesetzt). ``ports`` ist die bereits formatierte Port-Liste
    als Text (z. B. ``"23, 2323"``). ``severity`` ist bereits genau "critical" oder
    "notable" (der Aufrufer hat das gemappt). ``reason`` ist der Klartext-Grund.
    """

    device_label: str
    ports: str
    severity: str
    reason: str


@dataclass(frozen=True)
class CveFinding:
    """Ein CVE-Befund EINES Geraets (neutral, Aufrufer befuellt).

    ``device_label`` ist der Match-Schluessel. ``cve_id`` die CVE-Kennung,
    ``cvss_score`` der CVSS-Wert (fuer Sortierung UND fuer das critical/notable-
    Mapping ueber ``cvss_critical_min``), ``severity`` der ROHE severity-Text aus der
    CVE-Quelle (nur als Beleg mitgefuehrt -- die Burden-Einstufung laeuft hier ueber
    ``cvss_score``, nicht ueber diesen Rohwert), ``service`` der betroffene Dienst.
    """

    device_label: str
    cve_id: str
    cvss_score: float
    severity: str
    service: str


@dataclass(frozen=True)
class NetFinding:
    """Ein netzweiter Befund (kein Einzelgeraet-Port/-CVE), z. B. IP-Konflikt.

    ``kind`` ist die Art ("IP-Konflikt"/"DNS-Umgehung"/"Rogue-DHCP" ...),
    ``device_label`` der Match-Schluessel (das betroffene Geraet, vom Aufrufer
    bestimmt -- z. B. bei ARP die kollidierende IP/MAC), ``description`` der
    Klartext, ``severity`` bereits genau "critical" oder "notable" (das ARP-Mapping
    "high"->"critical"/"medium"->"notable" hat der Aufrufer VOR dem Setzen gemacht).
    """

    kind: str
    device_label: str
    description: str
    severity: str


# ── Ergebnis-Datentraeger (frozen) ──────────────────────────────────────────


@dataclass(frozen=True)
class SecurityReport:
    """Das Gesamtergebnis der Berichts-Aggregation (alles fuer den api-Rand/Frontend).

    ``score`` ist der aus ``compute_security_score`` berechnete Netz-Gesundheit-Score
    (samt Zaehlern/Level). Die drei OFFENEN Listen sind bereits sortiert:
      * ``port_findings`` -- critical vor notable, dann ``device_label``;
      * ``cve_findings`` -- nach ``cvss_score`` absteigend;
      * ``net_findings`` -- critical vor notable.
    Die ``acknowledged_*``-Listen sind die vom Nutzer bestaetigten (quittierten)
    Gegenstuecke -- sie werden UNVERAENDERT durchgereicht und fliessen NICHT in den
    Score/die Burdens ein. ``device_labels`` sind alle beruecksichtigten Geraete
    (Basis N), schon ohne archivierte (der Aufrufer hat sie vorgefiltert).
    """

    score: SecurityScore
    port_findings: list[PortFinding]
    cve_findings: list[CveFinding]
    net_findings: list[NetFinding]
    acknowledged_port_findings: list[PortFinding]
    acknowledged_cve_findings: list[CveFinding]
    acknowledged_net_findings: list[NetFinding]
    device_labels: list[str]


# ── Reine Funktionen (keine I/O, keine Uhr) ─────────────────────────────────

# Rang je severity-Stufe: hoeher = schwerer. Fuer das Maximum ueber Quellen und
# fuer die critical-vor-notable-Sortierung. "none" = kein offener Befund.
_SEVERITY_RANK = {"critical": 2, "notable": 1, "none": 0}


def severity_rank(severity: str) -> int:
    """Ordnet eine severity-Stufe einem Rang zu: critical > notable > none.

    Hilfsfunktion fuer das Maximum ueber die Quellen (schwerstes Vergehen je Geraet)
    und fuer die critical-vor-notable-Sortierung. Unbekannte Werte rangieren wie
    "none" (0) -- ein nicht klassifizierter Befund darf die Schwere nicht heben.
    """
    return _SEVERITY_RANK.get(severity, 0)


def _cve_severity(cvss_score: float, cvss_critical_min: float) -> str:
    """Mappt einen CVSS-Wert auf "critical"/"notable" fuer die Burden-Einstufung.

    ``cvss_score >= cvss_critical_min`` -> "critical", sonst "notable". Die Schwelle
    ``cvss_critical_min`` kommt als Parameter herein (Default 9.0) und stammt spaeter
    aus den analysis-Settings -- hier nicht hartkodiert.
    """
    return "critical" if cvss_score >= cvss_critical_min else "notable"


def build_device_burdens(
    device_labels: list[str],
    port_findings: list[PortFinding],
    cve_findings: list[CveFinding],
    net_findings: list[NetFinding],
    cvss_critical_min: float = 9.0,
) -> list[DeviceBurden]:
    """Bestimmt je Geraet das SCHWERSTE OFFENE Vergehen ueber alle drei Quellen.

    Fuer JEDES ``device_label`` aus ``device_labels`` wird das Maximum der severity
    ueber die zu diesem Geraet gehoerenden OFFENEN Befunde gebildet:
      * ``PortFinding.severity`` und ``NetFinding.severity`` sind bereits genau
        "critical"/"notable" (der Aufrufer hat sie gemappt, inkl. ARP
        "high"->"critical"/"medium"->"notable");
      * ``CveFinding`` wird ueber ``cvss_score`` gemappt: ``>= cvss_critical_min``
        -> "critical", sonst "notable" (Schwelle als Parameter, Default 9.0, spaeter
        aus Settings).
    Ein Geraet ohne JEDEN offenen Befund bekommt ``worst_severity`` "none". Nur OFFENE
    Befunde zaehlen -- die acknowledged-Listen werden hier gar nicht gereicht und
    fliessen damit NICHT ein. ``device_label`` ist der Match-Schluessel zwischen den
    Quellen. Deterministisch, keine Uhr, keine I/O.
    """
    burdens: list[DeviceBurden] = []
    for label in device_labels:
        worst_rank = 0  # 0 == "none"
        for port in port_findings:
            if port.device_label == label:
                worst_rank = max(worst_rank, severity_rank(port.severity))
        for cve in cve_findings:
            if cve.device_label == label:
                mapped = _cve_severity(cve.cvss_score, cvss_critical_min)
                worst_rank = max(worst_rank, severity_rank(mapped))
        for net in net_findings:
            if net.device_label == label:
                worst_rank = max(worst_rank, severity_rank(net.severity))

        if worst_rank >= 2:
            worst_severity = "critical"
        elif worst_rank == 1:
            worst_severity = "notable"
        else:
            worst_severity = "none"
        burdens.append(DeviceBurden(device_label=label, worst_severity=worst_severity))
    return burdens


def build_security_report(
    device_labels: list[str],
    port_findings: list[PortFinding],
    cve_findings: list[CveFinding],
    net_findings: list[NetFinding],
    ack_port: list[PortFinding],
    ack_cve: list[CveFinding],
    ack_net: list[NetFinding],
    critical_weight: float = 1.0,
    notable_weight: float = 0.3334,
    level_good_min: int = 80,
    level_mid_min: int = 50,
    cvss_critical_min: float = 9.0,
) -> SecurityReport:
    """Baut den vollstaendigen Sicherheitsbericht aus den Rohbefunden.

    Schritte:
      1. ``build_device_burdens`` ueber die OFFENEN Befunde (schwerstes Vergehen je
         Geraet, CVE-Mapping ueber ``cvss_critical_min``).
      2. ``compute_security_score`` ueber die Burdens (Gewichte/Schwellen als
         Parameter).
      3. Sortiert die drei OFFENEN Listen: Ports critical-vor-notable dann
         ``device_label``; CVE nach ``cvss_score`` absteigend; Netz
         critical-vor-notable.
      4. Reicht die ``ack_*``-Listen UNVERAENDERT durch (sie fliessen NICHT in
         Burdens/Score ein) und gibt ``device_labels`` als Basis N mit heraus.

    Alle Gewichte und Schwellen kommen als Parameter mit Defaults herein (spaeter aus
    analysis-Settings). Deterministisch, keine Uhr, keine I/O.
    """
    burdens = build_device_burdens(
        device_labels,
        port_findings,
        cve_findings,
        net_findings,
        cvss_critical_min=cvss_critical_min,
    )
    score = compute_security_score(
        burdens,
        critical_weight=critical_weight,
        notable_weight=notable_weight,
        level_good_min=level_good_min,
        level_mid_min=level_mid_min,
    )

    # Ports: schwer vor leicht (critical vor notable), dann stabil nach device_label.
    sorted_ports = sorted(
        port_findings,
        key=lambda p: (-severity_rank(p.severity), p.device_label),
    )
    # CVE: nach CVSS absteigend (das schwerste oben).
    sorted_cves = sorted(cve_findings, key=lambda c: c.cvss_score, reverse=True)
    # Netz: schwer vor leicht (critical vor notable).
    sorted_nets = sorted(net_findings, key=lambda n: -severity_rank(n.severity))

    return SecurityReport(
        score=score,
        port_findings=sorted_ports,
        cve_findings=sorted_cves,
        net_findings=sorted_nets,
        acknowledged_port_findings=ack_port,
        acknowledged_cve_findings=ack_cve,
        acknowledged_net_findings=ack_net,
        device_labels=device_labels,
    )
