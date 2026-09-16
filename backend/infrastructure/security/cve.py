"""v2-Adapter fuer den Port ``CveLookup`` -- stdlib-reimplementiert (DF2).

Reimplementiert ``modules/cve.py`` verhaltensgleich (SEC.1b-Charakterisierung) mit
stdlib-only (``urllib``), OHNE ``modules``-Import (kein ADR-0007). Die Daten-Tabelle
``PORT_TO_KEYWORDS`` wandert als v2-Konstante mit.

S3-HEILUNGEN (Muster i -- Warn-Log + Ergebnis behalten, Loop ueberlebt):
  * E.2 (Altcode: NVD-Fehler -> {} -> [] still): der Fetch faengt weiterhin, gibt {}
    zurueck, aber LOGGT ``nvd_fetch_failed`` (vorher kein Log). Ergebnis bleibt []
    (Wire unveraendert) -- der Betreiber unterscheidet jetzt "NVD down" von "0 Treffer".
  * E.3 (Altcode: kaputte metrics -> ("UNKNOWN",0.0) still): Parse faengt weiterhin,
    LOGGT ``cve_severity_parse_failed``, Ergebnis bleibt ("UNKNOWN", 0.0).
  * Loop-Schutz: ``lookup_for_host`` iteriert ueber Ports; ein fehlgeschlagener
    Port-Lookup (geloggt) killt die anderen NICHT.

CVE-Frontend-Sichtbarkeit (NVD-down im UI statt nur im Log) ist eine PRODUKT-
Entscheidung, NICHT SEC.4 -- als Naht-Notiz festgehalten (Muster ii / SEC.3-Erweiterung,
falls je gewuenscht).

SEC.3-Abweichung eingehalten: KEIN ``is_public``/``risk_level`` (toter lookup-v2-Pfad
E.6/DF3) -- der Adapter liefert reine ``CveFinding``.
"""

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Sequence
from typing import Any

import structlog

from ports.security import CveFinding, PortQuery

_logger = structlog.get_logger(__name__)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Daten-Tabelle aus modules/cve.py als v2-Konstante (reine Daten, kein I/O).
PORT_TO_KEYWORDS: dict[int, list[str]] = {
    21: ["ftp"],
    22: ["openssh", "ssh"],
    23: ["telnet"],
    25: ["smtp", "postfix", "sendmail"],
    53: ["bind dns", "unbound dns"],
    80: ["apache http", "nginx", "iis"],
    110: ["pop3"],
    111: ["rpcbind"],
    139: ["samba netbios"],
    143: ["imap dovecot"],
    161: ["snmp"],
    389: ["ldap openldap"],
    443: ["apache ssl", "nginx ssl", "openssl"],
    445: ["samba smb", "windows smb"],
    554: ["rtsp"],
    631: ["cups ipp"],
    873: ["rsync"],
    993: ["imaps"],
    995: ["pop3s"],
    1433: ["mssql microsoft sql"],
    1723: ["pptp vpn"],
    2049: ["nfs"],
    3306: ["mysql mariadb"],
    3389: ["rdp remote desktop"],
    5432: ["postgresql"],
    5900: ["vnc"],
    6379: ["redis"],
    8080: ["apache tomcat", "http proxy"],
    8443: ["https tomcat"],
    9200: ["elasticsearch"],
    27017: ["mongodb"],
    32400: ["plex media"],
    5960: ["ndi newtek"],
}

# "interessante" Ports zuerst (Altcode-Prio-Liste).
_PRIORITY_PORTS = [445, 3389, 22, 21, 80, 443, 3306, 5432, 6379, 27017, 9200]
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


def _fetch_cves(keyword: str, results_per_page: int) -> dict[str, Any]:
    """Eine NVD-Abfrage. E.2-Heilung: Fehler werden GELOGGT (vorher still), [] bleibt."""
    params = urllib.parse.urlencode(
        {"keywordSearch": keyword, "resultsPerPage": results_per_page, "startIndex": 0}
    )
    url = f"{NVD_API}?{params}"
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "CERNIS PRO-NetworkScanner/3.0",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data: dict[str, Any] = json.loads(resp.read())
            return data
    except Exception as exc:
        # E.2-Heilung (Muster i): vorher stilles {} -- jetzt geloggt, Ergebnis bleibt {}.
        _logger.warning("nvd_fetch_failed", keyword=keyword, error=str(exc))
        return {}


def _parse_severity(metrics: dict[str, Any]) -> tuple[str, float]:
    """Severity/Score aus den NVD-metrics. E.3-Heilung: Parse-Fehler werden GELOGGT."""
    for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if version in metrics:
            m = metrics[version]
            if isinstance(m, list) and m:
                m = m[0]
            try:
                cvss = m.get("cvssData", m)
                score = float(cvss.get("baseScore", 0))
                sev = str(cvss.get("baseSeverity", m.get("baseSeverity", "UNKNOWN"))).upper()
                return sev, score
            except Exception as exc:
                # E.3-Heilung (Muster i): vorher stilles UNKNOWN -- jetzt geloggt.
                _logger.warning("cve_severity_parse_failed", version=version, error=str(exc))
    return "UNKNOWN", 0.0


def _lookup_for_port(port: int, service: str, max_results: int = 3) -> list[CveFinding]:
    """CVEs fuer EINEN Port (Altcode lookup_cves_for_port, ohne time.sleep-Mock-Bedarf)."""
    keywords = PORT_TO_KEYWORDS.get(port, [])
    if service and len(service) > 3:
        svc_words = service.lower().split()[:2]
        keywords = svc_words + keywords
    if not keywords:
        return []

    keyword = keywords[0]
    time.sleep(0.6)  # NVD-Rate-Limit (5 req/30s ohne API-Key) -- Altcode-treu.

    data = _fetch_cves(keyword, results_per_page=max_results)
    if not data or "vulnerabilities" not in data:
        return []

    findings: list[CveFinding] = []
    for item in data["vulnerabilities"][:max_results]:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")

        descs = cve.get("descriptions", [])
        desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
        if len(desc) > 200:
            desc = desc[:197] + "…"

        severity, score = _parse_severity(cve.get("metrics", {}))
        published = cve.get("published", "")[:10]

        findings.append(
            CveFinding(
                cve_id=cve_id,
                description=desc,
                severity=severity,
                cvss_score=score,
                published=published,
                port=port,
                service=service,
                url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            )
        )
    return findings


class CveLookupAdapter:
    """Erfuellt das ``CveLookup``-Protocol (NVD-HTTP, stdlib)."""

    async def lookup_for_host(self, ports: Sequence[PortQuery]) -> list[CveFinding]:
        import asyncio

        return await asyncio.to_thread(self._lookup_for_host_sync, list(ports))

    def _lookup_for_host_sync(self, ports: list[PortQuery]) -> list[CveFinding]:
        all_cves: list[CveFinding] = []
        checked: set[int] = set()

        sorted_ports = sorted(ports, key=lambda p: (0 if p.port in _PRIORITY_PORTS else 1, p.port))

        for p in sorted_ports[:5]:  # max_ports = 5 (Altcode)
            if p.port in checked:
                continue
            checked.add(p.port)
            # Loop-Schutz (Muster i): per-Item-try IN der Schleife -- ein fehlschlagender
            # Port-Lookup (auch ein unerwarteter Fehler ausserhalb der inneren
            # _fetch_cves-Faenge) killt die ANDEREN Ports NICHT.
            try:
                all_cves.extend(_lookup_for_port(p.port, p.service))
            except Exception as exc:
                _logger.warning("cve_port_lookup_failed", port=p.port, error=str(exc))

        all_cves.sort(key=lambda c: (_SEVERITY_ORDER.get(c.severity, 4), -c.cvss_score))
        return all_cves
