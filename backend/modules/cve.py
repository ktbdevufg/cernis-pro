"""
CERNIS PRO CVE Lookup
Queries NIST NVD API for CVEs matching open ports and service names.
https://nvd.nist.gov/developers/vulnerabilities
"""
import urllib.request
import json
import time
from dataclasses import dataclass, field, asdict
from functools import lru_cache

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Map common ports/services to CPE search keywords
PORT_TO_KEYWORDS = {
    21:    ["ftp"],
    22:    ["openssh", "ssh"],
    23:    ["telnet"],
    25:    ["smtp", "postfix", "sendmail"],
    53:    ["bind dns", "unbound dns"],
    80:    ["apache http", "nginx", "iis"],
    110:   ["pop3"],
    111:   ["rpcbind"],
    139:   ["samba netbios"],
    143:   ["imap dovecot"],
    161:   ["snmp"],
    389:   ["ldap openldap"],
    443:   ["apache ssl", "nginx ssl", "openssl"],
    445:   ["samba smb", "windows smb"],
    554:   ["rtsp"],
    631:   ["cups ipp"],
    873:   ["rsync"],
    993:   ["imaps"],
    995:   ["pop3s"],
    1433:  ["mssql microsoft sql"],
    1723:  ["pptp vpn"],
    2049:  ["nfs"],
    3306:  ["mysql mariadb"],
    3389:  ["rdp remote desktop"],
    5432:  ["postgresql"],
    5900:  ["vnc"],
    6379:  ["redis"],
    8080:  ["apache tomcat", "http proxy"],
    8443:  ["https tomcat"],
    9200:  ["elasticsearch"],
    27017: ["mongodb"],
    32400: ["plex media"],
    5960:  ["ndi newtek"],
}


@dataclass
class CVEEntry:
    cve_id: str
    description: str
    severity: str        # CRITICAL / HIGH / MEDIUM / LOW
    cvss_score: float
    published: str
    port: int = 0
    service: str = ""
    url: str = ""

    def to_dict(self):
        return asdict(self)


def _fetch_cves(keyword: str, results_per_page: int = 5) -> list[dict]:
    """Query NVD API for CVEs matching keyword."""
    params = urllib.parse.urlencode({  # type: ignore
        "keywordSearch": keyword,
        "resultsPerPage": results_per_page,
        "startIndex": 0,
    })
    url = f"{NVD_API}?{params}"
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "CERNIS PRO-NetworkScanner/3.0",
            "Accept": "application/json",
        })
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except Exception:
        return {}


def _parse_severity(metrics: dict) -> tuple[str, float]:
    """Extract severity and CVSS score from metrics."""
    for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if version in metrics:
            m = metrics[version]
            if isinstance(m, list) and m:
                m = m[0]
            try:
                score = float(m.get("cvssData", m).get("baseScore", 0))
                sev   = m.get("cvssData", m).get("baseSeverity",
                        m.get("baseSeverity", "UNKNOWN")).upper()
                return sev, score
            except Exception:
                pass
    return "UNKNOWN", 0.0


def lookup_cves_for_port(port: int, service: str = "", max_results: int = 3) -> list[CVEEntry]:
    """Return CVEs for a given port/service. Rate-limited."""
    keywords = PORT_TO_KEYWORDS.get(port, [])

    # Also use service name from scan
    if service and len(service) > 3:
        svc_words = service.lower().split()[:2]
        keywords = svc_words + keywords

    if not keywords:
        return []

    keyword = keywords[0]
    time.sleep(0.6)  # NVD rate limit: 5 req/30s without API key

    data = _fetch_cves(keyword, results_per_page=max_results)
    if not data or "vulnerabilities" not in data:
        return []

    results = []
    for item in data["vulnerabilities"][:max_results]:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")

        # Description
        descs = cve.get("descriptions", [])
        desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
        if len(desc) > 200:
            desc = desc[:197] + "…"

        # Severity
        metrics = cve.get("metrics", {})
        severity, score = _parse_severity(metrics)

        published = cve.get("published", "")[:10]

        results.append(CVEEntry(
            cve_id=cve_id,
            description=desc,
            severity=severity,
            cvss_score=score,
            published=published,
            port=port,
            service=service,
            url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        ))

    return results


def lookup_cves_for_host(ports: list[dict], max_ports: int = 5) -> list[CVEEntry]:
    """Look up CVEs for all open ports of a host. Limits to avoid hammering NVD."""
    all_cves = []
    checked = set()

    # Prioritize interesting ports
    priority = [445, 3389, 22, 21, 80, 443, 3306, 5432, 6379, 27017, 9200]
    sorted_ports = sorted(ports, key=lambda p: (
        0 if p["port"] in priority else 1, p["port"]
    ))

    for p in sorted_ports[:max_ports]:
        port = p["port"]
        if port in checked:
            continue
        checked.add(port)
        cves = lookup_cves_for_port(port, p.get("service", ""))
        all_cves.extend(cves)

    # Sort by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    all_cves.sort(key=lambda c: (sev_order.get(c.severity, 4), -c.cvss_score))
    return all_cves


import urllib.parse  # noqa: E402 - needed for _fetch_cves
