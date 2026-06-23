// Sicherheitsbericht-API-Client (CERNIS PRO 2.0, Etappe 3)
//
// Duenner reiner Wrapper ueber client.js fuer den aggregierten Sicherheitsbericht
// (GET /api/report/security). Stil bewusst wie api/cve.js / api/dnsWatch.js /
// api/monitoring.js: kleine reine Mapper, snake_case -> camelCase, KEIN erfundener
// Fallback (null bleibt ehrlich null). Pfad bleibt relativ; NIE einen Host
// hartkodieren.
//
// Wire-Form (aus backend/api/report.py, verifiziert, NICHT aendern):
//   GET /api/report/security -> {
//     score: { score:int, level:str ("gut"/"maessig"/"kritisch"),
//       device_count:int, total_burden:float, critical_devices:int,
//       notable_devices:int, clean_devices:int,
//       contributions: [ { device_label, worst_severity ("critical"/"notable"),
//         burden_value:float } ] },
//     port_findings: [ { device_label, ports:str, severity ("critical"/"notable"),
//       reason } ],
//     cve_findings: [ { device_label, cve_id, cvss_score:float, severity:str,
//       service } ],
//     net_findings: [ { kind, device_label, description,
//       severity ("critical"/"notable") } ],
//     acknowledged_port_findings / acknowledged_cve_findings /
//       acknowledged_net_findings -> gleiche Formen wie oben,
//     device_count:int, has_scan:bool, rogue_dhcp_checked_ts: float|null
//   }
// KEIN 404-Fall: liegt kein Scan vor, ist das ein DATUM (has_scan false + leere
// Listen + Score 100), kein Fehler.

import { apiGet } from "./client.js";

// Ein Score-Beitrag (belastetes Geraet) -> View-Struktur. burdenValue bleibt der
// rohe Lastwert (die View formatiert mit zwei Nachkommastellen selbst).
function mappeBeitrag(c) {
  return {
    deviceLabel: c.device_label,
    worstSeverity: c.worst_severity,
    burdenValue: c.burden_value,
  };
}

// Der Score-Block -> View-Struktur. Alle Zahlen roh durchgereicht; level traegt
// das Backend-Vokabular ("gut"/"maessig"/"kritisch") unveraendert.
function mappeScore(s) {
  return {
    score: s.score,
    level: s.level,
    deviceCount: s.device_count,
    totalBurden: s.total_burden,
    criticalDevices: s.critical_devices,
    notableDevices: s.notable_devices,
    cleanDevices: s.clean_devices,
    contributions: (s.contributions ?? []).map(mappeBeitrag),
  };
}

// Ein Port-Befund -> View-Struktur (camelCase). Reihenfolge des Backends bleibt.
function mappePortBefund(p) {
  return {
    deviceLabel: p.device_label,
    ports: p.ports,
    severity: p.severity,
    reason: p.reason,
  };
}

// Ein CVE-Befund -> View-Struktur. cvssScore roh (die View badge-formatiert).
function mappeCveBefund(c) {
  return {
    deviceLabel: c.device_label,
    cveId: c.cve_id,
    cvssScore: c.cvss_score,
    severity: c.severity,
    service: c.service,
  };
}

// Ein netzweiter Befund -> View-Struktur. kind/description durchgereicht.
function mappeNetBefund(n) {
  return {
    kind: n.kind,
    deviceLabel: n.device_label,
    description: n.description,
    severity: n.severity,
  };
}

// GET /api/report/security -> der aggregierte Sicherheitsbericht (Score + offene/
// quittierte Befunde + ehrliche Statusfelder). rogueDhcpCheckedTs bleibt ehrlich
// null (noch nie geprueft); die drei Finding-Listen und die drei acknowledged*-
// Listen werden ueber denselben jeweiligen Mapper gefuehrt. Fehlt ein Block
// wider Erwarten, fallen die Listen auf [] (gefahrloses Mappen). Bei !ok/Netzfehler
// -> ApiError (die View faengt das und zeigt den Fehlerhinweis).
export async function fetchSecurityReport() {
  const backend = await apiGet("/api/report/security");
  return {
    score: mappeScore(backend?.score ?? {}),
    portFindings: (backend?.port_findings ?? []).map(mappePortBefund),
    cveFindings: (backend?.cve_findings ?? []).map(mappeCveBefund),
    netFindings: (backend?.net_findings ?? []).map(mappeNetBefund),
    acknowledgedPortFindings: (backend?.acknowledged_port_findings ?? []).map(mappePortBefund),
    acknowledgedCveFindings: (backend?.acknowledged_cve_findings ?? []).map(mappeCveBefund),
    acknowledgedNetFindings: (backend?.acknowledged_net_findings ?? []).map(mappeNetBefund),
    deviceCount: backend?.device_count ?? 0,
    hasScan: Boolean(backend?.has_scan),
    rogueDhcpCheckedTs: backend?.rogue_dhcp_checked_ts ?? null,
  };
}

export default {
  fetchSecurityReport,
};
