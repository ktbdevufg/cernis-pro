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
//       service, description } ],
//     net_findings: [ { kind, device_label, description,
//       severity ("critical"/"notable") } ],
//     acknowledged_port_findings / acknowledged_cve_findings /
//       acknowledged_net_findings -> gleiche Formen wie oben,
//     device_count:int, has_scan:bool, rogue_dhcp_checked_ts: float|null
//   }
// KEIN 404-Fall: liegt kein Scan vor, ist das ein DATUM (has_scan false + leere
// Listen + Score 100), kein Fehler.

import { apiDownload, apiGet } from "./client.js";

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
    description: c.description ?? "",
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

// GET /api/report/security/pdf -> loest den Browser-Download des Sicherheitsberichts
// als PDF aus (Blob via apiDownload). Der echte Dateiname kommt vom Backend ueber
// Content-Disposition (CERNISPRO_Netzwerk-Sicherheitsbericht_<datum>.pdf); der
// defaultName hier ist nur Fallback. Bei !ok/Netzfehler -> ApiError (die View faengt
// das und zeigt einen dezenten PDF-Fehlerhinweis).
export async function fetchSecurityReportPdf() {
  return apiDownload(
    "/api/report/security/pdf",
    null,
    "CERNISPRO_Netzwerk-Sicherheitsbericht.pdf",
  );
}

// ── Bestandsbericht (Etappe 3) ─────────────────────────────────────────────────
//
// Wire-Form (aus backend/api/report.py InventoryReportOut, verifiziert, NICHT
// aendern):
//   GET /api/report/inventory -> {
//     total:int, known:int, unknown:int, active_24h:int,
//     trusted:int, watch:int, neutral:int,
//     vendor_distribution: [ { label:str, count:int } ],
//     category_distribution: [ { label:str, count:int } ],
//     device_rows: [ { device_label, vendor, last_ip, first_seen_text,
//       last_seen_text, last_seen_ts:float, times_seen:int, category,
//       is_known:bool, trust_state ("neutral"/"trusted"/"watch"),
//       source ("scan"/"manual"), archived:bool } ],
//     archived_rows: [ gleiche Form wie device_rows ]
//   }
// KEIN 404-Fall: leerer Bestand = alle Zaehler 0 + leere Listen (kein Fehler).

// Ein Verteilungs-Eintrag (Hersteller/Kategorie) -> View-Struktur. Zahlen roh.
function mappeVerteilung(e) {
  return {
    label: e.label,
    count: e.count,
  };
}

// Eine Geraete-Zeile -> View-Struktur (camelCase). Zeitstempel/Zaehler roh
// durchgereicht; die View formatiert selbst. Reihenfolge des Backends bleibt.
function mappeGeraeteZeile(r) {
  return {
    deviceLabel: r.device_label,
    vendor: r.vendor,
    lastIp: r.last_ip,
    firstSeenText: r.first_seen_text,
    lastSeenText: r.last_seen_text,
    lastSeenTs: r.last_seen_ts,
    timesSeen: r.times_seen,
    category: r.category,
    isKnown: r.is_known,
    trustState: r.trust_state,
    source: r.source,
    archived: r.archived,
  };
}

// GET /api/report/inventory -> der aggregierte Bestandsbericht (Zaehler +
// Verteilungen + aktive/archivierte Geraete-Zeilen). Fehlt ein Block wider
// Erwarten, fallen Zaehler auf 0 und Listen auf [] (gefahrloses Mappen, Muster
// fetchSecurityReport). Bei !ok/Netzfehler -> ApiError (die View faengt das und
// zeigt den Fehlerhinweis).
export async function fetchInventoryReport() {
  const backend = await apiGet("/api/report/inventory");
  return {
    total: backend?.total ?? 0,
    known: backend?.known ?? 0,
    unknown: backend?.unknown ?? 0,
    active24h: backend?.active_24h ?? 0,
    trusted: backend?.trusted ?? 0,
    watch: backend?.watch ?? 0,
    neutral: backend?.neutral ?? 0,
    vendorDistribution: (backend?.vendor_distribution ?? []).map(mappeVerteilung),
    categoryDistribution: (backend?.category_distribution ?? []).map(mappeVerteilung),
    deviceRows: (backend?.device_rows ?? []).map(mappeGeraeteZeile),
    archivedRows: (backend?.archived_rows ?? []).map(mappeGeraeteZeile),
  };
}

// GET /api/report/inventory/pdf -> loest den Browser-Download des Bestandsberichts
// als PDF aus (Blob via apiDownload). Der echte Dateiname kommt vom Backend ueber
// Content-Disposition; der defaultName hier ist nur Fallback. Bei !ok/Netzfehler
// -> ApiError (die View faengt das und zeigt einen dezenten PDF-Fehlerhinweis).
export async function fetchInventoryReportPdf() {
  return apiDownload(
    "/api/report/inventory/pdf",
    null,
    "CERNISPRO_Netzwerk-Bestandsbericht.pdf",
  );
}

// GET /api/report/manual/pdf?lang=de|en -> loest den Browser-Download des
// Benutzerhandbuchs als PDF in der gewaehlten Sprache aus (Blob via apiDownload).
// lang faellt sicher auf "de" zurueck, wenn nicht "en". Der echte Dateiname kommt
// vom Backend ueber Content-Disposition; der defaultName hier ist nur Fallback.
// Bei !ok/Netzfehler -> ApiError (die View faengt das und zeigt einen dezenten
// PDF-Fehlerhinweis).
export async function fetchManualPdf(lang) {
  const sprache = lang === "en" ? "en" : "de";
  return apiDownload(
    `/api/report/manual/pdf?lang=${sprache}`,
    null,
    sprache === "en" ? "CERNISPRO_User-Manual.pdf" : "CERNISPRO_Benutzerhandbuch.pdf",
  );
}

// ── CVE-Bericht (Etappe 3) ─────────────────────────────────────────────────────
//
// Wire-Form (aus backend/api/report.py CveReportOut, verifiziert, NICHT aendern):
//   GET /api/report/cve -> {
//     generated_findings_total:int, active_total:int, acknowledged_total:int,
//     new_total:int, affected_devices:int, hosts_total:int, hosts_checked:int,
//     coverage_text:str, highest_severity:str, oldest_published:str,
//     severity_counts: [ { severity:str, count:int } ]  (immer 5 Stufen),
//     device_rows: [ { device_label, mac, finding_count:int, highest_severity,
//       highest_cvss:float, services } ],
//     service_rows: [ { service, finding_count:int, device_count:int,
//       highest_severity, highest_cvss:float, oldest_published } ],
//     all_rows: [ { device_label, mac, cve_id, severity, cvss_score:float,
//       service, port:int, first_seen_text, first_seen_ts:float, published,
//       acknowledged:bool, is_new:bool } ]
//   }
// ACHTUNG: CveFindingRowOut traegt KEIN ip-Feld (per grep verifiziert) -> es gibt
// im JSON kein ip; der Mapper setzt ip auf "" (das device_label traegt die IP, wenn
// kein Name vorhanden ist). KEIN 404-Fall: leerer Stand ist ein DATUM (Zaehler 0 +
// leere Listen), kein Fehler.

// Eine Severity-Verteilungs-Zahl -> View-Struktur. Stufe + Anzahl roh.
function mappeSeverityCount(c) {
  return {
    severity: c.severity,
    count: c.count,
  };
}

// Eine Geraete-Zeile (Sektion 2) -> View-Struktur (camelCase). highestCvss roh
// (die View formatiert mit einer Nachkommastelle). Reihenfolge des Backends bleibt.
function mappeCveGeraet(r) {
  return {
    deviceLabel: r.device_label,
    mac: r.mac,
    findingCount: r.finding_count,
    highestSeverity: r.highest_severity,
    highestCvss: r.highest_cvss,
    services: r.services,
  };
}

// Eine Dienst-Zeile (Sektion 3) -> View-Struktur. oldestPublished roher NVD-String
// (die View formatiert lokal). Reihenfolge des Backends bleibt.
function mappeCveDienst(r) {
  return {
    service: r.service,
    findingCount: r.finding_count,
    deviceCount: r.device_count,
    highestSeverity: r.highest_severity,
    highestCvss: r.highest_cvss,
    oldestPublished: r.oldest_published,
  };
}

// Eine vollstaendige Befund-Zeile (Sektion 4) -> View-Struktur. ip fehlt in der
// Wire-Form (CveFindingRowOut hat kein ip-Feld) -> sicher auf "" gemappt;
// firstSeenText kommt schon fertig formatiert vom Backend. (Eigener Name, da der
// Sicherheitsbericht oben bereits einen mappeCveBefund fuehrt.)
function mappeCveBefundZeile(r) {
  return {
    deviceLabel: r.device_label,
    mac: r.mac,
    ip: r.ip ?? "",
    cveId: r.cve_id,
    severity: r.severity,
    cvssScore: r.cvss_score,
    service: r.service,
    port: r.port,
    firstSeenText: r.first_seen_text,
    firstSeenTs: r.first_seen_ts,
    published: r.published,
    acknowledged: r.acknowledged,
    isNew: r.is_new,
  };
}

// GET /api/report/cve -> der aggregierte CVE-Bericht (Kennzahlen + Severity-
// Verteilung + Geraete-/Dienst-Sektion + vollstaendige Befundliste). Fehlt ein
// Block wider Erwarten, fallen Zaehler auf 0 und Listen auf [] (gefahrloses Mappen,
// Muster fetchInventoryReport). Bei !ok/Netzfehler -> ApiError (die View faengt das
// und zeigt den Fehlerhinweis).
export async function fetchCveReport() {
  const backend = await apiGet("/api/report/cve");
  return {
    generatedFindingsTotal: backend?.generated_findings_total ?? 0,
    activeTotal: backend?.active_total ?? 0,
    acknowledgedTotal: backend?.acknowledged_total ?? 0,
    newTotal: backend?.new_total ?? 0,
    affectedDevices: backend?.affected_devices ?? 0,
    hostsTotal: backend?.hosts_total ?? 0,
    hostsChecked: backend?.hosts_checked ?? 0,
    coverageText: backend?.coverage_text ?? "",
    highestSeverity: backend?.highest_severity ?? "UNKNOWN",
    oldestPublished: backend?.oldest_published ?? "",
    severityCounts: (backend?.severity_counts ?? []).map(mappeSeverityCount),
    deviceRows: (backend?.device_rows ?? []).map(mappeCveGeraet),
    serviceRows: (backend?.service_rows ?? []).map(mappeCveDienst),
    allRows: (backend?.all_rows ?? []).map(mappeCveBefundZeile),
  };
}

// GET /api/report/cve/pdf -> loest den Browser-Download des CVE-Berichts als PDF
// aus (Blob via apiDownload). Der echte Dateiname kommt vom Backend ueber
// Content-Disposition (CERNISPRO_CVE-Bericht_<datum>.pdf); der defaultName hier ist
// nur Fallback. Bei !ok/Netzfehler -> ApiError (die View faengt das und zeigt einen
// dezenten PDF-Fehlerhinweis).
export async function fetchCveReportPdf() {
  return apiDownload("/api/report/cve/pdf", null, "CERNISPRO_CVE-Bericht.pdf");
}

// ── Aussenkontakte-Bericht (Etappe 3) ──────────────────────────────────────────
//
// Wire-Form (aus backend/api/report.py OutboundReportOut, verifiziert, NICHT
// aendern):
//   GET /api/report/outbound/recordings -> [ { id:str, label:str } ]
//   GET /api/report/outbound?recording_id=... -> {
//     recording_label:str, recording_scope:str ("single"/"all"),
//     contacts_total:int, remote_total:int, local_total:int,
//     connection_total:int, countries_total:int, operators_total:int,
//     tracker_contacts:int, threat_contacts:int, flagged_contacts:int,
//     country_distribution: [ { country:str, count:int } ],
//     operator_distribution: [ { operator:str, count:int } ],
//     contact_rows: [ { remote_ip, hostname, country, operator, asn, app_name,
//       first_seen_text, last_seen_text, first_seen_ts:float, last_seen_ts:float,
//       total_count:int, peak_count:int, is_local:bool, tracker_lists:[str],
//       threat_lists:[str] } ]
//   }
// ``recording_id`` ist OPTIONAL: leer/None = alle Aufzeichnungen zusammengefasst,
// ein Wert = nur diese. KEIN 404-Fall: leerer Stand ist ein DATUM (alle Zaehler 0 +
// leere Listen), kein Fehler.

// Ein Land-Verteilungs-Eintrag -> View-Struktur. Zahlen roh durchgereicht.
function mappeOutboundLand(e) {
  return {
    country: e.country,
    count: e.count,
  };
}

// Ein Betreiber-Verteilungs-Eintrag -> View-Struktur. Zahlen roh durchgereicht.
function mappeOutboundBetreiber(e) {
  return {
    operator: e.operator,
    count: e.count,
  };
}

// Eine Aussenkontakt-Zeile -> View-Struktur (camelCase). Anzeige-Texte kommen schon
// fertig vom Backend (Leerstring statt None); Zeitstempel/Zaehler roh durchgereicht.
// tracker_lists/threat_lists fallen sicher auf [] (Muster der CVE-Mapper).
function mappeOutboundKontakt(r) {
  return {
    remoteIp: r.remote_ip,
    hostname: r.hostname,
    country: r.country,
    operator: r.operator,
    asn: r.asn,
    appName: r.app_name,
    firstSeenText: r.first_seen_text,
    lastSeenText: r.last_seen_text,
    firstSeenTs: r.first_seen_ts,
    lastSeenTs: r.last_seen_ts,
    totalCount: r.total_count,
    peakCount: r.peak_count,
    isLocal: r.is_local,
    trackerLists: r.tracker_lists ?? [],
    threatLists: r.threat_lists ?? [],
  };
}

// GET /api/report/outbound/recordings -> die waehlbaren Aufzeichnungen fuers
// Bezugsrahmen-Dropdown (schlanke Wire-Form: id + label). Leere Liste = DATUM (noch
// keine Aufzeichnungen), kein Fehler. Bei !ok/Netzfehler -> ApiError (die View faengt
// das still ab und zeigt nur "Alle").
export async function fetchOutboundReportRecordings() {
  const backend = await apiGet("/api/report/outbound/recordings");
  return (backend ?? []).map((r) => ({ id: r.id, label: r.label }));
}

// GET /api/report/outbound?recording_id=... -> der aggregierte Aussenkontakte-
// Bericht (EINE Aufzeichnung oder alle). recordingId leer/null -> ohne Query (alle).
// Fehlt ein Block wider Erwarten, fallen Zaehler auf 0 und Listen auf [] (gefahrloses
// Mappen, Muster fetchCveReport). Bei !ok/Netzfehler -> ApiError (die View faengt das
// und zeigt den Fehlerhinweis).
export async function fetchOutboundReport(recordingId) {
  const pfad = recordingId
    ? `/api/report/outbound?recording_id=${encodeURIComponent(recordingId)}`
    : "/api/report/outbound";
  const backend = await apiGet(pfad);
  return {
    recordingLabel: backend?.recording_label ?? "",
    recordingScope: backend?.recording_scope ?? "all",
    contactsTotal: backend?.contacts_total ?? 0,
    remoteTotal: backend?.remote_total ?? 0,
    localTotal: backend?.local_total ?? 0,
    connectionTotal: backend?.connection_total ?? 0,
    countriesTotal: backend?.countries_total ?? 0,
    operatorsTotal: backend?.operators_total ?? 0,
    trackerContacts: backend?.tracker_contacts ?? 0,
    threatContacts: backend?.threat_contacts ?? 0,
    flaggedContacts: backend?.flagged_contacts ?? 0,
    countryDistribution: (backend?.country_distribution ?? []).map(mappeOutboundLand),
    operatorDistribution: (backend?.operator_distribution ?? []).map(mappeOutboundBetreiber),
    contactRows: (backend?.contact_rows ?? []).map(mappeOutboundKontakt),
  };
}

// GET /api/report/outbound/pdf?recording_id=... -> loest den Browser-Download des
// Aussenkontakte-Berichts als PDF aus (Blob via apiDownload). recordingId leer/null
// -> ohne Query (alle). Der echte Dateiname kommt vom Backend ueber Content-
// Disposition; der defaultName hier ist nur Fallback. Bei !ok/Netzfehler -> ApiError
// (die View faengt das und zeigt einen dezenten PDF-Fehlerhinweis).
export async function fetchOutboundReportPdf(recordingId) {
  const pfad = recordingId
    ? `/api/report/outbound/pdf?recording_id=${encodeURIComponent(recordingId)}`
    : "/api/report/outbound/pdf";
  return apiDownload(pfad, null, "CERNISPRO_Netzwerk-Aussenkontakte-Bericht.pdf");
}

export default {
  fetchSecurityReport,
  fetchSecurityReportPdf,
  fetchInventoryReport,
  fetchInventoryReportPdf,
  fetchCveReport,
  fetchCveReportPdf,
  fetchManualPdf,
  fetchOutboundReportRecordings,
  fetchOutboundReport,
  fetchOutboundReportPdf,
};
