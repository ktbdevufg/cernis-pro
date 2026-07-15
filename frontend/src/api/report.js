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

// GET /api/report/security/pdf?lang=de|en -> loest den Browser-Download des
// Sicherheitsberichts als PDF in der gewaehlten Sprache aus (Blob via apiDownload).
// lang faellt sicher auf "de" zurueck, wenn nicht "en" (Muster fetchManualPdf). Der
// echte Dateiname kommt vom Backend ueber Content-Disposition
// (CERNISPRO_Netzwerk-Sicherheitsbericht_<datum>.pdf bzw. die englische Entsprechung);
// der defaultName hier ist nur Fallback. Bei !ok/Netzfehler -> ApiError (die View
// faengt das und zeigt einen dezenten PDF-Fehlerhinweis).
export async function fetchSecurityReportPdf(lang) {
  const sprache = lang === "en" ? "en" : "de";
  return apiDownload(
    `/api/report/security/pdf?lang=${sprache}`,
    null,
    sprache === "en"
      ? "CERNISPRO_Network-Security-Report.pdf"
      : "CERNISPRO_Netzwerk-Sicherheitsbericht.pdf",
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

// GET /api/report/inventory/pdf?lang=de|en -> loest den Browser-Download des
// Bestandsberichts als PDF in der gewaehlten Sprache aus (Blob via apiDownload). lang
// faellt sicher auf "de" zurueck, wenn nicht "en" (Muster fetchManualPdf). Der echte
// Dateiname kommt vom Backend ueber Content-Disposition; der defaultName hier ist nur
// Fallback. Bei !ok/Netzfehler -> ApiError (die View faengt das und zeigt einen
// dezenten PDF-Fehlerhinweis).
export async function fetchInventoryReportPdf(lang) {
  const sprache = lang === "en" ? "en" : "de";
  return apiDownload(
    `/api/report/inventory/pdf?lang=${sprache}`,
    null,
    sprache === "en"
      ? "CERNISPRO_Network-Inventory-Report.pdf"
      : "CERNISPRO_Netzwerk-Bestandsbericht.pdf",
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

// GET /api/report/cve/pdf?lang=de|en -> loest den Browser-Download des CVE-Berichts
// als PDF in der gewaehlten Sprache aus (Blob via apiDownload). lang faellt sicher auf
// "de" zurueck, wenn nicht "en" (Muster fetchManualPdf). Der echte Dateiname kommt vom
// Backend ueber Content-Disposition (CERNISPRO_CVE-Bericht_<datum>.pdf bzw. die
// englische Entsprechung); der defaultName hier ist nur Fallback. Bei !ok/Netzfehler
// -> ApiError (die View faengt das und zeigt einen dezenten PDF-Fehlerhinweis).
export async function fetchCveReportPdf(lang) {
  const sprache = lang === "en" ? "en" : "de";
  return apiDownload(
    `/api/report/cve/pdf?lang=${sprache}`,
    null,
    sprache === "en" ? "CERNISPRO_CVE-Report.pdf" : "CERNISPRO_CVE-Bericht.pdf",
  );
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

// GET /api/report/outbound/pdf?recording_id=...&lang=de|en -> loest den Browser-
// Download des Aussenkontakte-Berichts als PDF in der gewaehlten Sprache aus (Blob via
// apiDownload). recordingId leer/null -> ohne recording_id (alle); lang wird IMMER
// angehaengt und faellt sicher auf "de" zurueck, wenn nicht "en" (Muster
// fetchManualPdf). Der echte Dateiname kommt vom Backend ueber Content-Disposition;
// der defaultName hier ist nur Fallback. Bei !ok/Netzfehler -> ApiError (die View
// faengt das und zeigt einen dezenten PDF-Fehlerhinweis).
export async function fetchOutboundReportPdf(recordingId, lang) {
  const sprache = lang === "en" ? "en" : "de";
  const pfad = recordingId
    ? `/api/report/outbound/pdf?recording_id=${encodeURIComponent(recordingId)}&lang=${sprache}`
    : `/api/report/outbound/pdf?lang=${sprache}`;
  return apiDownload(
    pfad,
    null,
    sprache === "en"
      ? "CERNISPRO_Network-External-Contacts-Report.pdf"
      : "CERNISPRO_Netzwerk-Aussenkontakte-Bericht.pdf",
  );
}

// ── DNS-Waechter-Bericht (Etappe 3) ────────────────────────────────────────────
//
// Wire-Form (aus backend/api/report.py DnsWatchReportOut, verifiziert, NICHT
// aendern):
//   GET /api/report/dns-watch -> {
//     host_scope:str ("local_host"),
//     expected_servers:[str], doh_providers:[str],
//     contacts_total:int, active_total:int, acknowledged_total:int,
//     expected_active:int, open_active:int, doh_active:int, flagged_active:int,
//     category_distribution: [ { category:str, count:int } ]  (immer die drei
//       Kategorien "offen"/"moegliche_doh"/"erwartungsgemaess", auch mit count 0),
//     app_distribution: [ { app_name:str, count:int } ],
//     contact_rows: [ { remote_ip, hostname, category, app_name, port:int,
//       connection_count:int, acknowledged:bool } ]
//   }
// hostname/app_name kommen schon fertig (Leerstring statt None) vom Backend;
// category ist der ROHE Kategorie-Schluessel. KEIN Dropdown, KEIN recording_id --
// genau zwei Routen wie beim Bestandsbericht. KEIN 404-Fall: leerer Stand ist ein
// DATUM (alle Zaehler 0 + leere Listen), kein Fehler.

// Ein Kategorie-Verteilungs-Eintrag -> View-Struktur. category roher Schluessel,
// count roh durchgereicht.
function mappeDnsKategorie(e) {
  return {
    category: e.category,
    count: e.count,
  };
}

// Ein Programm-Verteilungs-Eintrag -> View-Struktur. appName roh (Leerstring vom
// Backend als "(ohne)" gefuehrt), count roh durchgereicht.
function mappeDnsProgramm(e) {
  return {
    appName: e.app_name,
    count: e.count,
  };
}

// Eine DNS-relevante Kontakt-Zeile -> View-Struktur (camelCase). Anzeige-Texte
// kommen schon fertig vom Backend (Leerstring statt None); category ist der rohe
// Kategorie-Schluessel, Zaehler roh durchgereicht. Reihenfolge des Backends bleibt.
function mappeDnsKontakt(r) {
  return {
    remoteIp: r.remote_ip,
    hostname: r.hostname,
    category: r.category,
    appName: r.app_name,
    port: r.port,
    connectionCount: r.connection_count,
    acknowledged: r.acknowledged,
  };
}

// GET /api/report/dns-watch -> der aggregierte DNS-Waechter-Bericht (Bezugsrahmen +
// Listen + Kennzahlen + Verteilungen + Kontaktliste). Fehlt ein Block wider Erwarten,
// fallen Zaehler auf 0 und Listen auf [] (gefahrloses Mappen, Muster fetchCveReport).
// Bei !ok/Netzfehler -> ApiError (die View faengt das und zeigt den Fehlerhinweis).
export async function fetchDnsWatchReport() {
  const backend = await apiGet("/api/report/dns-watch");
  return {
    hostScope: backend?.host_scope ?? "local_host",
    expectedServers: backend?.expected_servers ?? [],
    dohProviders: backend?.doh_providers ?? [],
    contactsTotal: backend?.contacts_total ?? 0,
    activeTotal: backend?.active_total ?? 0,
    acknowledgedTotal: backend?.acknowledged_total ?? 0,
    expectedActive: backend?.expected_active ?? 0,
    openActive: backend?.open_active ?? 0,
    dohActive: backend?.doh_active ?? 0,
    flaggedActive: backend?.flagged_active ?? 0,
    categoryDistribution: (backend?.category_distribution ?? []).map(mappeDnsKategorie),
    appDistribution: (backend?.app_distribution ?? []).map(mappeDnsProgramm),
    contactRows: (backend?.contact_rows ?? []).map(mappeDnsKontakt),
  };
}

// GET /api/report/dns-watch/pdf?lang=de|en -> loest den Browser-Download des
// DNS-Waechter-Berichts als PDF in der gewaehlten Sprache aus (Blob via apiDownload).
// lang faellt sicher auf "de" zurueck, wenn nicht "en" (Muster fetchManualPdf). Der
// echte Dateiname kommt vom Backend ueber Content-Disposition; der defaultName hier ist
// nur Fallback. Bei !ok/Netzfehler -> ApiError (die View faengt das und zeigt einen
// dezenten PDF-Fehlerhinweis).
export async function fetchDnsWatchReportPdf(lang) {
  const sprache = lang === "en" ? "en" : "de";
  return apiDownload(
    `/api/report/dns-watch/pdf?lang=${sprache}`,
    null,
    sprache === "en" ? "CERNISPRO_DNS-Watch-Report.pdf" : "CERNISPRO_DNS-Waechter-Bericht.pdf",
  );
}

// ── DNS-Umgehungs-Bericht (netzweit, Etappe 6) ─────────────────────────────────
//
// Zweiter Bezugsrahmen des DNS-Waechter-Berichts: NICHT der host-lokale Bericht oben
// (fetchDnsWatchReport), sondern die NETZWEITE Umgehung — welche Geraete im Netz den
// erwarteten DNS umgehen. Naht wie der Aussenkontakte-Bericht: ein Recordings-Dropdown
// (Bezugsrahmen) plus der recording_id-parametrisierte Bericht + PDF.
//
// Wire-Form (aus backend/api/report.py, verifiziert, NICHT aendern):
//   GET /api/report/dns-bypass/recordings -> [ { id:str, label:str } ]
//   GET /api/report/dns-bypass?recording_id=... -> {
//     recording_label:str, recording_scope:str ("single"/"all"),
//     expected_servers:[str],
//     queries_total:int, bypass_total:int, expected_total:int, bypass_devices:int,
//     resolver_distribution: [ { dst_ip:str, count:int, resolver_name:str } ],
//     bypass_rows: [ { src_ip, device_name, is_self:bool, dst_ip, resolver_name,
//       is_doh:bool, doh_source_name, query_count:int, sample_qnames:[str] } ]
//   }
// ``recording_id`` ist OPTIONAL: leer/None = alle Aufzeichnungen zusammengefasst, ein
// Wert = nur diese. KEIN 404-Fall: leerer Stand ist ein DATUM (alle Zaehler 0 + leere
// Listen), kein Fehler.

// Ein Resolver-Verteilungs-Eintrag (Ziel-IP + Anzahl) -> View-Struktur. Zahlen roh.
function mappeBypassResolver(e) {
  return {
    dstIp: e.dst_ip,
    count: e.count,
    // Best-effort Ziel-Name; leer/fehlt -> null (nur die rohe IP zeigen).
    resolverName: e.resolver_name || null,
  };
}

// Eine Umgeher-Zeile -> View-Struktur (camelCase). Anzeige-Texte kommen schon fertig
// vom Backend (Leerstring statt None); deviceName/dohSourceName ehrlich als null
// belassen, wenn nicht vorhanden (kein erfundener Fallback). sampleQnames faellt
// sicher auf [] (Muster der Outbound-Mapper). Zaehler roh; Reihenfolge des Backends
// bleibt.
function mappeBypassZeile(r) {
  return {
    srcIp: r.src_ip,
    deviceName: r.device_name ?? null,
    // Markiert die Zeile des eigenen Hosts (source=SELF); die View zeigt dann "Dieser
    // Rechner" dezent unter dem Hostnamen. Fehlt/false -> normale Zeile.
    isSelf: Boolean(r.is_self),
    dstIp: r.dst_ip,
    // Best-effort Ziel-Name; leer/fehlt -> null (nur die rohe IP zeigen).
    resolverName: r.resolver_name || null,
    isDoh: Boolean(r.is_doh),
    dohSourceName: r.doh_source_name ?? null,
    queryCount: r.query_count,
    sampleQnames: r.sample_qnames ?? [],
  };
}

// GET /api/report/dns-bypass/recordings -> die waehlbaren Aufzeichnungen fuers
// Bezugsrahmen-Dropdown (schlanke Wire-Form: id + label). Leere Liste = DATUM (noch
// keine Aufzeichnungen), kein Fehler. Bei !ok/Netzfehler -> ApiError (die View faengt
// das still ab und zeigt nur "Alle"). Muster fetchOutboundReportRecordings.
export async function fetchDnsBypassReportRecordings() {
  const backend = await apiGet("/api/report/dns-bypass/recordings");
  return (backend ?? []).map((r) => ({ id: r.id, label: r.label }));
}

// GET /api/report/dns-bypass?recording_id=... -> der aggregierte netzweite DNS-
// Umgehungs-Bericht (EINE Aufzeichnung oder alle). recordingId leer/null -> ohne Query
// (alle). Fehlt ein Block wider Erwarten, fallen Zaehler auf 0 und Listen auf []
// (gefahrloses Mappen, Muster fetchOutboundReport). Bei !ok/Netzfehler -> ApiError (die
// View faengt das und zeigt den Fehlerhinweis).
export async function fetchDnsBypassReport(recordingId) {
  const pfad = recordingId
    ? `/api/report/dns-bypass?recording_id=${encodeURIComponent(recordingId)}`
    : "/api/report/dns-bypass";
  const backend = await apiGet(pfad);
  return {
    recordingLabel: backend?.recording_label ?? "",
    recordingScope: backend?.recording_scope ?? "all",
    expectedServers: backend?.expected_servers ?? [],
    queriesTotal: backend?.queries_total ?? 0,
    bypassTotal: backend?.bypass_total ?? 0,
    expectedTotal: backend?.expected_total ?? 0,
    bypassDevices: backend?.bypass_devices ?? 0,
    resolverDistribution: (backend?.resolver_distribution ?? []).map(mappeBypassResolver),
    bypassRows: (backend?.bypass_rows ?? []).map(mappeBypassZeile),
  };
}

// GET /api/report/dns-bypass/pdf?recording_id=...&lang=de|en -> loest den Browser-
// Download des netzweiten DNS-Umgehungs-Berichts als PDF in der gewaehlten Sprache aus
// (Blob via apiDownload). recordingId leer/null -> ohne recording_id (alle); lang wird
// IMMER angehaengt und faellt sicher auf "de" zurueck, wenn nicht "en" (Muster
// fetchManualPdf). Der echte Dateiname kommt vom Backend ueber Content-Disposition; der
// defaultName hier ist nur Fallback. Bei !ok/Netzfehler -> ApiError (die View faengt das
// und zeigt einen dezenten PDF-Fehlerhinweis).
export async function fetchDnsBypassReportPdf(recordingId, lang) {
  const sprache = lang === "en" ? "en" : "de";
  const pfad = recordingId
    ? `/api/report/dns-bypass/pdf?recording_id=${encodeURIComponent(recordingId)}&lang=${sprache}`
    : `/api/report/dns-bypass/pdf?lang=${sprache}`;
  return apiDownload(
    pfad,
    null,
    sprache === "en"
      ? "CERNISPRO_Network-DNS-Bypass-Report.pdf"
      : "CERNISPRO_DNS-Umgehungs-Bericht.pdf",
  );
}

// ── Verhaltensprofil-Bericht (Etappe 5) ────────────────────────────────────────
//
// Wire-Form (aus backend/api/report.py, verifiziert, NICHT aendern):
//   GET /api/report/behavior/recordings -> [ { id:str, label:str } ]
//     (waehlbare RECURRING-Aufgaben furs Bezugsrahmen-Dropdown)
//   GET /api/report/behavior?task_id=... -> {
//     scope:str ("single"/"all"), report_label:str,
//     entries: [ { label, recorded_days:int, has_enough_data:bool,
//       deviation_count:int, busiest_slot_start:int|null,
//       busiest_weekday:int|null } ],
//     single_profile: null | { recorded_days:int, has_enough_data:bool,
//       deviation_count:int,
//       day_band: [ { slot_start:int, activity_count:int, is_deviation:bool } ],
//       week_heatmap: [ { weekday:int, slot_start:int, activity_count:int,
//         is_deviation:bool } ] },
//     single_label: str|null }
//   GET /api/report/behavior/pdf?task_id=... -> PDF-Download (Blob)
// ``task_id`` ist OPTIONAL: leer/None = alle Geraete zusammengefasst, ein Wert =
// nur diese Aufgabe. KEIN 404-Fall: leerer Stand ist ein DATUM (leere Listen),
// kein Fehler.

// GET /api/report/behavior/recordings -> die waehlbaren wiederkehrenden Aufgaben
// fuers Bezugsrahmen-Dropdown (schlanke Wire-Form: id + label). Leere Liste = DATUM
// (keine Aufgaben mit Verhaltensdaten), kein Fehler. Bei !ok/Netzfehler -> ApiError
// (die View faengt das still ab). Muster fetchDnsBypassReportRecordings.
export async function fetchBehaviorReportTasks() {
  const backend = await apiGet("/api/report/behavior/recordings");
  return (backend ?? []).map((t) => ({ id: t.id, label: t.label }));
}

// GET /api/report/behavior?task_id=... -> der aggregierte Verhaltensprofil-Bericht
// (EINE Aufgabe mit Tagesband/Wochen-Heatmap oder alle Geraete als Uebersicht).
// taskId leer/null -> ohne Query (alle). Fehlt ein Block wider Erwarten, fallen
// Zaehler auf 0 und Listen auf [] (gefahrloses Mappen, Muster fetchDnsBypassReport);
// singleProfile bleibt ehrlich null im all-Bezug. Bei !ok/Netzfehler -> ApiError
// (die View faengt das und zeigt den Fehlerhinweis).
export async function fetchBehaviorReport(taskId) {
  const pfad = taskId
    ? `/api/report/behavior?task_id=${encodeURIComponent(taskId)}`
    : "/api/report/behavior";
  const backend = await apiGet(pfad);
  return {
    scope: backend?.scope ?? "all",
    reportLabel: backend?.report_label ?? "",
    entries: (backend?.entries ?? []).map((e) => ({
      label: e.label,
      recordedDays: e.recorded_days ?? 0,
      hasEnoughData: e.has_enough_data ?? false,
      deviationCount: e.deviation_count ?? 0,
      busiestSlotStart: e.busiest_slot_start ?? null,
      busiestWeekday: e.busiest_weekday ?? null,
    })),
    singleProfile: backend?.single_profile
      ? {
          recordedDays: backend.single_profile.recorded_days ?? 0,
          hasEnoughData: backend.single_profile.has_enough_data ?? false,
          deviationCount: backend.single_profile.deviation_count ?? 0,
          dayBand: (backend.single_profile.day_band ?? []).map((s) => ({
            slotStart: s.slot_start,
            activityCount: s.activity_count,
            isDeviation: s.is_deviation,
          })),
          weekHeatmap: (backend.single_profile.week_heatmap ?? []).map((s) => ({
            weekday: s.weekday,
            slotStart: s.slot_start,
            activityCount: s.activity_count,
            isDeviation: s.is_deviation,
          })),
        }
      : null,
    singleLabel: backend?.single_label ?? null,
  };
}

// GET /api/report/behavior/pdf?task_id=...&lang=de|en -> loest den Browser-Download des
// Verhaltensprofil-Berichts als PDF in der gewaehlten Sprache aus (Blob via
// apiDownload). taskId leer/null -> ohne task_id (alle); lang wird IMMER angehaengt und
// faellt sicher auf "de" zurueck, wenn nicht "en" (Muster fetchManualPdf). Der echte
// Dateiname kommt vom Backend ueber Content-Disposition; der defaultName hier ist nur
// Fallback. Bei !ok/Netzfehler -> ApiError (die View faengt das und zeigt einen dezenten
// PDF-Fehlerhinweis).
export async function fetchBehaviorReportPdf(taskId, lang) {
  const sprache = lang === "en" ? "en" : "de";
  const pfad = taskId
    ? `/api/report/behavior/pdf?task_id=${encodeURIComponent(taskId)}&lang=${sprache}`
    : `/api/report/behavior/pdf?lang=${sprache}`;
  return apiDownload(
    pfad,
    null,
    sprache === "en"
      ? "CERNISPRO_Behavior-Profile-Report.pdf"
      : "CERNISPRO_Verhaltensprofil-Bericht.pdf",
  );
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
  fetchDnsWatchReport,
  fetchDnsWatchReportPdf,
  fetchDnsBypassReportRecordings,
  fetchDnsBypassReport,
  fetchDnsBypassReportPdf,
  fetchBehaviorReportTasks,
  fetchBehaviorReport,
  fetchBehaviorReportPdf,
};
