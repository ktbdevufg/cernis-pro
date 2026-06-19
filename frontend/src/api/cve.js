// CVE-Monitoring-API-Client (CERNIS PRO 2.0)
//
// Kleiner reiner Helfer um die CVE-Nähte des Backends (Etappe 2, ADR 0037).
// Stil bewusst wie api/route.js / api/analysis.js: dünner Wrapper über client.js,
// snake_case -> camelCase, KEIN erfundener Fallback (fehlt ein Feld -> null).
//
// Wire-Form (aus backend/api/cve.py, ADR 0037):
//   GET  /api/cve              -> Liste AKTIVER (nicht quittierter) Befunde, je
//        { mac, ip, cve_id, port, service, severity, cvss_score, description,
//          url, published, first_seen_ts, last_seen_ts, is_new }. Leer -> [].
//   GET  /api/cve/host/{mac}   -> aktive Befunde EINES Hosts (gleiche Form).
//   GET  /api/cve/acknowledged -> Liste QUITTIERTER (ausgeblendeter) Befunde
//        (gleiche Form wie GET /api/cve, Etappe 3a). Leer -> [].
//   POST /api/cve/acknowledge  { mac, cve_id, port, action } -> { ok: true }.
//        action ist "ack" | "unack"; ein anderer Wert -> HTTP 422 (kein stiller
//        Durchlauf). "ack" blendet aus, "unack" reaktiviert (CveView nutzt beides).
//   GET  /api/cve/status       -> { hosts_total, hosts_due, hosts_checked,
//          findings_total, findings_active, sleeping }.

import { apiGet, apiPost } from "./client.js";

// Ein roher Befund aus GET /api/cve -> View-Struktur (camelCase). Fehlende Werte
// bleiben null (kein erfundener Wert); cvssScore null = "kein Score bekannt".
function mappeBefund(b) {
  return {
    mac: b.mac ?? null,
    ip: b.ip ?? null,
    cveId: b.cve_id ?? null,
    port: b.port ?? null,
    service: b.service ?? null,
    severity: b.severity ?? null,
    cvssScore: b.cvss_score ?? null,
    description: b.description ?? null,
    url: b.url ?? null,
    published: b.published ?? null,
    firstSeenTs: b.first_seen_ts ?? null,
    lastSeenTs: b.last_seen_ts ?? null,
    isNew: Boolean(b.is_new),
  };
}

// Alle aktiven (nicht quittierten) CVE-Befunde, gerätübergreifend. Fehlt die
// Antwort (null/undefined) -> [], damit der Aufrufer gefahrlos darüber mappen kann.
export async function fetchCveFindings() {
  const backend = await apiGet("/api/cve");
  return (backend ?? []).map(mappeBefund);
}

// Aktive Befunde EINES Hosts (über die MAC). Unbekannte MAC -> [] (Backend liefert
// eine leere Liste, kein Fehler). Aktuell nicht von der View genutzt, aber Teil der
// Naht — bereitgestellt für eine spätere Host-Detail-Einbindung.
export async function fetchCveFindingsForHost(mac) {
  const backend = await apiGet(`/api/cve/host/${encodeURIComponent(mac)}`);
  return (backend ?? []).map(mappeBefund);
}

// Alle quittierten (ausgeblendeten) Befunde, gerätübergreifend (Etappe 3a). Gleiche
// Wire-Form wie /api/cve, daher derselbe Mapper. Fehlt die Antwort -> [].
export async function fetchAcknowledgedCveFindings() {
  const backend = await apiGet("/api/cve/acknowledged");
  return (backend ?? []).map(mappeBefund);
}

// Quittiert ("ack") bzw. reaktiviert ("unack") einen Befund pro (mac, cveId, port).
// Liefert die Wire-Antwort { ok: true } durch — das Frontend mutiert nichts
// optimistisch, sondern lädt die Liste nach dem ack neu. Wirft ApiError bei
// Netz-/HTTP-Fehler; der Aufrufer fängt das und zeigt den Fehlerhinweis.
export async function acknowledgeCve(mac, cveId, port, action) {
  return apiPost("/api/cve/acknowledge", { mac, cve_id: cveId, port, action });
}

// Schlanker Worker-/Prüf-Status. Macht den Hintergrundprozess sichtbar: prüft
// gerade / schläft (sleeping), wie viele Hosts gesamt/fällig/geprüft, wie viele
// Befunde gesamt/aktiv. Fehlende Felder -> null bzw. sleeping -> false (ehrlich:
// "kein Status bekannt" statt "schläft").
export async function fetchCveStatus() {
  const s = await apiGet("/api/cve/status");
  return {
    hostsTotal: s?.hosts_total ?? null,
    hostsDue: s?.hosts_due ?? null,
    hostsChecked: s?.hosts_checked ?? null,
    findingsTotal: s?.findings_total ?? null,
    findingsActive: s?.findings_active ?? null,
    sleeping: Boolean(s?.sleeping),
  };
}

export default {
  fetchCveFindings,
  fetchCveFindingsForHost,
  fetchAcknowledgedCveFindings,
  acknowledgeCve,
  fetchCveStatus,
};
