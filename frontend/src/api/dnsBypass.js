// Netzweiter DNS-Umgehungs-Waechter: Mapper + REST-Aufrufe (CERNIS PRO 2.0, E5)
//
// Lese-/Steuerpfade der NETZWEITEN DNS-Umgehungs-Sicht (Reiter 2 des DNS-
// Waechters). Uebersetzt die Backend-Antworten (snake_case, aus
// backend/api/dns_bypass.py, Etappe 4b) in die camelCase-View-Struktur. Stil
// bewusst wie api/dnsWatch.js und api/outboundLog.js: kleine reine Mapper,
// null = ehrlich nicht vorhanden (KEIN erfundener Fallback), Fehler ueber
// ApiError. Pfade bleiben relativ; NIE einen Host hartkodieren.
//
// Wire-Form (verifiziert, aus backend/api/dns_bypass.py, NICHT aendern),
// Prefix /api/dns-bypass:
//   GET  ""        -> { findings:[ {src_ip,device_name,dst_ip,is_doh,
//                        doh_source_name,query_count,sample_qnames[]} ],
//                        expected_servers[], queries_total, bypass_total,
//                        expected_total, bypass_devices, recording }
//   GET  "/status" -> { recording, collected_queries, permission_error }
//   POST "/start" Body {interface?} -> {ok:true} | {ok:false, error:<text>}
//   POST "/stop"   -> {ok:true}
//
// Der Start-Helfer kann legitim scheitern (z. B. keine Rechte): das Backend
// reicht den Fehlertext als {ok:false, error} mit HTTP 200 durch (S3, kein
// stiller Fallback) -- startDnsBypass gibt genau dieses Objekt weiter, die View
// zeigt den Text ruhig an.
//
// KEINE Quittier-/Ack-Route: die 4b-Routen kennen keine Quittierung; hier wird
// daher bewusst KEINE gebaut (nur sichtbar machen, nicht markieren).

import { apiGet, apiPost } from "./client.js";

// Basis-Pfad der netzweiten Umgehungs-Ressource (relativ; Vite-Proxy leitet ans
// Backend).
const BASIS = "/api/dns-bypass";

// Ein Umgehungs-Befund-Wire-dict (snake_case) -> View-Objekt (camelCase). Je
// (srcIp, dstIp)-Gruppe eine Zeile. deviceName/dohSourceName bleiben ehrlich
// null, wenn sie fehlen (?? null) -- kein erfundener Name. isDoh ist eine
// heuristische Ziel-Bewertung (neutral, nicht gesichert). sampleQnames faellt
// auf [] zurueck, falls das Feld fehlt.
export function mappeBefund(f) {
  return {
    srcIp: f.src_ip,
    deviceName: f.device_name ?? null,
    // Ob die Quell-IP der eigene Host ist (Geraet mit source=self) -- treibt das
    // "eigener Host"-Badge in der Zeile. Fehlt das Feld -> false (ehrlich).
    isSelf: Boolean(f.is_self),
    dstIp: f.dst_ip,
    // Best-effort Ziel-Resolver-Name (Bestand > bekannte Resolver > PTR); fehlt er,
    // bleibt es bei der rohen IP (?? null -- kein erfundener Name).
    resolverName: f.resolver_name ?? null,
    isDoh: Boolean(f.is_doh),
    dohSourceName: f.doh_source_name ?? null,
    queryCount: f.query_count,
    sampleQnames: f.sample_qnames ?? [],
  };
}

// GET "" -> die verdichtete netzweite Umgehungs-Sicht. Uebersetzt findings in
// die View-Form und reicht Zaehler/expectedServers/recording durch. Leere/
// fehlende Felder fallen ehrlich auf 0/[]/false zurueck (kein erfundener Wert).
// recording sagt ehrlich, ob gerade mitgelesen wird -- ein Leerbefund bei
// recording=false bedeutet: es wird NICHT mitgelesen, nicht "alles sauber".
export async function fetchDnsBypass() {
  const backend = await apiGet(BASIS);
  return {
    findings: (backend.findings ?? []).map(mappeBefund),
    expectedServers: backend.expected_servers ?? [],
    queriesTotal: backend.queries_total ?? 0,
    bypassTotal: backend.bypass_total ?? 0,
    expectedTotal: backend.expected_total ?? 0,
    bypassDevices: backend.bypass_devices ?? 0,
    recording: Boolean(backend.recording),
  };
}

// GET "/status" -> billiger Status-Poll (laeuft die Aufzeichnung? wie viele
// Anfragen sind gesammelt? traegt die Plattform die Erfassung?), ohne die teure
// Verdichtung. collectedQueries faellt auf 0 zurueck, falls das Feld fehlt.
//
// permissionError traegt denselben stabilen Marker wie der SNI-Status: liegt er
// an, ist die Erfassung auf dieser Plattform gar nicht moeglich und die Ansicht
// graut sie aus, statt den Anwender starten zu lassen. Fehlt das Feld oder ist
// es leer -> null (ehrlich "kein Hindernis bekannt", nicht "" als Marker).
export async function fetchDnsBypassStatus() {
  const backend = await apiGet(`${BASIS}/status`);
  return {
    recording: Boolean(backend.recording),
    collectedQueries: backend.collected_queries ?? 0,
    permissionError: backend.permission_error || null,
  };
}

// POST "/start" -> startet die Aufzeichnung ON-DEMAND. interface ist optional
// (null -> das Backend waehlt sein Default-Interface). Das Backend reicht einen
// legitimen Start-Fehler als {ok:false, error:<text>} mit HTTP 200 durch (S3,
// kein 500) -- dieses Objekt wird UNVERAENDERT weitergegeben, damit die View
// zwischen Erfolg ({ok:true}) und ehrlichem Fehlertext unterscheiden kann.
export async function startDnsBypass(iface = null) {
  const body = {};
  if (iface !== null && iface !== undefined) {
    body.interface = iface;
  }
  return apiPost(`${BASIS}/start`, body);
}

// POST "/stop" -> stoppt die Aufzeichnung (idempotent/best-effort). {ok:true}.
export async function stopDnsBypass() {
  return apiPost(`${BASIS}/stop`, {});
}

export default {
  mappeBefund,
  fetchDnsBypass,
  fetchDnsBypassStatus,
  startDnsBypass,
  stopDnsBypass,
};
