// Fritz-Detail-API-Client (CERNIS PRO 2.0)
//
// Kleine reine Helfer um GET /api/fritz/detail. Stil bewusst wie
// api/interfaces.js / api/devices.js: dünne Wrapper über client.js, snake->camel,
// kein erfundener Fallback (fehlt ein Feld -> leer/null/0/false/[]).
//
// Wire-Form (aus backend/api/fritz.py), snake_case:
//   { reachable, host, auth_error,
//     device: {model, firmware, is_fiber, total_hosts},
//     wan: {connected, uptime_secs, ip_external, ip_external_v6,
//           upstream_kbps, downstream_kbps, bytes_sent, bytes_recv},
//     dsl: {sync, downstream_kbps, upstream_kbps, snr_downstream, snr_upstream,
//           attn_downstream, attn_upstream},
//     wlan_24: {enabled, ssid, channel, clients},
//     wlan_5:  {enabled, ssid, channel, clients},
//     wlan_clients: [{mac, ip, hostname, signal_dbm, speed_mbps, band}],
//     log: [{id, timestamp, message}],
//     port_forwardings: [{enabled, description, protocol, external_port,
//                         internal_ip, internal_port}] }
//
// Der Endpunkt liefert 200 mit vollem Snapshot ODER 200 mit {reachable:false}
// ODER 502 bei Auth-Fehler. Der 502-Fall wird hier NICHT geworfen, sondern in
// ein Leer-Detail mit authError-Flag übersetzt (die UI zeigt dann die
// Auth-Hinweis-Maske). Andere Fehler (Netz/500) fliegen weiter.

import { apiGet, ApiError } from "./client.js";

// Ein Wire-Gerät -> View-Gerät. Fehlende Felder -> sinnvolle Leerwerte.
function mappeDevice(device) {
  const d = device ?? {};
  return {
    model: d.model ?? "",
    firmware: d.firmware ?? "",
    isFiber: d.is_fiber === true,
    totalHosts: d.total_hosts ?? 0,
  };
}

function mappeWan(wan) {
  const w = wan ?? {};
  return {
    connected: w.connected === true,
    uptimeSecs: w.uptime_secs ?? 0,
    ipExternal: w.ip_external ?? "",
    ipExternalV6: w.ip_external_v6 ?? "",
    upstreamKbps: w.upstream_kbps ?? 0,
    downstreamKbps: w.downstream_kbps ?? 0,
    bytesSent: w.bytes_sent ?? 0,
    bytesRecv: w.bytes_recv ?? 0,
  };
}

function mappeDsl(dsl) {
  const d = dsl ?? {};
  return {
    sync: d.sync === true,
    downstreamKbps: d.downstream_kbps ?? 0,
    upstreamKbps: d.upstream_kbps ?? 0,
    snrDownstream: d.snr_downstream ?? 0,
    snrUpstream: d.snr_upstream ?? 0,
    attnDownstream: d.attn_downstream ?? 0,
    attnUpstream: d.attn_upstream ?? 0,
  };
}

function mappeWlan(wlan) {
  const w = wlan ?? {};
  return {
    enabled: w.enabled === true,
    ssid: w.ssid ?? "",
    channel: w.channel ?? 0,
    clients: w.clients ?? 0,
  };
}

function mappeWlanClient(client) {
  const c = client ?? {};
  return {
    mac: c.mac ?? "",
    ip: c.ip ?? "",
    hostname: c.hostname ?? "",
    signalDbm: c.signal_dbm ?? 0,
    speedMbps: c.speed_mbps ?? 0,
    band: c.band ?? "",
  };
}

function mappeLogEintrag(eintrag) {
  const e = eintrag ?? {};
  return {
    id: e.id ?? 0,
    timestamp: e.timestamp ?? "",
    message: e.message ?? "",
  };
}

function mappePortForwarding(pf) {
  const p = pf ?? {};
  return {
    enabled: p.enabled === true,
    description: p.description ?? "",
    protocol: p.protocol ?? "",
    externalPort: p.external_port ?? 0,
    internalIp: p.internal_ip ?? "",
    internalPort: p.internal_port ?? 0,
  };
}

// Voller Wire-Snapshot -> View-Form. snake_case -> camelCase über alle
// Sub-Objekte. Bewusst testbar exportiert.
export function mappeDetail(wire) {
  const w = wire ?? {};
  return {
    reachable: w.reachable === true,
    host: w.host ?? "",
    authError: w.auth_error === true,
    device: mappeDevice(w.device),
    wan: mappeWan(w.wan),
    dsl: mappeDsl(w.dsl),
    wlan24: mappeWlan(w.wlan_24),
    wlan5: mappeWlan(w.wlan_5),
    wlanClients: (w.wlan_clients ?? []).map(mappeWlanClient),
    log: (w.log ?? []).map(mappeLogEintrag),
    portForwardings: (w.port_forwardings ?? []).map(mappePortForwarding),
  };
}

// Leer-Detail mit gesetztem authError-Flag: nicht erreichbar, Auth fehlgeschlagen.
// Baut auf mappeDetail auf, damit die Leerwerte aus EINER Quelle kommen.
function authFehlerDetail() {
  return { ...mappeDetail({}), reachable: false, authError: true };
}

// Ruft GET /api/fritz/detail und übersetzt die Antwort in die View-Form.
// 502 (Auth-Fehler) -> authFehlerDetail() statt zu werfen; die UI zeigt dann den
// Auth-Hinweis. Alle anderen Fehler (Netz/500/...) fliegen weiter.
export async function fetchFritzDetail() {
  try {
    const antwort = await apiGet("/api/fritz/detail");
    return mappeDetail(antwort);
  } catch (fehler) {
    if (fehler instanceof ApiError && fehler.status === 502) {
      return authFehlerDetail();
    }
    throw fehler;
  }
}

// Bytes dezimal formatieren: GB = n/1e9 mit einer Nachkommastelle; ab 1 TB in TB.
// Reine Funktion, bewusst testbar exportiert.
export function formatBytes(n) {
  const wert = Number(n) || 0;
  const gb = wert / 1e9;
  if (gb >= 1000) {
    return `${(gb / 1000).toFixed(1)} TB`;
  }
  return `${gb.toFixed(1)} GB`;
}

// Uptime aus Sekunden -> "124d 19h 40m". Führende Null-Einheiten weglassen,
// mindestens "0m". Reine Funktion, bewusst testbar exportiert.
export function formatUptime(secs) {
  const gesamt = Math.max(0, Math.floor(Number(secs) || 0));
  const tage = Math.floor(gesamt / 86400);
  const stunden = Math.floor((gesamt % 86400) / 3600);
  const minuten = Math.floor((gesamt % 3600) / 60);

  const teile = [];
  if (tage > 0) {
    teile.push(`${tage}d`);
  }
  if (stunden > 0 || tage > 0) {
    teile.push(`${stunden}h`);
  }
  teile.push(`${minuten}m`);
  return teile.join(" ");
}

export default { fetchFritzDetail, mappeDetail, formatBytes, formatUptime };
