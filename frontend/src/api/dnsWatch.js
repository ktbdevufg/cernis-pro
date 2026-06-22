// DNS-Wächter-Mapper (CERNIS PRO 2.0)
//
// Übersetzt die Backend-Antwort von GET /api/dns-watch (DNS-relevante
// Außenkontakte DIESES Hosts + Listen + Scope-Marker, snake_case) in die
// camelCase-Struktur der DnsWatchView. Stil bewusst wie api/outbound.js und
// api/traffic.js: kleine reine Helfer, null = ehrlich nicht vorhanden (KEIN
// erfundener Fallback).
//
// Wire-Form (aus backend/api/dns_watch.py, NICHT ändern):
//   GET /api/dns-watch -> {
//     contacts: [ { remote_ip:str, remote_port:int|null, category:str
//       ("erwartungsgemaess"/"offen"/"moegliche_doh"), hostname:str|null,
//       app_name:str|null, pid:int|null, connection_count:int,
//       acknowledged:bool } ],
//     host_scope:str, counts:{erwartungsgemaess:int, offen:int, moegliche_doh:int},
//     expected_servers:[str], doh_providers:[str] }
//   POST /api/dns-watch/acknowledge  Body {remote_ip:str, category:str,
//     action:"ack"|"unack"} -> {ok:true}

import { apiGet, apiPost } from "./client.js";

// Ein Wire-Kontakt -> View-Kontakt. snake_case -> camelCase. Jedes optionale
// Feld bleibt ehrlich null, wenn es fehlt (?? null), kein erfundener Ersatz.
// connectionCount/category/acknowledged werden unverändert durchgereicht.
function mappeKontakt(kontakt) {
  return {
    remoteIp: kontakt.remote_ip,
    remotePort: kontakt.remote_port ?? null,
    category: kontakt.category,
    hostname: kontakt.hostname ?? null,
    appName: kontakt.app_name ?? null,
    pid: kontakt.pid ?? null,
    connectionCount: kontakt.connection_count,
    acknowledged: Boolean(kontakt.acknowledged),
  };
}

// Ruft GET /api/dns-watch und übersetzt die Antwort in die View-Form. Gibt
// { contacts, hostScope, counts, expectedServers, dohProviders } zurück.
// hostScope bleibt ehrlich null, wenn der Marker fehlt (die View blendet den
// Banner dann weg, S3-ehrlich). counts/Listen fallen auf leere Form zurück.
export async function fetchDnsWatch() {
  const backend = await apiGet("/api/dns-watch");
  return {
    contacts: (backend.contacts ?? []).map(mappeKontakt),
    hostScope: backend.host_scope ?? null,
    counts: backend.counts ?? {},
    expectedServers: backend.expected_servers ?? [],
    dohProviders: backend.doh_providers ?? [],
  };
}

// Quittiert (oder entquittiert) einen Befund pro (remoteIp, category) über
// POST /api/dns-watch/acknowledge. action ist "ack" oder "unack" (der Body-
// Constraint des Backends erzwingt das; ein anderer Wert -> 422). Die Antwort
// {ok:true} wird unverändert durchgereicht.
export async function acknowledgeDnsWatch(remoteIp, category, action) {
  return apiPost("/api/dns-watch/acknowledge", {
    remote_ip: remoteIp,
    category,
    action,
  });
}

export default { fetchDnsWatch, acknowledgeDnsWatch };
