// Außenkontakte-Mapper (CERNIS PRO 2.0)
//
// Übersetzt die Backend-Antwort von GET /api/outbound/contacts (Liste der
// aggregierten Außenkontakte DIESES Hosts, snake_case) in die camelCase-Struktur
// der OutboundView. Stil bewusst wie api/traffic.js: kleine reine Helfer,
// null = ehrlich nicht vorhanden (KEIN erfundener Fallback).
//
// Wire-Form (aus backend/api/outbound.py, NICHT ändern):
//   GET /api/outbound/contacts -> { contacts: [ {
//     remote_ip:str, remote_port:int|null, hostname:str|null, country:str|null,
//     operator:str|null, asn:str|null, app_name:str|null, pid:int|null,
//     connection_count:int } ], host_scope:str }
//   host_scope ist aktuell "local_host".

import { apiGet } from "./client.js";

// Ein Wire-Kontakt -> View-Kontakt. snake_case -> camelCase. Jedes optionale
// Feld bleibt ehrlich null, wenn es fehlt (?? null), kein erfundener Ersatz.
// connectionCount wird als Zahl durchgereicht.
function mappeKontakt(kontakt) {
  return {
    remoteIp: kontakt.remote_ip,
    remotePort: kontakt.remote_port ?? null,
    hostname: kontakt.hostname ?? null,
    country: kontakt.country ?? null,
    operator: kontakt.operator ?? null,
    asn: kontakt.asn ?? null,
    appName: kontakt.app_name ?? null,
    pid: kontakt.pid ?? null,
    connectionCount: kontakt.connection_count,
  };
}

// Ruft GET /api/outbound/contacts und übersetzt die Antwort in die View-Form.
// Gibt { contacts: [...], hostScope } zurück. hostScope bleibt ehrlich null,
// wenn der Marker fehlt (die View blendet den Banner dann weg, S3-ehrlich).
export async function fetchOutboundContacts() {
  const backend = await apiGet("/api/outbound/contacts");
  return {
    contacts: (backend.contacts ?? []).map(mappeKontakt),
    hostScope: backend.host_scope ?? null,
  };
}

export default { fetchOutboundContacts };
