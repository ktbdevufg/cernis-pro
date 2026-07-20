// Traffic-Mapper (CERNIS PRO 2.0)
//
// Übersetzt die Backend-Antwort von GET /api/traffic (Liste von Apps mit
// eingebetteten Verbindungen, snake_case) in EXAKT die Struktur, die TrafficView
// früher aus dem lokalen Mock bekam, jetzt aber aus der API. So bleibt das
// View-Markup praktisch unverändert. Stil bewusst wie api/resolver.js: kleine
// reine Helfer, null = ehrlich nicht vorhanden (kein erfundener Fallback).
//
// Wire-Form (aus backend/api/traffic.py):
//   App: { app_name (string|null), pids[], connection_count (int),
//          total_send_rate_bps (num|null), total_recv_rate_bps (num|null),
//          connections[] }
//   Connection: { l4 ("tcp"/"udp"), status (string), local {ip,port}|null,
//          remote {ip,port}|null, pid, app_name, bytes_sent, bytes_received,
//          send_rate_bps, recv_rate_bps }
//   GET /api/traffic/permission: { ok (bool), error (string|null) }

import { apiGet, apiPost } from "./client.js";

// Maximale IP-Anzahl pro PTR-Call (Backend POST /api/resolve/ptr: >256 -> 422).
// Sichtbare IPs werden in Blöcken zu höchstens so vielen gesendet.
const PTR_BLOCKGROESSE = 256;

// Kleine, bewusst kurz gehaltene Portkarte: leitet aus dem PORT einen
// Dienst-HINWEIS ab (NICHT gemessen, analog resolver service_hint). Unbekannter
// Port -> null (kein erfundenes Label). Erweiterbar durch einen Eintrag mehr.
const PORT_DIENSTE = {
  443: "https",
  80: "http",
  53: "dns",
  22: "ssh",
  5353: "mdns",
};

function dienstHinweis(port) {
  if (port === null || port === undefined) {
    return null;
  }
  return PORT_DIENSTE[port] ?? null;
}

// Icon-Schlüssel aus dem app_name ABLEITEN (Teilstring, case-insensitive, erste
// Übereinstimmung gewinnt). Reiner Icon-Anker, keine Aussage über die App. Die
// Reihenfolge ist die Prüfreihenfolge.
const ICON_REGELN = [
  { keys: ["chrome", "firefox", "safari", "browser"], icon: "browser" },
  { keys: ["ssh", "sshd", "remote-desktop", "rdp", "vnc"], icon: "remote" },
  { keys: ["claude", "gpt", "llm"], icon: "ai" },
  { keys: ["curl", "wget"], icon: "transfer" },
  { keys: ["node", "npm", "deno", "bun"], icon: "node" },
  { keys: ["uvicorn", "gunicorn", "python", "fastapi"], icon: "server" },
  { keys: ["mail", "smtp", "imap", "thunderbird"], icon: "mail" },
  { keys: ["music", "spotify"], icon: "music" },
  { keys: ["sql", "postgres", "mysql", "redis", "db"], icon: "db" },
];

function iconAusName(appName) {
  // app_name===null -> eigener "unattributed"-Anker (die ehrliche None-Gruppe).
  if (appName === null || appName === undefined) {
    return "unattributed";
  }
  const klein = String(appName).toLowerCase();
  for (const regel of ICON_REGELN) {
    if (regel.keys.some((k) => klein.includes(k))) {
      return regel.icon;
    }
  }
  return "unknown";
}

// Eine Wire-Connection -> View-Verbindung. remote/port aus remote?.ip/?.port
// (null bleibt null = ziel-lose Verbindung). state unverändert durchreichen
// (die View tönt es über i18n). host=null (die Liste liefert keinen PTR-Namen;
// der aufgelöste Name kommt erst im LookupPanel). notable=false für ALLE (das
// Backend markiert nichts als auffällig — keine Frontend-Heuristik).
function mappeConnection(conn) {
  const remote = conn.remote?.ip ?? null;
  const port = conn.remote?.port ?? null;
  return {
    remote,
    port,
    service: dienstHinweis(port),
    state: conn.status,
    notable: false,
    host: null,
    // Zusatzfelder fürs ehrliche Markieren ziel-loser Zeilen (Multicast/mDNS).
    l4: conn.l4,
    local: conn.local ? { ip: conn.local.ip, port: conn.local.port } : null,
  };
}

// Eine Wire-App -> View-App. name = app_name (null bleibt null; die View zeigt
// dafür ein ehrliches Gruppenlabel). down/up aus total_recv/send_rate_bps: null
// bleibt null (NICHT 0) — das Backend liefert Bits/s erst mit Poller; ohne Root
// ist der Normalfall null, und die View zeigt dafür ein ehrliches "—". Keine
// erfundene Umrechnung. connectionCount für Sortierung/Anzeige durchreichen.
function mappeApp(app) {
  return {
    name: app.app_name ?? null,
    icon: iconAusName(app.app_name),
    down: app.total_recv_rate_bps ?? null,
    up: app.total_send_rate_bps ?? null,
    notable: false,
    connectionCount: app.connection_count,
    conns: (app.connections ?? []).map(mappeConnection),
  };
}

// Ruft GET /api/traffic und übersetzt die App-Liste in die View-Struktur.
export async function fetchTraffic() {
  const backend = await apiGet("/api/traffic");
  return backend.map(mappeApp);
}

// Zustände der Durchsatz-Sicht (Stufe 2), Spiegel von domain.TrafficPermissionState.
// Als benannte Konstanten, damit die View nicht mit nackten Strings vergleicht.
//
// Der Unterschied zwischen NEEDS_PRIVILEGES und NOT_APPLICABLE ist wesentlich:
// im ersten Fall KÖNNTE die Plattform es (behebbar, Rechte erlangbar), im zweiten
// bietet sie die Messung gar nicht an (macOS — nicht behebbar, erhöhte Rechte
// bewirken dort nichts). Beide liefern ok===false mit Text; nur `state` trennt sie.
export const TRAFFIC_PERMISSION_STATE = {
  GRANTED: "granted",
  NEEDS_PRIVILEGES: "needs_privileges",
  NOT_APPLICABLE: "not_applicable",
};

// Ruft GET /api/traffic/permission. { ok, error, state } wird unverändert
// durchgereicht — der error-Text kommt direkt aus dem Backend (nicht neu
// erfinden); die View zeigt ihn bei ok===false als ruhigen Hinweis-Streifen.
export async function fetchTrafficPermission() {
  const backend = await apiGet("/api/traffic/permission");
  return {
    ok: Boolean(backend.ok),
    error: backend.error ?? null,
    state: backend.state ?? null,
  };
}

// Löst PTR-Namen für eine Menge von Remote-IPs nachträglich auf (lazy, nicht-
// blockierende Anreicherung der Verkehrsliste). Ruft POST /api/resolve/ptr.
//
// Eingabe: beliebige Sammlung von IPs; leere/ungültige Werte werden verworfen
// und vor dem Senden dedupliziert. >256 IPs werden in Blöcken gesendet (mehrere
// Calls) und die Ergebnisse zu EINEM Plain-Object IP->name|null zusammengeführt.
//
// Rückgabe: Plain-Object { ip: name|null }. Jede erfolgreich angefragte IP ist
// als Schlüssel enthalten (null = kein PTR-Name). Schlägt ein Block-Call fehl,
// werden dessen IPs einfach NICHT ins Ergebnis aufgenommen — die Anreicherung
// ist Beiwerk, kein Pflichtpfad (der Aufrufer behält dann die IP als IP).
export async function fetchPtrNames(ips) {
  const eindeutig = [
    ...new Set(
      [...(ips ?? [])].filter(
        (ip) => typeof ip === "string" && ip.length > 0,
      ),
    ),
  ];

  const ergebnis = {};
  for (let i = 0; i < eindeutig.length; i += PTR_BLOCKGROESSE) {
    const block = eindeutig.slice(i, i + PTR_BLOCKGROESSE);
    try {
      const antwort = await apiPost("/api/resolve/ptr", { ips: block });
      Object.assign(ergebnis, antwort);
    } catch {
      // Block-Fehler tolerieren: diese IPs bleiben unaufgelöst (als IP stehen),
      // statt die ganze Anreicherung zu verwerfen.
    }
  }
  return ergebnis;
}

export default { fetchTraffic, fetchTrafficPermission, fetchPtrNames };
