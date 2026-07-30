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
//   GET /api/traffic/permission: { ok (bool), error (string|null),
//          state (string|null), cause (string|null) }

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

// Ursachen des nicht-nutzbaren Falls, Spiegel von domain.TrafficPermissionCause.
// Ebenfalls benannte Konstanten, damit die View nicht mit nackten Strings vergleicht.
//
// Zwei Ursachen innerhalb von NEEDS_PRIVILEGES, die in ok/error/state zusammenfallen,
// aber verschiedene Erklärungen verlangen: TOOL_MISSING (das Systemwerkzeug
// ss/iproute2 fehlt — Dauerzustand) gegen MEASUREMENT_FAILED (der laufende Messlauf
// ist gescheitert — vorübergehend).
//
// Eine dritte innerhalb von NOT_APPLICABLE: PRIVILEGE_DECLINED — die Messung wäre auf
// dieser Plattform technisch möglich, das System gibt die Zahlen aber nur an dauerhaft
// mit erhöhten Rechten laufende Programme heraus, und CERNIS verzichtet bewusst
// darauf (Windows). Ohne diese Ursache wäre der Fall von der echten Plattformgrenze
// (macOS — cause null) nicht zu unterscheiden, und die View zeigte dort den
// macOS-Text. Ohne dieses Feld müsste die View die Ursache aus dem Freitext von
// `error` erraten. Bei granted ist `cause` null (keine Ursache).
export const TRAFFIC_PERMISSION_CAUSE = {
  TOOL_MISSING: "tool_missing",
  MEASUREMENT_FAILED: "measurement_failed",
  PRIVILEGE_DECLINED: "privilege_declined",
};

// Wählt den Sprachschlüssel des Durchsatz-Hinweises aus dem Rechte-Befund.
//
// Reine Funktion (Befund rein, Schlüssel raus) und bewusst HIER statt als Closure in
// der View: sie ist die Stelle, an der aus einer Backend-Auskunft ein angezeigter
// Satz wird, und genau das muss prüfbar sein, ohne die Komponente zu rendern. Die
// View ruft sie auf — es gibt nur diese eine Auswahl, keinen Nachbau.
//
// REIHENFOLGE: zuerst die URSACHE, dann der Zustand. Das ist der Kern der Sache. Der
// Zustand not_applicable trägt zwei verschiedene Fälle: die echte Plattformgrenze
// (macOS — das System kennt die Messung nicht) und den bewussten Verzicht (Windows —
// das System gäbe die Zahlen her, aber nur an dauerhaft privilegierte Programme).
// Entschiede der Zustand zuerst, bekäme Windows den macOS-Text — und der behauptet
// ausgerechnet, unter Windows sei die Messung möglich. Genau dieser Widerspruch
// stand vorher über der Ansicht.
//
// Jeder unbekannte oder fehlende Wert fällt auf den neutralen Text zurück: die
// Anzeige darf nie leer sein.
export function trafficPermissionSchluessel(permission) {
  if (permission?.cause === TRAFFIC_PERMISSION_CAUSE.PRIVILEGE_DECLINED) {
    return "beobachten.traffic.durchsatzRechteVerzicht";
  }
  if (permission?.cause === TRAFFIC_PERMISSION_CAUSE.TOOL_MISSING) {
    return "beobachten.traffic.durchsatzWerkzeugFehlt";
  }
  if (permission?.cause === TRAFFIC_PERMISSION_CAUSE.MEASUREMENT_FAILED) {
    return "beobachten.traffic.durchsatzMessungFehlgeschlagen";
  }
  if (permission?.state === TRAFFIC_PERMISSION_STATE.NOT_APPLICABLE) {
    return "beobachten.traffic.durchsatzNichtMessbar";
  }
  return "beobachten.traffic.durchsatzOhneWerte";
}

// Ruft GET /api/traffic/permission. { ok, error, state, cause } wird unverändert
// durchgereicht — der error-Text kommt direkt aus dem Backend (nicht neu
// erfinden); die View zeigt ihn bei ok===false als ruhigen Hinweis-Streifen.
export async function fetchTrafficPermission() {
  const backend = await apiGet("/api/traffic/permission");
  return {
    ok: Boolean(backend.ok),
    error: backend.error ?? null,
    state: backend.state ?? null,
    cause: backend.cause ?? null,
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
