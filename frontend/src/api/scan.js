// Scan-Mapper (CERNIS PRO 2.0)
//
// Übersetzt die Backend-Formen des Netzwerk-Scans in EXAKT die Struktur, die
// ScanTable/ScanDetailPanel früher aus mockData/scanMock bekamen. Zwei Quellen
// teilen sich denselben Mapper: der WebSocket-Live-Strom (/ws/scan) UND die
// REST-Lesepfade (GET /api/history…). Stil bewusst wie api/traffic.js: kleine
// reine Helfer, kein erfundener Fallback (fehlt ein Feld -> leer/null).
//
// Wire-Formen:
//   host_detail / REST-host: { ip, mac, vendor, rtt_ms, hostname, smb_name,
//     smb_domain, os_guess, os_accuracy, scan_method, ports[{port,state,service}],
//     mdns_services[], ssdp_services[], is_ndi, is_unknown, category, label,
//     tags[], notes, source }
//   host_found (schnell): { ip, rtt_ms, mac, vendor, is_unknown, source }
//   GET /api/history           -> [{ id, scanned_at, cidr, host_count }]
//   GET /api/history/{id}      -> { id, scanned_at, cidr, host_count, hosts[] }

import { apiGet } from "./client.js";

// Icon-Schlüssel aus GERÄTE-Merkmalen (vendor / os_guess / ports) ABLEITEN.
// Reihenfolge ist die Prüfreihenfolge — erste Übereinstimmung gewinnt. Reiner
// Icon-Anker, keine Aussage über das Gerät. Teilstring-Vergleich, case-insens.
const ICON_REGELN = [
  // OS-getriebene Schlüssel zuerst (eindeutiger als der Hersteller).
  { test: (v, os) => os.includes("ios") || os.includes("android"), icon: "phone" },
  { test: (v, os) => v.includes("avm") || v.includes("fritz") || os.includes("fritz"), icon: "router" },
  { test: (v) => v.includes("synology") || v.includes("nas"), icon: "nas" },
  {
    test: (v, os, ports) =>
      (v.includes("brother") || v.includes("hp")) &&
      ports.some((p) => p === 9100 || p === 515 || p === 631),
    icon: "printer",
  },
  {
    test: (v, os, ports) => v.includes("reolink") || ports.includes(554),
    icon: "camera",
  },
  { test: (v) => v.includes("sonos"), icon: "speaker" },
  {
    test: (v, os, ports) =>
      (v.includes("samsung") || os.includes("tizen") || v.includes("lg")) &&
      ports.some((p) => p === 8001 || p === 8002 || p === 9197),
    icon: "tv",
  },
  { test: (v) => v.includes("philips hue") || v.includes("signify"), icon: "thermostat" },
  { test: (v, os) => v.includes("espressif") || os.includes("rtos"), icon: "bulb" },
  { test: (v) => v.includes("raspberry"), icon: "iot" },
  {
    test: (v, os) =>
      v.includes("apple") ||
      v.includes("dell") ||
      os.includes("linux") ||
      os.includes("windows") ||
      os.includes("macos"),
    icon: "laptop",
  },
];

// vendor/osGuess + Portnummern auf einen Icon-Schlüssel abbilden. ports kann die
// Wire-Form ({port,…}) oder eine reine Nummernliste sein — beides wird auf
// Nummern reduziert. Keine Übereinstimmung -> "unknown".
export function iconAusGeraet(vendor, osGuess, ports) {
  const v = String(vendor ?? "").toLowerCase();
  const os = String(osGuess ?? "").toLowerCase();
  const nummern = (ports ?? []).map((p) =>
    typeof p === "number" ? p : p?.port,
  );
  for (const regel of ICON_REGELN) {
    if (regel.test(v, os, nummern)) {
      return regel.icon;
    }
  }
  return "unknown";
}

// Voller Host (REST-host ODER WS-host_detail, identische Form) -> View-Gerät.
// Beide Quellen unterscheiden sich nur im Detailgrad, nicht in der Form, daher
// ein gemeinsamer Mapper. proto konstant "tcp" (das Wire kennt nur port/state/
// service; die Scan-Ports sind TCP, mDNS/SSDP sind separate Listen). Ports mit
// state!=="open" werden TROTZDEM aufgenommen (die View zeigt alle).
export function mappeHost(host) {
  const ports = (host.ports ?? []).map((p) => ({
    num: p.port,
    proto: "tcp",
    service: p.service ?? null,
  }));
  return {
    icon: iconAusGeraet(host.vendor, host.os_guess, host.ports),
    ip: host.ip,
    // Primäre IPv6 (leer, wenn keine). ipv6All ergänzt die weiteren IPv6.
    ipv6: host.ipv6 ?? "",
    ipv6All: host.ipv6_all ?? [],
    mac: host.mac,
    // Stabiler Anzeige-/Auswahl-Schlüssel: MAC bevorzugt, fällt auf IP zurück,
    // wenn keine MAC vorhanden ist. Verhindert Schlüssel-Kollisionen bei Hosts
    // ohne MAC (Netzadresse .0, Gateway-Phantome, ARP-Reste).
    schluessel: host.mac || host.ip,
    vendor: host.vendor ?? "",
    hostname: host.hostname ?? "",
    osGuess: host.os_guess ?? "",
    ports,
    pingMs: typeof host.rtt_ms === "number" ? Math.round(host.rtt_ms) : null,
    // Es gibt derzeit keine verlässliche "neu/auffällig"-Quelle im Scan-Wire
    // (is_unknown bedeutet backendseitig "per MAC identifiziert", NICHT "neu im
    // Netz"). isNew/notable bleiben false, bis ein echtes Baseline-Signal
    // (Abgleich gegen die devices-DB, first_seen/is_known) im Wire vorhanden ist.
    // Die Felder bleiben im View-Objekt erhalten, damit ein späterer Baseline-
    // Abgleich sie nur noch füllen muss.
    isNew: false,
    notable: false,
    label: host.label ?? undefined,
    tags: host.tags ?? undefined,
    notes: host.notes ?? undefined,
    // Weitere IPs derselben MAC (MAC-Gruppierung): Proxy-ARP/Spoofing-Info,
    // leer im Normalfall. Das Detail-Panel zeigt sie als ruhige Zusatzinfo.
    additionalIps: host.additional_ips ?? [],
  };
}

// Schneller host_found-Frame -> View-Gerät. Nur ip, rtt_ms, mac, vendor,
// is_unknown, source vorhanden; fehlende Felder leer/Default. Ein späteres
// host_detail ersetzt diesen Eintrag (gleicher mac-Schlüssel).
export function mappeHostFound(frame) {
  return {
    icon: iconAusGeraet(frame.vendor, "", []),
    ip: frame.ip,
    // host_found kennt keine IPv6; leer als Default (ein späteres host_detail
    // ergänzt sie).
    ipv6: "",
    ipv6All: [],
    mac: frame.mac,
    // Stabiler Anzeige-/Auswahl-Schlüssel: MAC bevorzugt, fällt auf IP zurück,
    // wenn keine MAC vorhanden ist. Verhindert Schlüssel-Kollisionen bei Hosts
    // ohne MAC (Netzadresse .0, Gateway-Phantome, ARP-Reste).
    schluessel: frame.mac || frame.ip,
    vendor: frame.vendor ?? "",
    hostname: "",
    osGuess: "",
    ports: [],
    pingMs: typeof frame.rtt_ms === "number" ? Math.round(frame.rtt_ms) : null,
    // Es gibt derzeit keine verlässliche "neu/auffällig"-Quelle im Scan-Wire
    // (is_unknown bedeutet backendseitig "per MAC identifiziert", NICHT "neu im
    // Netz"). isNew/notable bleiben false, bis ein echtes Baseline-Signal
    // (Abgleich gegen die devices-DB, first_seen/is_known) im Wire vorhanden ist.
    // Die Felder bleiben im View-Objekt erhalten, damit ein späterer Baseline-
    // Abgleich sie nur noch füllen muss.
    isNew: false,
    notable: false,
    label: undefined,
    tags: undefined,
    notes: undefined,
  };
}

// Filtert Phantom-Einträge ohne jede Geräte-Identität heraus. Ein Phantom hat
// KEINE MAC, keine offenen Ports UND keinen Hostname (z. B. Netzadresse .0,
// Gateway-Phantome, ARP-Reste). Sobald EINES dieser Merkmale vorhanden ist,
// bleibt der Eintrag ein echtes Gerät und wird angezeigt.
export function istEchtesGeraet(g) {
  const hatMac = Boolean(g.mac);
  const hatPorts = Array.isArray(g.ports) && g.ports.length > 0;
  const hatHostname = Boolean(g.hostname);
  return hatMac || hatPorts || hatHostname;
}

// Ruft GET /api/history und übersetzt die Liste in die View-Form. snake_case ->
// camelCase (scanned_at -> scannedAt, host_count -> hostCount), id durchgereicht.
// Neueste zuerst (Reihenfolge des Backends bleibt erhalten).
export async function fetchScanHistory(limit = 20) {
  const backend = await apiGet("/api/history", { limit });
  return (backend ?? []).map((eintrag) => ({
    id: eintrag.id,
    scannedAt: eintrag.scanned_at,
    cidr: eintrag.cidr,
    hostCount: eintrag.host_count,
  }));
}

// Ruft GET /api/history/{id} und übersetzt den gespeicherten Scan. Die Hosts
// laufen durch denselben mappeHost wie der Live-Strom (eine Mapper-Quelle).
export async function fetchScanDetail(id) {
  const backend = await apiGet(`/api/history/${id}`);
  return {
    id: backend.id,
    scannedAt: backend.scanned_at,
    cidr: backend.cidr,
    hostCount: backend.host_count,
    geraete: (backend.hosts ?? []).map(mappeHost),
  };
}

export default {
  fetchScanHistory,
  fetchScanDetail,
  mappeHost,
  mappeHostFound,
  iconAusGeraet,
  istEchtesGeraet,
};
