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
    // mDNS-Dienst-Typen (roh, z.B. "_googlecast._tcp.local."). Die Anzeige kürzt
    // sie lesbar. Leere Liste, wenn keine mDNS-Dienste erkannt.
    mdnsServices: (host.mdns_services ?? []).map((s) => s.type).filter(Boolean),
    // SSDP-/UPnP-Dienste (eigene Spalte, eigenes Erkennungsverfahren — NICHT mit
    // mDNS zusammenlegen). Nur server/st/location: die drei Felder, die BEIDE
    // Quellen führen. Das in der DB zusätzlich gespeicherte ip fehlt im
    // WebSocket-Frame und wird darum bewusst nicht übernommen (sonst bliebe eine
    // darauf gebaute Anzeige im Live-Scan leer). Leere Liste, wenn keine
    // SSDP-Dienste erkannt.
    ssdpServices: (host.ssdp_services ?? []).map((s) => ({
      server: s.server ?? "",
      st: s.st ?? "",
      location: s.location ?? "",
    })),
    // NDI-Videostream-Quelle (eigenes Signal, eigenes Badge in der Anzeige).
    isNdi: host.is_ndi === true,
    pingMs: typeof host.rtt_ms === "number" ? Math.round(host.rtt_ms) : null,
    // isNew aus der Baseline: das Backend liefert is_known (Vorzustand VOR record_seen).
    // is_known === false -> echter Neuzugang in diesem Scan. Beim Folgescan ist die MAC
    // bekannt -> is_known:true -> Flag fällt automatisch weg. Hosts ohne MAC liefern
    // is_known:true -> nie "neu" (korrekt). Auffälligkeit (notable) läuft jetzt
    // über analysisSeverity unten, nicht mehr über ein eigenes Feld.
    isNew: host.is_known === false,
    // isChanged aus der Baseline (ADR 0020): bekanntes Gerät mit IP-Wechsel
    // (DHCP). Disjunkt zu isNew (neu = unbekannt). Beim Folgescan ist die neue IP
    // die Baseline -> Flag fällt automatisch weg.
    isChanged: host.is_changed === true,
    // Achse B (ADR 0029+0030): das Backend bewertet Auffälligkeit fertig im
    // host_detail-Frame. analysisSeverity ist "critical" | "notable" | null,
    // flaggedPorts trägt die geflaggten Portnummern je Stufe. Hier nur
    // durchreichen — NICHT neu verrechnen. Defensive Lesung: ältere Frames ohne
    // flagged_ports fallen auf das leere Default-Objekt zurück.
    analysisSeverity: host.analysis_severity ?? null,
    flaggedPorts: host.flagged_ports ?? { critical: [], notable: [] },
    // Quittierte Ports (Schnitt 8a/ADR 0031): Portnummern, deren Achse-B-Bewertung
    // der Nutzer quittiert hat. Wie flaggedPorts nur durchreichen, nicht verrechnen.
    // Ältere Frames ohne acknowledged_ports fallen auf die leere Liste zurück.
    acknowledgedPorts: host.acknowledged_ports ?? [],
    // notable bleibt als Detail-Panel-Signal erhalten, ist aber KEINE zweite
    // Achse-B-Quelle: es leitet sich aus analysisSeverity ab (eine Wahrheit).
    notable: (host.analysis_severity ?? null) !== null,
    label: host.label ?? undefined,
    // Einordnung/Vertrauensstatus (trust_state) aus der devices-DB. Defensiver
    // Default "neutral", wenn das Frame ihn (noch) nicht trägt — Stil wie die
    // übrigen kuratierten Felder.
    trustState: host.trust_state ?? "neutral",
    // SMB-/NetBIOS-Name aus dem Scan (kann leer sein). Wird u. a. von der
    // CVE-Ansicht als letzter Rückfall für den Anzeige-Namen genutzt.
    smbName: host.smb_name ?? "",
    tags: host.tags ?? undefined,
    notes: host.notes ?? undefined,
    // Weitere IPs derselben MAC (MAC-Gruppierung): Proxy-ARP/Spoofing-Info,
    // leer im Normalfall. Das Detail-Panel zeigt sie als ruhige Zusatzinfo.
    additionalIps: host.additional_ips ?? [],
    // Quelle des Hosts: "ping" (aktiv im Netz geantwortet) vs. "fritzbox"
    // (DHCP-Import, ping-still). Steuert den matten Status-Böppel in der Tabelle.
    source: host.source ?? null,
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
    mdnsServices: [],
    // Das schnelle Frame trägt keine SSDP-Dienste — leer wie mdnsServices. Das
    // nachfolgende host_detail (gleicher schluessel) liefert die echten Werte.
    ssdpServices: [],
    isNdi: false,
    pingMs: typeof frame.rtt_ms === "number" ? Math.round(frame.rtt_ms) : null,
    // Es gibt derzeit keine verlässliche "neu/auffällig"-Quelle im Scan-Wire
    // (is_unknown bedeutet backendseitig "per MAC identifiziert", NICHT "neu im
    // Netz"). isNew/notable bleiben false, bis ein echtes Baseline-Signal
    // (Abgleich gegen die devices-DB, first_seen/is_known) im Wire vorhanden ist.
    // Die Felder bleiben im View-Objekt erhalten, damit ein späterer Baseline-
    // Abgleich sie nur noch füllen muss.
    isNew: false,
    // isChanged bleibt im schnellen Frame false; das nachfolgende host_detail
    // (gleicher schluessel) liefert den echten Wert.
    isChanged: false,
    // Achse B (ADR 0029+0030): das schnelle Frame trägt keine Auffälligkeits-
    // Daten — wie isNew/isChanged hier schon leer sind. Das nachfolgende
    // host_detail (gleicher schluessel) liefert die echten Werte.
    analysisSeverity: null,
    flaggedPorts: { critical: [], notable: [] },
    // Quittierte Ports (Schnitt 8a): das schnelle Frame trägt keine — leer, wie
    // flaggedPorts. Das nachfolgende host_detail (gleicher schluessel) füllt sie.
    acknowledgedPorts: [],
    notable: false,
    label: undefined,
    // Einordnung/Vertrauensstatus: das schnelle Frame trägt keinen — Default-
    // Platzhalter "neutral", analog zu isNew/label hier. Das nachfolgende
    // host_detail (gleicher schluessel) liefert den echten Wert.
    trustState: "neutral",
    tags: undefined,
    notes: undefined,
    // Quelle des Hosts: "ping" (aktiv) vs. "fritzbox" (Import). Steuert den
    // matten Status-Böppel in der Tabelle.
    source: frame.source ?? null,
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
