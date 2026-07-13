// DNS-Server-Vertrauensmodell: Mapper + REST-Aufrufe (CERNIS PRO 2.0, E6)
//
// Lese-/Steuerpfade der Verwaltungs-Rubrik „DNS-Server & Vertrauen" (ADR 0043).
// Uebersetzt die Backend-Antworten (snake_case, aus backend/api, Etappe 5) in die
// camelCase-View-Struktur. Stil bewusst wie api/dnsBypass.js: kleine reine Mapper,
// null = ehrlich nicht vorhanden (KEIN erfundener Fallback), Fehler ueber ApiError.
// Pfade bleiben relativ; NIE einen Host hartkodieren.
//
// Wire-Form (verifiziert, E5, Prefix /api/dns-trust, NICHT aendern):
//   GET  ""          -> [ { ip, category, trust_state, first_seen, last_seen,
//                          display_name, notes, is_platform_placeholder,
//                          plausibility: { in_inventory, first_seen_days, vendor,
//                          open_ports[], display_name } | null } ]
//     category    in {gateway, local_private, public_resolver, unknown, threat_listed}
//     trust_state in {trusted, neutral, rejected}
//   POST "/decision" Body { ip, decision: "trust"|"reject"|"reset" } -> {ok:true}

import { apiGet, apiPost } from "./client.js";

// Basis-Pfad der Vertrauens-Ressource (relativ; Vite-Proxy leitet ans Backend).
const BASIS = "/api/dns-trust";

// Die Plausibilitaets-Indizien (snake_case) -> View-Objekt (camelCase). Der ganze
// Block ist optional: fehlt er (plausibility null), gibt der Mapper null zurueck --
// die View liest daraus „nicht im Bestand". Einzelne fehlende Felder fallen ehrlich
// auf null/[] zurueck, es wird NICHTS erfunden.
export function mappePlausibilitaet(p) {
  if (p === null || p === undefined) {
    return null;
  }
  return {
    inInventory: Boolean(p.in_inventory),
    firstSeenDays: p.first_seen_days ?? null,
    vendor: p.vendor ?? null,
    openPorts: p.open_ports ?? [],
    displayName: p.display_name ?? null,
  };
}

// Ein DNS-Server-Wire-dict (snake_case) -> View-Objekt (camelCase). displayName/
// notes bleiben ehrlich null, wenn sie fehlen (?? null). category/trustState werden
// unveraendert durchgereicht (die View gruppiert danach). plausibility ist der
// verschachtelte Indizien-Block oder null.
export function mappeServer(s) {
  return {
    ip: s.ip,
    category: s.category,
    trustState: s.trust_state,
    firstSeen: s.first_seen ?? null,
    lastSeen: s.last_seen ?? null,
    displayName: s.display_name ?? null,
    notes: s.notes ?? null,
    isPlatformPlaceholder: Boolean(s.is_platform_placeholder),
    plausibility: mappePlausibilitaet(s.plausibility),
  };
}

// GET "" -> die Liste der erkannten DNS-Server, jeweils in die View-Form uebersetzt.
// Fehlt die Liste ganz (unerwartet), faellt es ehrlich auf [] zurueck -- ein
// Leerbefund bedeutet: es wurden (noch) keine Server erkannt, nicht „alles gut".
export async function fetchDnsTrustServers() {
  const backend = await apiGet(BASIS);
  return (backend ?? []).map(mappeServer);
}

// POST "/decision" -> setzt die Vertrauens-Entscheidung fuer eine IP
// (trust|reject|reset). Gibt die Backend-Antwort ({ok:true}) unveraendert weiter;
// die View laedt danach die Liste neu, statt den Zustand lokal zu raten.
export async function setDnsTrustDecision(ip, decision) {
  return apiPost(`${BASIS}/decision`, { ip, decision });
}

export default {
  mappePlausibilitaet,
  mappeServer,
  fetchDnsTrustServers,
  setDnsTrustDecision,
};
