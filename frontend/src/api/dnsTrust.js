// DNS-Server-Vertrauensmodell: Mapper + REST-Aufrufe (CERNIS PRO 2.0, E6)
//
// Lese-/Steuerpfade der Verwaltungs-Rubrik „DNS-Server & Vertrauen" (ADR 0043).
// Uebersetzt die Backend-Antworten (snake_case, aus backend/api, Etappe 5) in die
// camelCase-View-Struktur. Stil bewusst wie api/dnsBypass.js: kleine reine Mapper,
// null = ehrlich nicht vorhanden (KEIN erfundener Fallback), Fehler ueber ApiError.
// Pfade bleiben relativ; NIE einen Host hartkodieren.
//
// Wire-Form (verifiziert, E5 + D4 E3, Prefix /api/dns-trust, NICHT aendern):
//   GET  ""          -> [ { ip, category, trust_state, first_seen, last_seen,
//                          display_name, notes, is_platform_placeholder,
//                          expected_rank, origin,
//                          plausibility: { in_inventory, first_seen_days, vendor,
//                          open_ports[], display_name } | null } ]
//     category      in {gateway, local_private, public_resolver, unknown, threat_listed}
//     trust_state   in {trusted, neutral, rejected}
//     expected_rank int, nutzergesetzte erwartete Prioritaet (0 = unrangiert)
//     origin        in {observed, manual, migrated} -- Herkunft des Eintrags (S63 L7d)
//   POST ""          Body { ip, name } -> {ok:true}; 409 = bereits erfasst, 422 = ip kaputt
//   POST "/decision" Body { ip, decision: "trust"|"reject"|"reset" } -> {ok:true}
//   POST "/rank"     Body { ip, rank } (rank >= 0; 0 = unrangiert) -> {ok:true}

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
    expectedRank: Number(s.expected_rank ?? 0),
    // Herkunft: fehlt sie (aeltere Antwort), ist "observed" der ehrliche Normalfall --
    // die Von-Hand-Kennzeichnung ist eine ZUSAETZLICHE Aussage, die nur das Backend
    // treffen kann; ohne sie wird nichts behauptet.
    origin: s.origin ?? "observed",
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

// POST "/rank" -> setzt die erwartete Prioritaet fuer eine IP (rank >= 0; 0 =
// unrangiert). Das Backend haelt die Rang-Sequenz kompakt (1..N); die View laedt
// danach neu, statt die Folge lokal zu raten.
export async function setDnsTrustRank(ip, rank) {
  return apiPost(`${BASIS}/rank`, { ip, rank });
}

// POST "" -> hinterlegt einen DNS-Server VON HAND (auch einen nie beobachteten). Er
// entsteht direkt als vertraut mit der Herkunft "manual". Der Name ist optional.
// Fehlerlagen (ApiError): 409 = die Adresse ist bereits erfasst, 422 = keine gueltige
// IP. Die View laedt danach die Liste neu, statt den neuen Eintrag lokal zu raten.
export async function createDnsTrustServer(ip, name) {
  return apiPost(BASIS, { ip, name });
}

export default {
  mappePlausibilitaet,
  mappeServer,
  fetchDnsTrustServers,
  createDnsTrustServer,
  setDnsTrustDecision,
  setDnsTrustRank,
};
