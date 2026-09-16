// Nutzungs-Zaehlung des Startseiten-Schnellzugriffs (CERNIS PRO 2.0)
//
// Zwei schmale REST-Aufrufe an backend/api/usage: eine Funktions-Oeffnung zaehlen
// und die Rangliste der meistgeoeffneten Funktionen holen. Stil wie api/dnsTrust.js:
// kleine reine Aufrufe, relative Pfade (NIE einen Host hartkodieren), Fehler ueber
// ApiError. Die Backend-Antwort ist bereits schlank (feature_id/count/last_used) und
// wird unveraendert durchgereicht -- kein Mapper noetig.
//
// Wire-Form (Prefix /api/usage):
//   POST "/record" Body { feature_id }        -> { ok: true }
//   GET  "/top?limit=5"                        -> [ { feature_id, count, last_used } ]

import { apiGet, apiPost } from "./client.js";

// Basis-Pfad der Zaehl-Ressource (relativ; Vite-Proxy leitet ans Backend).
const BASIS = "/api/usage";

// POST "/record" -> zaehlt EINE nutzer-ausgeloeste Funktions-Oeffnung. Gibt die
// Backend-Antwort ({ok:true}) unveraendert zurueck. Der Aufrufer (App.jsx) darf einen
// Fehler still schlucken -- die Zaehlung ist Nebensache und darf die Navigation nie stoeren.
export async function recordFeatureUsage(featureId) {
  return apiPost(`${BASIS}/record`, { feature_id: featureId });
}

// GET "/top" -> die Rangliste der meistgeoeffneten Funktionen (absteigend nach count).
// Fehlt die Liste ganz (unerwartet), faellt es ehrlich auf [] zurueck -- ein Leerbefund
// bedeutet: es wurde (noch) keine Funktion gezaehlt, nicht "alles gut".
export async function fetchTopFeatures(limit = 5) {
  const backend = await apiGet(`${BASIS}/top`, { limit });
  return backend ?? [];
}

export default {
  recordFeatureUsage,
  fetchTopFeatures,
};
