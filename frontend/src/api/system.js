// System-Info des Backends (CERNIS PRO 2.0)
//
// Ein schmaler REST-Aufruf an backend/api/system: die reduzierte Verfuegbarkeits-
// und Versions-Auskunft holen. Stil wie api/usage.js: kleiner reiner Aufruf,
// relativer Pfad (NIE einen Host hartkodieren), Fehler ueber ApiError.
//
// Die Backend-Antwort ist bereits Anzeige-Form und wird unveraendert durchgereicht
// -- kein Mapper noetig. Aufrufer (AppHeader) darf einen Fehler still schlucken und
// auf seinen i18n-Fallback zurueckfallen.
//
// Wire-Form:
//   GET  "/api/system/info" -> { version: "2.0.0 (x64deb.<sha>)", nmap, scapy }
//   POST "/api/open-url" Body { url } -> { ok: true } | { ok: false, error }

import { apiGet, apiPost } from "./client.js";

// Basis-Pfad der System-Info-Ressource (relativ; Vite-Proxy leitet ans Backend).
const BASIS = "/api/system";

// GET "/info" -> die reduzierte System-Auskunft. Enthaelt mindestens { version }
// (bereits Anzeige-Form). Wird unveraendert zurueckgegeben; wirft ApiError bei
// !ok oder Netzfehler (der Aufrufer entscheidet, ob er das still schluckt).
export async function fetchSystemInfo() {
  return apiGet(`${BASIS}/info`);
}

// POST "/api/open-url" -> oeffnet eine http/https-URL im Systembrowser (Backend
// via webbrowser.open). Zuverlaessiger als window.open in der Tauri-WebView, da
// same-origin. Der Endpunkt liegt direkt unter /api (NICHT /api/system), darum
// der volle Pfad statt BASIS. Body-Key ist exakt "url" (siehe OpenUrlBody im
// Backend). Wirft ApiError bei !ok oder Netzfehler (Aufrufer faellt dann auf
// window.open zurueck). Antwort ({ok:...}) wird unveraendert zurueckgegeben.
export async function openUrl(url) {
  return apiPost("/api/open-url", { url });
}

export default {
  fetchSystemInfo,
  openUrl,
};
