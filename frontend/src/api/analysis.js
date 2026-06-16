// Analysis-API-Client (CERNIS PRO 2.0)
//
// Kleiner reiner Helfer um den analysis-Service-Lookup. Stil bewusst wie
// api/settings.js: dünner Wrapper über client.js, kein erfundener Fallback.
//
// Wire-Form (aus backend/api/analysis.py):
//   GET /api/analysis/service?port=N -> { port: N, service: string|null }.
//        Ein gültiger, aber nicht gelisteter Port liefert service: null
//        (legitimer Leer-Zustand). Ein Port außerhalb 1–65535 -> HTTP 422
//        (kein stiller Fallback); der Aufrufer prüft die Range VOR dem Aufruf.
//   GET /api/analysis/rules/all -> Liste aller aktiven Regeln (Built-in + User)
//        je { id, title, severity, disabled: bool, ... }. Quelle für den Block
//        „Regel-An/Aus" (ADR 0028). Leere Lage -> [].

import { apiGet } from "./client.js";

// Schlägt den gängigen Service-Namen zu einem Port nach. Liefert den Namen oder
// null (gültiger, aber unbekannter Port). Wirft ApiError bei Netz-/HTTP-Fehler;
// der Aufrufer fängt das und zeigt den Leer-Zustand „—".
export async function lookupService(port) {
  const antwort = await apiGet("/api/analysis/service", { port });
  return antwort?.service ?? null;
}

// Holt ALLE aktuell aktiven Regeln (Built-in + User) mit Toggle-Status. Fehlt die
// Antwort (null/undefined), -> [], damit der Aufrufer gefahrlos darüber mappen kann.
export async function fetchAllRules() {
  return (await apiGet("/api/analysis/rules/all")) ?? [];
}

export default { lookupService, fetchAllRules };
