// Settings-API-Client (CERNIS PRO 2.0)
//
// Kleine reine Helfer um die Settings-Endpunkte des Backends. Stil bewusst wie
// api/interfaces.js / api/devices.js: dünne Wrapper über client.js, kein
// erfundener Fallback. Secrets laufen über einen eigenen /secrets/-Pfad.
//
// Wire-Form (aus backend/api/settings.py):
//   GET  /api/settings -> dict. Nicht-Secrets als Klartext-Werte; gesetzte
//        Secrets erscheinen als Wert "[REDACTED]" unter ihrem Key; nicht
//        gesetzte Secrets FEHLEN ganz.
//   PUT  /api/settings/{key}          Body { value } -> Nicht-Secret schreiben.
//   PUT  /api/settings/secrets/{key}  Body { value } -> Secret setzen; leerer
//        oder null-Wert LOESCHT (idempotent).

import { apiGet, apiPut } from "./client.js";

// Präsenz-Marker für gesetzte (aber nicht ausgelieferte) Secrets. Eine Quelle,
// damit View und Tests nicht je ihren eigenen String hartkodieren.
export const REDACTED = "[REDACTED]";

// Holt das rohe Settings-Dict. Fehlt es (null/undefined), -> {}, damit Aufrufer
// gefahrlos mit Optional-Chaining darauf zugreifen können.
export async function fetchSettings() {
  return (await apiGet("/api/settings")) ?? {};
}

// Schreibt ein Nicht-Secret-Setting per PUT /api/settings/{key}.
export async function updateSetting(key, value) {
  return apiPut(`/api/settings/${encodeURIComponent(key)}`, { value });
}

// Setzt ein Secret per PUT /api/settings/secrets/{key}. value darf "" oder null
// sein — das LOESCHT das Secret serverseitig (idempotent).
export async function updateSecret(key, value) {
  return apiPut(`/api/settings/secrets/${encodeURIComponent(key)}`, { value });
}

// Reine, testbare Prüfung: Ist das Secret unter key gesetzt? Das Backend liefert
// für gesetzte Secrets den Marker REDACTED; nicht gesetzte fehlen ganz.
export function secretGesetzt(settings, key) {
  return Boolean(settings?.[key] === REDACTED);
}

export default { fetchSettings, updateSetting, updateSecret, secretGesetzt, REDACTED };
