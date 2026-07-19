// Capture-Rechteeinrichtung (CERNIS PRO 2.0, Etappe 2)
//
// Kapselt die zwei Endpunkte, mit denen der Zugriff auf die Mitschnitt-Geräte
// (macOS: /dev/bpf*) abgefragt und eingerichtet wird. Stil bewusst wie
// api/traffic.js: kleine reine Helfer, ehrliche Werte, kein erfundener Fallback.
//
// Wire-Form (aus backend/api/capture_access.py, NICHT ändern):
//   GET  /api/capture-access        -> { state:  "granted"|"missing"|"not_applicable",
//                                        detail: string }
//   POST /api/capture-access/grant  -> { outcome: "granted"|"cancelled"|"failed"
//                                                 |"not_applicable",
//                                        reason:  string }
//
// WICHTIG — die drei Ausgänge bleiben unterscheidbar: "cancelled" ist KEIN Fehler,
// sondern die legitime Entscheidung des Nutzers, die Systemabfrage abzubrechen. Der
// Aufrufer muss dafür einen ruhigen Hinweis zeigen, keine Fehleroptik. Der HTTP-Status
// ist in allen vier Fällen 200 — deshalb wird hier NICHTS geworfen; ein Fehlschlag
// kommt als outcome="failed" mit Grund zurück, nicht als Exception.

import { apiGet, apiPost } from "./client.js";

// Die möglichen Zustände/Ausgänge als benannte Konstanten, damit die View nicht
// mit nackten Strings vergleicht (Tippfehler wären dort still wirkungslos).
export const CAPTURE_ACCESS_STATE = {
  GRANTED: "granted",
  MISSING: "missing",
  NOT_APPLICABLE: "not_applicable",
};

export const CAPTURE_ACCESS_OUTCOME = {
  GRANTED: "granted",
  CANCELLED: "cancelled",
  FAILED: "failed",
  NOT_APPLICABLE: "not_applicable",
};

// Ruft GET /api/capture-access. Liefert { state, detail } unverändert durch;
// detail ist der Klartext-Grund aus dem Backend (nicht neu erfinden).
export async function fetchCaptureAccess() {
  const backend = await apiGet("/api/capture-access");
  return {
    state: backend.state ?? null,
    detail: backend.detail ?? "",
  };
}

// Ruft POST /api/capture-access/grant und stößt damit die Systemabfrage an.
// Der Aufruf DAUERT, solange der native Dialog offen ist (Passwort/Touch ID) —
// die View muss dafür einen Warte-Zustand zeigen.
//
// Ein Netzwerk-/Transportfehler (Backend weg) wirft weiterhin; das ist ein echter
// Fehler und kein Ergebnis der Einrichtung. Die vier fachlichen Ausgänge kommen
// dagegen als Wert zurück.
export async function grantCaptureAccess() {
  const backend = await apiPost("/api/capture-access/grant", {});
  return {
    outcome: backend.outcome ?? null,
    reason: backend.reason ?? "",
  };
}

export default { fetchCaptureAccess, grantCaptureAccess };
