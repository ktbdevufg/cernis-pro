// Capture-Rechte (CERNIS PRO 2.0, Etappe 2 + Widerruf aus Etappe 3)
//
// Kapselt die drei Endpunkte, mit denen der Zugriff auf die Mitschnitt-Geräte
// (macOS: /dev/bpf*) abgefragt, eingerichtet und wieder widerrufen wird. Stil
// bewusst wie api/traffic.js: kleine reine Helfer, ehrliche Werte, kein erfundener
// Fallback.
//
// Wire-Form (aus backend/api/capture_access.py, NICHT ändern):
//   GET  /api/capture-access        -> { state:  "granted"|"missing"|"not_applicable",
//                                        detail: string,
//                                        members: string[] }
//   POST /api/capture-access/grant  -> { outcome: "granted"|"cancelled"|"failed"
//                                                 |"not_applicable",
//                                        reason:  string }
//   POST /api/capture-access/revoke -> { outcome: "revoked"|"cancelled"|"failed"
//                                                 |"not_applicable",
//                                        reason:  string }
//     Rumpf: { nur_mitgliedschaft: bool } — true entfernt NUR die eigene
//     Gruppenmitgliedschaft, false räumt die systemweite Einrichtung vollständig ab.
//
// Der Widerruf hat EIGENE Ausgangswerte ("revoked" statt "granted"): eine Rücknahme
// kann nicht "erteilt" ausgehen. Nicht mit den grant-Werten vermischen.
//
// members ist die Liste der Mitglieder der Capture-Gruppe. Die Mitschnitt-Geräte
// sind eine SYSTEMWEITE Ressource, die sich alle Konten des Macs teilen — die Liste
// zeigt vor einem Widerruf ehrlich, wer sonst noch betroffen wäre.
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

// Ausgänge des WIDERRUFS — bewusst eigene Konstanten: "revoked" statt "granted".
// Ein gemeinsamer Satz würde erlauben, den falschen Wert zu vergleichen, ohne dass
// es auffällt.
export const CAPTURE_ACCESS_REVOKE_OUTCOME = {
  REVOKED: "revoked",
  CANCELLED: "cancelled",
  FAILED: "failed",
  NOT_APPLICABLE: "not_applicable",
};

// Ruft GET /api/capture-access. Liefert { state, detail, members } unverändert
// durch; detail ist der Klartext-Grund aus dem Backend (nicht neu erfinden).
// members ist immer ein Array — fehlt oder verunglückt das Feld, ist die ehrliche
// Antwort "keine bekannt" (leer), nicht ein erfundener Eintrag.
export async function fetchCaptureAccess() {
  const backend = await apiGet("/api/capture-access");
  return {
    state: backend.state ?? null,
    detail: backend.detail ?? "",
    members: Array.isArray(backend.members)
      ? backend.members.filter((name) => typeof name === "string")
      : [],
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

// Ruft POST /api/capture-access/revoke und stößt damit die Systemabfrage an.
// nurMitgliedschaft=true entfernt AUSSCHLIESSLICH die eigene Gruppenmitgliedschaft
// und lässt die systemweite Einrichtung für die übrigen Mitglieder stehen;
// false räumt vollständig ab. Der Aufrufer MUSS diese Wahl vom Nutzer haben —
// hier wird nichts geraten.
//
// Wie beim Einrichten: der Aufruf DAUERT, solange der native Dialog offen ist, und
// die vier fachlichen Ausgänge kommen als Wert zurück (nur Transportfehler werfen).
export async function revokeCaptureAccess(nurMitgliedschaft) {
  const backend = await apiPost("/api/capture-access/revoke", {
    nur_mitgliedschaft: Boolean(nurMitgliedschaft),
  });
  return {
    outcome: backend.outcome ?? null,
    reason: backend.reason ?? "",
  };
}

export default { fetchCaptureAccess, grantCaptureAccess, revokeCaptureAccess };
