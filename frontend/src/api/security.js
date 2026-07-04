// Standardzugangs-Sonderfunktion: REST-Aufrufe (CERNIS PRO 2.0, Etappe 2)
//
// Frontend-Anbindung an den scharfen Opt-in-Pfad „Standardzugänge prüfen"
// (Backend Etappe 1, Vertrag NICHT ändern). Stil bewusst wie api/dnsTrust.js:
// kleine reine Funktionen, relative Pfade, apiGet/apiPost aus ./client.js,
// KEIN Host hartkodiert, Fehler über ApiError.
//
// Wire-Form (verifiziert, Etappe 1, NICHT ändern):
//   GET  "/api/security/default-creds/state" -> { armed: bool }
//   POST "/api/security/default-creds/arm"    Body { armed: bool } -> { armed }
//   POST "/api/security/default-creds"        Body { host, ports:[{port,service}],
//        vendor } -> list[cred-dict] (200) | 403 { ok:false, error:"..." }
//     Ein cred-dict trägt u. a. das Feld `note` (kann „selbstsigniertes
//     Zertifikat" enthalten).
//
// Zum 403-Fall: ein 403 ist hier ein FACHLICHER Zustand (nicht freigeschaltet
// oder Ziel nicht im privaten Netz), kein Absturz. Die View soll die vom Backend
// gelieferte error-message anzeigen können. apiPost aus client.js führt bei
// !response.ok NUR den Status, nicht die Body-message mit (es wirft
// „Unerwarteter HTTP-Status 403"). Darum baut checkDefaultCreds den POST hier
// bewusst selbst über fetch — gleiche Fehler-Form (ApiError mit status), aber
// die Fehler-Body-message (error) wird in die ApiError übernommen, damit die
// View sie ruhig zeigen kann. NIE einen Host hartkodieren (relativer Pfad,
// Vite-Proxy leitet ans Backend).

import { ApiError, apiGet, apiPost } from "./client.js";

// Basis-Pfad der Sonderfunktion (relativ; Vite-Proxy leitet ans Backend).
const BASIS = "/api/security/default-creds";

// GET state -> { armed: bool }. Der Freischalt-Zustand ist NICHT persistent; das
// Backend hält ihn sitzungsweit. Fehler (Backend nicht erreichbar) werden als
// ApiError durchgereicht — der Aufrufer behandelt das ruhig (kein stiller
// Fallback auf „armed").
export async function fetchDefaultCredsState() {
  return apiGet(`${BASIS}/state`);
}

// POST arm -> { armed }. Schaltet die Sonderfunktion für die aktuelle Sitzung
// frei (armed true) oder wieder ab (armed false). Fehler als ApiError.
export async function armDefaultCreds(armed) {
  return apiPost(`${BASIS}/arm`, { armed });
}

// POST default-creds -> list[cred-dict] bei 200. Eigener fetch (statt apiPost),
// damit die Fehler-Body-message des Backends (error) bei !ok in die ApiError
// wandert — die View unterscheidet den 403-Fachfall an ApiError.status===403 und
// zeigt ApiError.message. Netzfehler (kein HTTP-Status) -> ApiError(status=null),
// wie in client.js. Bei ok wird das geparste JSON (die cred-Liste) zurückgegeben.
export async function checkDefaultCreds(host, ports, vendor) {
  let response;
  try {
    response = await fetch(BASIS, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ host, ports, vendor }),
    });
  } catch (ursache) {
    // Netzfehler (Server nicht erreichbar, DNS, Abbruch o. Ä.): kein HTTP-Status.
    throw new ApiError(ursache?.message ?? "Netzwerkfehler", null);
  }

  if (!response.ok) {
    // Fehler-Body ehrlich auslesen: das Backend liefert bei 403
    // { ok:false, error:"..." }. Die error-message in die ApiError übernehmen,
    // damit die View sie zeigen kann; fehlt sie (unerwartet), auf den Status
    // zurückfallen. Ein nicht-JSON-Body darf hier NICHT crashen.
    let nachricht = `Unerwarteter HTTP-Status ${response.status}`;
    try {
      const body = await response.json();
      if (body && typeof body.error === "string" && body.error !== "") {
        nachricht = body.error;
      }
    } catch {
      // Body nicht lesbar/kein JSON -> beim Status-Text bleiben (kein Crash).
    }
    throw new ApiError(nachricht, response.status);
  }

  return response.json();
}

export default {
  fetchDefaultCredsState,
  armDefaultCreds,
  checkDefaultCreds,
};
