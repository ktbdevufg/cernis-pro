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

// -------------------------------------------------------------------------
// Etappe C: Standardzugangs-LISTE (die Credential-Datenbank).
//
// Getrennt von der scharfen Session-Sonderfunktion oben (arm/check): hier geht
// es um die Verwaltung der Kandidaten-Liste, die die aktive Prüfung speist —
// einsehen, hinzufügen, ändern, löschen, aktiv-schalten, auf Standard zurück.
//
// Wire-Form (Etappe C-Backend, bereits implementiert, NICHT ändern):
//   GET    "/api/security/default-creds-list"                 -> [eintrag, ...]
//   POST   "/api/security/default-creds-list"        Body eintrag -> 201 | 422 { ok:false, error }
//   PUT    "/api/security/default-creds-list/{id}"   Body eintrag -> 200 | 404 | 422
//   DELETE "/api/security/default-creds-list/{id}"                -> { ok:true }
//   POST   "/api/security/default-creds-list/{id}/aktiv" Body { aktiv } -> { ok:true }
//   POST   "/api/security/default-creds-list/reset"              -> { ok:true }
//
// Ein Eintrag: { eintrag_id, hersteller, modell, zustand,
//   kandidaten:[{ username, password, konfidenz }], quelle_url, aktiv, herkunft }.
//
// Für POST/PUT/DELETE gibt es in client.js KEIN apiDelete, und apiPost/apiPut
// tragen die Body-error-Meldung bei !ok NICHT mit (sie werfen nur den Status).
// Der Validierungsfall 422 ist aber ein FACHLICHER Zustand, dessen Meldung die
// View zeigen soll — darum bauen diese drei Funktionen den fetch bewusst selbst
// (gleiche Fehler-Form wie checkDefaultCreds: ApiError mit status, Body-error
// bei !ok übernommen). NIE einen Host hartkodieren (relativer Pfad, Vite-Proxy).

// Basis-Pfad der Listen-Verwaltung (relativ; Vite-Proxy leitet ans Backend).
const LISTE_BASIS = "/api/security/default-creds-list";

// Gemeinsamer !ok-Pfad für die eigenen fetches: die Body-error-message (falls
// vorhanden) in die ApiError übernehmen, sonst auf den Status-Text zurückfallen.
// Ein nicht-JSON-Body darf hier NICHT crashen. Muster wie checkDefaultCreds.
async function apiErrorAusAntwort(response) {
  let nachricht = `Unerwarteter HTTP-Status ${response.status}`;
  try {
    const body = await response.json();
    if (body && typeof body.error === "string" && body.error !== "") {
      nachricht = body.error;
    }
  } catch {
    // Body nicht lesbar/kein JSON -> beim Status-Text bleiben (kein Crash).
  }
  return new ApiError(nachricht, response.status);
}

// GET Liste -> Array von Einträgen. Fehler als ApiError (kein stiller Fallback).
export async function fetchDefaultCredsList() {
  return apiGet(LISTE_BASIS);
}

// POST neuer Eintrag -> 201 (der angelegte Eintrag) | 422 { ok:false, error }.
// Eigener fetch, damit die 422-Body-Meldung in die ApiError wandert.
export async function addDefaultCredsEintrag(eintrag) {
  let response;
  try {
    response = await fetch(LISTE_BASIS, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(eintrag),
    });
  } catch (ursache) {
    throw new ApiError(ursache?.message ?? "Netzwerkfehler", null);
  }
  if (!response.ok) {
    throw await apiErrorAusAntwort(response);
  }
  return response.json();
}

// PUT Eintrag ändern -> 200 | 404 | 422. Eigener fetch, damit die 422-Body-
// Meldung (Validierung) in die ApiError wandert.
export async function updateDefaultCredsEintrag(eintragId, eintrag) {
  let response;
  try {
    response = await fetch(`${LISTE_BASIS}/${encodeURIComponent(eintragId)}`, {
      method: "PUT",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(eintrag),
    });
  } catch (ursache) {
    throw new ApiError(ursache?.message ?? "Netzwerkfehler", null);
  }
  if (!response.ok) {
    throw await apiErrorAusAntwort(response);
  }
  return response.json();
}

// DELETE Eintrag -> { ok:true }. client.js hat kein apiDelete, darum eigener
// fetch (gleiche Fehler-Form). Ein 404 kommt als ApiError(status=404) an.
export async function deleteDefaultCredsEintrag(eintragId) {
  let response;
  try {
    response = await fetch(`${LISTE_BASIS}/${encodeURIComponent(eintragId)}`, {
      method: "DELETE",
      headers: { Accept: "application/json" },
    });
  } catch (ursache) {
    throw new ApiError(ursache?.message ?? "Netzwerkfehler", null);
  }
  if (!response.ok) {
    throw await apiErrorAusAntwort(response);
  }
  return response.json();
}

// POST aktiv -> { ok:true }. Nur ein Bool-Flag; apiPost genügt (keine fachliche
// Body-Meldung erwartet). Fehler als ApiError.
export async function setDefaultCredsEintragAktiv(eintragId, aktiv) {
  return apiPost(
    `${LISTE_BASIS}/${encodeURIComponent(eintragId)}/aktiv`,
    { aktiv },
  );
}

// POST reset -> { ok:true }. Setzt nur die mitgelieferten Einträge zurück;
// Benutzer-Einträge bleiben erhalten (Backend-Semantik). Fehler als ApiError.
export async function resetDefaultCredsList() {
  return apiPost(`${LISTE_BASIS}/reset`, {});
}

// -------------------------------------------------------------------------
// Etappe D: geräte-/modellbasierter Prüf-Workflow (die NEUE Prüf-Ansicht).
//
// Statt blind admin/admin gegen feste Ports zu schießen, geht die Prüfung jetzt
// vom Gerät aus: Hersteller/Modell -> Prüfplan ermitteln (drei Fälle) -> der
// Nutzer hakt Kandidaten an -> gezielte Prüfung -> Historie. Wire-Form (Etappe
// B/C-Backend, bereits implementiert, NICHT ändern):
//   POST "/api/security/default-creds/ermitteln"  Body { hersteller, modell }
//        -> { fall, eintraege:[{ eintrag_id, hersteller, modell, zustand,
//             kandidaten:[{ username, password, konfidenz }], quelle_url,
//             aktiv, herkunft }], quelle_urls:[...] }.
//        fall = "entwarnung" | "kandidaten" | "keine_infos".
//   POST "/api/security/default-creds/pruefen"     Body { host,
//        ports:[{ port, service }], kandidaten:[{ username, password }],
//        hersteller, modell } -> list[cred-dict { port, service, username,
//        password, note }] (200) | 403 { ok:false, error } (nicht armed ODER
//        Host nicht privat).
//   GET  "/api/security/default-creds/historie"       -> [ { id, geprueft_at,
//        host, hersteller, modell, fall, treffer_count } ] (neueste zuerst).
//   GET  "/api/security/default-creds/historie/{id}"  -> { ..., findings:[
//        { port, service, username, password, note } ] }.
//
// „ermitteln" und die Historie-GETs sind reine Lesefälle (apiGet/apiPost genügen).
// „pruefen" trägt wie checkDefaultCreds den 403 als FACHLICHEN Zustand, dessen
// Body-error die View zeigen soll — darum eigener fetch mit apiErrorAusAntwort.

// POST ermitteln -> { fall, eintraege, quelle_urls }. Kein Login-Versuch, nur
// der Prüfplan (Hersteller/Modell -> bekannte Kandidaten). apiPost genügt:
// hier gibt es keinen fachlichen Fehler-Body, den die View zeigen müsste.
export async function ermittlePruefplan(hersteller, modell) {
  return apiPost(`${BASIS}/ermitteln`, { hersteller, modell });
}

// POST pruefen -> list[cred-dict] (200) | 403 { ok:false, error }. Eigener fetch
// (wie checkDefaultCreds), damit die 403-Body-message (nicht armed / Host nicht
// privat) in die ApiError wandert und die View sie ruhig zeigen kann.
export async function pruefeKandidaten({
  host,
  ports,
  kandidaten,
  hersteller,
  modell,
}) {
  let response;
  try {
    response = await fetch(`${BASIS}/pruefen`, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ host, ports, kandidaten, hersteller, modell }),
    });
  } catch (ursache) {
    throw new ApiError(ursache?.message ?? "Netzwerkfehler", null);
  }
  if (!response.ok) {
    throw await apiErrorAusAntwort(response);
  }
  return response.json();
}

// GET historie -> Array von Prüf-Zusammenfassungen (neueste zuerst). Fehler als
// ApiError (kein stiller Fallback auf leere Historie).
export async function fetchDefaultCredsHistorie() {
  return apiGet(`${BASIS}/historie`);
}

// GET historie/{id} -> eine Prüfung samt findings. Fehler (u. a. 404) als
// ApiError; der Aufrufer behandelt das ruhig.
export async function fetchDefaultCredsHistorieDetail(id) {
  return apiGet(`${BASIS}/historie/${encodeURIComponent(id)}`);
}

export default {
  fetchDefaultCredsState,
  armDefaultCreds,
  checkDefaultCreds,
  fetchDefaultCredsList,
  addDefaultCredsEintrag,
  updateDefaultCredsEintrag,
  deleteDefaultCredsEintrag,
  setDefaultCredsEintragAktiv,
  resetDefaultCredsList,
  ermittlePruefplan,
  pruefeKandidaten,
  fetchDefaultCredsHistorie,
  fetchDefaultCredsHistorieDetail,
};
