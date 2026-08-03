// Lizenzaufstellung (CERNIS PRO 2.0)
//
// Zwei LESENDE Aufrufe an backend/api/license_manifest. Stil wie api/usage.js:
// kleine reine Aufrufe, relative Pfade (NIE einen Host hartkodieren), Fehler ueber
// ApiError. Die Backend-Antwort ist die Wire-Form der Aufstellung selbst (ein
// erzeugtes Bau-Artefakt mit eigenem schema_version) und wird UNVERAENDERT
// durchgereicht -- kein Mapper, keine Umdeutung, keine Ergaenzung.
//
// Wire-Form (Prefix /api/lizenzen):
//   GET ""                        -> {
//         schema_version, erzeugt_am, produktversion, plattform,
//         werk: { name, urheber, lizenz_id, lizenz_text, lizenz_text_quelle,
//                 quelltext_bezug, quelltext_bezug_quelle },
//         bestandteile: [ { name, fassung, ebene, lizenz_id, lizenz_id_quelle,
//                 lizenz_id_normalisiert, urhebervermerk, urhebervermerk_quelle,
//                 lizenz_text_ref, projektadresse, mitgeliefert, lizenz_text_quelle,
//                 -- ebene "python" zusaetzlich: lizenz_id_nur_classifier
//                 -- ebene "npm"    zusaetzlich: npm_ort
//                 -- ebene "daten"  zusaetzlich: pfad, lizenz_id_fundstelle
//                 -- ebene "programme" zusaetzlich: quelle_der_angabe,
//                    lieferndes_paket, zweck, fundstelle, plattform UND
//                    vorhanden (vorhanden | fehlt | nicht_zutreffend) } ],
//         luecken: [ { name, fassung, ebene, lizenz_id, fehlt: [...] } ],
//         ebene_nativ: { erhoben, zustand, zielplattform, hinweis,
//                 quelle_der_binaries, gelesene_binaries, eintraege }
//                 -- zustand: nicht_angefordert | erhoben | kein_paketverzeichnis
//       }
//       503 wenn die Aufstellung fehlt; das detail nennt die geprueften Pfade.
//   GET "/text?schluessel=<schluessel>" -> { schluessel, text }
//       Schluessel als ABFRAGEPARAMETER, weil sie Doppelpunkt und Schraegstrich
//       tragen (z. B. "paket:python/anyio", "spdx:MIT"). 404 bei unbekanntem
//       Schluessel, 503 ohne Aufstellung.
//
// WARUM DIESE DATEI NICHT apiGet AUS client.js NUTZT: apiGet wirft bei !ok einen
// ApiError OHNE detail (nur apiPost/liest den Fehler-Body). Die Ansicht muss beim
// 503 aber den ECHTEN Grund des Servers im Wortlaut zeigen -- die Liste der
// geprueften Pfade -- statt einen zu erfinden. Darum wird hier dieselbe Fehler-Form
// (ApiError mit status UND detail) erzeugt; client.js bleibt unangetastet.
//
// KEIN stiller Leerzustand: ein 503 wird als 503 weitergereicht und NICHT in eine
// leere Aufstellung verwandelt (Finding S3).

import { ApiError } from "./client.js";

// Basis-Pfad der Lizenz-Ressource (relativ; Vite-Proxy leitet ans Backend).
const BASIS = "/api/lizenzen";

// Liest den Begruendungstext aus einem Fehler-Body (FastAPI-Form {"detail": "..."}).
// Alles andere (kein JSON, kein detail, leerer Text) ergibt null -- es wird NICHTS
// erfunden und nichts gedeutet.
async function fehlerDetail(response) {
  try {
    const body = await response.json();
    const detail = body?.detail;
    return typeof detail === "string" && detail !== "" ? detail : null;
  } catch {
    return null;
  }
}

// GET mit Fehler-Detail. Relativer Pfad, params als Query (null/undefined werden
// uebersprungen). Bei Netzfehler -> ApiError(status null); bei !ok -> ApiError mit
// HTTP-Status UND detail des Backends; bei ok -> das geparste JSON.
async function holeMitDetail(pfad, params) {
  let url = pfad;
  if (params) {
    const query = new URLSearchParams();
    for (const [schluessel, wert] of Object.entries(params)) {
      if (wert !== null && wert !== undefined) {
        query.append(schluessel, String(wert));
      }
    }
    const queryString = query.toString();
    if (queryString) {
      url += `?${queryString}`;
    }
  }

  let response;
  try {
    response = await fetch(url, { headers: { Accept: "application/json" } });
  } catch (ursache) {
    // Netzfehler (Backend nicht erreichbar, Abbruch o. Ae.): kein HTTP-Status.
    throw new ApiError(ursache?.message ?? "Netzwerkfehler", null);
  }

  if (!response.ok) {
    throw new ApiError(
      `Unerwarteter HTTP-Status ${response.status}`,
      response.status,
      await fehlerDetail(response),
    );
  }

  return response.json();
}

// GET "" -> die Lizenzaufstellung OHNE Lizenztexte, unveraendert durchgereicht.
// Ein 503 (Aufstellung fehlt) wird als ApiError mit status 503 und dem detail des
// Servers weitergereicht -- NICHT in einen Leerzustand verwandelt. Fehlt der Rumpf
// unerwartet ganz, faellt es ehrlich auf null zurueck; der Aufrufer zeigt das als
// nicht belegt, statt eine leere Aufstellung vorzutaeuschen.
export async function fetchLicenseManifest() {
  const backend = await holeMitDetail(BASIS);
  return backend ?? null;
}

// GET "/text" -> EIN Lizenztext, zeichengleich wie in der Aufstellung. Der Text
// wird hier NICHT veraendert: nicht gekuerzt, nicht umbrochen, nicht uebersetzt,
// keine Zeilenumbrueche entfernt oder hinzugefuegt. Unbekannter Schluessel -> 404,
// fehlende Aufstellung -> 503; beides erreicht den Aufrufer als ApiError mit
// status und detail. Fehlt das Textfeld unerwartet, wird null zurueckgegeben --
// das heisst "nicht belegt", nicht "leerer Text".
export async function fetchLicenseText(schluessel) {
  const backend = await holeMitDetail(`${BASIS}/text`, { schluessel });
  return typeof backend?.text === "string" ? backend.text : null;
}

export default {
  fetchLicenseManifest,
  fetchLicenseText,
};
