// API-Client-Fundament (CERNIS PRO 2.0)
//
// Erster echter API-Anschluss des Frontends. Klein, framework-frei (nur fetch,
// kein axios), eine Datei. ALLE späteren Anbindungen richten sich an diesem
// Fundament aus — daher bewusst schlicht und mit stabiler Fehler-Form.
//
// Pfade bleiben IMMER relativ ("/api/..."); der Vite-Proxy leitet sie ans
// Backend (127.0.0.1:8765). NIE einen Host hartkodieren.

// Stabile Fehler-Form für alle API-Aufrufe: status (HTTP-Code oder null bei
// Netz-/Parse-Fehler) plus eine klare message. Aufrufer können auf instanceof
// ApiError prüfen und status auswerten.
export class ApiError extends Error {
  constructor(message, status = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

// GET auf einen relativen API-Pfad. params werden als Query angehängt
// (URLSearchParams; null/undefined-Werte werden übersprungen). Erwartet und
// akzeptiert JSON. Bei !response.ok ODER Netzfehler -> ApiError; bei ok ->
// das geparste JSON.
export async function apiGet(path, params) {
  let url = path;
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
    response = await fetch(url, {
      headers: { Accept: "application/json" },
    });
  } catch (ursache) {
    // Netzfehler (Server nicht erreichbar, DNS, Abbruch o. Ä.): kein HTTP-Status.
    throw new ApiError(ursache?.message ?? "Netzwerkfehler", null);
  }

  if (!response.ok) {
    throw new ApiError(
      `Unerwarteter HTTP-Status ${response.status}`,
      response.status,
    );
  }

  return response.json();
}

// POST auf einen relativen API-Pfad mit JSON-Body. Gleiche Fehler-Form wie
// apiGet (ApiError mit status/message). body wird als JSON serialisiert und mit
// Content-Type application/json gesendet. Bei !response.ok ODER Netzfehler ->
// ApiError; bei ok -> das geparste JSON.
export async function apiPost(path, body) {
  let response;
  try {
    response = await fetch(path, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });
  } catch (ursache) {
    // Netzfehler (Server nicht erreichbar, DNS, Abbruch o. Ä.): kein HTTP-Status.
    throw new ApiError(ursache?.message ?? "Netzwerkfehler", null);
  }

  if (!response.ok) {
    throw new ApiError(
      `Unerwarteter HTTP-Status ${response.status}`,
      response.status,
    );
  }

  return response.json();
}

// PUT auf einen relativen API-Pfad mit JSON-Body. Gleiche Fehler-Form wie
// apiPost (ApiError mit status/message). body wird als JSON serialisiert und mit
// Content-Type application/json gesendet. Bei !response.ok ODER Netzfehler ->
// ApiError; bei ok -> das geparste JSON.
// Default-Dateiname aus einem Content-Disposition-Header lesen. FastAPI sendet
// `attachment; filename="cernis-...csv"`. Wir lesen den filename="..."-Teil; fehlt
// der Header (oder lässt er sich nicht parsen), fällt es auf den Default-Namen
// zurück (kein erfundener Wert).
function dateinameAusHeader(header, defaultName) {
  if (!header) {
    return defaultName;
  }
  // filename="..." (mit Anführungszeichen) ODER filename=... (ohne).
  const treffer = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(header);
  return treffer ? decodeURIComponent(treffer[1]) : defaultName;
}

// Laufen wir in der Tauri-WebView? window.__TAURI__ wird von Tauri injiziert
// (withGlobalTauri=true). Im Browser-Dev (npm run dev) ist es nicht vorhanden.
function inTauri() {
  return typeof window !== "undefined" && Boolean(window.__TAURI__);
}

// Tauri-Zweig: nativer "Speichern unter"-Dialog + Datei schreiben. Der Nutzer
// wählt Ort und Namen selbst (maximale Nutzerwahl). Die Plugin-Funktionen werden
// per dynamischem import() ERST hier geladen — so muss der Browser-Dev-Pfad die
// Tauri-Pakete nie auflösen und bricht ohne Tauri nicht.
//
// save() liefert den gewählten Pfad oder null (Nutzer bricht ab). Bei null: sauber
// zurückkehren (KEIN Fehler). Sonst die Bytes an den gewählten Pfad schreiben und
// den Basisnamen zurückgeben. Der per Dialog gewählte Pfad erhält vom Dialog-Plugin
// automatisch Schreibzugriff — deshalb genügt fs:allow-write-file ohne breiten Scope.
async function speichernUeberTauriDialog(bytes, name) {
  const { save } = await import("@tauri-apps/plugin-dialog");
  const { writeFile } = await import("@tauri-apps/plugin-fs");

  const pfad = await save({ defaultPath: name });
  if (!pfad) {
    // Nutzer hat den Dialog abgebrochen: nichts schreiben, kein Fehler.
    return null;
  }

  await writeFile(pfad, bytes);

  // Nur den Dateinamen zurückgeben (nicht den vollen Pfad) — passt zum Rückgabewert
  // des Browser-Zweigs (Feedback-Text). Trenner \\ und / abdecken.
  const teile = pfad.split(/[\\/]/);
  return teile[teile.length - 1] || name;
}

// Browser-Dev-Fallback: klassisches Object-URL -> temporäres <a download> ->
// programmatischer Klick. In der Tauri-WebView löst genau das KEINEN Download aus
// (deshalb der Tauri-Zweig oben); im Browser funktioniert es weiterhin, damit
// npm run dev nutzbar bleibt.
//
// Warum Blob + Object-URL statt window.open(url)? Ein Object-URL trägt den vom
// Server gelieferten Dateinamen sauber ins <a download>; ein direktes Navigieren
// würde den Tab verlassen oder den Namen verlieren. Der Object-URL belegt Speicher,
// bis er freigegeben wird — darum revokeObjectURL nach dem Klick.
function speichernUeberBrowserDownload(blob, name) {
  const objektUrl = URL.createObjectURL(blob);
  const anker = document.createElement("a");
  anker.href = objektUrl;
  anker.download = name;
  document.body.appendChild(anker);
  anker.click();
  anker.remove();
  // Den Object-URL freigeben, sonst bleibt der Blob bis zum Tab-Schließen im Speicher.
  URL.revokeObjectURL(objektUrl);
  return name;
}

// Datei-Download über einen relativen API-Pfad. params werden wie bei apiGet als
// Query angehängt (URLSearchParams; null/undefined übersprungen). Anders als apiGet
// erwartet das hier KEIN JSON — wir holen die Antwort als Bytes und speichern sie.
//
// Zentraler Fix für die Tauri-App: In der Tauri-v2-WebView löst das Browser-Pattern
// (Object-URL + <a download>-Klick) KEINEN Download aus — die Datei "passiert nie".
// Darum wird in Tauri der native "Speichern unter"-Dialog genutzt (dialog + fs).
// Alle apiDownload-Nutzer (PDF-Berichte, Handbuch-PDF, CSV-Exporte) profitieren
// automatisch, weil der Fix zentral hier sitzt. Im Browser-Dev bleibt der Fallback.
//
// Bei !ok ODER Netzfehler -> ApiError (gleiche Form wie apiGet). Bei ok -> der
// tatsächlich verwendete Dateiname (für evtl. Feedback), oder null, wenn der Nutzer
// den nativen Speichern-Dialog abbricht. KEIN Host hartkodiert (relativer Pfad,
// Vite-Proxy).
export async function apiDownload(path, params, defaultName = "download") {
  let url = path;
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
    // Kein Accept: application/json — wir erwarten eine Datei (CSV/JSON/PDF-Bytes).
    response = await fetch(url);
  } catch (ursache) {
    // Netzfehler (Server nicht erreichbar, DNS, Abbruch o. Ä.): kein HTTP-Status.
    throw new ApiError(ursache?.message ?? "Netzwerkfehler", null);
  }

  if (!response.ok) {
    throw new ApiError(
      `Unerwarteter HTTP-Status ${response.status}`,
      response.status,
    );
  }

  // Dateiname wie bisher aus Content-Disposition als Vorschlag (Fallback: defaultName).
  const name = dateinameAusHeader(
    response.headers.get("Content-Disposition"),
    defaultName,
  );

  if (inTauri()) {
    // Bytes als Uint8Array aus arrayBuffer() für writeFile().
    const bytes = new Uint8Array(await response.arrayBuffer());
    return speichernUeberTauriDialog(bytes, name);
  }

  // Browser-Dev: Blob + Object-URL-Fallback.
  const blob = await response.blob();
  return speichernUeberBrowserDownload(blob, name);
}

export async function apiPut(path, body) {
  let response;
  try {
    response = await fetch(path, {
      method: "PUT",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });
  } catch (ursache) {
    // Netzfehler (Server nicht erreichbar, DNS, Abbruch o. Ä.): kein HTTP-Status.
    throw new ApiError(ursache?.message ?? "Netzwerkfehler", null);
  }

  if (!response.ok) {
    throw new ApiError(
      `Unerwarteter HTTP-Status ${response.status}`,
      response.status,
    );
  }

  return response.json();
}
