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

// Datei-Download über einen relativen API-Pfad. params werden wie bei apiGet als
// Query angehängt (URLSearchParams; null/undefined übersprungen). Anders als apiGet
// erwartet das hier KEIN JSON — wir holen die Antwort als Blob und lösen einen
// Browser-Download aus.
//
// Warum Blob + Object-URL statt direkt window.open(url)? Ein Object-URL trägt den
// vom Server gelieferten Dateinamen (Content-Disposition) sauber ins <a download>;
// ein direktes Navigieren würde den Tab verlassen oder den Namen verlieren. Der
// Object-URL belegt Speicher, bis er freigegeben wird — darum revokeObjectURL nach
// dem Klick (sonst leakt der Blob über die Sitzung).
//
// Bei !ok ODER Netzfehler -> ApiError (gleiche Form wie apiGet). Bei ok -> der
// tatsächlich verwendete Dateiname (für evtl. Feedback). KEIN Host hartkodiert
// (relativer Pfad, Vite-Proxy).
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

  const blob = await response.blob();
  const name = dateinameAusHeader(
    response.headers.get("Content-Disposition"),
    defaultName,
  );

  // Standard-Browser-Download-Pattern: Object-URL -> temporäres <a download> ->
  // programmatischer Klick -> wieder aus dem DOM entfernen -> Object-URL freigeben.
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
