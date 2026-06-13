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
