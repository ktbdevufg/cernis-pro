// SNI-Anbindung (CERNIS PRO 2.0)
//
// Konsumiert die passive SNI-Beobachtung des Backends (TLS ClientHello). Liefert
// pro Remote-IP den ECHTEN von einer App angefragten Hostnamen — das löst, dass
// bei AWS/CloudFront nur der Hoster (PTR) statt des echten Dienstes erscheint.
// SNI ist MANUELL, flüchtig und root-pflichtig. Stil bewusst wie api/traffic.js:
// kleine reine Helfer, ApiError-tolerant, null/leer = ehrlich nicht vorhanden.
//
// Wire-Form (aus backend/api/sni.py):
//   POST /api/sni/start  (Body optional {"interface":"..."})
//        -> {ok, error, available} | 403 {ok, error}
//   POST /api/sni/stop    -> {ok: true}
//   GET  /api/sni/status  -> {running, count, available, permission_error}
//   GET  /api/sni/observed
//        -> [{hostname, remote_ip, remote_port, app_name, pid, delta_ms, age_secs}]
//
// Bündelschlüssel der Verkehrsliste ist die Remote-IP (conn.remote). SNI liefert
// pro remote_ip einen hostname — das ist der Verknüpfungspunkt.

import { ApiError, apiGet, apiPost } from "./client.js";

// Startet die SNI-Beobachtung. Body NUR mit interface, wenn gesetzt, sonst leeres
// Objekt {}. Gibt {ok, error, available} zurück. Bei 403 ist die Fehler-Antwort
// der Body (fehlende Rechte) — das fangen wir GEZIELT ab (nicht generisch) und
// geben {ok:false, error} zurück, damit die View den Rechte-Hinweis zeigen kann.
// Bei jedem anderen Fehler ebenfalls {ok:false, error:<message>}.
export async function startSni(schnittstelle = null) {
  const body = schnittstelle ? { interface: schnittstelle } : {};
  try {
    const antwort = await apiPost("/api/sni/start", body);
    return {
      ok: Boolean(antwort.ok),
      error: antwort.error ?? null,
      available: antwort.available ?? null,
    };
  } catch (fehler) {
    if (fehler instanceof ApiError && fehler.status === 403) {
      // Fehlende Rechte: ehrlich als nicht-ok melden (der Backend-Body trägt den
      // Grund; der ApiError reicht hier dessen Status/Message bereits durch).
      return { ok: false, error: fehler.message, available: null };
    }
    return {
      ok: false,
      error: fehler instanceof Error ? fehler.message : String(fehler),
      available: null,
    };
  }
}

// Stoppt die SNI-Beobachtung. Best-effort: gibt {ok:true} zurück oder bei Fehler
// {ok:false} — wirft NIE (Stop darf die View nie kippen).
export async function stopSni() {
  try {
    await apiPost("/api/sni/stop", {});
    return { ok: true };
  } catch {
    return { ok: false };
  }
}

// Liest GET /api/sni/status. Reicht running/count/available durch und benennt
// permission_error -> permissionError um (camelCase nach Frontend-Konvention).
export async function fetchSniStatus() {
  const backend = await apiGet("/api/sni/status");
  return {
    running: Boolean(backend.running),
    count: backend.count ?? 0,
    available: backend.available ?? null,
    permissionError: backend.permission_error ?? null,
  };
}

// Reine, testbare Funktion: übersetzt die observed-Liste in eine Map
// remote_ip -> hostname. Bei mehreren Hostnamen pro IP gewinnt der NEUESTE
// (kleinstes age_secs). Einträge ohne remote_ip/hostname werden verworfen.
// Gibt ein Plain-Object {ip: hostname} zurück.
export function baueSniMap(observed) {
  const karte = {};
  const alter = {}; // ip -> bislang bestes (kleinstes) age_secs
  for (const eintrag of observed ?? []) {
    const ip = eintrag?.remote_ip;
    const hostname = eintrag?.hostname;
    if (!ip || !hostname) {
      continue;
    }
    const age = eintrag.age_secs ?? Infinity;
    if (!(ip in karte) || age < alter[ip]) {
      karte[ip] = hostname;
      alter[ip] = age;
    }
  }
  return karte;
}

// Ruft GET /api/sni/observed und baut die Map remote_ip -> hostname (siehe
// baueSniMap). Bei Fehler {} (leere Map, kein Werfen — die Anreicherung ist
// Beiwerk, kein Pflichtpfad).
export async function fetchSniMap() {
  try {
    const observed = await apiGet("/api/sni/observed");
    return baueSniMap(observed);
  } catch {
    return {};
  }
}

export default { startSni, stopSni, fetchSniStatus, fetchSniMap };
