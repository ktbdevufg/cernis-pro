// Aussenkontakte-Aufzeichnung: Mapper + REST-Aufrufe (CERNIS PRO 2.0)
//
// Lese-/Schreibpfade der Aussenkontakte-Aufzeichnung (E5). Uebersetzt die
// Backend-Antworten (snake_case, aus backend/api/outbound_log.py) in die
// camelCase-View-Struktur. Stil bewusst wie api/monitoring.js: kleine reine
// Mapper, null = ehrlich nicht vorhanden (KEIN erfundener Fallback), Fehler ueber
// ApiError. Pfade bleiben relativ; NIE einen Host hartkodieren.
//
// Wire-Form (verifiziert, NICHT aendern), Prefix /api/outbound/recordings:
//   GET    ""                  -> [ {id,label,purpose,mode,depth,state,interval_s,
//                                    created_at,effective_start,max_duration_s} ]
//   POST   ""  Body {label,purpose?,mode,depth,interval_s?,max_duration_s?} -> 201 dict
//   GET    "/{id}"             -> dict | 404
//   POST   "/{id}/start"       -> dict | 404 | 409 (nur EINE darf host-weit active sein)
//   POST   "/{id}/pause"       -> dict | 404 | 409
//   POST   "/{id}/resume"      -> dict | 404 | 409
//   POST   "/{id}/stop"        -> dict | 404 | 409
//   DELETE "/{id}"             -> 204 (idempotent)
//   GET    "/{id}/aggregate"   -> [ {remote_ip,first_seen,last_seen,total_count,
//                                    peak_count,remote_port,hostname,country,operator,
//                                    asn,app_name} ]  (E5b)
//   GET    "/{id}/detail?since=&until=" -> [ {ts,remote_ip,remote_port,hostname,country,
//                                    operator,asn,app_name,pid,connection_count} ]  (E5b)
//
//   mode:  "detail" | "aggregate"
//   depth: "anonymous" | "app_resolved"
//   state: "created" | "active" | "paused" | "finished"

import { apiGet, apiPost, ApiError } from "./client.js";

// Basis-Pfad der Aufzeichnungs-Ressource (relativ; Vite-Proxy leitet ans Backend).
const BASIS = "/api/outbound/recordings";

// Lokaler DELETE-Helfer: client.js kennt nur GET/POST/PUT, kein apiDelete. Statt
// das Fundament fuer einen einzigen Aufruf zu erweitern, hier ein kleiner
// fetch-Helfer im EXAKTEN Stil von apiGet/apiPost (Muster api/monitoring.js) --
// gleiche ApiError-Form (status = HTTP-Code oder null bei Netzfehler). Bei 204
// (DELETE-Antwort ohne Body) wird null geliefert; sonst das geparste JSON.
async function apiDelete(path) {
  let response;
  try {
    response = await fetch(path, {
      method: "DELETE",
      headers: { Accept: "application/json" },
    });
  } catch (ursache) {
    // Netzfehler (Server nicht erreichbar, DNS, Abbruch o. Ae.): kein HTTP-Status.
    throw new ApiError(ursache?.message ?? "Netzwerkfehler", null);
  }

  if (!response.ok) {
    throw new ApiError(`Unerwarteter HTTP-Status ${response.status}`, response.status);
  }

  // 204 (No Content) traegt keinen Body -- response.json() wuerde werfen.
  if (response.status === 204) {
    return null;
  }
  return response.json();
}

// Lokaler POST-Helfer fuer die Lifecycle-Aktionen (start/pause/resume/stop). Wie
// apiPost, ABER er reicht bei einem Fehler den Backend-detail-Text durch und
// erhaelt den HTTP-Status (status) in der ApiError. Bei 409 (host-weit schon eine
// active / unzulaessige Transition) unterscheidet die View den ruhigen Konflikt-
// Hinweis (status === 409) von anderen Fehlern. Der generische apiPost aus
// client.js verwirft den detail-Text -- darum hier ein eigener Pfad, OHNE client.js
// umzubauen (Muster api/monitoring.js apiPostMitDetail). Kein Body (die id traegt
// der Pfad). Bei ok -> geparstes JSON; bei !ok -> ApiError (message = detail-Text
// bzw. Fallback, status = HTTP-Code).
async function apiPostMitDetail(path) {
  let response;
  try {
    response = await fetch(path, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
    });
  } catch (ursache) {
    // Netzfehler (Server nicht erreichbar, DNS, Abbruch o. Ae.): kein HTTP-Status.
    throw new ApiError(ursache?.message ?? "Netzwerkfehler", null);
  }

  if (!response.ok) {
    // detail aus dem Fehler-Body ziehen (FastAPI: {"detail": "..."}). Schlaegt das
    // Parsen fehl oder fehlt detail, faellt es auf eine generische Meldung zurueck.
    let detail = null;
    try {
      const body = await response.json();
      if (body && typeof body.detail === "string") {
        detail = body.detail;
      }
    } catch {
      // Kein/kein JSON-Body: detail bleibt null -> generische Meldung.
    }
    throw new ApiError(detail ?? `Unerwarteter HTTP-Status ${response.status}`, response.status);
  }

  return response.json();
}

// ── Mapper (Wire-dict -> View-Objekt) ───────────────────────────────────────

// Ein Aufzeichnungs-Wire-dict (snake_case) -> View-Objekt (camelCase). Zahlen/null
// bleiben roh: intervalS/maxDurationS/effectiveStart sind je nach Modus/Zustand
// null (z. B. maxDurationS bei aggregate; effectiveStart vor dem ersten Start) --
// das bleibt EHRLICH null, kein erfundener Default. Die Modus-/Tiefe-/Zustands-
// Strings tragen das Backend-Vokabular unveraendert.
export function mappeRecording(r) {
  return {
    id: r.id,
    label: r.label,
    purpose: r.purpose ?? null,
    mode: r.mode,
    depth: r.depth,
    state: r.state,
    intervalS: r.interval_s ?? null,
    createdAt: r.created_at ?? null,
    effectiveStart: r.effective_start ?? null,
    maxDurationS: r.max_duration_s ?? null,
  };
}

// Ein Aggregat-Wire-dict (E5b) -> View-Objekt. Je Gegenstelle eine verdichtete
// Zeile (erstmals/zuletzt/wie oft). Optionale Felder bleiben ehrlich null.
export function mappeAggregat(a) {
  return {
    remoteIp: a.remote_ip,
    firstSeen: a.first_seen ?? null,
    lastSeen: a.last_seen ?? null,
    totalCount: a.total_count,
    peakCount: a.peak_count,
    remotePort: a.remote_port ?? null,
    hostname: a.hostname ?? null,
    country: a.country ?? null,
    operator: a.operator ?? null,
    asn: a.asn ?? null,
    appName: a.app_name ?? null,
  };
}

// Ein Detail-Wire-dict (E5b) -> View-Objekt. Je Zeitpunkt eine Zeile (Momentaufnahme
// einer Gegenstelle). ts roh durchgereicht (die View formatiert selbst); optionale
// Felder bleiben ehrlich null.
export function mappeDetail(d) {
  return {
    ts: d.ts,
    remoteIp: d.remote_ip,
    remotePort: d.remote_port ?? null,
    hostname: d.hostname ?? null,
    country: d.country ?? null,
    operator: d.operator ?? null,
    asn: d.asn ?? null,
    appName: d.app_name ?? null,
    pid: d.pid ?? null,
    connectionCount: d.connection_count,
  };
}

// ── REST-Aufrufe ─────────────────────────────────────────────────────────────

// GET "" -> alle Aufzeichnungen (Wire-Form -> View). Leer -> [].
export async function fetchRecordings() {
  const backend = await apiGet(BASIS);
  return (backend ?? []).map(mappeRecording);
}

// POST "" -> 201 + angelegte Aufzeichnung (Zustand "created"). Der Body traegt nur
// die gesetzten Felder: purpose/intervalS/maxDurationS werden NUR mitgegeben, wenn
// definiert -- so greift sonst der Backend-Default (z. B. max_duration_s = 86400 bei
// detail, interval_s = 60). NIE null senden, wenn der Default greifen soll. id/state/
// createdAt setzt das Backend. apiPost wirft bei 422 (Validierung) eine ApiError.
export async function createRecording({
  label,
  purpose,
  mode,
  depth,
  intervalS,
  maxDurationS,
}) {
  const payload = { label, mode, depth };
  if (purpose !== undefined && purpose !== null) {
    payload.purpose = purpose;
  }
  if (intervalS !== undefined && intervalS !== null) {
    payload.interval_s = intervalS;
  }
  if (maxDurationS !== undefined && maxDurationS !== null) {
    payload.max_duration_s = maxDurationS;
  }
  const backend = await apiPost(BASIS, payload);
  return mappeRecording(backend);
}

// GET "/{id}" -> EINE Aufzeichnung. 404 (unbekannte id) -> ApiError.
export async function fetchRecording(id) {
  const backend = await apiGet(`${BASIS}/${id}`);
  return mappeRecording(backend);
}

// POST "/{id}/start" -> Aufzeichnung ("created"/"paused" -> "active"). Bei 409
// (host-weit schon eine active / unzulaessige Transition) wirft apiPostMitDetail
// eine ApiError mit status === 409 und dem Backend-detail-Text -- die View zeigt
// dann den ruhigen Konflikt-Hinweis.
export async function startRecording(id) {
  const backend = await apiPostMitDetail(`${BASIS}/${id}/start`);
  return mappeRecording(backend);
}

// POST "/{id}/pause" -> Aufzeichnung ("active" -> "paused"). 409 -> ApiError.
export async function pauseRecording(id) {
  const backend = await apiPostMitDetail(`${BASIS}/${id}/pause`);
  return mappeRecording(backend);
}

// POST "/{id}/resume" -> Aufzeichnung ("paused" -> "active"). 409 (host-weit schon
// eine active / unzulaessige Transition) -> ApiError mit status === 409.
export async function resumeRecording(id) {
  const backend = await apiPostMitDetail(`${BASIS}/${id}/resume`);
  return mappeRecording(backend);
}

// POST "/{id}/stop" -> Aufzeichnung ({"active","paused"} -> "finished"). 409 -> ApiError.
export async function stopRecording(id) {
  const backend = await apiPostMitDetail(`${BASIS}/${id}/stop`);
  return mappeRecording(backend);
}

// DELETE "/{id}" -> 204 (kein Body). Idempotent im Backend (unbekannte id ist kein
// Fehler). Liefert null (kein Wert zurueck).
export async function deleteRecording(id) {
  return apiDelete(`${BASIS}/${id}`);
}

// GET "/{id}/aggregate" -> verdichtete Gegenstellen-Liste (E5b). Wird in E5a noch
// nicht in der UI genutzt, aber schon hier angelegt. Leer -> [].
export async function fetchAggregate(id) {
  const backend = await apiGet(`${BASIS}/${id}/aggregate`);
  return (backend ?? []).map(mappeAggregat);
}

// GET "/{id}/detail?since=&until=" -> Zeitpunkt-Liste (E5b). since/until (Unix-ts,
// optional) schraenken den Zeitraum ein -- nur gesetzte Grenzen werden als Query-
// Param angehaengt (Muster api/monitoring.js). Wird in E5a noch nicht in der UI
// genutzt. Leer -> [].
export async function fetchDetail(id, since = null, until = null) {
  const params = {};
  if (since !== null && since !== undefined) {
    params.since = since;
  }
  if (until !== null && until !== undefined) {
    params.until = until;
  }
  const backend = await apiGet(`${BASIS}/${id}/detail`, params);
  return (backend ?? []).map(mappeDetail);
}

export default {
  mappeRecording,
  mappeAggregat,
  mappeDetail,
  fetchRecordings,
  createRecording,
  fetchRecording,
  startRecording,
  pauseRecording,
  resumeRecording,
  stopRecording,
  deleteRecording,
  fetchAggregate,
  fetchDetail,
};
