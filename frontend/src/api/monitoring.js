// Monitoring-Mapper + REST-Aufrufe (CERNIS PRO 2.0)
//
// Lese-/Schreibpfade der monitoring-Domaene. Uebersetzt die Backend-Antworten
// (snake_case, aus backend/api/monitoring.py) in die camelCase-View-Struktur.
// Stil bewusst wie api/traffic.js: kleine reine Mapper, null = ehrlich nicht
// vorhanden (kein erfundener Fallback), Fehler ueber ApiError. Pfade bleiben
// relativ; NIE einen Host hartkodieren.
//
// Wire-Formen (aus backend/api/monitoring.py, verifiziert):
//   GET  /api/monitor/status        -> { tid: { alive, label }, ... }
//   GET  /api/monitor/events?limit  -> [ { target_id, label, event, rtt_ms,
//                                          ts, datetime }, ... ] (neueste zuerst)
//   GET  /api/monitor/rtt/{tid}?limit-> [ { rtt_ms, loss_pct, ts }, ... ]
//                                          (chronologisch aufsteigend)
//   POST /api/monitor/targets        -> { ok: true } (liefert KEIN Target zurueck)
//   DELETE /api/monitor/targets/{tid}-> { ok: true }
//
// Logging-Aufgaben (Schnitt B-Backend, verifiziert aus backend/api/monitoring.py):
//   POST   /api/monitor/logging            -> 201 + Task-dict
//   GET    /api/monitor/logging            -> [Task-dict, ...]
//   GET    /api/monitor/logging/{id}       -> Task-dict (404 moeglich)
//   POST   /api/monitor/logging/{id}/start -> Task-dict (409 Konflikt/Transition)
//   POST   /api/monitor/logging/{id}/pause -> Task-dict (409)
//   POST   /api/monitor/logging/{id}/resume-> Task-dict (409)
//   POST   /api/monitor/logging/{id}/stop  -> Task-dict (409)
//   DELETE /api/monitor/logging/{id}       -> 204 (KEIN Body)
//   GET    /api/monitor/logging/volume     -> { count, over_threshold }

import { apiGet, apiPost, ApiError } from "./client.js";

// Lokaler DELETE-Helfer: client.js kennt nur GET/POST/PUT, kein apiDelete. Statt
// client.js (Fundament aller Anbindungen) fuer einen einzigen Aufruf zu erweitern,
// hier ein kleiner fetch-Helfer im EXAKTEN Stil von apiGet/apiPost — gleiche
// ApiError-Fehler-Form (status = HTTP-Code oder null bei Netzfehler). Kein Body
// (der Pfad-Param traegt die id).
//
// Vertraegt sowohl 204 (leerer Body -- Logging-DELETE) als auch eine JSON-Antwort
// ({ok:true} -- targets-DELETE): bei 204 oder leerem Body wird null geliefert,
// sonst das geparste JSON. So deckt EIN Helfer beide DELETE-Pfade ab, ohne dass
// der 204-Fall an einem fehlenden Body-Parse scheitert.
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
// apiPost, ABER er reicht bei einem Fehler den Backend-detail-Text durch: das
// Logging-Backend liefert bei 409 (Ziel belegt / falscher Zustand) eine sprechende
// Konzept-Meldung im JSON-Feld "detail", die die View an der Karte anzeigt. Der
// generische apiPost aus client.js verwirft diesen Text (feste "Unerwarteter
// HTTP-Status"-Meldung) -- darum hier ein eigener Pfad, OHNE client.js fuer alle
// anderen Anbindungen umzubauen. Bei ok -> geparstes JSON; bei !ok -> ApiError,
// dessen message der detail-Text ist (Fallback: HTTP-Status), status = HTTP-Code.
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

// Das status-Objekt { tid: { alive, label } } -> Array gemappter Ziele. tid wird
// zum targetId (Object.entries). alive zu echtem Boolean; label durchgereicht.
// Gemeinsam genutzt von fetchMonitorStatus (REST) und monitorStream (WS-Connect).
export function mappeStatus(statusObjekt) {
  return Object.entries(statusObjekt ?? {}).map(([tid, eintrag]) => ({
    targetId: tid,
    label: eintrag.label,
    alive: Boolean(eintrag.alive),
  }));
}

// Ein Wire-Event -> View-Event (camelCase). rtt_ms bleibt null wenn null (kein
// erfundener Wert). ts (roher Unix-Float) und datetime (vorformatierter String)
// unveraendert durchgereicht — die View rundet/formatiert selbst.
function mappeEvent(event) {
  return {
    targetId: event.target_id,
    label: event.label,
    event: event.event,
    rttMs: event.rtt_ms ?? null,
    ts: event.ts,
    datetime: event.datetime,
  };
}

// Ein Wire-RTT-Sample -> View-Sample. rtt_ms/loss_pct bleiben null wenn null
// (ehrliche Luecke statt 0). ts roh durchgereicht.
function mappeRtt(sample) {
  return {
    rttMs: sample.rtt_ms ?? null,
    lossPct: sample.loss_pct ?? null,
    ts: sample.ts,
  };
}

// Ein Logging-Task-Wire-dict (snake_case) -> View-Objekt (camelCase). Die
// Zeitfelder bleiben roh (Unix-ts bzw. null -- die Restzeit-Logik rechnet selbst);
// null bleibt ehrlich null (kein erfundener Wert). Die Modus-/Zustands-Strings
// (captureMode/operationMode/state) tragen das Backend-Vokabular unveraendert.
export function mappeLoggingTask(task) {
  return {
    id: task.id,
    targetId: task.target_id,
    label: task.label,
    purpose: task.purpose,
    captureMode: task.capture_mode,
    operationMode: task.operation_mode,
    state: task.state,
    plannedStart: task.planned_start ?? null,
    plannedEnd: task.planned_end ?? null,
    maxDurationS: task.max_duration_s ?? null,
    createdAt: task.created_at ?? null,
    effectiveStart: task.effective_start ?? null,
    // Mess-Intervall in Sekunden (C-2). Backend liefert es immer (Default 5); fehlt es
    // wider Erwarten, faellt es ehrlich auf null (kein erfundener Default im Mapper --
    // die Karte zeigt es nur bei vorhandenem Wert).
    intervalS: task.interval_s ?? null,
    // Schwellwert-Alarm (Schnitt 5). Optional: das Backend liefert ein verschachteltes
    // threshold-dict (snake_case) ODER null (kein Schwellwert). null bleibt ehrlich null
    // (Muster intervalS) -- die Karte zeigt die Alarm-Zeile nur bei vorhandenem Objekt.
    threshold: task.threshold
      ? {
          condition: task.threshold.condition,
          limitMs: task.threshold.limit_ms,
          consecutiveN: task.threshold.consecutive_n,
          notifyDesktop: task.threshold.notify_desktop,
          notifyEmail: task.threshold.notify_email,
        }
      : null,
  };
}

// ── REST-Aufrufe ─────────────────────────────────────────────────────────────

// GET /api/monitor/status -> Array [{ targetId, label, alive }]. Das status-Objekt
// wird ueber mappeStatus in eine Liste uebersetzt.
export async function fetchMonitorStatus() {
  const backend = await apiGet("/api/monitor/status");
  return mappeStatus(backend);
}

// GET /api/monitor/events -> Liste gemappter Uebergangs-Ereignisse (neueste zuerst,
// Reihenfolge des Backends bleibt erhalten).
export async function fetchMonitorEvents(limit = 100) {
  const backend = await apiGet("/api/monitor/events", { limit });
  return (backend ?? []).map(mappeEvent);
}

// GET /api/monitor/rtt/{tid} -> RTT-Verlauf eines Targets, chronologisch
// aufsteigend (Reihenfolge des Backends bleibt erhalten).
export async function fetchRttHistory(targetId, limit = 120) {
  const backend = await apiGet(`/api/monitor/rtt/${targetId}`, { limit });
  return (backend ?? []).map(mappeRtt);
}

// POST /api/monitor/targets — legt ein benutzerdefiniertes Target an. Die id wird
// HIER erzeugt (`custom_<timestamp>`), interface="" und enabled=true sind die
// Backend-Defaults. Das Backend antwortet nur { ok: true }, liefert also KEIN
// Target zurueck — darum bauen wir das angelegte Ziel selbst zusammen und geben es
// zurueck (so kann die View es ohne erneuten Status-Abruf einfuegen).
export async function addMonitorTarget({ label, host }) {
  const id = `custom_${Date.now()}`;
  await apiPost("/api/monitor/targets", {
    id,
    label,
    host,
    interface: "",
    enabled: true,
  });
  return { id, label, host, interface: "", enabled: true };
}

// DELETE /api/monitor/targets/{tid} — entfernt ein Target nach id. Idempotent im
// Backend (fehlende id ist kein Fehler). Liefert die Backend-Antwort durch.
export async function deleteMonitorTarget(targetId) {
  return apiDelete(`/api/monitor/targets/${targetId}`);
}

// ── Logging-Aufgaben (Schnitt B-Backend) ─────────────────────────────────────

// POST /api/monitor/logging -> 201 + angelegter Task (Zustand CREATED). Der Body
// traegt die Modus-abhaengigen Felder: SCHEDULED braucht plannedStart+plannedEnd,
// IMMEDIATE braucht maxDurationS (das Frontend liefert nur die jeweils gueltigen).
// id/createdAt setzt das Backend. apiPost wirft bei 422 (Validierung) eine ApiError.
export async function createLoggingTask({
  targetId,
  label,
  purpose,
  captureMode,
  operationMode,
  plannedStart = null,
  plannedEnd = null,
  maxDurationS = null,
  intervalS = null,
  threshold = null,
}) {
  const payload = {
    target_id: targetId,
    label,
    purpose,
    capture_mode: captureMode,
    operation_mode: operationMode,
    planned_start: plannedStart,
    planned_end: plannedEnd,
    max_duration_s: maxDurationS,
  };
  // Mess-Intervall (C-2): nur senden, wenn gesetzt -- sonst weglassen, dann greift der
  // Backend-Default (5). Der Assistent reicht es NIE durch (still Default 5).
  if (intervalS !== null && intervalS !== undefined) {
    payload.interval_s = intervalS;
  }
  // Schwellwert-Alarm (Schnitt 5): nur senden, wenn gesetzt -- sonst weglassen, dann
  // legt das Backend die Aufgabe ohne Alarm an. Als snake_case-dict (Muster interval_s).
  // Der Assistent reicht es NIE durch (kein Schwellwert im gefuehrten Modus).
  if (threshold !== null && threshold !== undefined) {
    payload.threshold = {
      condition: threshold.condition,
      limit_ms: threshold.limitMs,
      consecutive_n: threshold.consecutiveN,
      notify_desktop: threshold.notifyDesktop,
      notify_email: threshold.notifyEmail,
    };
  }
  const backend = await apiPost("/api/monitor/logging", payload);
  return mappeLoggingTask(backend);
}

// GET /api/monitor/logging -> alle Aufgaben-Definitionen (Wire-Form -> View). Leer -> [].
export async function fetchLoggingTasks() {
  const backend = await apiGet("/api/monitor/logging");
  return (backend ?? []).map(mappeLoggingTask);
}

// GET /api/monitor/logging/{id} -> EINE Aufgabe. 404 (unbekannte id) -> ApiError.
export async function fetchLoggingTask(taskId) {
  const backend = await apiGet(`/api/monitor/logging/${taskId}`);
  return mappeLoggingTask(backend);
}

// POST /api/monitor/logging/{id}/start -> Aufgabe (CREATED -> ACTIVE). Bei 409
// (Ziel belegt / falscher Zustand) wirft apiPostMitDetail eine ApiError, deren
// message der Backend-detail-Text ist (die View zeigt ihn an der Karte).
export async function startLoggingTask(taskId) {
  const backend = await apiPostMitDetail(`/api/monitor/logging/${taskId}/start`);
  return mappeLoggingTask(backend);
}

// POST /api/monitor/logging/{id}/pause -> Aufgabe (ACTIVE -> PAUSED). 409 -> ApiError.
export async function pauseLoggingTask(taskId) {
  const backend = await apiPostMitDetail(`/api/monitor/logging/${taskId}/pause`);
  return mappeLoggingTask(backend);
}

// POST /api/monitor/logging/{id}/resume -> Aufgabe (PAUSED -> ACTIVE). 409 (Ziel
// belegt / falscher Zustand) -> ApiError mit dem Backend-detail-Text.
export async function resumeLoggingTask(taskId) {
  const backend = await apiPostMitDetail(`/api/monitor/logging/${taskId}/resume`);
  return mappeLoggingTask(backend);
}

// POST /api/monitor/logging/{id}/stop -> Aufgabe ({ACTIVE,PAUSED} -> FINISHED). 409 -> ApiError.
export async function stopLoggingTask(taskId) {
  const backend = await apiPostMitDetail(`/api/monitor/logging/${taskId}/stop`);
  return mappeLoggingTask(backend);
}

// DELETE /api/monitor/logging/{id} -> 204 (kein Body). Idempotent im Backend
// (unbekannte id ist kein Fehler). Liefert null (kein Wert zurueck).
export async function deleteLoggingTask(taskId) {
  return apiDelete(`/api/monitor/logging/${taskId}`);
}

// GET /api/monitor/logging/volume -> Mengen-Befund der RTT-Messdaten. Roh
// gemappt: { count, overThreshold }. count fehlt -> 0, overThreshold -> false.
export async function fetchLoggingVolume() {
  const backend = await apiGet("/api/monitor/logging/volume");
  return {
    count: backend?.count ?? 0,
    overThreshold: Boolean(backend?.over_threshold),
  };
}

// GET /api/monitor/logging/{id}/sla -> SLA-Kennzahlen einer Logging-Aufgabe (C-3).
// Gemappt: { uptimePct, downtimeMins, avgRttMs, samples }. uptimePct === null heisst
// "noch keine Auswertung" (zu wenig/keine Daten) -- das bleibt EHRLICH null (kein
// erfundener Default), die Karte zeigt dann den dezenten Hinweis. 404 (unbekannte id)
// -> ApiError (die Karte laesst die SLA-Zeile dann still weg).
export async function fetchLoggingSla(taskId) {
  const backend = await apiGet(`/api/monitor/logging/${taskId}/sla`);
  return {
    uptimePct: backend?.uptime_pct ?? null,
    downtimeMins: backend?.downtime_mins ?? null,
    avgRttMs: backend?.avg_rtt_ms ?? null,
    samples: backend?.samples ?? 0,
  };
}

export default {
  fetchMonitorStatus,
  fetchMonitorEvents,
  fetchRttHistory,
  addMonitorTarget,
  deleteMonitorTarget,
  createLoggingTask,
  fetchLoggingTasks,
  fetchLoggingTask,
  startLoggingTask,
  pauseLoggingTask,
  resumeLoggingTask,
  stopLoggingTask,
  deleteLoggingTask,
  fetchLoggingVolume,
  fetchLoggingSla,
};
