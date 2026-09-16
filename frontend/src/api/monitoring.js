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
//   GET    /api/monitor/logging/{id}/series-> { has_latency, metrics, outages,
//                                              heatmap, ranking } (Serien-Auswertung)

import { apiDownload, apiGet, apiPost, ApiError } from "./client.js";

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
    // Wiederkehrendes Tagesfenster (3b). Nur bei operationMode "recurring" fachlich
    // relevant; sonst tragen die Felder die Backend-Leerwerte (null / leere Liste). Die
    // Minuten/ts bleiben roh (die Karte formatiert selbst); recurWeekdays als Array (0..6).
    recurStartMinute: task.recur_start_minute ?? null,
    recurEndMinute: task.recur_end_minute ?? null,
    recurWeekdays: task.recur_weekdays ?? [],
    recurFrom: task.recur_from ?? null,
    recurUntil: task.recur_until ?? null,
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
  recurStartMinute = null,
  recurEndMinute = null,
  recurWeekdays = null,
  recurFrom = null,
  recurUntil = null,
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
  // Wiederkehrendes Tagesfenster (3b): nur im recurring-Fall mitgeben (snake_case). Die
  // Minuten/Wochentage sind dann gesetzt; recur_from/recur_until nur senden, wenn vorhanden
  // (Unix-ts) -- weglassen, wenn null (leeres Zeitraum-Feld = unbegrenzt bzw. ab sofort).
  if (operationMode === "recurring") {
    payload.recur_start_minute = recurStartMinute;
    payload.recur_end_minute = recurEndMinute;
    payload.recur_weekdays = recurWeekdays ?? [];
    if (recurFrom !== null && recurFrom !== undefined) {
      payload.recur_from = recurFrom;
    }
    if (recurUntil !== null && recurUntil !== undefined) {
      payload.recur_until = recurUntil;
    }
  }
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

// GET /api/monitor/logging/{id}/sla -> SLA-Kennzahlen + stuendlicher Chart einer
// Logging-Aufgabe (C-3 / Schnitt 1b). Gemappt: { uptimePct, downtimeMins, avgRttMs,
// samples, chart }. uptimePct === null heisst "noch keine Auswertung" (zu wenig/keine
// Daten) -- das bleibt EHRLICH null (kein erfundener Default), die Karte zeigt dann den
// dezenten Hinweis. 404 (unbekannte id) -> ApiError (die Karte laesst die SLA-Zeile
// dann still weg).
//
// since/until (Unix-ts, optional, Default null): schraenken den Auswertungs-Zeitraum
// auf [since, until) ein -- nur gesetzte Grenzen werden als Query-Param angehaengt
// (?since=...&until=...). Beide null -> ganzer Task-Zeitraum (Backend-Default). Muster
// wie apiGet("/api/monitor/events", { limit }): die gesetzten Params als Objekt.
//
// chart: stuendliche Buckets (snake_case vom Backend) -> camelCase. Jeder Bucket traegt
// { ts, datetime, uptime_pct, avg_rtt_ms, samples }. Fehlender/leerer chart -> [].
export async function fetchLoggingSla(taskId, since = null, until = null) {
  const params = {};
  if (since !== null && since !== undefined) {
    params.since = since;
  }
  if (until !== null && until !== undefined) {
    params.until = until;
  }
  const backend = await apiGet(`/api/monitor/logging/${taskId}/sla`, params);
  return {
    uptimePct: backend?.uptime_pct ?? null,
    downtimeMins: backend?.downtime_mins ?? null,
    avgRttMs: backend?.avg_rtt_ms ?? null,
    samples: backend?.samples ?? 0,
    chart: (backend?.chart ?? []).map((bucket) => ({
      ts: bucket.ts,
      datetime: bucket.datetime,
      uptimePct: bucket.uptime_pct,
      avgRttMs: bucket.avg_rtt_ms,
      samples: bucket.samples,
    })),
  };
}

// GET /api/monitor/logging/{id}/events -> Ereignis-/Anomalie-Flanken einer Logging-
// Aufgabe (Schnitt 1b-events). Speist die Event-Liste der Detailansicht. Jede Zeile
// snake->camel gemappt: { eventType, rttMs, ts }. Leer -> [].
//
// since/until (Unix-ts, optional, Default null): schraenken den Zeitraum auf
// [since, until) ein -- nur gesetzte Grenzen werden als Query-Param angehaengt
// (?since=...&until=...). Beide null -> alle Flanken des Tasks (Backend-Default).
// Muster wie fetchLoggingSla: die gesetzten Params als Objekt. 404 (unbekannte id)
// -> ApiError.
export async function fetchLoggingEvents(taskId, since = null, until = null) {
  const params = {};
  if (since !== null && since !== undefined) {
    params.since = since;
  }
  if (until !== null && until !== undefined) {
    params.until = until;
  }
  const backend = await apiGet(`/api/monitor/logging/${taskId}/events`, params);
  return (backend ?? []).map((row) => ({
    eventType: row.event_type,
    rttMs: row.rtt_ms ?? null,
    ts: row.ts,
  }));
}

// GET /api/monitor/logging/{id}/series -> Serien-Auswertung einer Logging-Aufgabe
// (Block 3c, zeitfreie Lese-Aggregation). Verdichtet die Outage-Flanken zu Tag-ueber-
// Tag-Mustern: Kennzahlen, einzelne Ausfaelle, Heatmap nach Tagesminute und eine
// Rangliste der auffaelligsten Uhrzeiten. Reine Lesesicht — greift NICHT ins Netz ein.
//
// since/until (Unix-ts, optional, Default null): schraenken den Auswertungs-Zeitraum
// auf [since, until) ein -- nur gesetzte Grenzen werden als Query-Param angehaengt
// (Muster fetchLoggingSla). slotMinutes (int 1..60, Default 10) steuert die zeitliche
// Koernung der Slot-Auswertung und wird IMMER mitgegeben (slot_minutes).
//
// Wire-Form (snake_case, aus backend/api/monitoring.py, verifiziert):
//   has_latency: bool
//   metrics: { availability_pct, outage_count, avg_outage_s, worst_slot_minute|null }
//   outages: [ { start_ts, end_ts|null, duration_s, minute_of_day|null, day_key|null } ]
//   heatmap: [ { minute_of_day, outage_count } ]
//   ranking: [ { minute_of_day, day_count, longest_outage_s } ]
//   latency_slots: [ { minute_of_day, sample_count, p95_rtt_ms, max_rtt_ms } ]
// Alle Zahlen sind roh/ungerundet (die View rundet bei der Anzeige). null bleibt ehrlich
// null (end_ts, minute_of_day, day_key, worst_slot_minute); leere Listen -> []. Die
// latency_slots sind nur befuellt, wenn die Aufzeichnung Latenz fuehrt (has_latency true,
// capture_mode reachability_latency); sonst leere Liste. 404 (unbekannte id) -> ApiError.
export async function fetchLoggingSeries(taskId, since = null, until = null, slotMinutes = 10) {
  const params = { slot_minutes: slotMinutes };
  if (since !== null && since !== undefined) {
    params.since = since;
  }
  if (until !== null && until !== undefined) {
    params.until = until;
  }
  const backend = await apiGet(`/api/monitor/logging/${taskId}/series`, params);
  const metrics = backend?.metrics ?? {};
  return {
    hasLatency: Boolean(backend?.has_latency),
    metrics: {
      availabilityPct: metrics.availability_pct ?? null,
      outageCount: metrics.outage_count ?? 0,
      avgOutageS: metrics.avg_outage_s ?? null,
      worstSlotMinute: metrics.worst_slot_minute ?? null,
    },
    outages: (backend?.outages ?? []).map((row) => ({
      startTs: row.start_ts,
      endTs: row.end_ts ?? null,
      durationS: row.duration_s,
      minuteOfDay: row.minute_of_day ?? null,
      dayKey: row.day_key ?? null,
    })),
    heatmap: (backend?.heatmap ?? []).map((row) => ({
      minuteOfDay: row.minute_of_day,
      outageCount: row.outage_count,
    })),
    ranking: (backend?.ranking ?? []).map((row) => ({
      minuteOfDay: row.minute_of_day,
      dayCount: row.day_count,
      longestOutageS: row.longest_outage_s,
    })),
    latencySlots: (backend?.latency_slots ?? []).map((row) => ({
      minuteOfDay: row.minute_of_day,
      sampleCount: row.sample_count,
      p95RttMs: row.p95_rtt_ms,
      maxRttMs: row.max_rtt_ms,
    })),
  };
}

// GET /api/monitor/logging/{id}/behavior -> Verhaltensprofil einer Logging-Aufgabe
// (Block 4, zeitfreie Lese-Aggregation). Verdichtet die wiederkehrende Aufzeichnung zu
// einem typischen Aktivitaetsmuster: Tagesband (ueber alle Wochentage gemittelt) und
// Wochen-Heatmap (Wochentag x Tageszeit), je Slot mit Aktivitaetszahl und Abweichungs-
// Markierung. Reine Lesesicht — greift NICHT ins Netz ein.
//
// since/until (Unix-ts, optional, Default null): schraenken den Auswertungs-Zeitraum auf
// [since, until) ein -- nur gesetzte Grenzen werden als Query-Param angehaengt (Muster
// fetchLoggingSeries). slotMinutes (int 15..60, Default 60) steuert die zeitliche Koernung
// der Slot-Auswertung und wird IMMER mitgegeben (slot_minutes).
//
// Wire-Form (snake_case, aus backend/api/monitoring.py, verifiziert):
//   recorded_days: int
//   has_enough_data: bool
//   deviation_count: int
//   day_band: [ { slot_start, activity_count, is_deviation } ]
//   week_heatmap: [ { weekday, slot_start, activity_count, is_deviation } ]
// slot_start ist die Minute seit Mitternacht (0..1440), weekday 0..6 (Mo=0). day_band und
// week_heatmap sind auch bei has_enough_data=false befuellt — ueber die Anzeige entscheidet
// das Frontend. null bleibt ehrlich null; fehlende Listen -> []. 404 (unbekannte id) ->
// ApiError.
export async function fetchLoggingBehavior(taskId, since = null, until = null, slotMinutes = 60) {
  const params = { slot_minutes: slotMinutes };
  if (since !== null && since !== undefined) {
    params.since = since;
  }
  if (until !== null && until !== undefined) {
    params.until = until;
  }
  const backend = await apiGet(`/api/monitor/logging/${taskId}/behavior`, params);
  return {
    recordedDays: backend?.recorded_days ?? null,
    hasEnoughData: Boolean(backend?.has_enough_data),
    deviationCount: backend?.deviation_count ?? null,
    dayBand: (backend?.day_band ?? []).map((row) => ({
      slotStart: row.slot_start,
      activityCount: row.activity_count,
      isDeviation: row.is_deviation,
    })),
    weekHeatmap: (backend?.week_heatmap ?? []).map((row) => ({
      weekday: row.weekday,
      slotStart: row.slot_start,
      activityCount: row.activity_count,
      isDeviation: row.is_deviation,
    })),
  };
}

// GET /api/export/logging/{id}?format=...&since=...&until=... -> Datei-Download
// (CSV/JSON/PDF) des Logging-Reports einer Aufgabe ueber einen Zeitraum (Schnitt 1c).
// Nutzt apiDownload (Blob + Browser-Download). Default-Dateiname
// cernis-monitoring-<taskId>.<format>; den echten Namen liefert in der Regel der
// Content-Disposition-Header des Backends (apiDownload bevorzugt ihn). since/until
// (Unix-ts, optional) schraenken den Zeitraum ein -- null wird von apiDownload
// ohnehin uebersprungen. Liefert den verwendeten Dateinamen (fuer evtl. Feedback);
// bei !ok/Netzfehler -> ApiError.
export async function downloadLoggingReport(taskId, format, since = null, until = null) {
  return apiDownload(
    `/api/export/logging/${taskId}`,
    { format, since, until },
    `cernis-monitoring-${taskId}.${format}`,
  );
}

export default {
  downloadLoggingReport,
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
  fetchLoggingEvents,
  fetchLoggingSeries,
  fetchLoggingBehavior,
};
