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

import { apiGet, apiPost, ApiError } from "./client.js";

// Lokaler DELETE-Helfer: client.js kennt nur GET/POST/PUT, kein apiDelete. Statt
// client.js (Fundament aller Anbindungen) fuer einen einzigen Aufruf zu erweitern,
// hier ein kleiner fetch-Helfer im EXAKTEN Stil von apiGet/apiPost — gleiche
// ApiError-Fehler-Form (status = HTTP-Code oder null bei Netzfehler). Kein Body
// (der Pfad-Param traegt die id), erwartet/akzeptiert JSON.
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

export default {
  fetchMonitorStatus,
  fetchMonitorEvents,
  fetchRttHistory,
  addMonitorTarget,
  deleteMonitorTarget,
};
