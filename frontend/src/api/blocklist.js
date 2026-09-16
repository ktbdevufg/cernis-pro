// Blocklist-API-Client (CERNIS PRO 2.0)
//
// Duenne, reine Wrapper um die Blocklist-Endpunkte (Verwaltung extern gepflegter
// Listen, Abgleich von Aussenkontakten). Stil bewusst wie api/report.js /
// api/maintenance.js: kleine reine Mapper, snake_case <-> camelCase, KEIN erfundener
// Fallback (null bleibt ehrlich null). Pfade bleiben relativ; NIE einen Host
// hartkodieren.
//
// client.js hat KEIN apiPatch und KEIN apiDelete. Beide werden hier lokal per fetch
// gebaut — mit derselben Fehler-Form wie client.js (ApiError mit status/message),
// die wir aus client.js importieren. PUT/POST/GET laufen ueber die vorhandenen
// apiGet/apiPost/apiPut.
//
// Wire-Form (verifiziert gegen backend/api/blocklist.py, NICHT aendern):
//   GET    /api/blocklist/sources               -> [SourceOut]
//   POST   /api/blocklist/sources               -> { source_id, license_hint }
//   POST   /api/blocklist/sources/upload        -> { source_id, entry_count }
//   PATCH  /api/blocklist/sources/{id}          -> { ok }
//   DELETE /api/blocklist/sources/{id}          -> { ok }
//   POST   /api/blocklist/sources/{id}/refresh  -> { source_id, ok, entry_count, error }
//   POST   /api/blocklist/refresh-due           -> { results: [RefreshOut] }
//   POST   /api/blocklist/reset-defaults        -> { ok }
//   GET    /api/blocklist/health                -> { issues: [HealthIssueOut] }
//   GET    /api/blocklist/settings              -> SettingsOut
//   PUT    /api/blocklist/settings              -> { ok }
//   POST   /api/blocklist/match                 -> { results: [ContactMatchOut] }

import { ApiError, apiGet, apiPost, apiPut } from "./client.js";

// ── Lokale PATCH/DELETE-Helfer (client.js hat sie nicht) ───────────────────────
// Bewusst exakt analog zu apiPut/apiPost in client.js: gleiche Header, gleiche
// ApiError-Form (status = HTTP-Code oder null bei Netzfehler).

// PATCH auf einen relativen API-Pfad mit JSON-Body. Gleiche Fehler-Form wie apiPut.
async function apiPatch(path, body) {
  let response;
  try {
    response = await fetch(path, {
      method: "PATCH",
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
    throw new ApiError(`Unerwarteter HTTP-Status ${response.status}`, response.status);
  }

  return response.json();
}

// DELETE auf einen relativen API-Pfad (kein Body). Gleiche Fehler-Form wie apiPut.
async function apiDelete(path) {
  let response;
  try {
    response = await fetch(path, {
      method: "DELETE",
      headers: { Accept: "application/json" },
    });
  } catch (ursache) {
    // Netzfehler (Server nicht erreichbar, DNS, Abbruch o. Ä.): kein HTTP-Status.
    throw new ApiError(ursache?.message ?? "Netzwerkfehler", null);
  }

  if (!response.ok) {
    throw new ApiError(`Unerwarteter HTTP-Status ${response.status}`, response.status);
  }

  return response.json();
}

// ── Mapper (snake_case -> camelCase) ───────────────────────────────────────────

// Eine Quellen-Definition -> View-Struktur. Alle Felder roh durchgereicht
// (group/fmt/origin/status tragen das Backend-Vokabular unveraendert; null bleibt
// ehrlich null bei url/lastFetchedTs/entryCount).
function mappeSource(s) {
  return {
    id: s.id,
    name: s.name,
    group: s.group,
    fmt: s.fmt,
    origin: s.origin,
    url: s.url ?? null,
    license: s.license,
    attributionRequired: s.attribution_required,
    enabled: s.enabled,
    lastFetchedTs: s.last_fetched_ts ?? null,
    status: s.status,
    entryCount: s.entry_count ?? null,
  };
}

// Ein Lade-Ergebnis (Einzel-Refresh / refresh-due) -> View-Struktur.
function mappeRefresh(r) {
  return {
    sourceId: r.source_id,
    ok: r.ok,
    entryCount: r.entry_count ?? null,
    error: r.error ?? null,
  };
}

// Ein Gesundheits-Befund -> View-Struktur.
function mappeHealthIssue(i) {
  return {
    sourceId: i.source_id,
    name: i.name,
    group: i.group,
    suggestedReplacementId: i.suggested_replacement_id ?? null,
  };
}

// Ein Treffer eines Kontakts -> View-Struktur.
function mappeMatch(m) {
  return {
    sourceId: m.source_id,
    sourceName: m.source_name,
    group: m.group,
    matchedOn: m.matched_on,
  };
}

// Das Abgleich-Ergebnis EINES Kontakts -> View-Struktur.
function mappeContactMatch(c) {
  return {
    remoteIp: c.remote_ip,
    hostname: c.hostname ?? null,
    matches: (c.matches ?? []).map(mappeMatch),
  };
}

// ── Endpunkt-Wrapper ───────────────────────────────────────────────────────────

// GET /sources -> alle Quellen-Definitionen (Wire-Form, hier camelCase gemappt).
export async function fetchSources() {
  const backend = await apiGet("/api/blocklist/sources");
  return (backend ?? []).map(mappeSource);
}

// POST /sources -> legt eine Nutzer-Quelle per URL an. group/fmt sind rohe Wire-
// Strings (Hebung im Backend; 422 bei ungueltigem Wert). Antwort: vergebene id +
// freundlicher Lizenz-Hinweis (oder null — kein erfundener Hinweis).
export async function addSource({ name, url, group, fmt }) {
  const backend = await apiPost("/api/blocklist/sources", { name, url, group, fmt });
  return {
    sourceId: backend.source_id,
    licenseHint: backend.license_hint ?? null,
  };
}

// POST /sources/upload -> importiert eine hochgeladene Liste. content ist der rohe
// Listentext. Antwort: vergebene id + Zahl sofort geparster Eintraege.
export async function uploadSource({ name, group, fmt, content }) {
  const backend = await apiPost("/api/blocklist/sources/upload", {
    name,
    group,
    fmt,
    content,
  });
  return {
    sourceId: backend.source_id,
    entryCount: backend.entry_count,
  };
}

// PATCH /sources/{id} -> partielles Update (nur gesetzte Felder). patch ist bereits
// in Wire-Form (camelCase deckt sich hier mit snake_case: name/url/group/fmt/enabled).
export async function updateSource(id, patch) {
  return apiPatch(`/api/blocklist/sources/${encodeURIComponent(id)}`, patch);
}

// DELETE /sources/{id} -> loescht eine Quelle samt Eintraegen (idempotent).
export async function deleteSource(id) {
  return apiDelete(`/api/blocklist/sources/${encodeURIComponent(id)}`);
}

// POST /sources/{id}/refresh -> laedt EINE Quelle. Ein Download-/Parse-Fehler ist
// KEIN HTTP-Fehler: er kommt als { ok:false, error } zurueck.
export async function refreshSource(id) {
  const backend = await apiPost(
    `/api/blocklist/sources/${encodeURIComponent(id)}/refresh`,
  );
  return mappeRefresh(backend);
}

// POST /refresh-due -> refresht alle faelligen Quellen (Intervall aus Settings).
// Antwort: je Quelle ein Lade-Ergebnis.
export async function refreshDue() {
  const backend = await apiPost("/api/blocklist/refresh-due");
  return { results: (backend?.results ?? []).map(mappeRefresh) };
}

// POST /reset-defaults -> Werkszustand der Listen (leeren + Werksquellen neu anlegen).
export async function resetDefaults() {
  return apiPost("/api/blocklist/reset-defaults");
}

// GET /health -> je BROKEN-Quelle ein Befund + optionaler Ersatzvorschlag.
export async function fetchHealth() {
  const backend = await apiGet("/api/blocklist/health");
  return { issues: (backend?.issues ?? []).map(mappeHealthIssue) };
}

// GET /settings -> Strenge + Refresh-Intervall + Gruppen-Feinschalter (camelCase).
export async function fetchSettings() {
  const backend = await apiGet("/api/blocklist/settings");
  return {
    strictness: backend.strictness,
    refreshIntervalDays: backend.refresh_interval_days,
    groupTrackerAdsEnabled: backend.group_tracker_ads_enabled,
    groupThreatEnabled: backend.group_threat_enabled,
  };
}

// PUT /settings -> schreibt die gesetzten Settings-Felder. patch ist camelCase und
// wird hier auf snake_case abgebildet; nur definierte Felder werden gesendet
// (undefined faellt raus -> Backend laesst sie unveraendert). 422 bei ungueltiger
// Strenge (kein stiller Fallback).
export async function writeSettings(patch) {
  const body = {};
  if (patch.strictness !== undefined) {
    body.strictness = patch.strictness;
  }
  if (patch.refreshIntervalDays !== undefined) {
    body.refresh_interval_days = patch.refreshIntervalDays;
  }
  if (patch.groupTrackerAdsEnabled !== undefined) {
    body.group_tracker_ads_enabled = patch.groupTrackerAdsEnabled;
  }
  if (patch.groupThreatEnabled !== undefined) {
    body.group_threat_enabled = patch.groupThreatEnabled;
  }
  return apiPut("/api/blocklist/settings", body);
}

// POST /match -> gleicht Aussenkontakte gegen die aktiven Listen ab. contacts ist ein
// Array { remoteIp, hostname? }; strictness optional (fehlt sie, liest das Backend die
// Settings). Wird von CC-4 (Block-Ansicht) genutzt — hier schon mit-exportiert.
export async function matchContacts(contacts, strictness) {
  const body = {
    contacts: (contacts ?? []).map((c) => ({
      remote_ip: c.remoteIp,
      hostname: c.hostname ?? null,
    })),
  };
  if (strictness !== undefined && strictness !== null) {
    body.strictness = strictness;
  }
  const backend = await apiPost("/api/blocklist/match", body);
  return { results: (backend?.results ?? []).map(mappeContactMatch) };
}

export default {
  fetchSources,
  addSource,
  uploadSource,
  updateSource,
  deleteSource,
  refreshSource,
  refreshDue,
  resetDefaults,
  fetchHealth,
  fetchSettings,
  writeSettings,
  matchContacts,
};
