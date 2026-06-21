// Geräte-Mapper (CERNIS PRO 2.0)
//
// Übersetzt die Backend-Antwort von PUT /api/devices/{mac} (kuratierte
// Gerätenotizen: label/tags/notes etc., snake_case) in die View-Form
// (camelCase) und kapselt den Schreibpfad. Stil bewusst wie api/interfaces.js:
// kleine reine Helfer, kein erfundener Fallback (fehlt ein Feld -> leer/null).
//
// Wire-Form (aus backend/api/devices.py):
//   { mac, vendor, label, notes, category, is_known, trust_state, hostname,
//     os_guess, tags[], open_ports[], last_ip, times_seen, first_seen,
//     last_seen }

import { apiPut } from "./client.js";

// Ein Wire-Gerät -> View-Gerät. snake_case -> camelCase. Fehlende Felder
// werden leer/null, nicht erfunden.
export function mappeDevice(wire) {
  return {
    mac: wire.mac,
    vendor: wire.vendor,
    label: wire.label,
    notes: wire.notes,
    category: wire.category,
    isKnown: wire.is_known === true,
    // Wertende Einschätzung (trusted/neutral/watch). Defensiver Default
    // "neutral" — kein erfundener Wert, falls das Feld fehlt.
    trustState: wire.trust_state ?? "neutral",
    hostname: wire.hostname,
    osGuess: wire.os_guess,
    tags: wire.tags ?? [],
    openPorts: wire.open_ports ?? [],
    lastIp: wire.last_ip ?? null,
    timesSeen: wire.times_seen ?? null,
    firstSeen: wire.first_seen ?? null,
    lastSeen: wire.last_seen ?? null,
  };
}

// Reine Funktion: kommagetrennter Text -> string[]. An "," splitten, jeden Teil
// trimmen, leere Teile wegwerfen. "" -> []. Bewusst testbar exportiert.
export function tagsAusText(text) {
  return (text ?? "")
    .split(",")
    .map((teil) => teil.trim())
    .filter((teil) => teil.length > 0);
}

// Schreibt die kuratierten Notizfelder (label/tags/notes) eines Geräts per
// PUT /api/devices/{mac} und gibt das aktualisierte Gerät in View-Form zurück.
// Der Body enthält nur die übergebenen Felder; category/is_known werden hier
// bewusst NICHT angefasst. trust_state wird nur mitgesendet, wenn trustState
// übergeben wurde (partielles Update — sonst weglassen).
export async function updateDeviceMeta(mac, { label, tags, notes, trustState }) {
  const body = { label, tags, notes };
  if (trustState !== undefined) {
    body.trust_state = trustState;
  }
  const antwort = await apiPut(
    `/api/devices/${encodeURIComponent(mac)}`,
    body,
  );
  return mappeDevice(antwort);
}

// Sofort-speichernder Helfer für den Einordnungs-Klick: schickt NUR
// { trust_state } per PUT /api/devices/{mac} und gibt das gemappte Gerät
// zurück. Entkoppelt vom Notizen-Speichern; is_known wird serverseitig
// konsistent gesetzt und kommt über das gemappte Gerät zurück.
export async function setTrustState(mac, trustState) {
  const antwort = await apiPut(`/api/devices/${encodeURIComponent(mac)}`, {
    trust_state: trustState,
  });
  return mappeDevice(antwort);
}

export default { updateDeviceMeta, setTrustState };
