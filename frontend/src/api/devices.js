// Geräte-Mapper (CERNIS PRO 2.0)
//
// Übersetzt die Backend-Antwort von PUT /api/devices/{mac} (kuratierte
// Gerätenotizen: label/tags/notes etc., snake_case) in die View-Form
// (camelCase) und kapselt den Schreibpfad. Stil bewusst wie api/interfaces.js:
// kleine reine Helfer, kein erfundener Fallback (fehlt ein Feld -> leer/null).
//
// Wire-Form (aus backend/api/devices.py):
//   { mac, vendor, label, notes, category, is_known, hostname, os_guess,
//     tags[], open_ports[], last_ip, times_seen, first_seen, last_seen }

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
// bewusst NICHT angefasst.
export async function updateDeviceMeta(mac, { label, tags, notes }) {
  const body = { label, tags, notes };
  const antwort = await apiPut(
    `/api/devices/${encodeURIComponent(mac)}`,
    body,
  );
  return mappeDevice(antwort);
}

export default { updateDeviceMeta };
