// Maintenance-API-Client (CERNIS PRO 2.0)
//
// Dünne, reine Wrapper um die Wartungs-Endpunkte des Backends (Daten-Löschung in
// zwei Stufen). Stil bewusst wie api/settings.js: knappe Helfer über client.js,
// kein erfundener Fallback, Fehler kommen als ApiError aus dem Client durch.
//
// Wire-Form (aus backend/api/maintenance.py):
//   POST /api/maintenance/reset-scan-data                       -> { ok: true }
//   POST /api/maintenance/factory-reset  Body { include_secrets } -> { ok: true }

import { apiPost } from "./client.js";

// Stufe 1: leert NUR Scan-/CVE-/Baseline-/Quittierungs-Befunde. Kein Body nötig.
export async function resetScanData() {
  return apiPost("/api/maintenance/reset-scan-data");
}

// Stufe 2 (Werkszustand): setzt alles zurück. includeSecrets entscheidet, ob die
// gespeicherten Zugangsdaten (Secrets im Schlüsselbund) mitentfernt werden.
export async function factoryReset(includeSecrets) {
  return apiPost("/api/maintenance/factory-reset", {
    include_secrets: includeSecrets,
  });
}

export default { resetScanData, factoryReset };
