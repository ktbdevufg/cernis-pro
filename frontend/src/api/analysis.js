// Analysis-API-Client (CERNIS PRO 2.0)
//
// Kleiner reiner Helfer um den analysis-Service-Lookup. Stil bewusst wie
// api/settings.js: dünner Wrapper über client.js, kein erfundener Fallback.
//
// Wire-Form (aus backend/api/analysis.py):
//   GET /api/analysis/service?port=N -> { port: N, service: string|null }.
//        Ein gültiger, aber nicht gelisteter Port liefert service: null
//        (legitimer Leer-Zustand). Ein Port außerhalb 1–65535 -> HTTP 422
//        (kein stiller Fallback); der Aufrufer prüft die Range VOR dem Aufruf.
//   GET /api/analysis/rules/all -> Liste aller aktiven Regeln (Built-in + User)
//        je { id, title, severity, disabled: bool, ... }. Quelle für den Block
//        „Regel-An/Aus" (ADR 0028). Leere Lage -> [].
//   POST /api/analysis/acknowledge { mac, port, severity, action } -> quittiert
//        bzw. nimmt die Quittierung eines bewerteten Ports zurück (Schnitt 8a,
//        ADR 0031). action ist "ack" | "unack". Wirkt erst beim nächsten Scan.

import { apiGet, apiPost } from "./client.js";

// Schlägt den gängigen Service-Namen zu einem Port nach. Liefert den Namen oder
// null (gültiger, aber unbekannter Port). Wirft ApiError bei Netz-/HTTP-Fehler;
// der Aufrufer fängt das und zeigt den Leer-Zustand „—".
export async function lookupService(port) {
  const antwort = await apiGet("/api/analysis/service", { port });
  return antwort?.service ?? null;
}

// Holt ALLE aktuell aktiven Regeln (Built-in + User) mit Toggle-Status. Fehlt die
// Antwort (null/undefined), -> [], damit der Aufrufer gefahrlos darüber mappen kann.
export async function fetchAllRules() {
  return (await apiGet("/api/analysis/rules/all")) ?? [];
}

// Reine, isoliert testbare Extraktion einer Portliste aus dem TEXT einer Datei
// (Schnitt 7, Konzept §3.2). Wird clientseitig nach FileReader.readAsText
// aufgerufen; NUR das Ergebnis-Array verlässt später das Frontend (über den
// bestehenden updateSetting-Pfad) — die rohe Datei wird NIE hochgeladen.
//
// Das Backend prüft Portlisten-Werte NICHT gegen (verifiziert), deshalb ist diese
// Validierung lückenlos und die einzige Schranke. Reine Zahlen-Extraktion: kein
// eval, kein JSON.parse, keine Pfad-/Code-Auswertung.
//
// Trennung: pro Zeile ein Port; zusätzlich tolerant gegen Komma/Semikolon als
// Trenner innerhalb einer Zeile. Pro Token: trimmen, alles ab '#' als Kommentar
// abschneiden, Leer-Token überspringen (zählt NICHT als ungültig). Gültig =
// ganzzahlig (kein Float, keine Buchstaben) UND 1 <= n <= 65535; sonst zählt das
// Token als „ungültig" (nicht still verworfen — die Anzahl wird angezeigt).
//
// Rückgabe: { gueltig: number[], ungueltig: number, gesamt: number }, wobei
// gueltig sortiert und dedupliziert ist und gesamt die Zahl der nicht-leeren
// Token (gültig + ungültig) ist.
// Quittiert die Achse-B-Bewertung eines Ports bzw. nimmt sie zurück (ADR 0031).
// action ist "ack" (quittieren) | "unack" (wieder scharf stellen). severity ist
// nur Audit-Metadatum fürs Backend. Wirft ApiError bei Netz-/HTTP-Fehler; der
// Aufrufer fängt das und zeigt den Fehlerhinweis am Port. Liefert die Wire-Antwort
// durch — das Frontend mutiert nichts optimistisch, der Effekt kommt beim nächsten
// Scan über das host_detail-Frame.
export async function acknowledge(mac, port, severity, action) {
  return apiPost("/api/analysis/acknowledge", { mac, port, severity, action });
}

export function parsePortliste(text) {
  const roh = typeof text === "string" ? text : "";
  const gueltigeSet = new Set();
  let ungueltig = 0;
  let gesamt = 0;

  for (const zeile of roh.split(/\r?\n/)) {
    for (const stueck of zeile.split(/[,;]/)) {
      // Kommentar ab '#' abschneiden, dann trimmen.
      const ohneKommentar = stueck.split("#")[0];
      const token = ohneKommentar.trim();
      if (token === "") {
        continue; // Leer-Token (oder reine Kommentarzeile) zählt nicht.
      }
      gesamt += 1;
      // Streng ganzzahlig: nur ASCII-Ziffern, keine Vorzeichen/Floats/Buchstaben.
      if (!/^\d+$/.test(token)) {
        ungueltig += 1;
        continue;
      }
      const port = Number(token);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        ungueltig += 1;
        continue;
      }
      gueltigeSet.add(port);
    }
  }

  const gueltig = [...gueltigeSet].sort((a, b) => a - b);
  return { gueltig, ungueltig, gesamt };
}

export default { lookupService, fetchAllRules, acknowledge, parsePortliste };
