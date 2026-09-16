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
//   GET  /api/sni/status  -> {running, count, available, permission_error,
//                             stopped_reason}
//   GET  /api/sni/observed
//        -> [{hostname, remote_ip, remote_port, app_name, pid, delta_ms, age_secs}]
//
// Bündelschlüssel der Verkehrsliste ist die Remote-IP (conn.remote). SNI liefert
// pro remote_ip einen hostname — das ist der Verknüpfungspunkt.

import { ApiError, apiGet, apiPost } from "./client.js";

// Ursachen-Klassen eines gescheiterten SNI-Starts. Sie sind das, woran die
// Ansicht ihre Anzeige festmacht — NICHT der Anzeigetext, der je nach Sprache und
// Backend-Version anders lautet.
//
// Warum der HTTP-Status und nicht der Text? Der Backend-Rand trennt die Fälle
// bereits sauber (backend/app.py): ein Rechte-Fehler (SniPermissionError, also
// fehlendes CAP_NET_RAW) wird auf 403 abgebildet, JEDER andere Start-Fehler
// (SniError: Helfer-Spawn, Gerät weg, scapy) auf 503. Der Status ist damit die
// verlässliche, maschinenlesbare Form, in der die Unterscheidung im Frontend
// ankommt. Der Begründungstext selbst ist Freitext und wird NICHT gedeutet.
export const SNI_START_URSACHE = {
  PERMISSION: "permission", // fehlende Rechte -> Einrichtung kann helfen
  OTHER: "other", // anderer Grund -> Rechte-Knopf würde nichts bewirken
};

// Startet die SNI-Beobachtung. Body NUR mit interface, wenn gesetzt, sonst leeres
// Objekt {}. Gibt {ok, error, available, ursache, grund} zurück:
//   ursache — SNI_START_URSACHE.* bei ok=false, sonst null.
//   grund   — der WÖRTLICHE Begründungstext des Backends oder null. Er wird
//             unverändert durchgereicht und nirgends gedeutet oder ergänzt.
// error bleibt unverändert das, was es war (kurze technische Meldung) — damit
// hängt kein bestehender Aufrufer daran ab.
export async function startSni(schnittstelle = null) {
  const body = schnittstelle ? { interface: schnittstelle } : {};
  try {
    const antwort = await apiPost("/api/sni/start", body);
    const ok = Boolean(antwort.ok);
    const fehlertext = antwort.error ?? null;
    return {
      ok,
      error: fehlertext,
      available: antwort.available ?? null,
      // Ein ok=false MIT 200 kommt aus der Vorprüfung (Npcap/libpcap fehlt) —
      // das ist kein Rechte-Fall, und der Text ist hier der echte Grund.
      ursache: ok ? null : SNI_START_URSACHE.OTHER,
      grund: ok ? null : fehlertext,
    };
  } catch (fehler) {
    if (fehler instanceof ApiError && fehler.status === 403) {
      // Fehlende Rechte: ehrlich als nicht-ok melden. Der Backend-Body trägt den
      // Grund (detail); er wird als grund mitgegeben, nicht gedeutet.
      return {
        ok: false,
        error: fehler.message,
        available: null,
        ursache: SNI_START_URSACHE.PERMISSION,
        grund: fehler.detail ?? null,
      };
    }
    // Jeder andere Fehlschlag (503 aus SniError, Netzfehler, kaputte Antwort):
    // KEIN Rechte-Fall. Ein Rechte-Knopf würde hier nichts bewirken.
    return {
      ok: false,
      error: fehler instanceof Error ? fehler.message : String(fehler),
      available: null,
      ursache: SNI_START_URSACHE.OTHER,
      grund: fehler instanceof ApiError ? (fehler.detail ?? null) : null,
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
// permission_error -> permissionError sowie stopped_reason -> stoppedReason um
// (camelCase nach Frontend-Konvention).
//
// stoppedReason traegt einen STABILEN Marker des Backends, wenn die Beobachtung
// sich SELBST beendet hat (SNI_POLL_FAILED, SNI_HELPER_DEAD); null heisst: kein
// Selbst-Abbruch. Der Marker wird hier NICHT gedeutet und NICHT in Text
// uebersetzt -- exakt das Muster von permission_error/NPCAP_MISSING: das Backend
// benennt die Lage, den Wortlaut besitzt das Frontend (i18n).
export async function fetchSniStatus() {
  const backend = await apiGet("/api/sni/status");
  return {
    running: Boolean(backend.running),
    count: backend.count ?? 0,
    available: backend.available ?? null,
    permissionError: backend.permission_error ?? null,
    stoppedReason: backend.stopped_reason ?? null,
  };
}

// Marker des Selbst-Abbruchs (aus stopped_reason, siehe Backend
// infrastructure/sni/sni_sniffer.py). Zwei Lagen, in denen die Beobachtung von
// selbst aufhoert: die Datenquelle antwortet beim Abholen nicht mehr, oder der
// Mitschnitt-Helfer ist beendet. Läuft die Beobachtung, liefert das Backend
// keinen Marker (null).
export const SNI_STOPPED_MARKER = {
  POLL_FAILED: "SNI_POLL_FAILED",
  HELPER_DEAD: "SNI_HELPER_DEAD",
};

// Marker -> i18n-Schlüssel des Anzeigetexts.
const SNI_STOPPED_SCHLUESSEL = {
  [SNI_STOPPED_MARKER.POLL_FAILED]: "beobachten.traffic.sniStoppedPollFailed",
  [SNI_STOPPED_MARKER.HELPER_DEAD]: "beobachten.traffic.sniStoppedHelperDead",
};

// Reine, testbare Auswahl: Marker -> i18n-Schlüssel. null/leer -> null (nichts
// anzuzeigen, kein Selbst-Abbruch). Ein UNBEKANNTER Marker fällt auf den
// neutralen Text zurück statt auf einen leeren Kasten: dass die Aufzeichnung
// beendet ist, stimmt in jeder dieser Lagen — nur der Grund ist dann nicht
// benennbar. Muster wie trafficPermissionSchluessel in api/traffic.js.
export function sniStoppedSchluessel(marker) {
  if (!marker) {
    return null;
  }
  return SNI_STOPPED_SCHLUESSEL[marker] ?? "beobachten.traffic.sniStoppedUnbekannt";
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

export default {
  startSni,
  stopSni,
  fetchSniStatus,
  fetchSniMap,
  sniStoppedSchluessel,
};
