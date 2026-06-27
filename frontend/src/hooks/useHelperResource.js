// Generischer Helfer-Ressourcen-Lifecycle-Hook (CERNIS PRO 2.0)
//
// Eine Backend-Helfer-Ressource (z. B. der EINE Sniffer hinter der SNI-Beobachtung)
// kann von mehreren Ansichten gleichzeitig gebraucht werden. Ohne Koordination
// würde das unmount/stop der einen Ansicht die andere abwürgen. Dieser Hook löst
// das über einen key-basierten Reference-Count: real GESTARTET wird beim ERSTEN
// acquire, real GESTOPPT erst beim LETZTEN release.
//
// Generisch über einen string-key, damit spätere Sniffer-Funktionen (LLDP/pcap)
// dieselbe Naht mit eigenem key nutzen können — ohne die Mechanik neu zu erfinden.
// Bewusst schlank: KEIN Dauer-Polling, KEINE spekulative Multi-Sniffer-
// Orchestrierung — nur refCount + injizierte start/stop/status.
//
// Defensiv (S3-Linie): Fehler werden in `error` gespiegelt, NIE nach außen
// geworfen. Kein console-Spam.

import { useCallback, useEffect, useState } from "react";

// Modul-globale Registry: eine Instanz für ALLE Hook-Instanzen, prozessweit.
// key (string) -> Eintrag. Kein React-Context nötig — die Registry lebt im Modul.
const registry = new Map();

// Legt den Eintrag für einen key lazy an und gibt ihn zurück.
function getEntry(key) {
  let eintrag = registry.get(key);
  if (!eintrag) {
    eintrag = {
      running: false,
      starting: false,
      error: null,
      refCount: 0,
      start: null, // zuletzt registrierter Start-Callback dieses key
      stop: null, // zuletzt registrierter Stop-Callback dieses key
      subscribers: new Set(), // Re-Render-Notifier der Hook-Instanzen
    };
    registry.set(key, eintrag);
  }
  return eintrag;
}

// Benachrichtigt alle Subscriber des key über eine Zustandsänderung.
function notify(key) {
  const eintrag = registry.get(key);
  if (!eintrag) {
    return;
  }
  for (const rerender of eintrag.subscribers) {
    rerender();
  }
}

// Der Hook. start/stop/status sind async; status ist optional.
//   start()  -> {ok, error}        (wie api/sni.js startSni)
//   stop()   -> best-effort
//   status() -> {running, ...}     (wie fetchSniStatus)
// Der Hook hängt NICHT an konkreten Feldnamen außer running/ok/error.
export function useHelperResource(key, { start, stop, status } = {}) {
  const eintrag = getEntry(key);

  // Beim (Re-)Render die zuletzt übergebenen Callbacks am Eintrag verankern,
  // damit acquire/release immer die aktuellsten nutzen.
  eintrag.start = start;
  eintrag.stop = stop;

  // Lokaler State nur als Re-Render-Auslöser (der echte Zustand liegt im Eintrag).
  const [, setTick] = useState(0);

  // Mount: als Subscriber registrieren; Unmount: wieder entfernen.
  useEffect(() => {
    const aktuellerEintrag = getEntry(key);
    const rerender = () => setTick((t) => t + 1);
    aktuellerEintrag.subscribers.add(rerender);
    return () => {
      aktuellerEintrag.subscribers.delete(rerender);
    };
  }, [key]);

  // Bedarf anmelden. Erst-acquire startet real; Folge-acquires zählen nur hoch.
  const acquire = useCallback(async () => {
    const e = getEntry(key);
    e.refCount += 1;
    if (e.refCount === 1 && !e.running) {
      e.starting = true;
      notify(key);
      try {
        const r = e.start ? await e.start() : null;
        if (r && r.ok === false) {
          e.error = r.error ?? "Start fehlgeschlagen";
          e.running = false;
        } else {
          e.running = true;
          e.error = null;
        }
      } catch (fehler) {
        e.error = String(fehler?.message ?? fehler);
        e.running = false;
      } finally {
        e.starting = false;
        notify(key);
      }
    } else {
      // Lief schon: nur sichtbar machen, dass die Ressource aktiv ist.
      e.running = true;
      notify(key);
    }
  }, [key]);

  // Bedarf abmelden. Letztes release stoppt real.
  const release = useCallback(async () => {
    const e = getEntry(key);
    if (e.refCount > 0) {
      e.refCount -= 1;
    }
    if (e.refCount === 0 && e.running) {
      try {
        if (e.stop) {
          await e.stop();
        }
      } finally {
        e.running = false;
        e.error = null;
        notify(key);
      }
    }
  }, [key]);

  // Optionaler externer Ist-Zustand: übernimmt ein laufendes Backend, falls der
  // Eintrag es noch nicht weiß. Reines Beiwerk — wirft nie.
  const syncStatus = useCallback(async () => {
    if (!status) {
      return;
    }
    try {
      const s = await status();
      const e = getEntry(key);
      if (s && s.running === true && !e.running) {
        e.running = true;
        notify(key);
      }
    } catch {
      // ignorieren (Beiwerk, nie werfen)
    }
  }, [key, status]);

  return {
    running: eintrag.running,
    starting: eintrag.starting,
    error: eintrag.error,
    refCount: eintrag.refCount,
    acquire,
    release,
    syncStatus,
  };
}

export default useHelperResource;
