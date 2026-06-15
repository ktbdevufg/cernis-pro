// Scan-Live-Strom (CERNIS PRO 2.0)
//
// Gekapselter WebSocket für den Netzwerk-Scan (/ws/scan). KEIN nacktes
// new WebSocket in der Komponente — die View kennt nur die Callbacks und das
// { stop() }-Handle. Einmal-Scan: kein Reconnect; bei scan_complete oder error
// schließt der Socket sich selbst.
//
// Protokoll: Frontend sendet nach onopen EINMAL die Config-JSON, das Backend
// antwortet mit einem Event-Strom. Die Frames werden über frame.type auf die
// passenden Callbacks dispatcht; host_found/host_detail laufen vorher durch den
// gemeinsamen Mapper aus ./scan.js (eine Mapper-Quelle für WS und REST).
//
// Fehler werden NIE geworfen, IMMER über onError gemeldet. Ein "fertig"-Flag
// verhindert Doppel-Callbacks (z. B. error gefolgt von onclose).

import { mappeHost, mappeHostFound } from "./scan.js";

// Baut die WS-URL RELATIV aus window.location: wss bei https, sonst ws; Host
// aus window.location.host; Pfad /ws/scan. NIE einen Host hartkodieren — der
// Vite-Proxy leitet /ws/ ans Backend.
function baueWsUrl() {
  const protokoll = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${protokoll}//${window.location.host}/ws/scan`;
}

// Startet einen Scan-Strom. Liefert ein Handle { stop() }. Alle Callbacks sind
// optional; fehlende werden schlicht übersprungen.
export function starteScanStream({
  cidr,
  onHostFound,
  onHostDetail,
  onProgress,
  onPhase,
  onStarted,
  onInfo,
  onComplete,
  onError,
}) {
  // Einmal-Flag: nach Abschluss (complete/error/stop) keine Callbacks mehr und
  // kein doppeltes onError aus einem nachgelagerten onclose.
  let fertig = false;

  const meldeFehler = (nachricht) => {
    if (fertig) {
      return;
    }
    fertig = true;
    onError?.(nachricht);
  };

  let socket;
  try {
    socket = new WebSocket(baueWsUrl());
  } catch {
    // Schon der Verbindungsaufbau kann werfen (ungültige URL o. Ä.) — als
    // Fehler über onError melden, nicht aus starteScanStream heraus werfen.
    meldeFehler("Scan-Verbindung fehlgeschlagen");
    return { stop() {} };
  }

  socket.onopen = () => {
    // EINE Config-Nachricht direkt nach dem Verbindungsaufbau. cidr ist das
    // Wichtige; die übrigen Felder haben Backend-Defaults.
    try {
      socket.send(
        JSON.stringify({
          cidr,
          port_scan: true,
          mdns_scan: true,
          resolve_hostnames: true,
          ssdp_scan: true,
        }),
      );
    } catch {
      meldeFehler("Scan-Konfiguration konnte nicht gesendet werden");
    }
  };

  socket.onmessage = (ereignis) => {
    if (fertig) {
      return;
    }
    let frame;
    try {
      frame = JSON.parse(ereignis.data);
    } catch {
      // Unlesbarer Frame: tolerieren (ein Aussetzer kippt den Scan nicht).
      return;
    }

    switch (frame.type) {
      case "host_found":
        onHostFound?.(mappeHostFound(frame));
        break;
      case "host_detail":
        onHostDetail?.(mappeHost(frame));
        break;
      case "progress":
        onProgress?.(frame);
        break;
      case "phase":
        onPhase?.(frame);
        break;
      case "scan_started":
        onStarted?.(frame);
        break;
      case "info":
        onInfo?.(frame);
        break;
      case "scan_complete":
        // Einmal-Scan: nach complete selbst schließen, keine Callbacks mehr.
        fertig = true;
        onComplete?.(frame);
        socket.close();
        break;
      case "error":
        // meldeFehler setzt fertig; danach den Socket schließen.
        meldeFehler(frame.message);
        socket.close();
        break;
      default:
        // Unbekannter Frame-Typ: ignorieren (vorwärtskompatibel).
        break;
    }
  };

  socket.onerror = () => {
    // Transport-Fehler vor scan_complete: generische Meldung (sofern nicht
    // schon abgeschlossen). onclose folgt; das fertig-Flag verhindert Doppeln.
    meldeFehler("Scan-Verbindung unterbrochen");
  };

  socket.onclose = () => {
    // Unerwartetes Schließen vor scan_complete -> Fehler. Nach regulärem
    // Abschluss (fertig===true) passiert hier nichts mehr.
    meldeFehler("Scan-Verbindung geschlossen");
  };

  return {
    // Sauber schließen, als fertig markieren, keine weiteren Callbacks.
    // Idempotent: mehrfaches stop() schadet nicht.
    stop() {
      if (fertig) {
        // Schon fertig: Socket ggf. trotzdem schließen, aber nichts melden.
        try {
          socket.close();
        } catch {
          // bereits geschlossen
        }
        return;
      }
      fertig = true;
      try {
        socket.close();
      } catch {
        // bereits geschlossen
      }
    },
  };
}

export default { starteScanStream };
