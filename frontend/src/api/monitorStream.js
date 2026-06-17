// Monitor-Live-Strom (CERNIS PRO 2.0)
//
// Gekapselter WebSocket fuer den Live-Monitor (/ws/monitor). Wie scanStream.js
// (KEIN nacktes new WebSocket in der Komponente, nur Callbacks + { stop() }),
// ABER endlos: der Monitor hat keinen "fertig"-Zustand. Statt sich zu schliessen
// verbindet er bei Verbindungsverlust nach kurzer Verzoegerung automatisch neu —
// SOLANGE stop() nicht gerufen wurde.
//
// Protokoll: Der Monitor sendet NICHTS nach onopen (anders als scanStream, das
// die Scan-Config schickt). Das Backend pusht von sich aus:
//   * Connect-Frame   { type: "monitor_status", status: { tid: {alive,label} } }
//   * Update-Frames    { type: "monitor_update", target_id, label, alive, rtt_ms,
//                        loss_pct, event (string|null), ts } (laufend)
//
// Fehler werden NIE geworfen, IMMER ueber onError gemeldet (darf bei jedem
// Reconnect-Versuch erneut feuern). Nach stop() feuert kein Callback mehr.

import { mappeStatus } from "./monitoring.js";

// Wartezeit vor einem Reconnect-Versuch (ms). EINE Konstante — bewusst kurz, der
// Live-Monitor soll nach einem Aussetzer zuegig wieder anhaengen.
const RECONNECT_VERZOEGERUNG_MS = 2000;

// Baut die WS-URL RELATIV aus window.location: wss bei https, sonst ws; Host aus
// window.location.host; Pfad /ws/monitor. NIE einen Host hartkodieren — der
// Vite-Proxy leitet /ws/ ans Backend (exakt wie scanStream.baueWsUrl).
function baueWsUrl() {
  const protokoll = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${protokoll}//${window.location.host}/ws/monitor`;
}

// Startet den Monitor-Strom. Liefert ein Handle { stop() }. Alle Callbacks sind
// optional; fehlende werden schlicht uebersprungen.
export function starteMonitorStream({ onStatus, onUpdate, onError, onOpen, onClose }) {
  // Gestoppt-Flag: nach stop() keine Callbacks mehr und kein Reconnect mehr.
  let gestoppt = false;
  // Referenzen, damit stop() den laufenden Reconnect-Timer loeschen und den
  // aktuellen Socket schliessen kann.
  let socket = null;
  let reconnectTimer = null;

  // Plant einen Reconnect-Versuch — aber nur wenn nicht gestoppt und nicht schon
  // ein Timer laeuft (kein doppeltes Verbinden aus onerror + onclose).
  const planeReconnect = () => {
    if (gestoppt || reconnectTimer !== null) {
      return;
    }
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null;
      verbinde();
    }, RECONNECT_VERZOEGERUNG_MS);
  };

  // Baut eine frische Verbindung auf. Bei Verlust (onclose/onerror) wird — sofern
  // nicht gestoppt — ein Reconnect geplant.
  const verbinde = () => {
    if (gestoppt) {
      return;
    }

    try {
      socket = new WebSocket(baueWsUrl());
    } catch {
      // Schon der Verbindungsaufbau kann werfen (ungueltige URL o. Ae.) — als
      // Fehler melden und erneut versuchen, nicht aus starteMonitorStream werfen.
      onError?.("Monitor-Verbindung fehlgeschlagen");
      planeReconnect();
      return;
    }

    socket.onopen = () => {
      if (gestoppt) {
        return;
      }
      // Kein Config-Senden — der Monitor pusht von sich aus.
      onOpen?.();
    };

    socket.onmessage = (ereignis) => {
      if (gestoppt) {
        return;
      }
      let frame;
      try {
        frame = JSON.parse(ereignis.data);
      } catch {
        // Unlesbarer Frame: tolerieren (ein Aussetzer kippt den Strom nicht).
        return;
      }

      switch (frame.type) {
        case "monitor_status":
          // Connect-Frame: status-Objekt wie in fetchMonitorStatus zu einer Liste
          // [{ targetId, label, alive }] mappen (eine Mapper-Quelle: monitoring.js).
          onStatus?.(mappeStatus(frame.status));
          break;
        case "monitor_update":
          // Laufendes Update -> camelCase. rtt_ms/loss_pct/event bleiben null wenn
          // null (ehrliche Luecke). ts roh durchgereicht (View formatiert).
          onUpdate?.({
            targetId: frame.target_id,
            label: frame.label,
            alive: Boolean(frame.alive),
            rttMs: frame.rtt_ms ?? null,
            lossPct: frame.loss_pct ?? null,
            event: frame.event ?? null,
            ts: frame.ts,
          });
          break;
        default:
          // Unbekannter Frame-Typ: ignorieren (vorwaertskompatibel).
          break;
      }
    };

    socket.onerror = () => {
      if (gestoppt) {
        return;
      }
      // Transport-Fehler: melden und Reconnect planen. onclose folgt meist; die
      // planeReconnect-Wache verhindert ein doppeltes Verbinden.
      onError?.("Monitor-Verbindung unterbrochen");
      planeReconnect();
    };

    socket.onclose = () => {
      if (gestoppt) {
        return;
      }
      // Verbindung verloren (NICHT endgueltig schliessen — Live-Monitor): melden
      // und Reconnect planen.
      onClose?.();
      planeReconnect();
    };
  };

  verbinde();

  return {
    // Endgueltig stoppen: Flag setzen, laufenden Reconnect-Timer loeschen, Socket
    // schliessen. Danach feuert kein Callback mehr. Idempotent: mehrfaches stop()
    // schadet nicht.
    stop() {
      gestoppt = true;
      if (reconnectTimer !== null) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
      if (socket) {
        try {
          socket.close();
        } catch {
          // bereits geschlossen
        }
      }
    },
  };
}

export default { starteMonitorStream };
