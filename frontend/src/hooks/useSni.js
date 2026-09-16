// SNI-Lifecycle-Hook (CERNIS PRO 2.0)
//
// Dünner, benannter Aufruf über useHelperResource mit dem festen key "sni".
// Die SNI-Beobachtung ist EINE globale Backend-Ressource (ein Sniffer); mehrere
// Ansichten (TrafficView, künftig OutboundView) teilen sie über den Reference-
// Count des Hooks. Keine weitere Logik hier.

import { useHelperResource } from "./useHelperResource.js";
import { startSni, stopSni, fetchSniStatus } from "../api/sni.js";

export function useSni() {
  return useHelperResource("sni", {
    start: startSni,
    stop: stopSni,
    status: fetchSniStatus,
  });
}

export default useSni;
