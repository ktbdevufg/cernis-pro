// Kopfzeilen-Pill "DNS-Aufzeichnung laeuft" (CERNIS PRO 2.0)
//
// Strukturgleich zum gelben OutboundRecordingPill, nur auf die NETZWEITE DNS-
// Umgehungs-Aufzeichnung bezogen: sichtbar, SOBALD eine DNS-Aufzeichnung laeuft
// (recording === true). Pulsierender Punkt, Text "DNS-Aufzeichnung laeuft",
// optional dezent die gesammelte Anzahl (collectedQueries). Klick fuehrt zur
// DNS-Waechter-Sicht (onOeffnen). Keine aktive Aufzeichnung -> nichts gerendert.
//
// Wie das Vorbild ist die DNS-Aufzeichnung eine NUTZERGESTARTETE Aufzeichnung
// (kein rotes Live-Monitoring): deshalb dieselbe gelbe Pill-Optik wie
// OutboundRecordingPill (gemeinsame CSS-Klassen/Tokens, kein eigenes CSS).
//
// Datengetrieben ueber einen EIGENEN, sichtbarkeitsbewussten Poll ueber die schon
// vorhandene fetchDnsBypassStatus() (billiger Status-Poll). Der Poll pausiert bei
// document.hidden -- ein unsichtbarer Tab pollt nicht. Fehler werden toleriert wie
// im Rest des Frontends: ein Ladefehler kippt nichts (Pill aus). KEIN t im
// Effect-Dep-Array (keine Render-Loop).

import { CircleDot } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { fetchDnsBypassStatus } from "../api/dnsBypass.js";
import "./OutboundRecordingPill.css";

// Poll-Intervall des Status (ms). Moderat (5 s): genug fuer eine
// Sichtbarkeits-Pill, kein Dauer-Polling im Sekundentakt.
const POLL_MS = 5000;

export default function DnsBypassRecordingPill({ onOeffnen }) {
  const { t } = useTranslation();

  // Laeuft gerade eine DNS-Aufzeichnung? Und wie viele Anfragen sind gesammelt?
  // Ausgangszustand: nicht laufend (Pill aus), 0 gesammelt.
  const [recording, setRecording] = useState(false);
  const [collectedQueries, setCollectedQueries] = useState(0);

  // Status pollen: sofort und dann alle POLL_MS. Sichtbarkeitsbewusst -- bei
  // verstecktem Tab (document.hidden) wird nicht gepollt. Fehler werden toleriert
  // (recording -> false -> Pill bleibt aus).
  useEffect(() => {
    let abgebrochen = false;

    const laden = async () => {
      if (document.hidden) {
        return;
      }
      try {
        const status = await fetchDnsBypassStatus();
        if (!abgebrochen) {
          setRecording(status.recording);
          setCollectedQueries(status.collectedQueries);
        }
      } catch {
        // Status nicht erreichbar: Pill bleibt aus, kein Hinweis.
        if (!abgebrochen) {
          setRecording(false);
        }
      }
    };

    laden();
    const id = setInterval(laden, POLL_MS);
    return () => {
      abgebrochen = true;
      clearInterval(id);
    };
  }, []);

  // Keine laufende Aufzeichnung -> nicht rendern.
  if (!recording) {
    return null;
  }

  // Gesammelte Anzahl nur zeigen, wenn schon etwas gesammelt wurde -- dezent, im
  // Rest-Slot des Vorbilds.
  const zaehlerText =
    collectedQueries > 0
      ? t("header.dnsRecCount", { count: collectedQueries })
      : null;

  return (
    <button
      type="button"
      className="outboundrec-pill"
      onClick={onOeffnen}
      title={t("header.dnsRecZurAnsicht")}
      aria-label={t("header.dnsRecZurAnsicht")}
    >
      <span className="outboundrec-pill__punkt" aria-hidden="true" />
      <CircleDot size={14} aria-hidden="true" />
      <span className="outboundrec-pill__text">{t("header.dnsRecOne")}</span>
      {zaehlerText && (
        <span className="outboundrec-pill__rest">· {zaehlerText}</span>
      )}
    </button>
  );
}
