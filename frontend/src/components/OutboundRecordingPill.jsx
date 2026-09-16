// Kopfzeilen-Pill "Aussenkontakte-Aufzeichnung laeuft" (CERNIS PRO 2.0, F3)
//
// Strukturgleich zum roten LivePill (LivePill.jsx), nur GELB und auf die
// Aussenkontakte-Aufzeichnung bezogen: sichtbar, SOBALD host-weit eine
// Aufzeichnung ACTIVE ist (host-weit gibt es hoechstens eine). Pulsierender
// Punkt, Text "Aussenkontakte-Aufzeichnung laeuft", bei einer Detail-Aufzeichnung
// mit bestimmbarem Ende zusaetzlich die Restzeit ("noch X"). Klick fuehrt zur
// Aussenkontakte-Ansicht (onOeffnen). Keine aktive Aufzeichnung -> nichts gerendert.
//
// Datengetrieben ueber einen EIGENEN, MODERATEN Poll (fetchRecordings alle 20s --
// kein Sekundentakt; das reicht und schont das Backend). Die Restzeit selbst
// laeuft per Sekunden-Tick rein clientseitig weiter (kein Backend). Fehler werden
// toleriert wie im Rest des Frontends: ein Ladefehler kippt nichts (Pill aus).
//
// Restzeit: Der generische Formatierer formatiereRestzeit (loggingTask.js) wird
// WIEDERVERWENDET -- er ist rein (t + Sekunden + i18n-Praefix) und nicht logging-
// spezifisch. Das Ende wird hier inline bestimmt (endeTs aus loggingTask.js passt
// NICHT: es kennt operationMode scheduled/immediate, nicht den Aufzeichnungs-modus
// detail/aggregate). Nur mode==="detail" mit effectiveStart + maxDurationS hat ein
// bestimmbares Ende; aggregate (zeitlich unbegrenzt) zeigt nur "laeuft".

import { CircleDot } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { fetchRecordings } from "../api/outboundLog.js";
import { formatiereRestzeit } from "./loggingTask.js";
import "./OutboundRecordingPill.css";

// Poll-Intervall der Aufzeichnungs-Liste (ms). Moderat (20 s): genug fuer eine
// Restzeit-Anzeige, kein Dauer-Polling im Sekundentakt.
const POLL_MS = 20000;

// Sekunden-Tick fuer die laufende Restzeit-Anzeige (rein clientseitig, kein Poll).
const TICK_MS = 1000;

export default function OutboundRecordingPill({ onOeffnen }) {
  const { t } = useTranslation();

  // Die aktuell aktive Aufzeichnung (state==="active") ODER null. Host-weit gibt es
  // hoechstens eine -- daher die erste/einzige active.
  const [aktiv, setAktiv] = useState(null);
  // Sekunden-Tick fuer die Restzeit (Wanduhr in Sekunden).
  const [jetzt, setJetzt] = useState(() => Date.now() / 1000);

  // Aufzeichnungen pollen: sofort und dann alle POLL_MS. Nur die ACTIVE behalten.
  // Fehler werden toleriert (leere Liste -> null -> Pill bleibt aus).
  useEffect(() => {
    let abgebrochen = false;

    const laden = async () => {
      try {
        const liste = await fetchRecordings();
        if (!abgebrochen) {
          setAktiv(liste.find((rec) => rec.state === "active") ?? null);
        }
      } catch {
        // Aufzeichnungen nicht erreichbar: Pill bleibt aus, kein Hinweis.
        if (!abgebrochen) {
          setAktiv(null);
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

  // Sekunden-Tick fuer die laufende Restzeit-Anzeige (kein Backend).
  useEffect(() => {
    const id = setInterval(() => setJetzt(Date.now() / 1000), TICK_MS);
    return () => clearInterval(id);
  }, []);

  // Keine aktive Aufzeichnung -> nicht rendern.
  if (aktiv === null) {
    return null;
  }

  // Ende NUR bestimmbar bei einer Detail-Aufzeichnung mit effektivem Start und
  // Maximaldauer: ende = effectiveStart + maxDurationS. Bei aggregate (zeitlich
  // unbegrenzt) oder fehlenden Feldern bleibt es null -> keine Restzeit, nur "laeuft".
  const ende =
    aktiv.mode === "detail" &&
    aktiv.effectiveStart !== null &&
    aktiv.maxDurationS !== null
      ? aktiv.effectiveStart + aktiv.maxDurationS
      : null;
  const restText =
    ende !== null
      ? formatiereRestzeit(Math.max(0, ende - jetzt), t, "header.outboundRecRest")
      : null;

  return (
    <button
      type="button"
      className="outboundrec-pill"
      onClick={onOeffnen}
      title={t("header.outboundRecZurAnsicht")}
      aria-label={t("header.outboundRecZurAnsicht")}
    >
      <span className="outboundrec-pill__punkt" aria-hidden="true" />
      <CircleDot size={14} aria-hidden="true" />
      <span className="outboundrec-pill__text">{t("header.outboundRecOne")}</span>
      {restText && <span className="outboundrec-pill__rest">· {restText}</span>}
    </button>
  );
}
