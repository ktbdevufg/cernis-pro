// Kopfzeilen-Pill "Live-Monitoring aktiv" (CERNIS PRO 2.0, §7)
//
// Sichtbar, SOBALD mindestens eine Logging-Aufgabe ACTIVE ist: ein rotes Pill mit
// pulsierendem Punkt, Text "Live-Monitoring aktiv" (bei 1) bzw. "N Monitorings
// aktiv", plus die Restzeit des naechsten endenden Tasks ("noch X"). Klick fuehrt
// zur Logging-Ansicht (onOeffnen). Kein aktiver Task -> nichts gerendert.
//
// Datengetrieben ueber einen EIGENEN, MODERATEN Poll (fetchLoggingTasks alle 20s
// -- kein Sekundentakt; das reicht fuer eine Restzeit-Anzeige und schont das
// Backend). Die Restzeit selbst laeuft per Sekunden-Tick rein clientseitig weiter
// (loggingTask.js), ohne dafuer das Backend zu fragen. Fehlertoleranz wie der Rest
// des Frontends: ein Ladefehler kippt nichts (Pill bleibt schlicht aus).

import { Activity } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { fetchLoggingTasks } from "../api/monitoring.js";
import { endeTs, formatiereRestzeit, ZUSTAND } from "./loggingTask.js";
import "./LivePill.css";

// Poll-Intervall der Aufgaben-Liste (ms). Moderat (20 s): genug fuer eine
// Restzeit-Anzeige, kein Dauer-Polling im Sekundentakt.
const POLL_MS = 20000;

// Sekunden-Tick fuer die laufende Restzeit-Anzeige (rein clientseitig, kein Poll).
const TICK_MS = 1000;

export default function LivePill({ onOeffnen }) {
  const { t } = useTranslation();

  // Aktuell aktive Aufgaben (nur ACTIVE), aus dem Poll.
  const [aktive, setAktive] = useState([]);
  // Sekunden-Tick fuer die Restzeit (Wanduhr in Sekunden).
  const [jetzt, setJetzt] = useState(() => Date.now() / 1000);

  // Aufgaben pollen: sofort und dann alle POLL_MS. Nur ACTIVE behalten. Fehler
  // werden toleriert (leere Liste -> Pill bleibt aus).
  useEffect(() => {
    let abgebrochen = false;

    const laden = async () => {
      try {
        const liste = await fetchLoggingTasks();
        if (!abgebrochen) {
          setAktive(liste.filter((task) => task.state === ZUSTAND.ACTIVE));
        }
      } catch {
        // Aufgaben nicht erreichbar: Pill bleibt aus, kein Hinweis in der Kopfzeile.
        if (!abgebrochen) {
          setAktive([]);
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

  // Kein aktiver Task -> nicht rendern (Maske §7).
  if (aktive.length === 0) {
    return null;
  }

  // Naechstes Ende (kleinster bestimmbarer Ende-ts) ueber alle aktiven Tasks.
  // Tasks ohne bestimmbares Ende (kein effective_start / kein Fenster) zaehlen
  // nicht in die Restzeit, halten das Pill aber sichtbar.
  const enden = aktive.map((task) => endeTs(task)).filter((ts) => ts !== null);
  const naechstesEnde = enden.length > 0 ? Math.min(...enden) : null;
  const restText =
    naechstesEnde !== null
      ? formatiereRestzeit(
          Math.max(0, naechstesEnde - jetzt),
          t,
          "beobachten.logging.rest",
        )
      : null;

  const text =
    aktive.length === 1
      ? t("header.liveOne")
      : t("header.liveMany", { count: aktive.length });

  return (
    <button
      type="button"
      className="live-pill"
      onClick={onOeffnen}
      title={t("header.liveZurAnsicht")}
      aria-label={t("header.liveZurAnsicht")}
    >
      <span className="live-pill__punkt" aria-hidden="true" />
      <Activity size={14} aria-hidden="true" />
      <span className="live-pill__text">{text}</span>
      {restText && <span className="live-pill__rest">· {restText}</span>}
    </button>
  );
}
