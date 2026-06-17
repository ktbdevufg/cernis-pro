// Live-Monitor-Ansicht (CERNIS PRO 2.0)
//
// Eigenständige "Beobachten"-Funktion: Status-Karten je Ziel (Erreichbarkeit +
// aktuelle Latenz, live), ein Ereignis-Log (Up/Offline-Übergänge) und das
// Verwalten eigener Ziele (hinzufügen/löschen). Der RTT-Graph ist bewusst NICHT
// hier — der kommt als eigenes Stück danach.
//
// Datenquelle: api/monitoring.js (REST-Vorladung + Schreibpfade) und
// api/monitorStream.js (endloser Live-Strom mit Auto-Reconnect). Muster der
// Vorladung und Fehlertoleranz wie ScanInhalt: ein Patzer beim Laden kippt die
// Ansicht NICHT (leere Liste statt Absturz). Token-Variablen aus tokens.css,
// nie feste Farben.

import { Activity, Plus, Trash2 } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import {
  addMonitorTarget,
  deleteMonitorTarget,
  fetchMonitorEvents,
  fetchMonitorStatus,
} from "../api/monitoring.js";
import { starteMonitorStream } from "../api/monitorStream.js";
import "./MonitorView.css";

// Obergrenze der im State gehaltenen Log-Zeilen: das Log wächst sonst während
// einer langen Sitzung unbegrenzt. Neueste vorne, ältere fallen hinten weg.
const MAX_LOG_EINTRAEGE = 100;

// Präfix der id, an dem ein vom Nutzer angelegtes (löschbares) Ziel erkennbar
// ist (vergeben in api/monitoring.addMonitorTarget). Die drei festen Ziele
// (gateway/internet/dns o. Ä.) tragen es NICHT und bleiben ohne Löschen-Button.
const EIGENES_ZIEL_PRAEFIX = "custom_";

// Formatiert eine RTT in Millisekunden auf eine Nachkommastelle ("8.0 ms").
// null = ehrliche Lücke -> "—" (kein erfundener Wert).
function formatRtt(rttMs) {
  if (rttMs === null || rttMs === undefined) {
    return "—";
  }
  return `${rttMs.toFixed(1)} ms`;
}

// Eine Status-Karte je Ziel. Ampel-Böppel + Label + aktuelle RTT + Zustandswort.
// Eigene Ziele tragen einen dezenten Löschen-Button (die drei festen nicht).
function StatusKarte({ ziel, eigen, onLoeschen }) {
  const { t } = useTranslation();

  // Ampel-Klasse: aktiv (alive true), offline (alive false) oder unbekannt
  // (alive weder true noch false — z. B. ein gerade ergänztes Ziel ohne Wert).
  const ampelKlasse =
    ziel.alive === true
      ? "monitor-karte__ampel monitor-karte__ampel--aktiv"
      : ziel.alive === false
        ? "monitor-karte__ampel monitor-karte__ampel--offline"
        : "monitor-karte__ampel monitor-karte__ampel--unbekannt";

  const zustandWort =
    ziel.alive === true ? t("beobachten.monitor.up") : t("beobachten.monitor.offline");

  return (
    <div className="monitor-karte">
      <div className="monitor-karte__kopf">
        <span className={ampelKlasse} aria-hidden="true" />
        <span className="monitor-karte__label">{ziel.label}</span>
        {eigen && (
          <button
            type="button"
            className="monitor-karte__loeschen"
            onClick={() => onLoeschen(ziel.targetId)}
            aria-label={t("beobachten.monitor.loeschen")}
            title={t("beobachten.monitor.loeschen")}
          >
            <Trash2 size={14} />
          </button>
        )}
      </div>

      <div className="monitor-karte__rtt monitor-mono">{formatRtt(ziel.rttMs ?? null)}</div>

      <div className="monitor-karte__zustand">
        {ziel.alive === true ? (
          <span className="monitor-karte__zustand-wort monitor-karte__zustand-wort--up">
            {zustandWort}
          </span>
        ) : ziel.alive === false ? (
          <span className="monitor-karte__zustand-wort monitor-karte__zustand-wort--down">
            {zustandWort}
          </span>
        ) : (
          <span className="monitor-karte__zustand-wort monitor-karte__zustand-wort--unbekannt">
            {t("beobachten.monitor.wartet")}
          </span>
        )}
      </div>
    </div>
  );
}

// Eine Ereignis-Zeile im Log. Färbung nach Übergangstyp (up/down/degraded);
// Zustandswörter über i18n. Rechts die RTT des Übergangs ("—" wenn null).
function EreignisZeile({ eintrag }) {
  const { t } = useTranslation();

  const wortKlasse =
    eintrag.event === "up"
      ? "monitor-log__wort monitor-log__wort--up"
      : eintrag.event === "degraded"
        ? "monitor-log__wort monitor-log__wort--degraded"
        : "monitor-log__wort monitor-log__wort--down";

  const wort =
    eintrag.event === "up"
      ? t("beobachten.monitor.eventUp")
      : eintrag.event === "degraded"
        ? t("beobachten.monitor.eventDegraded")
        : t("beobachten.monitor.eventDown");

  return (
    <li className="monitor-log__zeile">
      <span className="monitor-log__zeit monitor-mono">{eintrag.datetime}</span>
      <span className="monitor-log__label">{eintrag.label}</span>
      <span className={wortKlasse}>{wort}</span>
      <span className="monitor-log__rtt monitor-mono">{formatRtt(eintrag.rttMs ?? null)}</span>
    </li>
  );
}

export default function MonitorView() {
  const { t } = useTranslation();

  // Karten-Grundliste als Map nach targetId (Render aus Array). State reicht hier
  // — kein Hochlast-Merge wie beim Scan, der Monitor pusht moderat.
  const [karten, setKarten] = useState(new Map());
  // Ereignis-Log, neueste zuerst, auf MAX_LOG_EINTRAEGE begrenzt.
  const [log, setLog] = useState([]);
  // Eingabefelder für ein neues eigenes Ziel.
  const [neuLabel, setNeuLabel] = useState("");
  const [neuHost, setNeuHost] = useState("");
  // Dezenter Fehlerhinweis (z. B. Löschen fehlgeschlagen) oder null.
  const [fehler, setFehler] = useState(null);
  // Stream getrennt? onError/onClose setzen, onOpen löscht.
  const [getrennt, setGetrennt] = useState(false);

  // Aktives Stream-Handle ({ stop() }) — zum sauberen Schließen bei Unmount.
  const streamRef = useRef(null);

  // Setzt/aktualisiert eine einzelne Karte (immutabel: neue Map ableiten, damit
  // React rendert). Vorhandene Felder bleiben erhalten, nur die gelieferten
  // werden überschrieben.
  const aktualisiereKarte = (targetId, teil) => {
    setKarten((vorher) => {
      const naechste = new Map(vorher);
      const bestehend = naechste.get(targetId) ?? { targetId };
      naechste.set(targetId, { ...bestehend, ...teil });
      return naechste;
    });
  };

  // Beim Mount: erste Karten-Liste UND das Log per REST vorladen. Fehler werden
  // toleriert (leere Liste, kein Absturz — Muster wie ScanInhalt). Danach den
  // Live-Strom öffnen; bei Unmount sauber stoppen.
  useEffect(() => {
    let abgebrochen = false;

    (async () => {
      try {
        const liste = await fetchMonitorStatus();
        if (!abgebrochen) {
          setKarten(
            new Map(liste.map((z) => [z.targetId, { ...z, rttMs: null }])),
          );
        }
      } catch {
        // Kein Status erreichbar: leere Karten-Liste, kein Hinweis.
      }

      try {
        const ereignisse = await fetchMonitorEvents(100);
        if (!abgebrochen) {
          setLog(ereignisse.slice(0, MAX_LOG_EINTRAEGE));
        }
      } catch {
        // Kein Log erreichbar: leeres Log, kein Hinweis.
      }
    })();

    streamRef.current = starteMonitorStream({
      // Connect-Frame: ersetzt die Karten-Grundliste (targetId/label/alive). Eine
      // schon bekannte aktuelle RTT bleibt erhalten (nur alive/label aktualisieren).
      onStatus: (liste) => {
        setKarten((vorher) => {
          const naechste = new Map();
          for (const z of liste) {
            const bestehend = vorher.get(z.targetId);
            naechste.set(z.targetId, {
              ...z,
              rttMs: bestehend?.rttMs ?? null,
            });
          }
          return naechste;
        });
      },
      // Laufendes Update: alive + aktuelle rttMs der Karte live setzen (fehlt die
      // Karte noch, wird sie ergänzt). Trägt das Update ein event !== null, vorne
      // eine neue Log-Zeile einfügen (Liste begrenzen).
      onUpdate: ({ targetId, label, alive, rttMs, event, datetime }) => {
        aktualisiereKarte(targetId, { label, alive, rttMs });
        if (event !== null && event !== undefined) {
          setLog((vorher) =>
            [
              { targetId, label, event, rttMs: rttMs ?? null, datetime },
              ...vorher,
            ].slice(0, MAX_LOG_EINTRAEGE),
          );
        }
      },
      onOpen: () => setGetrennt(false),
      onError: () => setGetrennt(true),
      onClose: () => setGetrennt(true),
    });

    return () => {
      abgebrochen = true;
      streamRef.current?.stop();
      streamRef.current = null;
    };
  }, []);

  // Neues eigenes Ziel anlegen: bei Erfolg die Karte sofort ergänzen (alive
  // zunächst unbekannt). KEIN <form>-Submit — onClick (Hausmuster). Fehler
  // tolerieren (dezenter Hinweis, kein Absturz).
  const handleHinzufuegen = async () => {
    const label = neuLabel.trim();
    const host = neuHost.trim();
    if (!label || !host) {
      return;
    }
    try {
      const ziel = await addMonitorTarget({ label, host });
      aktualisiereKarte(ziel.id, {
        targetId: ziel.id,
        label: ziel.label,
        alive: null,
        rttMs: null,
      });
      setNeuLabel("");
      setNeuHost("");
      setFehler(null);
    } catch {
      setFehler(t("beobachten.monitor.ladeFehler"));
    }
  };

  // Eigenes Ziel löschen: optimistisch die Karte entfernen; bei Fehler dezent
  // melden (kein Absturz). Die feste Drei trägt keinen Löschen-Button, hierher
  // kommen also nur eigene Ziele.
  const handleLoeschen = async (targetId) => {
    setKarten((vorher) => {
      const naechste = new Map(vorher);
      naechste.delete(targetId);
      return naechste;
    });
    try {
      await deleteMonitorTarget(targetId);
      setFehler(null);
    } catch {
      setFehler(t("beobachten.monitor.ladeFehler"));
    }
  };

  const kartenListe = [...karten.values()];
  const kannHinzufuegen = neuLabel.trim() !== "" && neuHost.trim() !== "";

  return (
    <div className="monitor">
      {/* Dezenter Hinweisstreifen, wenn der Strom getrennt ist (Reconnect läuft). */}
      {getrennt && (
        <div className="monitor__getrennt" role="status">
          {t("beobachten.monitor.getrennt")}
        </div>
      )}

      {/* Dezenter Fehlerhinweis (z. B. Löschen fehlgeschlagen). */}
      {fehler && (
        <div className="monitor__fehler" role="note">
          {fehler}
        </div>
      )}

      {/* Status-Karten oben, responsives Grid. */}
      <div className="monitor__zieleTitel">{t("beobachten.monitor.zieleTitel")}</div>
      <div className="monitor__karten">
        {kartenListe.map((ziel) => (
          <StatusKarte
            key={ziel.targetId}
            ziel={ziel}
            eigen={String(ziel.targetId).startsWith(EIGENES_ZIEL_PRAEFIX)}
            onLoeschen={handleLoeschen}
          />
        ))}
      </div>

      {/* Eigene Ziele hinzufügen: schlichte Zeile unter den Karten. */}
      <div className="monitor__hinzufuegen">
        <input
          type="text"
          className="monitor__input"
          value={neuLabel}
          onChange={(e) => setNeuLabel(e.target.value)}
          placeholder={t("beobachten.monitor.label")}
          aria-label={t("beobachten.monitor.label")}
        />
        <input
          type="text"
          className="monitor__input monitor-mono"
          value={neuHost}
          onChange={(e) => setNeuHost(e.target.value)}
          placeholder={t("beobachten.monitor.host")}
          aria-label={t("beobachten.monitor.host")}
        />
        <button
          type="button"
          className="monitor__add-button"
          onClick={handleHinzufuegen}
          disabled={!kannHinzufuegen}
        >
          <Plus size={15} />
          {t("beobachten.monitor.hinzufuegen")}
        </button>
      </div>

      {/* Ereignis-Log unter den Zielen, neueste zuerst. */}
      <div className="monitor__logTitel">
        <Activity size={15} aria-hidden="true" />
        {t("beobachten.monitor.eventLogTitel")}
      </div>
      {log.length === 0 ? (
        <p className="monitor__log-leer">{t("beobachten.monitor.logLeer")}</p>
      ) : (
        <ul className="monitor__log">
          {log.map((eintrag, index) => (
            <EreignisZeile
              key={`${eintrag.targetId}-${eintrag.datetime}-${index}`}
              eintrag={eintrag}
            />
          ))}
        </ul>
      )}
    </div>
  );
}
