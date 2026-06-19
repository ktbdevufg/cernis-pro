// Live-Monitor-Ansicht (CERNIS PRO 2.0)
//
// Eigenständige "Beobachten"-Funktion: Status-Karten je Ziel (Erreichbarkeit +
// aktuelle Latenz, live) mit Mini-Sparkline, ein großer RTT-Verlaufsgraph des
// gewählten Ziels, ein Ereignis-Log (Up/Offline-Übergänge) und das Verwalten
// eigener Ziele (hinzufügen/löschen).
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
  fetchRttHistory,
} from "../api/monitoring.js";
import { fetchSettings, updateSetting } from "../api/settings.js";
import { starteMonitorStream } from "../api/monitorStream.js";
import { spieleSignalton } from "../lib/sound.js";
import RttGraph from "./RttGraph.jsx";
import RttSparkline from "./RttSparkline.jsx";
import "./MonitorView.css";

// Obergrenze der im State gehaltenen Log-Zeilen: das Log wächst sonst während
// einer langen Sitzung unbegrenzt. Neueste vorne, ältere fallen hinten weg.
const MAX_LOG_EINTRAEGE = 100;

// Obergrenze der je Ziel gehaltenen RTT-Verlaufswerte (gleitendes Live-Fenster).
// Ältester zuerst; ist die Reihe voll, fällt vorne der älteste weg.
const MAX_VERLAUF = 120;

// Präfix der id eines Gateway-Ziels (Default-Auswahl für den großen Graphen).
const GATEWAY_PRAEFIX = "gw_";

// Präfix der id, an dem ein vom Nutzer angelegtes (löschbares) Ziel erkennbar
// ist (vergeben in api/monitoring.addMonitorTarget). Die drei festen Ziele
// (gateway/internet/dns o. Ä.) tragen es NICHT und bleiben ohne Löschen-Button.
const EIGENES_ZIEL_PRAEFIX = "custom_";

// Settings-Key für den persistierten Signalton-Schalter (Muster wie
// scan_columns in ObserveView). Default ist AUS — kein überraschender Ton.
const MONITOR_SOUND_KEY = "monitor_sound";

// Formatiert eine RTT in Millisekunden auf eine Nachkommastelle ("8.0 ms").
// null = ehrliche Lücke -> "—" (kein erfundener Wert).
function formatRtt(rttMs) {
  if (rttMs === null || rttMs === undefined) {
    return "—";
  }
  return `${rttMs.toFixed(1)} ms`;
}

// Eine Status-Karte je Ziel. Ampel-Böppel + Label + aktuelle RTT + Sparkline +
// Zustandswort. Eigene Ziele tragen einen dezenten Löschen-Button (die drei
// festen nicht). Die Karte ist als Ganzes anklickbar (wählt das Ziel für den
// großen Graphen aus); die ausgewählte Karte hebt sich durch einen Akzent-Rand
// ab. Der Löschen-Button darf den Karten-Klick NICHT auslösen.
function StatusKarte({ ziel, eigen, verlauf, ausgewaehlt, onWaehlen, onLoeschen }) {
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

  const karteKlasse = ausgewaehlt
    ? "monitor-karte monitor-karte--aktivausgewaehlt"
    : "monitor-karte";

  return (
    <div
      className={karteKlasse}
      role="button"
      tabIndex={0}
      aria-pressed={ausgewaehlt}
      onClick={() => onWaehlen(ziel.targetId)}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onWaehlen(ziel.targetId);
        }
      }}
    >
      <div className="monitor-karte__kopf">
        <span className={ampelKlasse} aria-hidden="true" />
        <span className="monitor-karte__label">{ziel.label}</span>
        {eigen && (
          <button
            type="button"
            className="monitor-karte__loeschen"
            onClick={(event) => {
              // Löschen darf nicht zugleich die Karte auswählen.
              event.stopPropagation();
              onLoeschen(ziel.targetId);
            }}
            aria-label={t("beobachten.monitor.loeschen")}
            title={t("beobachten.monitor.loeschen")}
          >
            <Trash2 size={14} />
          </button>
        )}
      </div>

      <div className="monitor-karte__rtt monitor-mono">{formatRtt(ziel.rttMs ?? null)}</div>

      {/* Mini-Sparkline des jüngsten Verlaufs (rein dekorativ, unter der Zahl). */}
      <RttSparkline werte={verlauf} farbe="var(--color-accent)" />

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
  // RTT-Verlaufsreihen je Ziel: Map targetId -> Array der letzten Werte (ältester
  // zuerst, auf MAX_VERLAUF begrenzt). null-Werte sind echte Lücken.
  const [verlaeufe, setVerlaeufe] = useState(new Map());
  // Für den großen Graphen gewähltes Ziel (targetId) oder null (Default unten).
  const [gewaehltesZiel, setGewaehltesZiel] = useState(null);
  // Signalton bei Zustandswechsel an/aus. Default AUS (kein überraschender Ton
  // beim ersten Start); beim Mount aus den Settings nachgeladen, persistiert.
  const [tonAn, setTonAn] = useState(false);

  // Aktives Stream-Handle ({ stop() }) — zum sauberen Schließen bei Unmount.
  const streamRef = useRef(null);
  // Spiegelt tonAn als Ref, damit der im Stream-useEffect gebundene Callback
  // immer den aktuellen Wert sieht (statt eines veralteten Closure-Werts) —
  // tonAn darf NICHT ins Dependency-Array, sonst würde der Strom bei jedem
  // Schalter-Wechsel neu aufgebaut.
  const tonAnRef = useRef(false);

  // Hängt einen RTT-Wert hinten an die Reihe eines Ziels (immutabel) und kürzt
  // vorne auf MAX_VERLAUF. null wird mit angehängt (ehrliche Lücke).
  const haengeVerlaufAn = (targetId, rttMs) => {
    setVerlaeufe((vorher) => {
      const naechste = new Map(vorher);
      const reihe = naechste.get(targetId) ?? [];
      const ergaenzt = [...reihe, rttMs ?? null];
      naechste.set(
        targetId,
        ergaenzt.length > MAX_VERLAUF ? ergaenzt.slice(-MAX_VERLAUF) : ergaenzt,
      );
      return naechste;
    });
  };

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

  // tonAn immer in die Ref spiegeln, sobald sich der State ändert. So liest der
  // im Stream-useEffect gebundene onUpdate-Callback stets den aktuellen Wert.
  useEffect(() => {
    tonAnRef.current = tonAn;
  }, [tonAn]);

  // Beim Mount den persistierten Schalterzustand laden. Nur ein echter Boolean
  // übernimmt; sonst bleibt der Default false. Fehler werden toleriert (Muster
  // wie scan_columns in ObserveView).
  useEffect(() => {
    let abgebrochen = false;
    (async () => {
      try {
        const settings = await fetchSettings();
        if (abgebrochen) {
          return;
        }
        const roh = settings?.[MONITOR_SOUND_KEY];
        if (typeof roh === "boolean") {
          setTonAn(roh);
        }
      } catch {
        // Settings nicht erreichbar: Default (Ton aus) bleibt aktiv.
      }
    })();
    return () => {
      abgebrochen = true;
    };
  }, []);

  // Schalter umlegen: Zustand sofort setzen (UI reagiert live) und persistieren
  // (feuern und vergessen; Fehler nur loggen, UI nicht blockieren) — exakt das
  // Muster von handleSpaltenWechsel in ObserveView.
  const handleTonWechsel = (wert) => {
    setTonAn(wert);
    updateSetting(MONITOR_SOUND_KEY, wert).catch((fehler) => {
      console.error("monitor_sound speichern fehlgeschlagen", fehler);
    });
  };

  // Beim Mount: erste Karten-Liste UND das Log per REST vorladen. Fehler werden
  // toleriert (leere Liste, kein Absturz — Muster wie ScanInhalt). Danach den
  // Live-Strom öffnen; bei Unmount sauber stoppen.
  useEffect(() => {
    let abgebrochen = false;

    (async () => {
      let liste = [];
      try {
        liste = await fetchMonitorStatus();
        if (!abgebrochen) {
          setKarten(
            new Map(liste.map((z) => [z.targetId, { ...z, rttMs: null }])),
          );
        }
      } catch {
        // Kein Status erreichbar: leere Karten-Liste, kein Hinweis.
      }

      // Startreihen je Ziel laden: für jedes bekannte Ziel den RTT-Verlauf holen
      // und als Anfangsreihe (nur die rttMs, ältester zuerst) ablegen. Fehler je
      // Ziel werden toleriert (leere Reihe, kein Absturz). Parallel, dann sammeln.
      try {
        const reihen = await Promise.all(
          liste.map(async (z) => {
            try {
              const verlauf = await fetchRttHistory(z.targetId, MAX_VERLAUF);
              return [z.targetId, verlauf.map((s) => s.rttMs ?? null)];
            } catch {
              return [z.targetId, []];
            }
          }),
        );
        if (!abgebrochen) {
          setVerlaeufe(new Map(reihen));
        }
      } catch {
        // Unerwarteter Sammelfehler: leere Verläufe, kein Hinweis.
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
        // Neuen Wert hinten an die Verlaufsreihe des Ziels anhängen (null = Lücke).
        haengeVerlaufAn(targetId, rttMs);
        if (event !== null && event !== undefined) {
          // Ein echter Zustandswechsel (up/down/degraded): bei aktivem Schalter
          // einen kurzen Signalton spielen. tonAn über die Ref lesen, damit der
          // hier gebundene Callback nicht auf einem veralteten Closure-Wert sitzt.
          if (tonAnRef.current) {
            spieleSignalton();
          }
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

  // Effektiv ausgewähltes Ziel für den großen Graphen. Vorrang hat die
  // Nutzerwahl (gewaehltesZiel), sofern das Ziel noch existiert; sonst der
  // Default: das Gateway-Ziel (id beginnt mit "gw_"), sonst das erste Ziel.
  const nutzerwahlGueltig =
    gewaehltesZiel !== null && karten.has(gewaehltesZiel);
  const defaultZiel =
    kartenListe.find((z) => String(z.targetId).startsWith(GATEWAY_PRAEFIX)) ??
    kartenListe[0];
  const aktivesZiel = nutzerwahlGueltig
    ? karten.get(gewaehltesZiel)
    : defaultZiel;
  const aktiveTargetId = aktivesZiel?.targetId ?? null;
  const verlaufDesGewaehlten =
    aktiveTargetId !== null ? (verlaeufe.get(aktiveTargetId) ?? []) : [];
  const labelDesGewaehlten = aktivesZiel?.label ?? "";

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

      {/* Kopfzeile über den Karten: Zielen-Titel links, Signalton-Schalter rechts. */}
      <div className="monitor__kopfzeile">
        <div className="monitor__zieleTitel">{t("beobachten.monitor.zieleTitel")}</div>
        <label className="monitor__ton-schalter">
          <input
            type="checkbox"
            className="monitor__ton-checkbox"
            checked={tonAn}
            onChange={(e) => handleTonWechsel(e.target.checked)}
          />
          <span className="monitor__ton-label">{t("beobachten.monitor.tonSignal")}</span>
        </label>
      </div>
      <div className="monitor__karten">
        {kartenListe.map((ziel) => (
          <StatusKarte
            key={ziel.targetId}
            ziel={ziel}
            eigen={String(ziel.targetId).startsWith(EIGENES_ZIEL_PRAEFIX)}
            verlauf={verlaeufe.get(ziel.targetId) ?? []}
            ausgewaehlt={ziel.targetId === aktiveTargetId}
            onWaehlen={setGewaehltesZiel}
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

      {/* Großer RTT-Verlauf des gewählten Ziels, immer sichtbar. */}
      <RttGraph werte={verlaufDesGewaehlten} label={labelDesGewaehlten} />

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
