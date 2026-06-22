// Beobachten-Ansicht (CERNIS PRO 2.0)
// Zeigt zuerst eine Kachel-Übersicht der Funktionen. Klick auf eine aktive
// Kachel öffnet die zugehörige Funktion in derselben Fläche, mit Zurück-Weg.
//
// Funktionen:
//   "scan"     Netzwerk-Scan (aktiv) -> bestehende Scan-Tabelle
//   "traffic"  Per-App-Verkehr (aktiv) -> App-Liste + Verbindungs-Detail
//   "processes" Prozesse (gesperrt bis Beobachtung läuft)
//
// Datenquelle der Tabelle ist ausschließlich der Import aus mockData/scanMock.
// Die View weiß nicht, ob die Daten echt oder Platzhalter sind. Bei echter
// Anbindung wird nur dieser Import ausgetauscht.

import {
  Activity,
  FileClock,
  Globe,
  ListTree,
  Network,
  Radar,
  Repeat,
  ShieldAlert,
  ShieldQuestion,
} from "lucide-react";
import { memo, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { fetchInterfaces, primaeresInterface } from "../api/interfaces.js";
import {
  fetchScanDetail,
  fetchScanHistory,
  istEchtesGeraet,
} from "../api/scan.js";
import { starteScanStream } from "../api/scanStream.js";
import { fetchSettings, updateSetting } from "../api/settings.js";
import { CardGrid, FunctionShell } from "../components/AreaShell.jsx";
import ColumnManager from "../components/ColumnManager.jsx";
import DnsWatchView from "../components/DnsWatchView.jsx";
import FunctionCard from "../components/FunctionCard.jsx";
import LoggingPanel from "../components/LoggingPanel.jsx";
import MonitorView from "../components/MonitorView.jsx";
import OutboundView from "../components/OutboundView.jsx";
import ScanDetailPanel from "../components/ScanDetailPanel.jsx";
import ScanTable, {
  DEFAULT_SICHTBARE_SPALTEN,
} from "../components/ScanTable.jsx";
import TopologyView from "../components/TopologyView.jsx";
import TrafficView from "../components/TrafficView.jsx";
import WatchView from "./WatchView.jsx";
import "./ObserveView.css";

// Bildet die rohe Backend-Phase auf eine der drei Anzeige-Phasen ab. Bekannt
// sind aktuell "discovery" und "enrich" (mDNS/SSDP/NDI laufen innerhalb der
// enrich-Phase). "mdns" wird vorausschauend mit abgebildet. Unbekannte Phasen
// werden ROH durchgereicht (kein Absturz) — die Anzeige hebt dann schlicht
// keinen der drei Punkte hervor.
function mappePhase(roh) {
  if (roh === "discovery" || roh === "enrich" || roh === "mdns") {
    return roh;
  }
  return roh ?? null;
}

// Reihenfolge der Anzeige-Phasen unter der Toolbar (links nach rechts).
const PHASEN_REIHENFOLGE = ["discovery", "mdns", "enrich"];

// Settings-Key, unter dem die sichtbaren umschaltbaren Scan-Spalten persistiert
// werden (JSON-Array der IDs; fixe Spalten stehen NICHT drin).
const SCAN_COLUMNS_KEY = "scan_columns";

// Kachel-Definition: Schlüssel, Icon, Sperrstatus. Reihenfolge ist verbindlich.
const FUNKTIONEN = [
  { id: "scan", icon: Radar, locked: false },
  { id: "watch", icon: ShieldQuestion, locked: false },
  { id: "traffic", icon: Repeat, locked: false },
  { id: "outbound", icon: Globe, locked: false },
  { id: "dnswatch", icon: ShieldAlert, locked: false },
  { id: "monitor", icon: Activity, locked: false },
  { id: "logging", icon: FileClock, locked: false },
  { id: "topology", icon: Network, locked: false },
  { id: "processes", icon: ListTree, locked: true },
];

// Sweep-Overlay als eigene, memoisierte Komponente OHNE Props. Dadurch rendert
// React den Sweep-DOM-Knoten bei den häufigen setGeraete-Updates während eines
// Scans NICHT neu — die CSS-Animation läuft ununterbrochen durch (kein Ruckeln).
// Muss auf Modulebene stehen, sonst wird sie pro ScanInhalt-Render neu erzeugt
// und memo greift nicht.
const ScanSweep = memo(function ScanSweep() {
  return (
    <div className="scan-overlay" aria-hidden="true">
      <div className="scan-line" />
    </div>
  );
});

// Scan-Inhalt: Kopf-Leiste (Anzahl + "Scan starten" + Fortschritt) über der
// Tabelle. Quelle ist jetzt die echte API: beim Öffnen wird der letzte
// gespeicherte Scan per REST vorgeladen; "Scan starten" öffnet den WS-Strom
// und füllt die Tabelle LIVE. Geräte werden während des Scans nach MAC gemerged
// (host_detail gewinnt über host_found). Notizfelder (label/tags/notes) bleiben
// bewusst Platzhalter (eigener Folgeschnitt mit PUT /api/devices/{mac}).
function ScanInhalt() {
  const { t } = useTranslation();

  // Map-artig nach mac gemergte Geräteliste (Render-Quelle der Tabelle).
  const [geraete, setGeraete] = useState([]);
  const [scanLaeuft, setScanLaeuft] = useState(false);
  // Fortschritt des laufenden Scans oder null. {completed,total,pct,phase}.
  const [fortschritt, setFortschritt] = useState(null);
  const [scanError, setScanError] = useState(null);
  // Metadaten des zuletzt geladenen/abgeschlossenen Scans oder null.
  const [letzterScan, setLetzterScan] = useState(null);
  // Gewähltes Gerät über seinen stabilen Schlüssel (MAC oder, ohne MAC, IP);
  // null = keins. Der Schlüssel deckt auch Hosts ohne MAC kollisionsfrei ab.
  const [gewaehlterSchluessel, setGewaehlterSchluessel] = useState(null);

  // Erkannte Netzwerk-Schnittstellen (aus GET /api/interfaces).
  const [interfaces, setInterfaces] = useState([]);
  // Name des aktuell gewählten Interface (null = noch keins).
  const [gewaehltesIface, setGewaehltesIface] = useState(null);
  // Zu scannendes Netz (CIDR). Folgt der Interface-Auswahl, danach editierbar.
  const [cidr, setCidr] = useState("");
  // Aktive Anzeige-Phase während des Scans ("discovery"|"mdns"|"enrich"|null).
  const [phase, setPhase] = useState(null);

  // Sichtbare umschaltbare Spalten der Scan-Tabelle (Array der IDs). Default:
  // alle umschaltbaren außer ipv6 — wird beim Öffnen aus den Settings überschrieben.
  const [sichtbareSpalten, setSichtbareSpalten] = useState(
    DEFAULT_SICHTBARE_SPALTEN,
  );

  // Aktives Scan-Handle ({ stop() }) — zum sauberen Schließen bei Unmount.
  const streamRef = useRef(null);
  // mac -> Gerät: Merge-Quelle während des Live-Scans (Ref, kein State: die
  // Callbacks schieben das Ergebnis selbst per setGeraete in die Liste).
  const geraeteRef = useRef(new Map());

  // Beim Öffnen den letzten gespeicherten Scan vorladen. Fehler werden
  // toleriert (leere Tabelle, kein Absturz). KEIN automatischer Scan.
  useEffect(() => {
    let abgebrochen = false;
    (async () => {
      try {
        const liste = await fetchScanHistory(1);
        if (abgebrochen || liste.length === 0) {
          return;
        }
        const detail = await fetchScanDetail(liste[0].id);
        if (abgebrochen) {
          return;
        }
        // Merge-Puffer (Ref) mit dem vorgeladenen Scan füllen, damit ein
        // späteres Notizen-Speichern (handleGespeichert) das Gerät nach seinem
        // Schlüssel findet — auch ohne laufenden Live-Scan. Schlüssel (MAC oder
        // IP) statt nackter MAC: deckt auch Hosts ohne MAC kollisionsfrei ab.
        geraeteRef.current = new Map(
          detail.geraete.map((g) => [g.schluessel, g]),
        );
        setGeraete(detail.geraete);
        setLetzterScan({
          scannedAt: detail.scannedAt,
          cidr: detail.cidr,
          hostCount: detail.hostCount,
        });
      } catch {
        // Kein gespeicherter Scan erreichbar: leere Tabelle, kein Hinweis.
      }
    })();
    return () => {
      abgebrochen = true;
    };
  }, []);

  // Beim Öffnen die Netzwerk-Schnittstellen laden und das primäre Interface
  // (samt dessen CIDR) vorauswählen. Fehler werden toleriert (leere Liste ->
  // kein Vorauswahl-CIDR -> Start bleibt deaktiviert).
  useEffect(() => {
    let abgebrochen = false;
    (async () => {
      try {
        const liste = await fetchInterfaces();
        if (abgebrochen) {
          return;
        }
        setInterfaces(liste);
        const prim = primaeresInterface(liste);
        if (prim) {
          setGewaehltesIface(prim.name);
          setCidr(prim.networkCidr);
        }
      } catch {
        // Keine Interfaces erreichbar: leere Liste, Start bleibt deaktiviert.
      }
    })();
    return () => {
      abgebrochen = true;
    };
  }, []);

  // Cleanup beim Unmount: einen noch laufenden Scan sauber schließen.
  useEffect(() => {
    return () => {
      streamRef.current?.stop();
      streamRef.current = null;
    };
  }, []);

  // Beim Öffnen die persistierte Spaltenauswahl laden. Nur ein valides Array
  // (Strings) übernimmt die Sicht; sonst bleibt der Default. Fehler werden
  // toleriert (Default-Spalten, kein Hinweis).
  useEffect(() => {
    let abgebrochen = false;
    (async () => {
      try {
        const settings = await fetchSettings();
        if (abgebrochen) {
          return;
        }
        const roh = settings?.[SCAN_COLUMNS_KEY];
        if (Array.isArray(roh) && roh.every((id) => typeof id === "string")) {
          setSichtbareSpalten(roh);
        }
      } catch {
        // Settings nicht erreichbar: Default-Spalten bleiben aktiv.
      }
    })();
    return () => {
      abgebrochen = true;
    };
  }, []);

  // Spaltenauswahl ändern: Zustand sofort setzen (Tabelle reagiert live) und
  // persistieren (feuern und vergessen; Fehler nur loggen, UI nicht blockieren).
  const handleSpaltenWechsel = (neueSpalten) => {
    setSichtbareSpalten(neueSpalten);
    updateSetting(SCAN_COLUMNS_KEY, neueSpalten).catch((fehler) => {
      console.error("scan_columns speichern fehlgeschlagen", fehler);
    });
  };

  // Interface-Wechsel (Variante A): CIDR FOLGT der Auswahl. Auch wenn der
  // Nutzer das CIDR vorher manuell editiert hatte — ein Interface-Wechsel ist
  // eine bewusste Neuwahl und überschreibt das Feld auf das network_cidr des
  // gewählten Interface. Danach bleibt das Feld wieder frei editierbar.
  const handleIfaceWechsel = (name) => {
    setGewaehltesIface(name);
    const iface = interfaces.find((i) => i.name === name);
    setCidr(iface?.networkCidr ?? "");
  };

  // Startet einen Live-Scan. Bei bereits laufendem Scan ignorieren. Ohne CIDR
  // wird nicht gestartet (Fehlerhinweis). Setzt den Merge-Puffer und die
  // Anzeige zurück und öffnet den WS-Strom mit dem gewählten CIDR.
  const handleScanStart = () => {
    if (scanLaeuft) {
      return;
    }
    const zielCidr = cidr.trim();
    if (!zielCidr) {
      setScanError(t("beobachten.scan.cidrMissing"));
      return;
    }
    geraeteRef.current = new Map();
    setGeraete([]);
    setScanError(null);
    setFortschritt(null);
    setPhase(null);
    setScanLaeuft(true);

    streamRef.current = starteScanStream({
      cidr: zielCidr,
      // host_found: nur setzen, wenn der Schlüssel noch fehlt ODER der
      // bestehende Eintrag noch kein host_detail war (Detail gewinnt, wird nicht
      // überschrieben). Schlüssel (MAC oder IP) statt nackter MAC: so geht auch
      // ein Host ohne MAC verlustfrei in den Merge-Puffer.
      onHostFound: (g) => {
        if (!g.schluessel) {
          return;
        }
        const vorhanden = geraeteRef.current.get(g.schluessel);
        if (!vorhanden || !vorhanden.__detail) {
          geraeteRef.current.set(g.schluessel, g);
          setGeraete([...geraeteRef.current.values()]);
        }
      },
      // host_detail gewinnt IMMER über host_found (gleicher Schlüssel).
      onHostDetail: (g) => {
        if (!g.schluessel) {
          return;
        }
        geraeteRef.current.set(g.schluessel, { ...g, __detail: true });
        setGeraete([...geraeteRef.current.values()]);
      },
      onProgress: (f) => {
        setFortschritt({
          completed: f.completed,
          total: f.total,
          pct: f.pct,
          phase: f.phase,
        });
      },
      // phase: die aktive Anzeige-Phase aus frame.phase ableiten. Bei
      // status==="done" der letzten Phase NICHT zurücksetzen (das übernimmt
      // erst onComplete) — sonst flackert die Phasen-Zeile vor dem Abschluss.
      onPhase: (frame) => {
        if (frame.status === "done") {
          return;
        }
        setPhase(mappePhase(frame.phase));
      },
      onStarted: () => {},
      onInfo: () => {},
      onComplete: () => {
        setScanLaeuft(false);
        setFortschritt(null);
        setPhase(null);
        streamRef.current = null;
        setLetzterScan({
          scannedAt: new Date().toISOString(),
          cidr: zielCidr,
          hostCount: geraeteRef.current.size,
        });
      },
      onError: (msg) => {
        setScanError(msg ?? t("beobachten.scan.scanError"));
        setScanLaeuft(false);
        setFortschritt(null);
        setPhase(null);
        streamRef.current = null;
      },
    });
  };

  // Klick auf eine Zeile: wählt das Gerät; erneuter Klick auf dieselbe löscht.
  // Auswahl über den stabilen Schlüssel (MAC oder IP), nicht die nackte MAC.
  const handleSelect = (geraet) => {
    setGewaehlterSchluessel((aktuell) =>
      aktuell === geraet.schluessel ? null : geraet.schluessel,
    );
  };

  const gewaehltesGeraet =
    geraete.find((g) => g.schluessel === gewaehlterSchluessel) ?? null;

  // Naht nach dem Speichern der Notizen (ScanDetailPanel -> onGespeichert):
  // patcht NUR die kuratierten Felder (label/tags/notes/isKnown) in das
  // bestehende Listen-Gerät. Die Scan-Felder (ports, pingMs, additionalIps,
  // icon …) der Liste bleiben erhalten — kein Komplett-Ersatz. Gepatcht wird
  // über den Schlüssel des GEWÄHLTEN Geräts (nicht über aktualisiert.mac, das
  // bei Hosts ohne MAC leer/kollidierend wäre) — so trifft der Patch genau EIN
  // Gerät. Auch der Merge-Puffer (Ref) wird mitgezogen, damit ein späteres
  // setGeraete aus der Ref die Patches nicht überschreibt.
  const handleGespeichert = (aktualisiert) => {
    if (!gewaehltesGeraet) {
      return;
    }
    const schluessel = gewaehltesGeraet.schluessel;
    const vorhanden = geraeteRef.current.get(schluessel);
    if (!vorhanden) {
      return;
    }
    const gepatcht = {
      ...vorhanden,
      label: aktualisiert.label,
      tags: aktualisiert.tags,
      notes: aktualisiert.notes,
      isKnown: aktualisiert.isKnown,
      // Frisch gesetzte Einordnung haftet in der Liste und im Merge-Puffer (Ref)
      // innerhalb der Sitzung — sonst steht bei Wiederanwahl wieder "neutral".
      trustState: aktualisiert.trustState,
    };
    geraeteRef.current.set(schluessel, gepatcht);
    setGeraete([...geraeteRef.current.values()]);
  };

  // Leer-Hinweis nur im echten Leerlauf (kein Scan, kein Fehler, keine Geräte).
  const zeigeLeer =
    geraete.length === 0 && !scanLaeuft && !scanError;

  return (
    <div className="observe__scan">
      {scanError && (
        <div className="observe__hinweis" role="note">
          <span className="observe__hinweis-title">
            {t("beobachten.traffic.permissionTitle")}
          </span>
          <span className="observe__hinweis-text">{scanError}</span>
        </div>
      )}

      <div className="observe__toolbar">
        <span className="observe__toolbar-left">
          {/* Interface-Auswahl: zeigt je Option Name + IPv4/Prefix. Nicht-
              scanbare Interfaces sind sichtbar, aber deaktiviert (volles Bild
              wie in v1.0). Während eines Scans gesperrt. */}
          <select
            className="observe__iface-select"
            aria-label={t("beobachten.scan.ifaceLabel")}
            value={gewaehltesIface ?? ""}
            onChange={(e) => handleIfaceWechsel(e.target.value)}
            disabled={scanLaeuft}
          >
            {interfaces.map((iface) => {
              const prefix =
                iface.ipv4Prefix !== null ? `/${iface.ipv4Prefix}` : "";
              const adresse = iface.ipv4 ? ` — ${iface.ipv4}${prefix}` : "";
              return (
                <option
                  key={iface.name}
                  value={iface.name}
                  disabled={!iface.scanbar}
                >
                  {iface.name}
                  {adresse}
                </option>
              );
            })}
          </select>

          {/* CIDR-Feld: folgt der Interface-Auswahl, danach frei editierbar. */}
          <input
            type="text"
            className="observe__cidr-input"
            aria-label={t("beobachten.scan.cidrLabel")}
            value={cidr}
            onChange={(e) => setCidr(e.target.value)}
            placeholder="z.B. 172.18.0.0/22"
            disabled={scanLaeuft}
          />

          <span className="observe__count">
            {t("beobachten.scan.deviceCount", { count: geraete.length })}
          </span>
        </span>

        <span className="observe__toolbar-right">
          {/* Dezenter Fortschritt während des Scans: Text + schmaler Balken. */}
          {fortschritt && (
            <span className="observe__progress">
              <span className="observe__progress-text">
                {t("beobachten.scan.scanProgress", {
                  completed: fortschritt.completed,
                  total: fortschritt.total,
                })}
              </span>
              <span className="observe__progress-bar" aria-hidden="true">
                <span
                  className="observe__progress-fill"
                  style={{ width: `${fortschritt.pct ?? 0}%` }}
                />
              </span>
            </span>
          )}
          <ColumnManager
            sichtbar={sichtbareSpalten}
            onChange={handleSpaltenWechsel}
          />
          <button
            type="button"
            className="observe__scan-button"
            onClick={handleScanStart}
            disabled={scanLaeuft || cidr.trim() === ""}
          >
            {scanLaeuft
              ? t("beobachten.scan.scanRunningButton")
              : t("beobachten.scan.startScan")}
          </button>
        </span>
      </div>

      {/* Phasen-Zeile: nur während eines Scans. Drei Punkte mit Labels; die
          aktive Phase hervorgehoben, bereits erledigte gedimmt-grün. */}
      {scanLaeuft && (
        <div className="observe__phases" role="status">
          {PHASEN_REIHENFOLGE.map((p) => {
            const aktivIndex = PHASEN_REIHENFOLGE.indexOf(phase);
            const eigenIndex = PHASEN_REIHENFOLGE.indexOf(p);
            const istAktiv = phase === p;
            // Erledigt: liegt VOR der aktuell aktiven Phase (nur wenn die
            // aktive Phase bekannt ist, sonst nichts als erledigt markieren).
            const istFertig =
              aktivIndex >= 0 && eigenIndex >= 0 && eigenIndex < aktivIndex;
            const klasse = [
              "observe__phase",
              istAktiv ? "observe__phase--aktiv" : "",
              istFertig ? "observe__phase--fertig" : "",
            ]
              .filter(Boolean)
              .join(" ");
            const label =
              p === "discovery"
                ? t("beobachten.scan.scanPhasePing")
                : p === "mdns"
                  ? t("beobachten.scan.scanPhaseMdns")
                  : t("beobachten.scan.scanPhaseEnrich");
            return (
              <span key={p} className={klasse}>
                <span className="observe__phase-dot" aria-hidden="true" />
                {label}
              </span>
            );
          })}
        </div>
      )}

      {/* Dezente Anzeige des zuletzt geladenen/abgeschlossenen Scans. */}
      {letzterScan && (
        <span className="observe__lastscan">
          {t("beobachten.scan.lastScanLabel", {
            when: new Date(letzterScan.scannedAt).toLocaleString(),
          })}
        </span>
      )}

      {zeigeLeer ? (
        <p className="observe__leer">{t("beobachten.scan.historyEmpty")}</p>
      ) : (
        /* Scan-Bereich (position relative) trägt das Sweep-Overlay über der
           Tabelle. Der Sweep wird nur während eines laufenden Scans gerendert. */
        <div className="observe__scan-area">
          {scanLaeuft && <ScanSweep />}
          {/* Zwei-Spalten-Layout: Tabelle links, Panel rechts (nur bei Auswahl).
              Nur die ANZEIGE wird gefiltert (Phantome ohne jede Identität raus);
              der Merge-Puffer (geraeteRef) behält alles — keine Daten gehen
              verloren. */}
          <div className="observe__split">
            <ScanTable
              geraete={geraete.filter(istEchtesGeraet)}
              onSelect={handleSelect}
              selectedSchluessel={gewaehlterSchluessel}
              sichtbareSpalten={sichtbareSpalten}
            />
            {gewaehltesGeraet && (
              <ScanDetailPanel
                key={gewaehltesGeraet.schluessel}
                geraet={gewaehltesGeraet}
                onClose={() => setGewaehlterSchluessel(null)}
                onGespeichert={handleGespeichert}
              />
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default function ObserveView({
  refreshInterval = 0,
  onRefreshIntervalChange,
  initialFunction = null,
  onFunktionGeoeffnet,
}) {
  const { t } = useTranslation();
  // null -> Kachel-Übersicht; sonst die geöffnete Funktion. Eine von aussen
  // gewuenschte Funktion (initialFunction, z. B. vom Kopfzeilen-Live-Pill) wird
  // initial uebernommen.
  const [openFunction, setOpenFunction] = useState(initialFunction);
  // Ob die Logging-Detailansicht offen ist (NUR im logging-Zweig genutzt). Solange
  // true, blendet die FunctionShell ihren eigenen Zurück-Knopf aus (der wäre über dem
  // Detail-Zurück redundant). LoggingPanel meldet den Wechsel via onDetailChange.
  const [loggingDetailOffen, setLoggingDetailOffen] = useState(false);

  // Wechselt initialFunction (z. B. erneuter Pill-Klick bei bereits offenem
  // Beobachten-Bereich), die gewuenschte Funktion oeffnen und beim Eltern-State
  // quittieren, damit der Nutzer danach frei zur Uebersicht zurueck kann.
  useEffect(() => {
    if (initialFunction) {
      setOpenFunction(initialFunction);
      onFunktionGeoeffnet?.();
    }
  }, [initialFunction, onFunktionGeoeffnet]);

  // Detail-Flag beim Verlassen/Wechseln der Funktion zuruecksetzen: oeffnet man spaeter
  // erneut Logging, darf kein haengender true-Zustand die Shell-Zurück verbergen. Greift
  // bei jedem openFunction-Wechsel (auch zurueck zur Kachel-Uebersicht).
  useEffect(() => {
    setLoggingDetailOffen(false);
  }, [openFunction]);

  if (openFunction === "scan") {
    return (
      <FunctionShell
        title={t("beobachten.cards.scan.title")}
        onBack={() => setOpenFunction(null)}
      >
        <ScanInhalt />
      </FunctionShell>
    );
  }

  if (openFunction === "watch") {
    return (
      <FunctionShell
        title={t("beobachten.cards.watch.title")}
        onBack={() => setOpenFunction(null)}
      >
        <WatchView />
      </FunctionShell>
    );
  }

  if (openFunction === "traffic") {
    return (
      <FunctionShell
        title={t("beobachten.cards.traffic.title")}
        onBack={() => setOpenFunction(null)}
      >
        <TrafficView
          refreshInterval={refreshInterval}
          onRefreshIntervalChange={onRefreshIntervalChange}
        />
      </FunctionShell>
    );
  }

  if (openFunction === "outbound") {
    return (
      <FunctionShell
        title={t("beobachten.cards.outbound.title")}
        onBack={() => setOpenFunction(null)}
      >
        <OutboundView />
      </FunctionShell>
    );
  }

  if (openFunction === "dnswatch") {
    return (
      <FunctionShell
        title={t("beobachten.cards.dnswatch.title")}
        onBack={() => setOpenFunction(null)}
      >
        <DnsWatchView />
      </FunctionShell>
    );
  }

  if (openFunction === "monitor") {
    return (
      <FunctionShell
        title={t("beobachten.cards.monitor.title")}
        onBack={() => setOpenFunction(null)}
      >
        <MonitorView />
      </FunctionShell>
    );
  }

  if (openFunction === "logging") {
    return (
      <FunctionShell
        title={t("beobachten.cards.logging.title")}
        onBack={() => setOpenFunction(null)}
        zurueckVerbergen={loggingDetailOffen}
      >
        <LoggingPanel onDetailChange={setLoggingDetailOffen} />
      </FunctionShell>
    );
  }

  if (openFunction === "topology") {
    return (
      <FunctionShell
        title={t("beobachten.cards.topology.title")}
        onBack={() => setOpenFunction(null)}
      >
        <TopologyView />
      </FunctionShell>
    );
  }

  return (
    <CardGrid>
      {FUNKTIONEN.map(({ id, icon, locked }) => (
        <FunctionCard
          key={id}
          icon={icon}
          title={t(`beobachten.cards.${id}.title`)}
          subtitle={t(`beobachten.cards.${id}.subtitle`)}
          locked={locked}
          lockedReason={locked ? t(`beobachten.cards.${id}.locked`) : undefined}
          onOpen={() => setOpenFunction(id)}
        />
      ))}
    </CardGrid>
  );
}
