// Per-App-Verkehr (CERNIS PRO 2.0)
// Zwei-Spalten-Ansicht analog zum Scan-Muster: links die App-Liste, rechts das
// Verbindungs-Detail der gewählten App. Gleiche Designsprache, gleiche Wannen-
// Markierung der gewählten Zeile, gleiches Split-Verhalten.
//
// Datenquelle ist die echte API (api/traffic.js): GET /api/traffic für die Apps
// + GET /api/traffic/permission für den Rechte-Status. Drei-Zustände-Muster
// (laedt/ok/fehler) wie LookupPanel. Früher kam alles aus einem lokalen Mock.

import {
  ArrowLeftRight,
  Database,
  Globe,
  Hexagon,
  HelpCircle,
  Mail,
  MonitorSmartphone,
  Music,
  RefreshCw,
  ScanSearch,
  Server,
  Sparkles,
  X,
} from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { fetchSniMap } from "../api/sni.js";
import { useSni } from "../hooks/useSni.js";
import {
  fetchPtrNames,
  fetchTraffic,
  fetchTrafficPermission,
} from "../api/traffic.js";
import LookupPanel from "./LookupPanel.jsx";
import "./TrafficView.css";

// Abbildung der Icon-Schlüssel (aus api/traffic.js iconAusName) auf lucide-
// Komponenten. Reine Icon-Anker in der Logo-Akzentfarbe — keine Aussage.
const APP_ICONS = {
  browser: Globe,
  remote: MonitorSmartphone,
  ai: Sparkles,
  transfer: ArrowLeftRight,
  node: Hexagon,
  server: Server,
  mail: Mail,
  music: Music,
  db: Database,
  unknown: HelpCircle,
  unattributed: HelpCircle,
};

// Auswählbare Auto-Refresh-Intervalle (Sekunden) für das Kopf-Dropdown. Muss zu
// den in App.jsx erlaubten REFRESH_WERTE passen (dort die single source of
// truth für State/Persistenz); 0 = aus. Die Sekunden-Labels sind sprachneutral.
const REFRESH_OPTIONEN = [5, 10, 30, 60];

// Sammelt die eindeutigen echten Remote-IPs aller Verbindungen aller Apps
// (remote !== null). Grundlage für die lazy PTR-Anreicherung.
function sammleRemoteIps(apps) {
  const ips = new Set();
  for (const app of apps) {
    for (const conn of app.conns ?? []) {
      if (conn.remote !== null && conn.remote !== undefined) {
        ips.add(conn.remote);
      }
    }
  }
  return [...ips];
}

// Schreibt aufgelöste PTR-Namen (cache: ip->name|null) in den host-Wert der
// betroffenen Verbindungen. Reine Funktion: liefert eine neue apps-Struktur,
// berührt vorhandene Objekte nicht. Nur IPs mit Cache-Eintrag und echtem Namen
// (nicht null) werden gesetzt; alles andere bleibt host:null (= nur IP).
function reichereHostsAn(apps, cache) {
  return apps.map((app) => ({
    ...app,
    conns: (app.conns ?? []).map((conn) => {
      const name =
        conn.remote !== null && conn.remote !== undefined
          ? cache.get(conn.remote)
          : undefined;
      return name ? { ...conn, host: name } : conn;
    }),
  }));
}

// Überschreibt conn.host mit dem ECHTEN, von der App per TLS-ClientHello
// angefragten SNI-Hostnamen, wenn die SNI-Map (remote_ip -> hostname) einen
// Eintrag für conn.remote trägt. SNI SCHLÄGT PTR — diese Funktion wird daher
// NACH reichereHostsAn angewandt und überschreibt den PTR-Namen mit dem echten
// Domainnamen. Reine Funktion: neue apps-Struktur, vorhandene Objekte unberührt.
// Nur überschreiben, wenn ein SNI-Wert vorliegt; sonst PTR/host unverändert.
// sniMap ist eine echte Map (remote_ip -> hostname), überlebt Refreshes per Ref.
function reichereSniAn(apps, sniMap) {
  return apps.map((app) => ({
    ...app,
    conns: (app.conns ?? []).map((conn) => {
      const hostname =
        conn.remote !== null && conn.remote !== undefined
          ? sniMap.get(conn.remote)
          : undefined;
      return hostname ? { ...conn, host: hostname } : conn;
    }),
  }));
}

// Höchste vorhandene down-Rate für die Balken-Normierung (nur echte Raten
// zählen; null/—-Apps tragen nicht bei). Mindestens 1, damit nie durch 0.
function maxDown(apps) {
  return apps.reduce(
    (max, app) => (app.down !== null && app.down > max ? app.down : max),
    1,
  );
}

// Rohrate (bps) schlicht lesbar machen. Die echte Umrechnung kommt erst mit dem
// Poller; vorerst nur die Roh-Bits/s als ehrliche Zahl. null wird hier nie
// übergeben (Aufrufer prüft vorher und zeigt sonst "—").
function formatRate(t, bps) {
  return t("beobachten.traffic.rateBps", { value: bps });
}

// App-Anzeigename: echter Name oder das ehrliche None-Gruppen-Label.
function appLabel(t, app) {
  return app.name ?? t("beobachten.traffic.unattributed");
}

// Eine App-Zeile in der linken Liste. Klickbar; Klick meldet die App an
// onSelect. selected hebt die zum offenen Detail-Panel gehörende Zeile hervor.
// Ohne echte Rate (down===null): ruhiges "—" statt Balken; mit Rate: Balken.
function AppZeile({ app, onSelect, selected, anteil }) {
  const { t } = useTranslation();
  const Icon = APP_ICONS[app.icon] ?? HelpCircle;

  const rowKlasse = selected
    ? "traffic-app traffic-app--aktiv"
    : "traffic-app";

  const hatRate = app.down !== null;

  return (
    <button type="button" className={rowKlasse} onClick={() => onSelect(app)}>
      {selected && (
        // "Wanne" als Aktiv-Marker: vertikal, Wölbung nach innen zur Zeile
        // (gleicher SVG-Pfad wie in ScanTable).
        <span className="traffic-app__wanne" aria-hidden="true">
          <svg viewBox="0 0 10 100" preserveAspectRatio="none">
            <path d="M10,1 C5,1 3.5,5 3,13 L3,87 C3.5,95 5,99 10,99 C6,97 4.3,93 4,87 L4,13 C4.3,7 6,3 10,1 Z" />
          </svg>
        </span>
      )}

      <span className="traffic-app__icon" aria-hidden="true">
        <Icon size={16} />
      </span>

      <span className="traffic-app__body">
        <span className="traffic-app__head">
          <span className="traffic-app__name traffic-mono">
            {appLabel(t, app)}
          </span>
        </span>

        {/* Datenraten-Zeile: Balken nur bei echter Rate, sonst ruhiges "—".
            Daneben/dahinter die Verbindungsanzahl. */}
        <span className="traffic-app__rate">
          {hatRate ? (
            <>
              <span className="traffic-app__bar" aria-hidden="true">
                <span
                  className="traffic-app__bar-fill"
                  style={{ width: `${anteil}%` }}
                />
              </span>
              <span className="traffic-app__rate-value traffic-mono">
                {t("beobachten.traffic.down", {
                  value: formatRate(t, app.down),
                })}
              </span>
            </>
          ) : (
            <span className="traffic-app__rate-none" aria-hidden="true">
              —
            </span>
          )}
          <span className="traffic-app__conncount">
            {t("beobachten.traffic.connCount", { count: app.connectionCount })}
          </span>
        </span>
      </span>
    </button>
  );
}

// Linke Spalte: Kopfzeile mit Titel + Live-Indikator, darunter die App-Liste.
// Sortierung: connectionCount absteigend; die None-Gruppe (name===null) IMMER
// ans Ende, egal wie viele Verbindungen (ehrliche None-Gruppe unten).
// Der Live-Indikator erscheint NUR bei aktivem Auto-Refresh (refreshInterval > 0);
// der Refresh-Button bleibt davon unberührt immer sichtbar.
function AppListe({
  apps,
  onSelect,
  selectedName,
  onRefresh,
  refreshing,
  refreshInterval,
  onRefreshIntervalChange,
  sniAktiv,
  sniStartet,
  onSniStart,
  onSniStop,
}) {
  const { t } = useTranslation();
  const max = maxDown(apps);

  // SNI-Klasse: Grundklasse + Aktiv-Modifikator (visuelle Hervorhebung, wenn die
  // Beobachtung läuft). Klick toggelt: aktiv -> stop, sonst -> start.
  const sniKlasse = sniAktiv
    ? "traffic-list__sni traffic-list__sni--aktiv"
    : "traffic-list__sni";

  const sortiert = [...apps].sort((a, b) => {
    if (a.name === null && b.name !== null) return 1;
    if (b.name === null && a.name !== null) return -1;
    return b.connectionCount - a.connectionCount;
  });

  return (
    <div className="traffic-list">
      <div className="traffic-list__header">
        <span className="traffic-list__title">
          {t("beobachten.traffic.title")}
        </span>
        <span className="traffic-list__header-right">
          {/* SNI-Toggle LINKS vom Live-Indikator: startet/stoppt die passive
              SNI-Beobachtung. Aktiv -> stop, sonst -> start. Während des Starts
              disabled + "wird gestartet …". Erfordert erhöhte Rechte. */}
          <button
            type="button"
            className={sniKlasse}
            onClick={sniAktiv ? onSniStop : onSniStart}
            disabled={sniStartet}
            title={t("beobachten.traffic.sniHint")}
          >
            <ScanSearch size={15} />
            <span className="traffic-list__sni-label">
              {sniStartet
                ? t("beobachten.traffic.sniStarting")
                : sniAktiv
                  ? t("beobachten.traffic.sniActive")
                  : t("beobachten.traffic.sniToggle")}
            </span>
          </button>
          {/* Live-Indikator nur bei aktivem Auto-Refresh; schlichtes "live"
              (das Intervall zeigt das Dropdown direkt daneben). */}
          {refreshInterval > 0 && (
            <span className="traffic-list__live">
              <span className="traffic-list__live-dot" aria-hidden="true" />
              {t("beobachten.traffic.live")}
            </span>
          )}
          {/* Kompaktes Intervall-Dropdown: zog aus den Einstellungen hierher um.
              value/Persistenz bleiben in App.jsx; hier nur die Bedienung. */}
          <select
            className="traffic-list__interval"
            value={refreshInterval}
            onChange={(e) => onRefreshIntervalChange(Number(e.target.value))}
            aria-label={t("beobachten.traffic.refreshIntervalLabel")}
            title={t("beobachten.traffic.refreshIntervalLabel")}
          >
            <option value={0}>{t("beobachten.traffic.refreshOff")}</option>
            {REFRESH_OPTIONEN.map((secs) => (
              <option key={secs} value={secs}>
                {`${secs} s`}
              </option>
            ))}
          </select>
          {/* Immer sichtbar, unabhängig vom Auto-Intervall. Dezenter Lade-
              Zustand am Button (dreht/disabled); die Liste bleibt stehen. */}
          <button
            type="button"
            className={
              refreshing
                ? "traffic-list__refresh traffic-list__refresh--busy"
                : "traffic-list__refresh"
            }
            onClick={onRefresh}
            disabled={refreshing}
            aria-label={t("beobachten.traffic.refresh")}
            title={t("beobachten.traffic.refresh")}
          >
            <RefreshCw size={15} />
          </button>
        </span>
      </div>

      <div className="traffic-list__rows">
        {sortiert.map((app) => (
          <AppZeile
            key={app.name ?? "__unattributed__"}
            app={app}
            onSelect={onSelect}
            selected={app.name === selectedName}
            anteil={app.down !== null ? Math.round((app.down / max) * 100) : 0}
          />
        ))}
      </div>
    </div>
  );
}

// Bündelschlüssel einer Verbindung: echtes Ziel (remote-IP) + Port, sonst —
// bei ziel-losen Verbindungen — die lokale Seite (local-ip:port), damit gleich-
// artige ziel-lose Verbindungen sinnvoll zusammenfallen und nichts bei
// remote===null abstürzt. Ziel-lose Bündel werden NIE anklickbar (kein Lookup).
function buendelSchluessel(conn) {
  if (conn.remote !== null && conn.remote !== undefined) {
    return `r|${conn.remote}|${conn.port}`;
  }
  const lokal = conn.local ? `${conn.local.ip}:${conn.local.port}` : "?";
  return `l|${lokal}|${conn.l4 ?? "?"}|${conn.port ?? "?"}`;
}

// Bündelt Verbindungen nach Ziel+Port (bzw. lokaler Seite bei ziel-losen).
// Behält die übrigen Felder der ersten Verbindung des Bündels und zählt die
// Menge. Defensiv gegen remote===null (siehe buendelSchluessel).
function buendeleVerbindungen(conns) {
  const buendel = new Map();
  for (const conn of conns) {
    const schluessel = buendelSchluessel(conn);
    const vorhanden = buendel.get(schluessel);
    if (vorhanden) {
      vorhanden.count += 1;
    } else {
      buendel.set(schluessel, { ...conn, count: 1 });
    }
  }
  return [...buendel.values()];
}

// Eine gebündelte Ziel-Zeile MIT echtem Ziel. Der Zieltext (mono) ist der
// Lookup-Trigger — für JEDE Verbindung (F3-Klick-Trigger): Klick (oder
// Enter/Space) öffnet die Gegenstellen-Ansicht. Ist ein PTR-Name (host) lazy
// nachgereicht, steht der NAME prominent oben und die IP klein/gedämpft darunter;
// fehlt er (host null), steht schlicht die IP — KEIN "kein PTR"-Text (der gehört
// nur ins LookupPanel).
function BuendelZeile({ buendel, onLookup }) {
  const { t } = useTranslation();

  // Tastatur-Bedienbarkeit des als Button agierenden Ziel-Spans: Enter/Space
  // lösen das Nachschlagen aus (Space ohne Seiten-Scroll).
  const handleZielKey = (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onLookup(buendel);
    }
  };

  return (
    <li className="traffic-detail__conn">
      <div className="traffic-detail__conn-line">
        <span
          className="traffic-detail__conn-target"
          role="button"
          tabIndex={0}
          onClick={() => onLookup(buendel)}
          onKeyDown={handleZielKey}
          aria-label={t("beobachten.traffic.lookup")}
          title={t("beobachten.traffic.lookup")}
        >
          {buendel.host ? (
            <>
              <span className="traffic-detail__conn-host traffic-mono">
                {buendel.host}
              </span>
              <span className="traffic-detail__conn-ip traffic-mono">
                {buendel.remote}
              </span>
            </>
          ) : (
            <span className="traffic-detail__conn-ip traffic-mono">
              {buendel.remote}
            </span>
          )}
        </span>

        <span className="traffic-detail__conn-meta">
          {buendel.count > 1 && (
            <span className="traffic-detail__conn-bundle">
              {t("beobachten.traffic.bundlePill", { count: buendel.count })}
            </span>
          )}
          <span className="traffic-detail__conn-port traffic-mono">
            {t("beobachten.traffic.port", { value: buendel.port })}
          </span>
        </span>
      </div>

      <div className="traffic-detail__conn-sub">
        {buendel.service && (
          <span className="traffic-detail__conn-service">
            {buendel.service}
          </span>
        )}
        <span className="traffic-detail__conn-state">
          {t("beobachten.traffic.state", { value: buendel.state })}
        </span>
      </div>
    </li>
  );
}

// Eine ziel-lose Zeile (remote===null, z. B. mDNS/Multicast/UDP "none"): reiner
// Text, ausgegraut, NICHT anklickbar (kein role=button, kein onClick). Bei
// l4==="udp" und Port 5353 zusätzlich der mDNS-Hinweis. Steht am Ende der Liste.
function ZiellosZeile({ buendel }) {
  const { t } = useTranslation();
  const istMdns = buendel.l4 === "udp" && buendel.port === 5353;

  return (
    <li className="traffic-detail__conn traffic-detail__conn--ziellos">
      <div className="traffic-detail__conn-line">
        <span className="traffic-detail__conn-notarget">
          {t("beobachten.traffic.noTarget")}
          {istMdns && (
            <span className="traffic-detail__conn-mdns">
              {" · "}
              {t("beobachten.traffic.mdns")}
            </span>
          )}
        </span>
        <span className="traffic-detail__conn-meta">
          {buendel.count > 1 && (
            <span className="traffic-detail__conn-bundle">
              {t("beobachten.traffic.bundlePill", { count: buendel.count })}
            </span>
          )}
          {buendel.port !== null && (
            <span className="traffic-detail__conn-port traffic-mono">
              {t("beobachten.traffic.port", { value: buendel.port })}
            </span>
          )}
        </span>
      </div>
      <div className="traffic-detail__conn-sub">
        <span className="traffic-detail__conn-state">
          {t("beobachten.traffic.state", { value: buendel.state })}
        </span>
      </div>
    </li>
  );
}

// Wiederverwendbare Verbindungsliste: bündelt nach Ziel+Port. EINE schlichte
// Liste (keine Auffällig/Bekannt-Trennung — notable hat keine Datengrundlage).
// Echte Ziele zuerst (nach count absteigend), ziel-lose ans Ende. Die Klapp-
// Logik "erste N + mehr" bleibt für die echten Ziele (sinnvoll bei vielen).
const STANDARD_OFFEN = 10; // echte Ziele anfangs offen sichtbar

function ConnectionList({ conns, onLookup }) {
  const { t } = useTranslation();
  const [erweitert, setErweitert] = useState(false);

  const buendel = buendeleVerbindungen(conns);
  const echteZiele = buendel
    .filter((b) => b.remote !== null && b.remote !== undefined)
    .sort((a, b) => b.count - a.count);
  const ziellos = buendel.filter(
    (b) => b.remote === null || b.remote === undefined,
  );

  // Bei wenigen echten Zielen (bis STANDARD_OFFEN) alles offen, kein Toggle.
  // An STANDARD_OFFEN gekoppelt, damit der "alles offen"-Fall und die anfangs
  // sichtbare Menge konsistent bleiben (kein Toggle, der nichts verbirgt).
  const wenig = echteZiele.length <= STANDARD_OFFEN;
  const sichtbar =
    wenig || erweitert ? echteZiele : echteZiele.slice(0, STANDARD_OFFEN);
  const versteckt = echteZiele.length - sichtbar.length;
  const toggleSinnvoll = !wenig && (versteckt > 0 || erweitert);

  return (
    <div className="traffic-detail__connlist">
      <ul className="traffic-detail__conns">
        {sichtbar.map((b) => (
          <BuendelZeile
            key={`${b.remote}|${b.port}`}
            buendel={b}
            onLookup={onLookup}
          />
        ))}
        {/* Ziel-lose Verbindungen ans Ende, klar markiert und nicht anklickbar. */}
        {ziellos.map((b) => (
          <ZiellosZeile key={buendelSchluessel(b)} buendel={b} />
        ))}
      </ul>
      {toggleSinnvoll && (
        <button
          type="button"
          className="traffic-detail__toggle"
          onClick={() => setErweitert((v) => !v)}
        >
          {erweitert
            ? t("beobachten.traffic.showLess")
            : t("beobachten.traffic.showMore", { count: versteckt })}
        </button>
      )}
    </div>
  );
}

// Rechte Spalte: Verbindungs-Detail der gewählten App. Der Lookup einer
// Verbindung meldet deren Ziel über onLookup nach oben — dort öffnet TrafficView
// die Gegenstellen-Ansicht (LookupPanel) in dieser Spalte.
function AppDetailPanel({ app, onClose, onLookup }) {
  const { t } = useTranslation();
  const Icon = APP_ICONS[app.icon] ?? HelpCircle;

  // Raten-Zeile im Detail: echte Werte oder ehrliches "—" je Richtung.
  const downText =
    app.down !== null ? formatRate(t, app.down) : "—";
  const upText = app.up !== null ? formatRate(t, app.up) : "—";

  return (
    <aside className="traffic-detail">
      <div className="traffic-detail__header">
        <div className="traffic-detail__heading">
          <span className="traffic-detail__icon" aria-hidden="true">
            <Icon size={18} />
          </span>
          <div className="traffic-detail__title-group">
            <h3 className="traffic-detail__title traffic-mono">
              {appLabel(t, app)}
            </h3>
            <span className="traffic-detail__rates traffic-mono">
              {t("beobachten.traffic.down", { value: downText })}
              {" · "}
              {t("beobachten.traffic.up", { value: upText })}
              {" "}
              {t("beobachten.traffic.connCount", { count: app.connectionCount })}
            </span>
          </div>
        </div>
        <button
          type="button"
          className="traffic-detail__close"
          onClick={onClose}
          aria-label={t("beobachten.traffic.close")}
          title={t("beobachten.traffic.close")}
        >
          <X size={18} />
        </button>
      </div>

      <div className="traffic-detail__body">
        <ConnectionList conns={app.conns} onLookup={onLookup} />
      </div>
    </aside>
  );
}

// Ruhiger Hinweis-Streifen: zeigt den Backend-error-Text der Rechte-Naht
// ({ ok:false }). Reine Anzeige, kein Button, keine Eskalation.
function PermissionHinweis({ text }) {
  const { t } = useTranslation();
  return (
    <div className="traffic-permission" role="note">
      <span className="traffic-permission__title">
        {t("beobachten.traffic.permissionTitle")}
      </span>
      <span className="traffic-permission__text">{text}</span>
    </div>
  );
}

// Ruhiger SNI-Hinweisstreifen: zeigt den SNI-Fehlertext (z. B. fehlende Rechte)
// analog zu PermissionHinweis, hängt aber an der eigenen SNI-Naht (nicht an
// traffic-permission). Reine Anzeige, kein Button, keine Eskalation.
function SniHinweis({ text }) {
  const { t } = useTranslation();
  return (
    <div className="traffic-permission traffic-permission--sni" role="note">
      <span className="traffic-permission__title">
        {t("beobachten.traffic.permissionTitle")}
      </span>
      <span className="traffic-permission__text">{text}</span>
    </div>
  );
}

export default function TrafficView({
  refreshInterval = 0,
  onRefreshIntervalChange,
}) {
  const { t } = useTranslation();

  // Drei Zustände wie LookupPanel: "laedt" / "ok" / "fehler".
  const [status, setStatus] = useState("laedt");
  const [apps, setApps] = useState([]);
  // Rechte-Naht: null = noch unbekannt; sonst { ok, error }.
  const [permission, setPermission] = useState(null);

  // Gewählte App über den Namen; null = keine. Die None-Gruppe (name===null)
  // wird über einen eigenen Sentinel adressiert, damit sie wählbar bleibt.
  const [gewaehlterName, setGewaehlterName] = useState(undefined);

  // Nachzuschlagende Gegenstelle ({ ip, port }) oder null.
  const [lookupZiel, setLookupZiel] = useState(null);

  // Dezenter Lade-Zustand am Refresh-Button (dreht/disabled), OHNE den
  // "laedt"-Vollzustand auszulösen — die Liste bleibt beim Reload stehen.
  const [refreshing, setRefreshing] = useState(false);

  // Verhindert überlappende Reloads (Klick während Auto-Intervall o. ä.).
  const ladeLaeuft = useRef(false);

  // Client-Cache der PTR-Namen über Refreshes hinweg: ip -> name|null. Hält
  // bereits aufgelöste IPs fest (auch null = "kein PTR", damit nicht erneut
  // gefragt wird) und überlebt Auto-Refreshes. Bewusst useRef (kein State): die
  // Anreicherung steckt das Ergebnis selbst per setApps in die Liste.
  const ptrCache = useRef(new Map());

  // SNI-Naht: manuell startbare, root-pflichtige Beobachtung der echten von Apps
  // angefragten Domainnamen (TLS-ClientHello). sniAktiv steuert, ob der Refresh-
  // Pfad zusätzlich SNI anreichert; sniStartet ist der flüchtige Start-Zustand;
  // sniError trägt einen ruhigen Hinweis (z. B. fehlende Rechte). sniMap hält die
  // beobachteten remote_ip -> hostname über Refreshes hinweg (Ref, kein State:
  // die Anreicherung steckt das Ergebnis selbst per setApps in die Liste).
  // SNI-Lifecycle kommt jetzt aus dem geteilten Hook (Reference-Count über alle
  // Ansichten). Die Namen sniAktiv/sniStartet/sniError bleiben im restlichen Code
  // unverändert gültig — sie stammen nun aus dem Hook statt aus lokalem useState.
  const {
    running: sniAktiv,
    starting: sniStartet,
    error: sniError,
    acquire,
    release,
    syncStatus,
  } = useSni();
  const sniMap = useRef(new Map());

  // Spiegelt sniAktiv in eine Ref, damit der stabile Anreicherungs-Pfad
  // (reichereTrafficAn, useCallback []) den Live-Wert lesen kann, OHNE
  // ladeTraffic neu zu erzeugen — sonst würde das initiale Laden beim Toggle
  // erneut feuern (Lade-Flackern, Auswahl-Reset). Der eigentliche Reload nach
  // dem Toggle wird explizit über ladeTraffic(false) angestoßen.
  const sniAktivRef = useRef(false);

  // sniAktiv kommt jetzt aus dem Hook; die Ref muss bei jeder Änderung nachziehen,
  // damit der stabile Reload-Pfad (reichereTrafficAn) den Live-Wert liest.
  useEffect(() => {
    sniAktivRef.current = sniAktiv;
  }, [sniAktiv]);

  // Lazy, nicht-blockierende PTR-Anreicherung NACH dem Listen-Render: fragt nur
  // IPs OHNE Cache-Eintrag neu an, mischt das Ergebnis in den Cache und reichert
  // die bereits gerenderte Liste an (setApps mit reiner Map -> kein Neuladen,
  // kein Sprung der Auswahl). Schlägt der Call fehl, bleiben die IPs als IPs
  // stehen (fetchPtrNames toleriert das bereits blockweise).
  const reichereTrafficAn = useCallback(
    async (geladeneApps) => {
      const sichtbare = sammleRemoteIps(geladeneApps);
      const offen = sichtbare.filter((ip) => !ptrCache.current.has(ip));

      if (offen.length > 0) {
        const aufgeloest = await fetchPtrNames(offen);
        for (const [ip, name] of Object.entries(aufgeloest)) {
          ptrCache.current.set(ip, name);
        }
      }

      // Bei aktiver SNI-Beobachtung zusätzlich die beobachteten Hostnamen holen
      // und in sniMap mergen. SNI ist Beiwerk (fetchSniMap wirft nie, gibt {} bei
      // Fehler) — ein Patzer hier darf die PTR-Anreicherung nicht verhindern.
      if (sniAktivRef.current) {
        const beobachtet = await fetchSniMap();
        for (const [ip, hostname] of Object.entries(beobachtet)) {
          sniMap.current.set(ip, hostname);
        }
        // Erst PTR, dann SNI darüber: SNI schlägt PTR (echter Domainname statt
        // Hoster). reichereSniAn überschreibt nur, wo ein SNI-Wert vorliegt.
        setApps((aktuelle) =>
          reichereSniAn(
            reichereHostsAn(aktuelle, ptrCache.current),
            sniMap.current,
          ),
        );
        return;
      }

      // Ohne SNI nur PTR wie bisher. Auch ohne neuen Call anreichern: ein früherer
      // Refresh kann den Namen schon im Cache haben, während diese frisch geladene
      // Liste noch host:null trägt.
      setApps((aktuelle) => reichereHostsAn(aktuelle, ptrCache.current));
    },
    [],
  );

  // Eine Ladelogik für initiales Laden, manuellen Refresh und Auto-Intervall.
  // initial=true zeigt den Voll-"laedt"-Zustand (erstes Laden); sonst still:
  // NUR apps/permission aktualisieren, gewaehlterName/lookupZiel bleiben (kein
  // Sprung der Auswahl / des offenen Panels). Fällt die gewählte App nach dem
  // Reload weg, ergibt apps.find unten sauber null (kein Absturz).
  const ladeTraffic = useCallback(async (initial = false) => {
    if (ladeLaeuft.current) {
      return;
    }
    ladeLaeuft.current = true;
    if (initial) {
      setStatus("laedt");
    } else {
      setRefreshing(true);
    }

    try {
      const ergebnis = await fetchTraffic();
      setApps(ergebnis);
      setStatus("ok");
      // PTR-Namen lazy nachschieben — NICHT awaiten: die Liste ist schon
      // gezeigt, die Namen reichern sie im Hintergrund an. Eigene Fehler-
      // toleranz in fetchPtrNames; ein Patzer hier darf die Liste nicht kippen.
      reichereTrafficAn(ergebnis).catch(() => {});
    } catch {
      // Beim initialen Laden den Fehlerzustand zeigen; bei einem stillen Reload
      // die bestehende Liste stehen lassen (kein Kippen wegen einem Aussetzer).
      if (initial) {
        setStatus("fehler");
      }
    }

    // Rechte-Naht separat: ihr Fehlschlag soll die Liste nicht kippen.
    try {
      const rechte = await fetchTrafficPermission();
      setPermission(rechte);
    } catch {
      // Stiller Verzicht NUR für den optionalen Hinweis-Streifen: ohne
      // Rechte-Antwort einfach keinen Hinweis zeigen (kein falscher Alarm).
    }

    if (!initial) {
      setRefreshing(false);
    }
    ladeLaeuft.current = false;
  }, [reichereTrafficAn]);

  // Initiales Laden (mit Voll-"laedt"-Zustand).
  useEffect(() => {
    ladeTraffic(true);
  }, [ladeTraffic]);

  // Auto-Refresh-Intervall (Teil C): nur bei refreshInterval > 0. Ruft still
  // ladeTraffic() (kein "laedt"-Wechsel, Auswahl bleibt). Bei Änderung des
  // Intervalls / Unmount altes Intervall sauber clearen.
  useEffect(() => {
    if (!refreshInterval || refreshInterval <= 0) {
      return undefined;
    }
    const id = setInterval(() => {
      ladeTraffic(false);
    }, refreshInterval * 1000);
    return () => clearInterval(id);
  }, [refreshInterval, ladeTraffic]);

  // SNI-Start: meldet Bedarf am geteilten Hook an (acquire — start + starting/
  // error-Handling macht der Hook selbst) und stößt danach einen Reload an, damit
  // die SNI-Namen sofort einreichern. starting/error kommen reaktiv über
  // sniStartet/sniError aus dem Hook.
  const handleSniStart = useCallback(async () => {
    await acquire();
    sniAktivRef.current = true; // VOR dem Reload, damit er anreichert.
    ladeTraffic(false);
  }, [acquire, ladeTraffic]);

  // SNI-Stop: meldet Bedarf ab (release — der Hook stoppt erst beim letzten
  // release). Die bisherige Aufräum-Logik bleibt: Map leeren und einen Reload
  // anstoßen, damit die SNI-Namen verschwinden und auf PTR/IP zurückfallen.
  const handleSniStop = useCallback(async () => {
    await release();
    sniAktivRef.current = false; // VOR dem Reload, damit er NICHT mehr anreichert.
    sniMap.current = new Map();
    ladeTraffic(false);
  }, [release, ladeTraffic]);

  // Externen Ist-Zustand übernehmen: läuft SNI schon von einer anderen Ansicht,
  // erkennt TrafficView das beim Mount und schaltet aktiv (ohne neu zu starten).
  useEffect(() => {
    syncStatus();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Klick auf eine Zeile: wählt die App (name kann null sein -> Sentinel).
  const handleSelect = (app) => {
    setLookupZiel(null);
    setGewaehlterName((aktuell) =>
      aktuell === app.name ? undefined : app.name,
    );
  };

  // Lookup einer Verbindung: deren Ziel (IP + Port) merken.
  const handleLookup = (conn) => {
    setLookupZiel({ ip: conn.remote, port: conn.port });
  };

  const gewaehlteApp =
    gewaehlterName === undefined
      ? null
      : apps.find((app) => app.name === gewaehlterName) ?? null;

  const zeigePermission =
    permission !== null && permission.ok === false && permission.error;

  return (
    <div className="traffic">
      {zeigePermission && <PermissionHinweis text={permission.error} />}
      {sniError && <SniHinweis text={sniError} />}

      {status === "laedt" && (
        <p className="traffic-state-notice">
          {t("beobachten.traffic.loading")}
        </p>
      )}

      {status === "fehler" && (
        <p className="traffic-state-notice traffic-state-notice--error">
          {t("beobachten.traffic.error")}
        </p>
      )}

      {status === "ok" && (
        <div className="observe__split">
          <AppListe
            apps={apps}
            onSelect={handleSelect}
            selectedName={gewaehlterName}
            onRefresh={() => ladeTraffic(false)}
            refreshing={refreshing}
            refreshInterval={refreshInterval}
            onRefreshIntervalChange={onRefreshIntervalChange}
            sniAktiv={sniAktiv}
            sniStartet={sniStartet}
            onSniStart={handleSniStart}
            onSniStop={handleSniStop}
          />
          {gewaehlteApp &&
            (lookupZiel ? (
              <LookupPanel
                key={`${lookupZiel.ip}:${lookupZiel.port}`}
                ip={lookupZiel.ip}
                port={lookupZiel.port}
                onClose={() => setLookupZiel(null)}
              />
            ) : (
              <AppDetailPanel
                key={gewaehlteApp.name ?? "__unattributed__"}
                app={gewaehlteApp}
                onClose={() => setGewaehlterName(undefined)}
                onLookup={handleLookup}
              />
            ))}
        </div>
      )}
    </div>
  );
}
