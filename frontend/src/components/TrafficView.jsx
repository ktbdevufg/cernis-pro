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
  Server,
  Sparkles,
  X,
} from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { fetchTraffic, fetchTrafficPermission } from "../api/traffic.js";
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
function AppListe({ apps, onSelect, selectedName }) {
  const { t } = useTranslation();
  const max = maxDown(apps);

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
        <span className="traffic-list__live">
          <span className="traffic-list__live-dot" aria-hidden="true" />
          {t("beobachten.traffic.live")}
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

// Eine gebündelte Ziel-Zeile MIT echtem Ziel. Die IP (mono) ist der Lookup-
// Trigger — für JEDE Verbindung (F3-Klick-Trigger): Klick (oder Enter/Space)
// öffnet die Gegenstellen-Ansicht. host ist in der Liste immer null (der
// aufgelöste Name kommt erst im LookupPanel), daher nur die IP.
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
          <span className="traffic-detail__conn-ip traffic-mono">
            {buendel.remote}
          </span>
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
const STANDARD_OFFEN = 3; // echte Ziele anfangs offen sichtbar

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

  // Bei wenigen echten Zielen (<=4) alles offen, kein Toggle.
  const wenig = echteZiele.length <= 4;
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

export default function TrafficView() {
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

  useEffect(() => {
    let ignorieren = false;
    setStatus("laedt");

    fetchTraffic()
      .then((ergebnis) => {
        if (!ignorieren) {
          setApps(ergebnis);
          setStatus("ok");
        }
      })
      .catch(() => {
        if (!ignorieren) {
          setStatus("fehler");
        }
      });

    // Rechte-Naht separat: ihr Fehlschlag soll die Liste nicht kippen.
    fetchTrafficPermission()
      .then((ergebnis) => {
        if (!ignorieren) {
          setPermission(ergebnis);
        }
      })
      .catch(() => {
        // Stiller Verzicht NUR für den optionalen Hinweis-Streifen: ohne
        // Rechte-Antwort einfach keinen Hinweis zeigen (kein falscher Alarm).
      });

    return () => {
      ignorieren = true;
    };
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
