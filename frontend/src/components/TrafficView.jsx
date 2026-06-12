// Per-App-Verkehr (CERNIS PRO 2.0)
// Zwei-Spalten-Ansicht analog zum Scan-Muster: links die App-Liste, rechts das
// Verbindungs-Detail der gewählten App. Gleiche Designsprache, gleiche Wannen-
// Markierung der gewählten Zeile, gleiches Split-Verhalten.
//
// Datenquelle ist ausschließlich der Import aus mockData/trafficMock. Die
// Komponente weiß nicht, ob die Daten echt oder Platzhalter sind. Bei echter
// Anbindung wird nur dieser Import ausgetauscht.

import {
  Globe,
  HelpCircle,
  Mail,
  Music,
  RefreshCw,
  TerminalSquare,
  X,
} from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import trafficMock from "../mockData/trafficMock.js";
import LookupPanel from "./LookupPanel.jsx";
import "./TrafficView.css";

// Abbildung der Mock-Icon-Schlüssel auf lucide-Komponenten.
// Hält den Mock frei von Komponenten-Referenzen.
const APP_ICONS = {
  browser: Globe,
  music: Music,
  mail: Mail,
  terminal: TerminalSquare,
  refresh: RefreshCw,
  unknown: HelpCircle,
};

// Schwelle für die Balken-Normierung; der breiteste Balken entspricht der
// höchsten down-Rate der Liste (ruhiger Anteil, kein flackerndes Diagramm).
function maxDown(apps) {
  return apps.reduce((max, app) => (app.down > max ? app.down : max), 1);
}

// Datenraten-Formatierung: ab 1000 KB/s als "x.x MB/s", sonst "<n> KB/s".
function formatRate(t, kbPerSec) {
  if (kbPerSec >= 1000) {
    return t("beobachten.traffic.rateMb", {
      value: (kbPerSec / 1000).toFixed(1),
    });
  }
  return t("beobachten.traffic.rateKb", { value: kbPerSec });
}

// Eine App-Zeile in der linken Liste. Klickbar; Klick meldet die App an
// onSelect. selected hebt die zum offenen Detail-Panel gehörende Zeile hervor.
function AppZeile({ app, onSelect, selected, anteil }) {
  const { t } = useTranslation();
  const Icon = APP_ICONS[app.icon] ?? HelpCircle;

  const rowKlasse = selected
    ? "traffic-app traffic-app--aktiv"
    : "traffic-app";

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
          <span className="traffic-app__name traffic-mono">{app.name}</span>
          {app.notable && (
            <span className="traffic-app__pill">
              {t("beobachten.traffic.notablePill")}
            </span>
          )}
        </span>

        {/* Ruhige Datenraten-Zeile: dünner Balken (Anteil down/max) + Zahl. */}
        <span className="traffic-app__rate">
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
        </span>
      </span>
    </button>
  );
}

// Linke Spalte: Kopfzeile mit Titel + Live-Indikator, darunter die App-Liste.
function AppListe({ apps, onSelect, selectedName }) {
  const { t } = useTranslation();
  const max = maxDown(apps);

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
        {apps.map((app) => (
          <AppZeile
            key={app.name}
            app={app}
            onSelect={onSelect}
            selected={app.name === selectedName}
            anteil={Math.round((app.down / max) * 100)}
          />
        ))}
      </div>
    </div>
  );
}

// Bündelt Verbindungen nach Ziel: gleicher host (bzw. gleiche remote-IP, wenn
// host=null) UND gleicher port werden zu EINEM Bündel zusammengefasst. Behält
// die übrigen Felder der ersten Verbindung des Bündels und zählt die Menge.
// Bewusst als reine Hilfsfunktion: später auch im Scan-Detail (Ports) nutzbar.
function buendeleVerbindungen(conns) {
  const buendel = new Map();
  for (const conn of conns) {
    const ziel = conn.host ?? conn.remote;
    const schluessel = `${ziel}|${conn.port}`;
    const vorhanden = buendel.get(schluessel);
    if (vorhanden) {
      vorhanden.count += 1;
    } else {
      buendel.set(schluessel, { ...conn, count: 1 });
    }
  }
  return [...buendel.values()];
}

// Eine gebündelte Ziel-Zeile. host prominent + IP gedämpft; ohne host nur IP
// (mono) plus Hinweis "kein PTR-Record". Rechts ×N-Pill (falls N>1) und Port.
// Das Ziel selbst (Name bzw. IP) ist der Lookup-Trigger — für JEDE Verbindung,
// nicht nur notable; Klick (oder Enter/Space) öffnet die Gegenstellen-Ansicht.
// Wiederverwendbar gehalten (siehe ConnectionList): keine traffic-spezifische
// Annahme außer den Verbindungs-Feldern selbst.
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
              <span className="traffic-detail__conn-host">{buendel.host}</span>
              <span className="traffic-detail__conn-ip traffic-mono">
                {buendel.remote}
              </span>
            </>
          ) : (
            <>
              <span className="traffic-detail__conn-ip traffic-mono">
                {buendel.remote}
              </span>
              <span className="traffic-detail__conn-noptr">
                {t("beobachten.traffic.noPtr")}
              </span>
            </>
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
        <span className="traffic-detail__conn-service">{buendel.service}</span>
        <span className="traffic-detail__conn-state">
          {t("beobachten.traffic.state", { value: buendel.state })}
        </span>
      </div>
    </li>
  );
}

// Wiederverwendbare Verbindungs-/Ziel-Liste: bündelt nach Ziel+Port, trennt
// "Auffällig" (immer offen) von "Bekannte Ziele" (erste paar offen, Rest hinter
// einem Toggle). Bewusst eigenständig gehalten, damit das Scan-Detail-Panel
// dieselbe Bündel-/Klapp-Logik für offene Ports nutzen kann.
const STANDARD_OFFEN = 3; // bekannte Ziele anfangs offen sichtbar

function ConnectionList({ conns, onLookup }) {
  const { t } = useTranslation();
  const [erweitert, setErweitert] = useState(false);

  const buendel = buendeleVerbindungen(conns);
  const auffaellig = buendel.filter((b) => b.notable);
  // Bekannte Ziele nach Anzahl (×N) absteigend.
  const bekannt = buendel
    .filter((b) => !b.notable)
    .sort((a, b) => b.count - a.count);

  // Bei wenigen Verbindungen (<=4 gesamt) alles offen, kein Toggle.
  const wenig = conns.length <= 4;
  const sichtbarBekannt =
    wenig || erweitert ? bekannt : bekannt.slice(0, STANDARD_OFFEN);
  const versteckt = bekannt.length - sichtbarBekannt.length;
  const toggleSinnvoll = !wenig && (versteckt > 0 || erweitert);

  return (
    <div className="traffic-detail__connlist">
      {auffaellig.length > 0 && (
        <section className="traffic-detail__section">
          <h4 className="traffic-detail__section-heading">
            {t("beobachten.traffic.sections.notable")}
          </h4>
          <ul className="traffic-detail__conns">
            {auffaellig.map((b) => (
              <BuendelZeile
                key={`${b.host ?? b.remote}|${b.port}`}
                buendel={b}
                onLookup={onLookup}
              />
            ))}
          </ul>
        </section>
      )}

      {bekannt.length > 0 && (
        <section className="traffic-detail__section">
          <h4 className="traffic-detail__section-heading">
            {t("beobachten.traffic.sections.known")}
          </h4>
          <ul className="traffic-detail__conns">
            {sichtbarBekannt.map((b) => (
              <BuendelZeile
                key={`${b.host ?? b.remote}|${b.port}`}
                buendel={b}
                onLookup={onLookup}
              />
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
        </section>
      )}
    </div>
  );
}

// Rechte Spalte: Verbindungs-Detail der gewählten App. Der 'nachschlagen'-Link
// einer Verbindung meldet deren Ziel über onLookup nach oben — dort öffnet
// TrafficView die Gegenstellen-Ansicht (LookupPanel) in dieser Spalte.
function AppDetailPanel({ app, onClose, onLookup }) {
  const { t } = useTranslation();
  const Icon = APP_ICONS[app.icon] ?? HelpCircle;

  return (
    <aside className="traffic-detail">
      <div className="traffic-detail__header">
        <div className="traffic-detail__heading">
          <span className="traffic-detail__icon" aria-hidden="true">
            <Icon size={18} />
          </span>
          <div className="traffic-detail__title-group">
            <h3 className="traffic-detail__title traffic-mono">{app.name}</h3>
            <span className="traffic-detail__rates traffic-mono">
              {t("beobachten.traffic.down", {
                value: formatRate(t, app.down),
              })}
              {" · "}
              {t("beobachten.traffic.up", { value: formatRate(t, app.up) })}
              {" "}
              {t("beobachten.traffic.connCount", {
                count: app.conns.length,
              })}
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
        {app.notable && (
          <p className="traffic-detail__notice">
            {t("beobachten.traffic.unknownTarget")}
          </p>
        )}

        <ConnectionList conns={app.conns} onLookup={onLookup} />
      </div>
    </aside>
  );
}

export default function TrafficView() {
  const { apps } = trafficMock;

  // Gewählte App über den Namen (eindeutiger Schlüssel im Mock); null = keine.
  const [gewaehlterName, setGewaehlterName] = useState(null);

  // Nachzuschlagende Gegenstelle ({ ip, port }) oder null. Ist sie gesetzt,
  // tritt die Gegenstellen-Ansicht in der rechten Spalte an die Stelle des
  // Verbindungs-Details; Schließen kehrt zur App-Ansicht zurück.
  const [lookupZiel, setLookupZiel] = useState(null);

  // Klick auf eine Zeile: wählt die App; erneuter Klick auf dieselbe löscht.
  // Ein Wechsel schließt eine offene Gegenstellen-Ansicht (gehört zur alten App).
  const handleSelect = (app) => {
    setLookupZiel(null);
    setGewaehlterName((aktuell) =>
      aktuell === app.name ? null : app.name,
    );
  };

  // 'nachschlagen' einer Verbindung: deren Ziel (IP + Port) merken; die rechte
  // Spalte zeigt daraufhin die Gegenstellen-Ansicht.
  const handleLookup = (conn) => {
    setLookupZiel({ ip: conn.remote, port: conn.port });
  };

  const gewaehlteApp =
    apps.find((app) => app.name === gewaehlterName) ?? null;

  return (
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
            key={gewaehlteApp.name}
            app={gewaehlteApp}
            onClose={() => setGewaehlterName(null)}
            onLookup={handleLookup}
          />
        ))}
    </div>
  );
}
