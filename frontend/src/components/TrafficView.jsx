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

// Rechte Spalte: Verbindungs-Detail der gewählten App.
function AppDetailPanel({ app, onClose }) {
  const { t } = useTranslation();
  const Icon = APP_ICONS[app.icon] ?? HelpCircle;

  // TEMP: 'nachschlagen' fuehrt spaeter zur Gegenstellen-Ansicht (Fakten +
  // externe Links, diagnostics/cpnetcheck) — noch nicht gebaut.
  const handleNachschlagen = (conn) => {
    // Bewusst ohne Funktion (Platzhalter, kein Ziel).
    void conn;
  };

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

        <section className="traffic-detail__section">
          <h4 className="traffic-detail__section-heading">
            {t("beobachten.traffic.connections", {
              count: app.conns.length,
            })}
          </h4>

          <ul className="traffic-detail__conns">
            {app.conns.map((conn) => (
              <li key={conn.remote} className="traffic-detail__conn">
                <div className="traffic-detail__conn-line">
                  <span className="traffic-detail__conn-remote traffic-mono">
                    {conn.remote}
                  </span>
                  <span className="traffic-detail__conn-service">
                    {conn.service}
                  </span>
                  {conn.notable && (
                    <button
                      type="button"
                      className="traffic-detail__lookup"
                      onClick={() => handleNachschlagen(conn)}
                    >
                      {t("beobachten.traffic.lookup")}
                    </button>
                  )}
                </div>
                <span className="traffic-detail__conn-state">
                  {t("beobachten.traffic.state", { value: conn.state })}
                </span>
              </li>
            ))}
          </ul>
        </section>
      </div>
    </aside>
  );
}

export default function TrafficView() {
  const { apps } = trafficMock;

  // Gewählte App über den Namen (eindeutiger Schlüssel im Mock); null = keine.
  const [gewaehlterName, setGewaehlterName] = useState(null);

  // Klick auf eine Zeile: wählt die App; erneuter Klick auf dieselbe löscht.
  const handleSelect = (app) => {
    setGewaehlterName((aktuell) =>
      aktuell === app.name ? null : app.name,
    );
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
      {gewaehlteApp && (
        <AppDetailPanel
          key={gewaehlteApp.name}
          app={gewaehlteApp}
          onClose={() => setGewaehlterName(null)}
        />
      )}
    </div>
  );
}
