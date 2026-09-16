// Großer RTT-Verlaufsgraph eines EINZELNEN Ziels (CERNIS PRO 2.0)
//
// Propsgesteuert, KEIN eigener Fetch und kein eigener State — die Werte kommen
// fertig von MonitorView (initial aus fetchRttHistory, live aus dem WS-Strom).
// Zeichnet ein ruhiges SVG-Verlaufsfeld im Stil der Monitor-Karten: Card-Fläche,
// dezente Gridlinien mit ms-Beschriftung, x ohne Beschriftung (gleitendes
// Live-Fenster). Token-Variablen aus tokens.css, nie feste Farben.

import { useTranslation } from "react-i18next";

import "./RttGraph.css";

// Koordinatensystem des viewBox. Höhe ~180px laut Vorgabe; die Breite ist nur
// das interne Raster (preserveAspectRatio="none" streckt auf 100 %).
const VB_BREITE = 100;
const VB_HOEHE = 180;
// Vertikaler Innenrand, damit die Linie und die Beschriftungen Luft haben.
const RAND_OBEN = 14;
const RAND_UNTEN = 14;

// Eine Gridlinie + ihre ms-Beschriftung (min/mid/max). wert in ms, y im
// viewBox-Raster. Beschriftung auf eine Nachkommastelle gerundet.
function formatMs(wert) {
  return `${wert.toFixed(1)} ms`;
}

// Props:
//   werte   Array von Zahlen (ältester zuerst); null = Lücke
//   label   Ziel-Bezeichnung für die Kopfzeile
//   farbe   CSS-Var-String (Default "var(--color-accent)")
export default function RttGraph({ werte, label, farbe = "var(--color-accent)" }) {
  const { t } = useTranslation();

  const reihe = Array.isArray(werte) ? werte : [];

  // Indizes mit echtem Zahlenwert (Lücken raus für Skalierung und Linie).
  const echtePunkte = reihe
    .map((wert, index) => ({ wert, index }))
    .filter((p) => typeof p.wert === "number" && Number.isFinite(p.wert));

  // Kopfzeile immer rendern; bei zu wenigen Punkten eine ruhige Leer-Meldung
  // statt eines leeren Kastens.
  const kopf = (
    <div className="rtt-graph__kopf">
      <span className="rtt-graph__titel">
        {t("beobachten.monitor.verlaufTitel")}
        {label ? <span className="rtt-graph__label"> · {label}</span> : null}
      </span>
      <span className="rtt-graph__hinweis">{t("beobachten.monitor.liveFenster")}</span>
    </div>
  );

  if (echtePunkte.length < 2) {
    return (
      <div className="rtt-graph">
        {kopf}
        <p className="rtt-graph__leer">{t("beobachten.monitor.verlaufLeer")}</p>
      </div>
    );
  }

  let min = Infinity;
  let max = -Infinity;
  for (const p of echtePunkte) {
    if (p.wert < min) min = p.wert;
    if (p.wert > max) max = p.wert;
  }
  const spanne = max - min || 1;
  const mid = (min + max) / 2;

  const zeichenHoehe = VB_HOEHE - RAND_OBEN - RAND_UNTEN;
  const maxIndex = reihe.length - 1 || 1;

  // y-Position eines ms-Werts im Raster (invertiert: groß = oben).
  const yVon = (wert) => RAND_OBEN + (1 - (wert - min) / spanne) * zeichenHoehe;

  const punkte = echtePunkte
    .map((p) => {
      const x = (p.index / maxIndex) * VB_BREITE;
      return `${x.toFixed(2)},${yVon(p.wert).toFixed(2)}`;
    })
    .join(" ");

  // 3 dezente Gridlinien: max oben, mid mittig, min unten — je mit Beschriftung.
  const gridLinien = [max, mid, min];

  return (
    <div className="rtt-graph">
      {kopf}
      <svg
        className="rtt-graph__svg"
        viewBox={`0 0 ${VB_BREITE} ${VB_HOEHE}`}
        preserveAspectRatio="none"
        role="img"
        aria-label={`${t("beobachten.monitor.verlaufTitel")} ${label ?? ""}`}
      >
        {/* Gridlinien quer (volle Breite), dezent. */}
        {gridLinien.map((wert, i) => (
          <line
            key={`grid-${i}`}
            className="rtt-graph__grid"
            x1="0"
            x2={VB_BREITE}
            y1={yVon(wert).toFixed(2)}
            y2={yVon(wert).toFixed(2)}
            vectorEffect="non-scaling-stroke"
          />
        ))}
        <polyline
          points={punkte}
          fill="none"
          stroke={farbe}
          strokeWidth="1.5"
          strokeLinecap="round"
          strokeLinejoin="round"
          vectorEffect="non-scaling-stroke"
        />
      </svg>
      {/* ms-Beschriftung der Gridlinien außerhalb des gestreckten SVG (sonst
          würde der Text mitverzerrt). Per CSS an den Zeilen ausgerichtet. */}
      <div className="rtt-graph__achse" aria-hidden="true">
        {gridLinien.map((wert, i) => (
          <span
            key={`label-${i}`}
            className="rtt-graph__achse-wert"
            style={{
              top: `${(yVon(wert) / VB_HOEHE) * 100}%`,
            }}
          >
            {formatMs(wert)}
          </span>
        ))}
      </div>
    </div>
  );
}
