// SLA-Verlaufsgraph einer Logging-Aufgabe (CERNIS PRO 2.0)
//
// Propsgesteuert, KEIN eigener Fetch und kein eigener State — die Buckets kommen
// fertig aus LoggingTaskDetail (fetchLoggingSla.chart). Zeichnet EINE Reihe je
// modus: "uptime" (Verfügbarkeit % je Stunden-Bucket, feste Y-Achse 0–100 %) oder
// "rtt" (Ø-RTT je Bucket, min/max-skaliert wie RttGraph). Die Tabs SELBST liegen
// NICHT hier (die Detailansicht steuert über den modus-Prop) — diese Komponente
// bleibt bewusst zustandsarm.
//
// Stil-Vorbild RttGraph: gestrecktes SVG (preserveAspectRatio="none"), 3 dezente
// Gridlinien mit Achsen-Overlay (% bzw. ms) daneben (nicht im verzerrten SVG),
// ruhige Leer-Meldung bei < 2 Punkten. Nur Token-Variablen aus tokens.css, nie
// feste Farben.

import { useTranslation } from "react-i18next";

import "./SlaChart.css";

// Koordinatensystem des viewBox (wie RttGraph). Höhe ~180px; die Breite ist nur das
// interne Raster (preserveAspectRatio="none" streckt auf 100 %).
const VB_BREITE = 100;
const VB_HOEHE = 180;
const RAND_OBEN = 14;
const RAND_UNTEN = 14;

// Reihen-Farbe je modus: uptime -> Akzent (Türkis), rtt -> Link-Ton (klar
// unterscheidbarer Blau-Ton, beide aus tokens.css — keine feste Farbe).
const FARBE = {
  uptime: "var(--color-accent)",
  rtt: "var(--color-link)",
};

// Achsen-Beschriftung je modus. uptime auf ganze %, rtt auf eine Nachkommastelle.
function formatWert(wert, modus) {
  return modus === "uptime" ? `${Math.round(wert)} %` : `${wert.toFixed(1)} ms`;
}

// Props:
//   buckets  Array [{ ts, datetime, uptimePct, avgRttMs, samples }] (älteste zuerst)
//   modus    "uptime" | "rtt"
//   label    optionale Bezeichnung für die Kopfzeile
export default function SlaChart({ buckets, modus = "uptime", label }) {
  const { t } = useTranslation();

  const reihe = Array.isArray(buckets) ? buckets : [];
  // Den modus-passenden Wert je Bucket ziehen (uptimePct bzw. avgRttMs). null bleibt
  // ehrliche Lücke (kein erfundener 0-Wert) und fällt für Skalierung/Linie raus.
  const feld = modus === "uptime" ? "uptimePct" : "avgRttMs";
  const echtePunkte = reihe
    .map((bucket, index) => ({ wert: bucket[feld], index }))
    .filter((p) => typeof p.wert === "number" && Number.isFinite(p.wert));

  const titel =
    modus === "uptime"
      ? t("beobachten.logging.chartTab.uptime")
      : t("beobachten.logging.chartTab.rtt");

  const kopf = (
    <div className="sla-chart__kopf">
      <span className="sla-chart__titel">
        {titel}
        {label ? <span className="sla-chart__label"> · {label}</span> : null}
      </span>
    </div>
  );

  // Zu wenige Punkte: ruhige Leer-Meldung statt leerem Kasten (wie RttGraph).
  if (echtePunkte.length < 2) {
    return (
      <div className="sla-chart">
        {kopf}
        <p className="sla-chart__leer">{t("beobachten.logging.chartLeer")}</p>
      </div>
    );
  }

  // Y-Skala: uptime fest 0–100 % (vergleichbare Höhe über Zeiträume hinweg), rtt
  // min/max-skaliert wie RttGraph (Latenz hat keine feste Obergrenze).
  let min;
  let max;
  if (modus === "uptime") {
    min = 0;
    max = 100;
  } else {
    min = Infinity;
    max = -Infinity;
    for (const p of echtePunkte) {
      if (p.wert < min) min = p.wert;
      if (p.wert > max) max = p.wert;
    }
  }
  const spanne = max - min || 1;
  const mid = (min + max) / 2;

  const zeichenHoehe = VB_HOEHE - RAND_OBEN - RAND_UNTEN;
  const maxIndex = reihe.length - 1 || 1;

  // y-Position eines Werts im Raster (invertiert: groß = oben).
  const yVon = (wert) => RAND_OBEN + (1 - (wert - min) / spanne) * zeichenHoehe;

  const punkte = echtePunkte
    .map((p) => {
      const x = (p.index / maxIndex) * VB_BREITE;
      return `${x.toFixed(2)},${yVon(p.wert).toFixed(2)}`;
    })
    .join(" ");

  // 3 dezente Gridlinien: max oben, mid mittig, min unten — je mit Beschriftung.
  const gridLinien = [max, mid, min];
  const farbe = FARBE[modus] ?? "var(--color-accent)";

  // Dezente x-Beschriftung: erste/letzte datetime des sichtbaren Ausschnitts.
  const ersteZeit = reihe[0]?.datetime ?? null;
  const letzteZeit = reihe[reihe.length - 1]?.datetime ?? null;

  return (
    <div className="sla-chart">
      {kopf}
      <svg
        className="sla-chart__svg"
        viewBox={`0 0 ${VB_BREITE} ${VB_HOEHE}`}
        preserveAspectRatio="none"
        role="img"
        aria-label={`${titel} ${label ?? ""}`}
      >
        {gridLinien.map((wert, i) => (
          <line
            key={`grid-${i}`}
            className="sla-chart__grid"
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

      {/* Achsen-Beschriftung außerhalb des gestreckten SVG (sonst mitverzerrt). */}
      <div className="sla-chart__achse" aria-hidden="true">
        {gridLinien.map((wert, i) => (
          <span
            key={`label-${i}`}
            className="sla-chart__achse-wert"
            style={{ top: `${(yVon(wert) / VB_HOEHE) * 100}%` }}
          >
            {formatWert(wert, modus)}
          </span>
        ))}
      </div>

      {/* Dezente x-Achse: erste/letzte Bucket-Zeit, sonst ohne Beschriftung. */}
      {(ersteZeit || letzteZeit) && (
        <div className="sla-chart__zeit" aria-hidden="true">
          <span>{ersteZeit}</span>
          <span>{letzteZeit}</span>
        </div>
      )}
    </div>
  );
}
