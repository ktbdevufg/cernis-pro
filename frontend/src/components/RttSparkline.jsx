// Mini-RTT-Sparkline (CERNIS PRO 2.0)
//
// Reine, propsgesteuerte SVG-Polyline OHNE eigenen State. Sitzt klein neben der
// RTT-Zahl in jeder Status-Karte und zeichnet den jüngsten Verlauf des Ziels.
// Token-Variablen aus tokens.css, nie feste Farben. Rein dekorativ
// (aria-hidden) — die belastbare Zahl steht daneben.

// Kleiner vertikaler Rand (Anteil der Höhe), damit die Linie nicht am oberen/
// unteren Rand klebt.
const RAND_ANTEIL = 0.12;

// Feste interne Breite des viewBox-Koordinatensystems. Die tatsächliche Breite
// kommt über CSS (100 %); preserveAspectRatio="none" streckt frei.
const VB_BREITE = 100;

// Zeichnet eine Polyline über die (nicht-null) Werte, y-skaliert auf deren
// min..max. null-Werte sind Lücken und werden für Skalierung wie Linie schlicht
// übersprungen — die benachbarten realen Punkte verbinden sich.
//
// Props:
//   werte   Array von Zahlen (ältester zuerst); null = Lücke
//   farbe   CSS-Var-String (Default "var(--color-accent)")
//   hoehe   Pixel-Höhe (Default 24)
//   breite  optionale feste Pixel-Breite (sonst 100 % via viewBox)
export default function RttSparkline({
  werte,
  farbe = "var(--color-accent)",
  hoehe = 24,
  breite,
}) {
  const reihe = Array.isArray(werte) ? werte : [];

  // Indizes mit echtem Zahlenwert (null/undefined ausgefiltert) — getragen wird
  // sowohl die Skalierung als auch die x-Position (Index in der Gesamtreihe).
  const echtePunkte = reihe
    .map((wert, index) => ({ wert, index }))
    .filter((p) => typeof p.wert === "number" && Number.isFinite(p.wert));

  // Bei <2 Werten nichts zeichnen — leeres svg, kein Absturz.
  if (echtePunkte.length < 2) {
    return (
      <svg
        className="rtt-sparkline"
        width={breite}
        height={hoehe}
        aria-hidden="true"
      />
    );
  }

  let min = Infinity;
  let max = -Infinity;
  for (const p of echtePunkte) {
    if (p.wert < min) min = p.wert;
    if (p.wert > max) max = p.wert;
  }
  // Flacher Verlauf (alle Werte gleich): Spanne künstlich auf 1 setzen, damit
  // die Linie mittig statt am Rand liegt (Division durch 0 vermeiden).
  const spanne = max - min || 1;

  const randPx = hoehe * RAND_ANTEIL;
  const zeichenHoehe = hoehe - 2 * randPx;
  // x über den Index in der GESAMTreihe (Lücken halten ihren Platz, die Linie
  // springt einfach über sie hinweg). Letzter Index spannt die volle Breite.
  const maxIndex = reihe.length - 1 || 1;

  const punkte = echtePunkte
    .map((p) => {
      const x = (p.index / maxIndex) * VB_BREITE;
      // y invertiert (SVG-Ursprung oben): großer Wert -> kleiner y.
      const y = randPx + (1 - (p.wert - min) / spanne) * zeichenHoehe;
      return `${x.toFixed(2)},${y.toFixed(2)}`;
    })
    .join(" ");

  return (
    <svg
      className="rtt-sparkline"
      width={breite}
      height={hoehe}
      viewBox={`0 0 ${VB_BREITE} ${hoehe}`}
      preserveAspectRatio="none"
      aria-hidden="true"
    >
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
  );
}
