// Datenraten-Darstellung (CERNIS PRO 2.0)
//
// Wandelt eine rohe Durchsatzrate in bit/s in Einheit + sprachrichtig
// formatierte Zahl. Reine Funktion ohne i18n-Abhängigkeit: sie liefert nur den
// STABILEN i18n-Schlüssel (beobachten.traffic.rate*) und den fertigen Zahlen-
// Text; die Einheit selbst steht in den Sprachdateien, nicht hier.
//
// Netzwerk-Konvention: Dezimal-Präfixe zur Basis 1000 (kbit/s = 1000 bit/s),
// NICHT 1024 — 1024er-Stufen sind Speicher-, keine Übertragungskonvention.

// Aufsteigende Stufen: ab welcher Rate (bit/s) welcher i18n-Schlüssel gilt und
// durch welchen Faktor der Rohwert dafür geteilt wird. Reihenfolge = Suchrichtung
// (größte Stufe zuerst).
const STUFEN = [
  { ab: 1e9, faktor: 1e9, key: "beobachten.traffic.rateGbit", stellen: 1 },
  { ab: 1e6, faktor: 1e6, key: "beobachten.traffic.rateMbit", stellen: 1 },
  { ab: 1e3, faktor: 1e3, key: "beobachten.traffic.rateKbit", stellen: 1 },
];

// Unterste Stufe (unter 1000 bit/s, inkl. 0): rohe bit/s ohne Nachkommastelle.
const BIT_STUFE = {
  faktor: 1,
  key: "beobachten.traffic.rateBit",
  stellen: 0,
};

// Wählt die passende Stufe nach dem BETRAG des Wertes. Negative Raten kommen
// fachlich nicht vor; falls doch, werden sie NICHT kaschiert, sondern mit dem
// Minuszeichen in der Einheit ihres Betrags gezeigt.
function waehleStufe(bps) {
  const betrag = Math.abs(bps);
  return STUFEN.find((stufe) => betrag >= stufe.ab) ?? BIT_STUFE;
}

// Zerlegt eine Rohrate (bit/s) in i18n-Schlüssel + fertigen Zahlen-Text.
// ``sprache`` ist i18n.language (Muster formatiereZahl in LoggingPanel.jsx:
// toLocaleString -> DE Komma, EN Punkt).
//
// Nachkommastellen: bit/s keine, größere Einheiten höchstens eine
// (maximumFractionDigits, kein minimum -> "1 Mbit/s" statt "1,0 Mbit/s").
//
// Keine Zahl (null/undefined/NaN) -> null. Der Aufrufer entscheidet dann selbst,
// was er zeigt (in TrafficView der Gedankenstrich) — kein stiller Ersatzwert.
export function zerlegeDatenrate(bps, sprache) {
  if (bps === null || bps === undefined || !Number.isFinite(Number(bps))) {
    return null;
  }
  const roh = Number(bps);
  const stufe = waehleStufe(roh);
  const wert = roh / stufe.faktor;
  return {
    key: stufe.key,
    value: wert.toLocaleString(sprache, {
      maximumFractionDigits: stufe.stellen,
    }),
  };
}

// Bequeme Fassung für die Ansicht: übersetzt gleich mit. ``t`` ist die i18n-
// Übersetzungsfunktion. Liefert null, wenn zerlegeDatenrate null liefert.
export function formatiereDatenrate(t, bps, sprache) {
  const teile = zerlegeDatenrate(bps, sprache);
  return teile === null ? null : t(teile.key, { value: teile.value });
}
