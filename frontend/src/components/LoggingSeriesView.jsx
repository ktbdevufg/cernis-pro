// Serien-Auswertung einer Logging-Aufgabe (CERNIS PRO 2.0, Block 3c)
//
// Zweite Ansicht der Detailseite (nur bei operationMode "recurring"): verdichtet die
// Aufzeichnung zu Tag-ueber-Tag-Mustern. Sie laedt selbst ueber fetchLoggingSeries
// (analog LoggingTaskDetail, mit abgebrochen-Flag im useEffect) und steht propsgesteuert
// auf taskId + since + until. Reine Lesesicht — greift NICHT ins Netz ein.
//
// Aufbau von oben nach unten: Kennzahlen-Kopf (vier Kacheln) -> zwei segmentierte
// Controls (Was zeigen / Darstellung) -> CERNIS-Auto-Empfehlung als Textzeile mit
// Wiederherstellen-Link -> optionale Median+Band-Ueberlagerung (nur Einzellinien) ->
// SVG-Visualisierung je Darstellung (Heatmap / Einzellinien / Rangliste / Latenz) ->
// feste Detailtabelle GANZ UNTEN (Outage- bzw. Latenz-Tabelle je nach "Was zeigen").
//
// "Was zeigen" ist wirksam (maximale Wahlfreiheit, nie bevormundend):
//   wasAbbrueche -> Outage-Sicht (Visualisierung + Outage-Tabelle wie bisher).
//   wasLatenz    -> Latenz-Sicht (LatenzSvg + Latenz-Tabelle); nur bei hasLatency.
//   wasAlles     -> Outage-Sicht; bei hasLatency zusaetzlich die Latenz-Tabelle als
//                   zweiter Block. Ohne Latenz schlicht die Outage-Sicht (kein Leerblock).
//
// Intelligentes Ausgrauen: ohne Latenz (capture_mode interface_status/reachability)
// sind die latenzbezogenen Optionen disabled+ausgegraut; faellt die aktive Auswahl
// dadurch weg, fragt sie sichtbar auf wasAlles bzw. heatmap zurueck. Im Latenz-Kontext
// (wasLatenz) ist die Outage-Rangliste fachlich unpassend und wird ausgegraut; eine im
// aktuellen Kontext datenlose Darstellung zeigt einen ehrlichen Hinweis statt Leerbild.
//
// Stil wie der Bestand: Fehlertoleranz wie LoggingTaskDetail (ein Ladefehler kippt die
// Ansicht nicht), SVG wie SlaChart (viewBox-Raster, non-scaling-stroke, Achsen-Text
// ausserhalb des gestreckten SVG, ruhige Leer-Meldung), alle Texte ueber i18n, alle
// Farben ueber Tokens (tokens.css), nie feste Farben.

import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { fetchLoggingSeries } from "../api/monitoring.js";
import "./LoggingSeriesView.css";

// Koernung der Slot-Auswertung in Minuten (Backend-Default 10). Fest gehalten — die
// Ansicht bietet (noch) keinen Regler dafuer, gibt den Wert aber sauber als Dep weiter.
const SLOT_MINUTES = 10;

// viewBox-Raster der SVGs (wie SlaChart): gestreckte Breite 100, feste Hoehe. Eine
// Tageszeit-Achse spannt 0..1440 Minuten auf die 100 Raster-Einheiten.
const VB_BREITE = 100;
const VB_HOEHE = 150;
const RAND_OBEN = 10;
const RAND_UNTEN = 10;
const MINUTEN_PRO_TAG = 1440;

// Lokale Tagesminute (0..1439) -> "HH:MM". null/NaN -> "—".
function formatTagesminute(minute) {
  if (minute === null || minute === undefined || Number.isNaN(minute)) {
    return "—";
  }
  const stunden = Math.floor(minute / 60);
  const rest = minute % 60;
  return `${String(stunden).padStart(2, "0")}:${String(rest).padStart(2, "0")}`;
}

// Unix-ts (Sekunden) -> lesbare lokale Zeit (sprachabhaengig). null/NaN -> "—".
function formatZeit(ts, sprache) {
  if (ts === null || ts === undefined || Number.isNaN(ts)) {
    return "—";
  }
  return new Date(ts * 1000).toLocaleString(sprache);
}

// RTT in Millisekunden -> "12 ms" (eine Nachkommastelle). null/NaN -> "—".
function formatRtt(ms) {
  if (ms === null || ms === undefined || Number.isNaN(ms)) {
    return "—";
  }
  return `${Math.round(ms * 10) / 10} ms`;
}

// Dauer in Sekunden -> lesbar: "12 s" bzw. "1 m 02 s". null/NaN -> "—".
function formatDauer(sekunden) {
  if (sekunden === null || sekunden === undefined || Number.isNaN(sekunden)) {
    return "—";
  }
  const ganz = Math.round(sekunden);
  if (ganz < 60) {
    return `${ganz} s`;
  }
  const minuten = Math.floor(ganz / 60);
  const rest = ganz % 60;
  return `${minuten} m ${String(rest).padStart(2, "0")} s`;
}

// Eine Kennzahl-Kachel (Wert prominent, Bezeichnung dezent) — Optik wie LoggingTaskDetail.
function Kennzahl({ wert, label }) {
  return (
    <div className="logging-serie__kennzahl">
      <span className="logging-serie__kennzahl-wert">{wert}</span>
      <span className="logging-serie__kennzahl-label">{label}</span>
    </div>
  );
}

// CERNIS-Auto-Empfehlung der Darstellung aus den Daten ableiten. Reine Anzeige-Heuristik,
// kein fachliches Urteil: Heatmap nach Uhrzeit ist das Schluesselbild und der Default.
// Gibt es eine klare zeitliche Haeufung (Rangliste-Spitze ueber mehrere Tage), empfiehlt
// CERNIS die Rangliste; liegen viele Tage mit verteilten Ausfaellen vor, die Einzellinien.
function empfehlungBerechnen(serie) {
  if (!serie) {
    return "heatmap";
  }
  const ranking = serie.ranking ?? [];
  const tage = new Set((serie.outages ?? []).map((o) => o.dayKey).filter(Boolean));
  // Klarer Uhrzeit-Hotspot ueber mehrere Tage -> Rangliste sticht das Muster heraus.
  if (ranking.length > 0 && (ranking[0]?.dayCount ?? 0) >= 3) {
    return "rangliste";
  }
  // Viele Tage mit Ausfaellen -> Einzellinien zeigen die Tag-ueber-Tag-Streuung.
  if (tage.size >= 4) {
    return "einzellinien";
  }
  return "heatmap";
}

// Props:
//   taskId   id der Aufgabe (selbst geladen)
//   since    Unix-ts (Sekunden) oder null — untere Grenze des Auswertungsfensters
//   until    Unix-ts (Sekunden) oder null — obere Grenze
export default function LoggingSeriesView({ taskId, since = null, until = null }) {
  const { t, i18n } = useTranslation();

  // Geladene Serie (null = noch nicht geladen / nicht vorhanden) + Lade-/Fehlerzustand.
  const [serie, setSerie] = useState(null);
  const [laedt, setLaedt] = useState(false);
  const [fehler, setFehler] = useState(false);

  // Was zeigen: "wasAbbrueche" | "wasLatenz" | "wasAlles" (Default wasAlles).
  const [wasZeigen, setWasZeigen] = useState("wasAlles");
  // Darstellung: "einzellinien" | "heatmap" | "rangliste" (Default heatmap).
  const [darstellung, setDarstellung] = useState("heatmap");
  // Median+Band-Ueberlagerung (nur Einzellinien, Default aus).
  const [medianBand, setMedianBand] = useState(false);

  // Laedt die Serie fuer den aktuellen Ausschnitt. Fehler -> dezenter Hinweis, kein
  // Absturz (Muster LoggingTaskDetail). Deps: taskId/since/until/SLOT_MINUTES.
  useEffect(() => {
    let abgebrochen = false;

    (async () => {
      setLaedt(true);
      setFehler(false);
      try {
        const geladen = await fetchLoggingSeries(taskId, since, until, SLOT_MINUTES);
        if (!abgebrochen) {
          setSerie(geladen);
        }
      } catch {
        if (!abgebrochen) {
          setSerie(null);
          setFehler(true);
        }
      } finally {
        if (!abgebrochen) {
          setLaedt(false);
        }
      }
    })();

    return () => {
      abgebrochen = true;
    };
  // t BEWUSST NICHT in den Deps: react-i18next liefert bei jedem Render eine neue
  // t-Referenz -> mit t in den Deps feuert der State-setzende Effekt endlos (Loop).
  // t wird hier nur fuer statische Texte genutzt, keine Reaktivitaet noetig.
  }, [taskId, since, until]);

  const hatLatenz = serie?.hasLatency ?? false;
  // Latenz-Kontext: die Sicht dreht sich um Antwortzeiten (nur sinnvoll bei hasLatency).
  const imLatenzKontext = wasZeigen === "wasLatenz" && hatLatenz;

  // Intelligentes Ausgrauen: ohne Latenz sind "wasLatenz" und die Median+Band-Checkbox
  // gesperrt. Faellt die aktive Auswahl dadurch weg, sichtbar auf den ehrlichen Default
  // zuruecksetzen (wasAlles bzw. heatmap) — und die Ueberlagerung abschalten.
  useEffect(() => {
    if (!hatLatenz) {
      if (wasZeigen === "wasLatenz") {
        setWasZeigen("wasAlles");
      }
      if (medianBand) {
        setMedianBand(false);
      }
    }
  }, [hatLatenz, wasZeigen, medianBand]);

  // Im Latenz-Kontext ist die Outage-Rangliste fachlich unpassend (sie zaehlt Ausfaelle,
  // keine Antwortzeiten). Steht die Darstellung dort auf "rangliste", sichtbar auf den
  // Latenz-Default (heatmap) zuruecksetzen, damit kein leeres/falsches Bild stehen bleibt.
  useEffect(() => {
    if (wasZeigen === "wasLatenz" && hatLatenz && darstellung === "rangliste") {
      setDarstellung("heatmap");
    }
  }, [wasZeigen, hatLatenz, darstellung]);

  // CERNIS-Empfehlung aus den Daten (Anzeige-Heuristik, memoisiert ueber die Serie).
  const empfehlung = useMemo(() => empfehlungBerechnen(serie), [serie]);

  // Kennzahlen aufbereiten (roh -> Anzeige; null -> "—").
  const m = serie?.metrics ?? null;
  const verfuegbarkeitWert =
    m && m.availabilityPct !== null
      ? `${Number(m.availabilityPct).toLocaleString(i18n.language, { maximumFractionDigits: 1 })} %`
      : "—";
  const abbruecheWert = m ? String(m.outageCount ?? 0) : "—";
  const dauerWert = m && m.avgOutageS !== null ? formatDauer(m.avgOutageS) : "—";
  const fensterWert = m ? formatTagesminute(m.worstSlotMinute) : "—";

  return (
    <div className="logging-serie">
      <h3 className="logging-serie__titel" id="help.monitor.series">
        {t("beobachten.logging.serie.titel")}
      </h3>

      {fehler && (
        <div className="logging-serie__fehler" role="note">
          {t("beobachten.logging.detailFehler")}
        </div>
      )}

      {/* ── Kennzahlen-Kopf (vier Kacheln) ───────────────────────────────────── */}
      <div className="logging-serie__kennzahlen">
        <Kennzahl
          wert={verfuegbarkeitWert}
          label={t("beobachten.logging.serie.kennzahl.verfuegbarkeit")}
        />
        <Kennzahl wert={abbruecheWert} label={t("beobachten.logging.serie.kennzahl.abbrueche")} />
        <Kennzahl wert={dauerWert} label={t("beobachten.logging.serie.kennzahl.dauer")} />
        <Kennzahl wert={fensterWert} label={t("beobachten.logging.serie.kennzahl.fenster")} />
      </div>

      {/* ── Segmentierte Controls: Was zeigen / Darstellung ──────────────────── */}
      <div className="logging-serie__controls">
        <div className="logging-serie__control">
          <span className="logging-serie__control-label">
            {t("beobachten.logging.serie.wasZeigen.titel")}
          </span>
          <div className="logging-serie__segmente" role="tablist">
            {[
              { key: "wasAbbrueche", disabled: false },
              { key: "wasLatenz", disabled: !hatLatenz },
              { key: "wasAlles", disabled: false },
            ].map((opt) => (
              <button
                key={opt.key}
                type="button"
                role="tab"
                aria-selected={wasZeigen === opt.key}
                disabled={opt.disabled}
                className={
                  wasZeigen === opt.key
                    ? "logging-serie__segment logging-serie__segment--aktiv"
                    : "logging-serie__segment"
                }
                onClick={() => setWasZeigen(opt.key)}
              >
                {t(`beobachten.logging.serie.wasZeigen.${opt.key.replace("was", "").toLowerCase()}`)}
              </button>
            ))}
          </div>
        </div>

        <div className="logging-serie__control">
          <span className="logging-serie__control-label">
            {t("beobachten.logging.serie.darstellung.titel")}
          </span>
          <div className="logging-serie__segmente" role="tablist">
            {["einzellinien", "heatmap", "rangliste"].map((key) => {
              // Im Latenz-Kontext ist die Outage-Rangliste fachlich unpassend -> ausgrauen.
              const disabled = imLatenzKontext && key === "rangliste";
              return (
                <button
                  key={key}
                  type="button"
                  role="tab"
                  aria-selected={darstellung === key}
                  disabled={disabled}
                  className={
                    darstellung === key
                      ? "logging-serie__segment logging-serie__segment--aktiv"
                      : "logging-serie__segment"
                  }
                  onClick={() => setDarstellung(key)}
                >
                  {t(`beobachten.logging.serie.darstellung.${key}`)}
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* ── CERNIS-Auto-Empfehlung: reine Textzeile + Wiederherstellen ───────── */}
      <div className="logging-serie__empfehlung">
        <span className="logging-serie__empfehlung-text">
          {t("beobachten.logging.serie.empfehlung", {
            modus: t(`beobachten.logging.serie.darstellung.${empfehlung}`),
          })}
        </span>
        {darstellung !== empfehlung && (
          <button
            type="button"
            className="logging-serie__empfehlung-link"
            onClick={() => setDarstellung(empfehlung)}
          >
            {t("beobachten.logging.serie.wiederherstellen")}
          </button>
        )}
      </div>

      {/* ── Median+Band-Ueberlagerung (nur die Outage-Einzellinien) ──────────── */}
      {/* Nicht im Latenz-Kontext: dort rendert LatenzSvg, die Ueberlagerung haette
          keine Wirkung. */}
      {darstellung === "einzellinien" && !imLatenzKontext && (
        <label className="logging-serie__overlay">
          <input
            type="checkbox"
            checked={medianBand}
            disabled={!hatLatenz}
            onChange={(e) => setMedianBand(e.target.checked)}
          />
          <span>{t("beobachten.logging.serie.medianBand")}</span>
        </label>
      )}

      {/* Ohne Latenz: kurze Erklaerzeile, warum die Latenz-Optionen gesperrt sind. */}
      {!hatLatenz && (
        <p className="logging-serie__keine-latenz">
          {t("beobachten.logging.serie.keineLatenz")}
        </p>
      )}

      {/* ── Visualisierung je Sicht/Darstellung (reines SVG) ─────────────────── */}
      {/* Latenz-Kontext: die latency_slots ueber die Tageszeit (LatenzSvg). Die
          Darstellung-Wahl bleibt waehlbar (heatmap/einzellinien zeigen dieselbe
          Latenz-Achse), nur die Outage-Rangliste ist gesperrt. Sonst die bisherige
          Outage-Visualisierung je Darstellung. */}
      <div className="logging-serie__visual">
        {imLatenzKontext ? (
          <LatenzSvg serie={serie} t={t} />
        ) : (
          <>
            {darstellung === "heatmap" && <HeatmapSvg serie={serie} t={t} />}
            {darstellung === "einzellinien" && (
              <EinzellinienSvg serie={serie} medianBand={medianBand} t={t} />
            )}
            {darstellung === "rangliste" && <Rangliste serie={serie} t={t} />}
          </>
        )}
      </div>

      {/* ── Feste Detailtabelle GANZ UNTEN ───────────────────────────────────── */}
      {/* "Was zeigen" filtert sichtbar: Latenz -> nur die Latenz-Tabelle; Abbrueche ->
          nur die Outage-Tabelle; Alles -> Outage-Tabelle, bei hasLatency zusaetzlich die
          Latenz-Tabelle als zweiter Block mit eigener Ueberschrift. */}
      {imLatenzKontext ? (
        <>
          <div className="logging-serie__tabelle-titel">
            {t("beobachten.logging.serie.latenzTabelle.titel")}
          </div>
          <LatenzTabelle serie={serie} t={t} />
        </>
      ) : (
        <>
          <div className="logging-serie__tabelle-titel">
            {t("beobachten.logging.serie.tabelle.titelAbbrueche")}
          </div>
          <OutageTabelle serie={serie} sprache={i18n.language} t={t} />
          {wasZeigen === "wasAlles" && hatLatenz && (
            <>
              <div className="logging-serie__tabelle-titel">
                {t("beobachten.logging.serie.latenzTabelle.titel")}
              </div>
              <LatenzTabelle serie={serie} t={t} />
            </>
          )}
        </>
      )}

      {laedt && <div className="logging-serie__laedt" aria-hidden="true" />}
    </div>
  );
}

// ── Heatmap: horizontale Tageszeit-Leiste ─────────────────────────────────────
// Je heatmap-Slot ein Feld, Einfaerbung nach outage_count (Intensitaet ueber die
// Token-Akzentfarbe via Opacity-Abstufung), x = minuteOfDay. Achsen-Zeitbeschriftung
// (HH:MM) ausserhalb des gestreckten SVG.
function HeatmapSvg({ serie, t }) {
  const slots = serie?.heatmap ?? [];
  if (slots.length === 0) {
    return <p className="logging-serie__leer">{t("beobachten.logging.serie.tabelle.leer")}</p>;
  }
  const maxCount = slots.reduce((acc, s) => Math.max(acc, s.outageCount ?? 0), 0) || 1;
  // Slot-Breite aus der Koernung: jeder Slot deckt SLOT_MINUTES Minuten ab.
  const slotBreite = (SLOT_MINUTES / MINUTEN_PRO_TAG) * VB_BREITE;
  const zeichenHoehe = VB_HOEHE - RAND_OBEN - RAND_UNTEN;

  // Stunden-Marken (00:00, 06:00, 12:00, 18:00, 24:00) fuer die Achse.
  const marken = [0, 360, 720, 1080, 1440];

  return (
    <div className="logging-serie__chart">
      <svg
        className="logging-serie__svg"
        viewBox={`0 0 ${VB_BREITE} ${VB_HOEHE}`}
        preserveAspectRatio="none"
        role="img"
        aria-label={t("beobachten.logging.serie.darstellung.heatmap")}
      >
        {slots.map((slot, i) => {
          const x = ((slot.minuteOfDay ?? 0) / MINUTEN_PRO_TAG) * VB_BREITE;
          const intensitaet = (slot.outageCount ?? 0) / maxCount;
          return (
            <rect
              key={`slot-${i}`}
              x={x.toFixed(2)}
              y={RAND_OBEN}
              width={Math.max(slotBreite, 0.4).toFixed(2)}
              height={zeichenHoehe}
              fill="var(--color-accent)"
              fillOpacity={(0.12 + 0.88 * intensitaet).toFixed(2)}
            />
          );
        })}
      </svg>
      <div className="logging-serie__zeit-achse" aria-hidden="true">
        {marken.map((minute) => (
          <span
            key={`marke-${minute}`}
            className="logging-serie__zeit-marke"
            style={{ left: `${(minute / MINUTEN_PRO_TAG) * 100}%` }}
          >
            {formatTagesminute(minute === 1440 ? 1439 : minute).replace("23:59", "24:00")}
          </span>
        ))}
      </div>
    </div>
  );
}

// ── Einzellinien: pro distinktem day_key eine dezente Linie der Outage-Lage ───
// Tageszeit-Achse (0..1440). Jeder Outage eines Tages ein Punkt (x = minuteOfDay,
// y = Dauer relativ). Bei aktivem medianBand zusaetzlich eine Median-Linie + Band,
// berechnet aus den Tageslinien. Defensiv: < 2 Tage -> ruhige Leer-Meldung.
function EinzellinienSvg({ serie, medianBand, t }) {
  const outages = (serie?.outages ?? []).filter(
    (o) => o.dayKey && o.minuteOfDay !== null && o.minuteOfDay !== undefined,
  );
  // Nach Tag gruppieren.
  const proTag = new Map();
  for (const o of outages) {
    if (!proTag.has(o.dayKey)) {
      proTag.set(o.dayKey, []);
    }
    proTag.get(o.dayKey).push(o);
  }
  const tage = [...proTag.keys()].sort();
  if (tage.length < 2) {
    return <p className="logging-serie__leer">{t("beobachten.logging.serie.tabelle.leer")}</p>;
  }

  const zeichenHoehe = VB_HOEHE - RAND_OBEN - RAND_UNTEN;
  const maxDauer =
    outages.reduce((acc, o) => Math.max(acc, o.durationS ?? 0), 0) || 1;
  // y aus Dauer (gross = oben). x aus Tagesminute.
  const xVon = (minute) => (minute / MINUTEN_PRO_TAG) * VB_BREITE;
  const yVon = (dauer) => RAND_OBEN + (1 - (dauer ?? 0) / maxDauer) * zeichenHoehe;

  const tagesLinien = tage.map((tag) => {
    const punkte = proTag
      .get(tag)
      .slice()
      .sort((a, b) => a.minuteOfDay - b.minuteOfDay)
      .map((o) => `${xVon(o.minuteOfDay).toFixed(2)},${yVon(o.durationS).toFixed(2)}`)
      .join(" ");
    return { tag, punkte };
  });

  // Median + Band aus den Tageslinien: je grobem Tagesminute-Raster der Median der
  // Dauern ueber alle Tage (plus min/max als Band). "berechnet" — abgeleitete Sicht.
  let medianPfad = null;
  let bandPfad = null;
  if (medianBand) {
    const koernung = 60; // ein Stuetzpunkt je Stunde
    const stuetz = [];
    for (let minute = 0; minute <= MINUTEN_PRO_TAG; minute += koernung) {
      const fenster = outages.filter(
        (o) => o.minuteOfDay >= minute && o.minuteOfDay < minute + koernung,
      );
      if (fenster.length === 0) {
        continue;
      }
      const dauern = fenster.map((o) => o.durationS ?? 0).sort((a, b) => a - b);
      const median = dauern[Math.floor(dauern.length / 2)];
      stuetz.push({
        minute,
        median,
        min: dauern[0],
        max: dauern[dauern.length - 1],
      });
    }
    if (stuetz.length >= 2) {
      medianPfad = stuetz
        .map((s) => `${xVon(s.minute).toFixed(2)},${yVon(s.median).toFixed(2)}`)
        .join(" ");
      const oben = stuetz.map((s) => `${xVon(s.minute).toFixed(2)},${yVon(s.max).toFixed(2)}`);
      const unten = stuetz
        .slice()
        .reverse()
        .map((s) => `${xVon(s.minute).toFixed(2)},${yVon(s.min).toFixed(2)}`);
      bandPfad = [...oben, ...unten].join(" ");
    }
  }

  const marken = [0, 360, 720, 1080, 1440];

  return (
    <div className="logging-serie__chart">
      <svg
        className="logging-serie__svg"
        viewBox={`0 0 ${VB_BREITE} ${VB_HOEHE}`}
        preserveAspectRatio="none"
        role="img"
        aria-label={t("beobachten.logging.serie.darstellung.einzellinien")}
      >
        {bandPfad && (
          <polygon points={bandPfad} fill="var(--color-accent)" fillOpacity="0.12" />
        )}
        {tagesLinien.map((linie, i) => (
          <polyline
            key={`tag-${i}`}
            points={linie.punkte}
            fill="none"
            stroke="var(--color-link)"
            strokeWidth="1"
            strokeOpacity="0.45"
            strokeLinejoin="round"
            vectorEffect="non-scaling-stroke"
          />
        ))}
        {medianPfad && (
          <polyline
            points={medianPfad}
            fill="none"
            stroke="var(--color-accent)"
            strokeWidth="1.5"
            strokeLinejoin="round"
            vectorEffect="non-scaling-stroke"
          />
        )}
      </svg>
      <div className="logging-serie__zeit-achse" aria-hidden="true">
        {marken.map((minute) => (
          <span
            key={`marke-${minute}`}
            className="logging-serie__zeit-marke"
            style={{ left: `${(minute / MINUTEN_PRO_TAG) * 100}%` }}
          >
            {minute === 1440 ? "24:00" : formatTagesminute(minute)}
          </span>
        ))}
      </div>
    </div>
  );
}

// ── Rangliste: ranking-Eintraege absteigend (Tageszeit-Slot, dayCount, longest) ─
function Rangliste({ serie, t }) {
  const ranking = serie?.ranking ?? [];
  if (ranking.length === 0) {
    return <p className="logging-serie__leer">{t("beobachten.logging.serie.tabelle.leer")}</p>;
  }
  // Absteigend nach Anzahl betroffener Tage, dann nach laengstem Ausfall.
  const sortiert = ranking
    .slice()
    .sort(
      (a, b) =>
        (b.dayCount ?? 0) - (a.dayCount ?? 0) ||
        (b.longestOutageS ?? 0) - (a.longestOutageS ?? 0),
    );
  return (
    <table className="logging-serie__rangliste">
      <thead>
        <tr>
          <th>{t("beobachten.logging.serie.rangliste.slot")}</th>
          <th>{t("beobachten.logging.serie.rangliste.tage")}</th>
          <th>{t("beobachten.logging.serie.rangliste.laengster")}</th>
        </tr>
      </thead>
      <tbody>
        {sortiert.map((eintrag, i) => (
          <tr key={`rang-${i}`}>
            <td className="logging-serie__mono">{formatTagesminute(eintrag.minuteOfDay)}</td>
            <td>{eintrag.dayCount ?? 0}</td>
            <td className="logging-serie__mono">{formatDauer(eintrag.longestOutageS)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

// ── Latenz-Visualisierung: latency_slots ueber die Tageszeit ──────────────────
// Je Slot ein Balken, x = minuteOfDay, Hoehe nach p95RttMs (skaliert auf das Maximum
// aller p95-Werte). Token-Farbe var(--color-link) (Latenz), abgesetzt von der Outage-
// Akzentfarbe. Achsen-Zeitbeschriftung (HH:MM) ausserhalb des gestreckten SVG wie
// HeatmapSvg. Leere latencySlots -> ruhige Leer-Meldung (eigener Latenz-Leer-Text).
function LatenzSvg({ serie, t }) {
  const slots = serie?.latencySlots ?? [];
  if (slots.length === 0) {
    // Datenlose Darstellung im aktuellen (Latenz-)Kontext -> ehrlicher Hinweis statt
    // Leerbild (KEIN stiller Leerzustand).
    return (
      <p className="logging-serie__leer">{t("beobachten.logging.serie.darstellung.latenzLeer")}</p>
    );
  }
  const maxP95 = slots.reduce((acc, s) => Math.max(acc, s.p95RttMs ?? 0), 0) || 1;
  // Slot-Breite aus der Koernung: jeder Slot deckt SLOT_MINUTES Minuten ab.
  const slotBreite = (SLOT_MINUTES / MINUTEN_PRO_TAG) * VB_BREITE;
  const zeichenHoehe = VB_HOEHE - RAND_OBEN - RAND_UNTEN;

  const marken = [0, 360, 720, 1080, 1440];

  return (
    <div className="logging-serie__chart">
      <svg
        className="logging-serie__svg"
        viewBox={`0 0 ${VB_BREITE} ${VB_HOEHE}`}
        preserveAspectRatio="none"
        role="img"
        aria-label={t("beobachten.logging.serie.latenzTabelle.titel")}
      >
        {slots.map((slot, i) => {
          const x = ((slot.minuteOfDay ?? 0) / MINUTEN_PRO_TAG) * VB_BREITE;
          const anteil = (slot.p95RttMs ?? 0) / maxP95;
          const hoehe = Math.max(anteil * zeichenHoehe, 0.5);
          // Balken von unten nach oben (hohe p95 = hoher Balken).
          const y = RAND_OBEN + (zeichenHoehe - hoehe);
          return (
            <rect
              key={`lat-${i}`}
              x={x.toFixed(2)}
              y={y.toFixed(2)}
              width={Math.max(slotBreite, 0.4).toFixed(2)}
              height={hoehe.toFixed(2)}
              fill="var(--color-link)"
              fillOpacity="0.7"
            />
          );
        })}
      </svg>
      <div className="logging-serie__zeit-achse" aria-hidden="true">
        {marken.map((minute) => (
          <span
            key={`marke-${minute}`}
            className="logging-serie__zeit-marke"
            style={{ left: `${(minute / MINUTEN_PRO_TAG) * 100}%` }}
          >
            {minute === 1440 ? "24:00" : formatTagesminute(minute)}
          </span>
        ))}
      </div>
    </div>
  );
}

// ── Latenz-Detailtabelle: je Slot eine Zeile (Uhrzeit / Messpunkte / p95 / Max) ─
// Aufsteigend nach minuteOfDay (Bucketung wie die Heatmap). Leere Slots -> Leer-Text.
function LatenzTabelle({ serie, t }) {
  const slots = serie?.latencySlots ?? [];
  if (slots.length === 0) {
    return (
      <p className="logging-serie__leer">{t("beobachten.logging.serie.latenzTabelle.leer")}</p>
    );
  }
  const sortiert = slots
    .slice()
    .sort((a, b) => (a.minuteOfDay ?? 0) - (b.minuteOfDay ?? 0));
  return (
    <table className="logging-serie__tabelle">
      <thead>
        <tr>
          <th>{t("beobachten.logging.serie.latenzTabelle.slot")}</th>
          <th>{t("beobachten.logging.serie.latenzTabelle.messpunkte")}</th>
          <th>{t("beobachten.logging.serie.latenzTabelle.p95")}</th>
          <th>{t("beobachten.logging.serie.latenzTabelle.max")}</th>
        </tr>
      </thead>
      <tbody>
        {sortiert.map((slot, i) => (
          <tr key={`lat-row-${i}`}>
            <td className="logging-serie__mono">{formatTagesminute(slot.minuteOfDay)}</td>
            <td>{slot.sampleCount ?? 0}</td>
            <td className="logging-serie__mono">{formatRtt(slot.p95RttMs)}</td>
            <td className="logging-serie__mono">{formatRtt(slot.maxRttMs)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

// ── Feste Detailtabelle: je Outage eine Zeile (von / bis / Dauer) ─────────────
// Immer sichtbar als ehrliche Basis. "Was zeigen" filtert nur, wo es sinnvoll ist:
// wasAbbrueche/wasLatenz/wasAlles zeigen alle Outages — die Outage-Tabelle ist und
// bleibt die ehrliche Basis (auch bei wasLatenz ohne Latenz). end_ts null -> "noch offen".
function OutageTabelle({ serie, sprache, t }) {
  const outages = serie?.outages ?? [];
  if (outages.length === 0) {
    return <p className="logging-serie__leer">{t("beobachten.logging.serie.tabelle.leer")}</p>;
  }
  return (
    <table className="logging-serie__tabelle">
      <thead>
        <tr>
          <th>{t("beobachten.logging.serie.tabelle.von")}</th>
          <th>{t("beobachten.logging.serie.tabelle.bis")}</th>
          <th>{t("beobachten.logging.serie.tabelle.dauer")}</th>
        </tr>
      </thead>
      <tbody>
        {outages.map((o, i) => (
          <tr key={`out-${i}`}>
            <td className="logging-serie__mono">{formatZeit(o.startTs, sprache)}</td>
            <td className="logging-serie__mono">
              {o.endTs === null
                ? t("beobachten.logging.serie.tabelle.nochOffen")
                : formatZeit(o.endTs, sprache)}
            </td>
            <td className="logging-serie__mono">{formatDauer(o.durationS)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
