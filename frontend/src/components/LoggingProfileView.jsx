// Verhaltensprofil einer Logging-Aufgabe (CERNIS PRO 2.0, Block 4)
//
// Dritte Ansicht der Detailseite (nur bei operationMode "recurring"): verdichtet die
// wiederkehrende Aufzeichnung zu einem typischen Aktivitaetsmuster. Sie laedt selbst
// ueber fetchLoggingBehavior (analog LoggingSeriesView, mit abgebrochen-Flag im
// useEffect) und steht propsgesteuert auf taskId + since + until. Reine Lesesicht —
// greift NICHT ins Netz ein.
//
// Aufbau von oben nach unten: Kennzahlen-Kopf (vier Kacheln: Aktivste Zeit / Aktivste
// Tage / Abweichungen gesamt / Aufzeichnungstage) -> Leerzustand-Weiche: bei zu wenig
// Daten (hasEnoughData false) eine ruhige Hinweisbox mit Fortschritt statt Diagrammen;
// sonst zwei SVG-Visualisierungen (Tagesmuster-Band + Wochenmuster-Heatmap) plus eine
// kurze Hinweis-/Legendenzeile. KEINE Ziele-Sektion (bewusst auf spaeter verschoben).
//
// Stil wie der Bestand: Fehlertoleranz wie LoggingSeriesView (ein Ladefehler kippt die
// Ansicht nicht, ruhige Meldung), SVG wie SlaChart/LoggingSeriesView (viewBox-Raster,
// non-scaling-stroke, Achsen-Text ausserhalb des gestreckten SVG), alle Texte ueber
// i18n, alle Farben ueber Tokens (tokens.css) — accent fuer typisch, severity fuer
// Abweichung, nie feste Farben.

import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { fetchLoggingBehavior } from "../api/monitoring.js";
import "./LoggingProfileView.css";

// Koernung der Slot-Auswertung in Minuten (Backend-Default 60, gueltig 15..60). Fest
// gehalten — die Ansicht bietet (noch) keinen Regler dafuer, gibt den Wert aber sauber
// als Dep weiter.
const SLOT_MINUTES = 60;

// Mindestanzahl Aufzeichnungstage fuer ein belastbares Muster (zwei volle Wochen).
// Entspricht dem Backend-Default min_days; spaeter soll dieser Wert aus den analysis-
// Settings kommen — bis dahin lokal als Klartext-Konstante gefuehrt.
const MINDEST_TAGE = 14;

// viewBox-Raster der SVGs (wie SlaChart/LoggingSeriesView): gestreckte Breite 100, feste
// Hoehe. Eine Tageszeit-Achse spannt 0..1440 Minuten auf die 100 Raster-Einheiten.
const VB_BREITE = 100;
const VB_HOEHE = 150;
const RAND_OBEN = 10;
const RAND_UNTEN = 10;
const MINUTEN_PRO_TAG = 1440;

// Wochentags-Reihenfolge (0=Mo..6=So, wie das Backend weekday liefert). Die Labels
// kommen uebersetzt aus i18n (beobachten.logging.profil.wochentag.*).
const WOCHENTAGE = [0, 1, 2, 3, 4, 5, 6];
const WOCHENTAG_KEY = ["mo", "di", "mi", "do", "fr", "sa", "so"];

// Lokale Tagesminute (0..1439) -> "HH:MM". null/NaN -> "—".
function formatTagesminute(minute) {
  if (minute === null || minute === undefined || Number.isNaN(minute)) {
    return "—";
  }
  const stunden = Math.floor(minute / 60);
  const rest = minute % 60;
  return `${String(stunden).padStart(2, "0")}:${String(rest).padStart(2, "0")}`;
}

// Slot-Start (Minute seit Mitternacht) -> "HH:MM–HH:MM"-Bereich ueber slotMinutes.
// Endet der Slot bei 1440, als "24:00" anzeigen. null -> "—".
function formatSlotBereich(slotStart, slotMinutes) {
  if (slotStart === null || slotStart === undefined || Number.isNaN(slotStart)) {
    return "—";
  }
  const ende = slotStart + slotMinutes;
  const endeText = ende >= MINUTEN_PRO_TAG ? "24:00" : formatTagesminute(ende);
  return `${formatTagesminute(slotStart)}–${endeText}`;
}

// Eine Kennzahl-Kachel (Wert prominent, Bezeichnung dezent) — Optik wie LoggingSeriesView.
function Kennzahl({ wert, label }) {
  return (
    <div className="logging-profil__kennzahl">
      <span className="logging-profil__kennzahl-wert">{wert}</span>
      <span className="logging-profil__kennzahl-label">{label}</span>
    </div>
  );
}

// Props:
//   taskId   id der Aufgabe (selbst geladen)
//   since    Unix-ts (Sekunden) oder null — untere Grenze des Auswertungsfensters
//   until    Unix-ts (Sekunden) oder null — obere Grenze
export default function LoggingProfileView({ taskId, since = null, until = null }) {
  const { t } = useTranslation();

  // Geladenes Profil (null = noch nicht geladen / nicht vorhanden) + Lade-/Fehlerzustand.
  const [profil, setProfil] = useState(null);
  const [laedt, setLaedt] = useState(false);
  const [fehler, setFehler] = useState(false);

  // Laedt das Profil fuer den aktuellen Ausschnitt. Fehler -> dezenter Hinweis, kein
  // Absturz (Muster LoggingSeriesView). Deps: taskId/since/until/SLOT_MINUTES.
  useEffect(() => {
    let abgebrochen = false;

    (async () => {
      setLaedt(true);
      setFehler(false);
      try {
        const geladen = await fetchLoggingBehavior(taskId, since, until, SLOT_MINUTES);
        if (!abgebrochen) {
          setProfil(geladen);
        }
      } catch {
        if (!abgebrochen) {
          setProfil(null);
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

  const dayBand = profil?.dayBand ?? [];
  const weekHeatmap = profil?.weekHeatmap ?? [];
  const recordedDays = profil?.recordedDays ?? 0;
  const hatGenugDaten = profil?.hasEnoughData ?? false;

  // Aktivste Zeit: der Slot mit dem hoechsten activityCount im Tagesband (als
  // HH:MM-Bereich). Leeres Band -> "—".
  const aktivsteZeitWert = useMemo(() => {
    if (dayBand.length === 0) {
      return "—";
    }
    let best = null;
    for (const slot of dayBand) {
      if (best === null || (slot.activityCount ?? 0) > (best.activityCount ?? 0)) {
        best = slot;
      }
    }
    return formatSlotBereich(best?.slotStart, SLOT_MINUTES);
  }, [dayBand]);

  // Aktivste Tage: Wochentag(e) mit der hoechsten Summe activityCount in der Heatmap.
  // Mehrere gleichauf -> kommagetrennt (uebersetzte Mo..So-Kuerzel). Leer -> "—".
  const aktivsteTageWert = useMemo(() => {
    if (weekHeatmap.length === 0) {
      return "—";
    }
    const summe = new Map();
    for (const zelle of weekHeatmap) {
      const tag = zelle.weekday;
      summe.set(tag, (summe.get(tag) ?? 0) + (zelle.activityCount ?? 0));
    }
    let max = 0;
    for (const wert of summe.values()) {
      max = Math.max(max, wert);
    }
    if (max === 0) {
      return "—";
    }
    const tage = WOCHENTAGE.filter((tag) => (summe.get(tag) ?? 0) === max);
    return tage.map((tag) => t(`beobachten.logging.profil.wochentag.${WOCHENTAG_KEY[tag]}`)).join(", ");
  }, [weekHeatmap, t]);

  const abweichungenWert = profil ? String(profil.deviationCount ?? 0) : "—";
  const aufzeichnungstageWert = profil ? String(recordedDays) : "—";

  return (
    <div className="logging-profil">
      <h3 className="logging-profil__titel" id="help.monitor.profile">
        {t("beobachten.logging.profil.titel")}
      </h3>

      {fehler && (
        <div className="logging-profil__fehler" role="note">
          {t("beobachten.logging.detailFehler")}
        </div>
      )}

      {/* ── Kennzahlen-Kopf (vier Kacheln) ───────────────────────────────────── */}
      <div className="logging-profil__kennzahlen">
        <Kennzahl
          wert={aktivsteZeitWert}
          label={t("beobachten.logging.profil.kennzahl.aktivsteZeit")}
        />
        <Kennzahl
          wert={aktivsteTageWert}
          label={t("beobachten.logging.profil.kennzahl.aktivsteTage")}
        />
        <Kennzahl
          wert={abweichungenWert}
          label={t("beobachten.logging.profil.kennzahl.abweichungen")}
        />
        <Kennzahl
          wert={aufzeichnungstageWert}
          label={t("beobachten.logging.profil.kennzahl.aufzeichnungstage")}
        />
      </div>

      {/* ── Leerzustand-Weiche: zu wenig Daten -> ruhige Hinweisbox, KEINE Diagramme ── */}
      {hatGenugDaten ? (
        <>
          <div className="logging-profil__visual">
            <div className="logging-profil__abschnitt-titel">
              {t("beobachten.logging.profil.tagesmuster.titel")}
            </div>
            <Tagesmuster dayBand={dayBand} t={t} />
          </div>

          <div className="logging-profil__visual">
            <div className="logging-profil__abschnitt-titel">
              {t("beobachten.logging.profil.wochenmuster.titel")}
            </div>
            <Wochenmuster weekHeatmap={weekHeatmap} t={t} />
          </div>

          {/* Hinweis + knappe Legende (typisch / Abweichung). */}
          <p className="logging-profil__hinweis">{t("beobachten.logging.profil.hinweis")}</p>
          <div className="logging-profil__legende" aria-hidden="true">
            <span className="logging-profil__legende-eintrag">
              <span className="logging-profil__legende-feld logging-profil__legende-feld--typisch" />
              {t("beobachten.logging.profil.legende.typisch")}
            </span>
            <span className="logging-profil__legende-eintrag">
              <span className="logging-profil__legende-feld logging-profil__legende-feld--abweichung" />
              {t("beobachten.logging.profil.legende.abweichung")}
            </span>
          </div>
        </>
      ) : (
        <Leerzustand recordedDays={recordedDays} t={t} />
      )}

      {laedt && <div className="logging-profil__laedt" aria-hidden="true" />}
    </div>
  );
}

// ── Leerzustand: noch zu wenig Daten ──────────────────────────────────────────
// Ruhige Hinweisbox mit Fortschritt "recordedDays / MINDEST_TAGE Tage" und Text:
// ein Muster braucht mindestens zwei volle Wochen, CERNIS sammelt weiter. Der
// Fortschrittsbalken ist ein schlichtes div (Token-Farben).
function Leerzustand({ recordedDays, t }) {
  const anteil = Math.max(0, Math.min(1, recordedDays / MINDEST_TAGE));
  return (
    <div className="logging-profil__leerzustand" role="note">
      <p className="logging-profil__leerzustand-text">
        {t("beobachten.logging.profil.leerzustand.text")}
      </p>
      <div className="logging-profil__fortschritt">
        <div className="logging-profil__fortschritt-bahn">
          <div
            className="logging-profil__fortschritt-fueller"
            style={{ width: `${(anteil * 100).toFixed(0)}%` }}
          />
        </div>
        <span className="logging-profil__fortschritt-label logging-profil__mono">
          {t("beobachten.logging.profil.leerzustand.fortschritt", {
            tage: recordedDays,
            ziel: MINDEST_TAGE,
          })}
        </span>
      </div>
    </div>
  );
}

// ── Tagesmuster (Band): 24h-Achse, je Slot ein Block ──────────────────────────
// Tageszeit-Achse (0..1440 auf das VB-Raster). Je dayBand-Slot ein Balken, dessen
// Hoehe proportional zum activityCount ist; isDeviation-Slots in severity-Farbe
// (Token) statt accent. Achsen-Zeitbeschriftung (HH:MM) ausserhalb des gestreckten
// SVG. Leeres Band -> ruhiger Leer-Hinweis.
function Tagesmuster({ dayBand, t }) {
  if (dayBand.length === 0) {
    return <p className="logging-profil__leer">{t("beobachten.logging.profil.tagesmuster.leer")}</p>;
  }
  const maxCount = dayBand.reduce((acc, s) => Math.max(acc, s.activityCount ?? 0), 0) || 1;
  const zeichenHoehe = VB_HOEHE - RAND_OBEN - RAND_UNTEN;
  // Slot-Breite aus der Koernung: jeder Slot deckt SLOT_MINUTES Minuten ab.
  const slotBreite = (SLOT_MINUTES / MINUTEN_PRO_TAG) * VB_BREITE;

  // Stunden-Marken (00:00, 06:00, 12:00, 18:00, 24:00) fuer die Achse.
  const marken = [0, 360, 720, 1080, 1440];

  return (
    <div className="logging-profil__chart">
      <svg
        className="logging-profil__svg"
        viewBox={`0 0 ${VB_BREITE} ${VB_HOEHE}`}
        preserveAspectRatio="none"
        role="img"
        aria-label={t("beobachten.logging.profil.tagesmuster.titel")}
      >
        {dayBand.map((slot, i) => {
          const x = ((slot.slotStart ?? 0) / MINUTEN_PRO_TAG) * VB_BREITE;
          const anteil = (slot.activityCount ?? 0) / maxCount;
          const hoehe = Math.max(anteil * zeichenHoehe, 0.5);
          const y = RAND_OBEN + (zeichenHoehe - hoehe);
          // Abweichung -> severity-Farbe (orange Token), sonst accent.
          const farbe = slot.isDeviation ? "var(--sev-med-bd)" : "var(--color-accent)";
          return (
            <rect
              key={`tag-${i}`}
              x={x.toFixed(2)}
              y={y.toFixed(2)}
              width={Math.max(slotBreite, 0.4).toFixed(2)}
              height={hoehe.toFixed(2)}
              fill={farbe}
              fillOpacity={slot.isDeviation ? "0.85" : (0.18 + 0.82 * anteil).toFixed(2)}
            />
          );
        })}
      </svg>
      <div className="logging-profil__zeit-achse" aria-hidden="true">
        {marken.map((minute) => (
          <span
            key={`marke-${minute}`}
            className="logging-profil__zeit-marke"
            style={{ left: `${(minute / MINUTEN_PRO_TAG) * 100}%` }}
          >
            {minute === 1440 ? "24:00" : formatTagesminute(minute)}
          </span>
        ))}
      </div>
    </div>
  );
}

// ── Wochenmuster (Heatmap): 7 Zeilen (Wochentag) x Tageszeit-Slot (Spalten) ────
// Zellenfarbe accent-Token mit Deckkraft proportional zu activityCount; isDeviation-
// Zellen mit severity-Rand/-Farbe. Stil wie die HeatmapSvg-Logik in LoggingSeriesView.
// Wochentag-Labels (Mo..So, uebersetzt) ausserhalb des SVG. Leere Heatmap -> Leer-Hinweis.
function Wochenmuster({ weekHeatmap, t }) {
  if (weekHeatmap.length === 0) {
    return <p className="logging-profil__leer">{t("beobachten.logging.profil.wochenmuster.leer")}</p>;
  }
  const maxCount = weekHeatmap.reduce((acc, z) => Math.max(acc, z.activityCount ?? 0), 0) || 1;
  const zeilenHoehe = (VB_HOEHE - RAND_OBEN - RAND_UNTEN) / WOCHENTAGE.length;
  // Slot-Breite aus der Koernung: jeder Slot deckt SLOT_MINUTES Minuten ab.
  const slotBreite = (SLOT_MINUTES / MINUTEN_PRO_TAG) * VB_BREITE;

  const marken = [0, 360, 720, 1080, 1440];

  return (
    <div className="logging-profil__heatmap">
      {/* Wochentag-Labels links, ausserhalb des gestreckten SVG. */}
      <div className="logging-profil__wochentage" aria-hidden="true">
        {WOCHENTAGE.map((tag) => (
          <span key={`wt-${tag}`} className="logging-profil__wochentag">
            {t(`beobachten.logging.profil.wochentag.${WOCHENTAG_KEY[tag]}`)}
          </span>
        ))}
      </div>
      <div className="logging-profil__chart logging-profil__chart--heatmap">
        <svg
          className="logging-profil__svg"
          viewBox={`0 0 ${VB_BREITE} ${VB_HOEHE}`}
          preserveAspectRatio="none"
          role="img"
          aria-label={t("beobachten.logging.profil.wochenmuster.titel")}
        >
          {weekHeatmap.map((zelle, i) => {
            const x = ((zelle.slotStart ?? 0) / MINUTEN_PRO_TAG) * VB_BREITE;
            const reihe = WOCHENTAGE.indexOf(zelle.weekday);
            if (reihe < 0) {
              return null;
            }
            const y = RAND_OBEN + reihe * zeilenHoehe;
            const intensitaet = (zelle.activityCount ?? 0) / maxCount;
            return (
              <rect
                key={`zelle-${i}`}
                x={x.toFixed(2)}
                y={y.toFixed(2)}
                width={Math.max(slotBreite, 0.4).toFixed(2)}
                height={Math.max(zeilenHoehe - 0.4, 0.4).toFixed(2)}
                fill="var(--color-accent)"
                fillOpacity={(0.1 + 0.9 * intensitaet).toFixed(2)}
                stroke={zelle.isDeviation ? "var(--sev-med-bd)" : "none"}
                strokeWidth={zelle.isDeviation ? "1" : "0"}
                vectorEffect="non-scaling-stroke"
              />
            );
          })}
        </svg>
        <div className="logging-profil__zeit-achse" aria-hidden="true">
          {marken.map((minute) => (
            <span
              key={`marke-${minute}`}
              className="logging-profil__zeit-marke"
              style={{ left: `${(minute / MINUTEN_PRO_TAG) * 100}%` }}
            >
              {minute === 1440 ? "24:00" : formatTagesminute(minute)}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}
