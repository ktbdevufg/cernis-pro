// Verhaltensprofil-Bericht — In-App-Ansicht (CERNIS PRO 2.0, Etappe 5b)
//
// Sechste Kachel des Reporting-Bereichs. Verdichtet den aggregierten Verhaltens-
// profil-Bericht (GET /api/report/behavior) zu einer ruhigen Lesesicht. Wie der
// DNS-Waechter-Bericht traegt die View OBEN einen Bezugsrahmen-Umschalter (Optik
// der DnsWatchScreen-Reiter):
//   "Diese Aufgabe" -> das Profil EINER wiederkehrenden Aufgabe (Tagesband +
//                      Wochen-Heatmap), gewaehlt ueber ein Aufgaben-Dropdown.
//   "Alle Geraete"  -> eine Uebersichtstabelle je Aufgabe/Geraet (Default).
// Der Umschalter-Zustand ist reiner Frontend-State; der Bericht laedt je nach Bezug
// (eigener useEffect mit abgebrochen-Flag). Konsistent zum Aussenkontakte- und DNS-
// Umgehungs-Bericht (Aufzeichnungs-/Aufgaben-Dropdown).
//
// Achse B des Produkts: der Bericht BESCHREIBT und ORDNET EIN — er urteilt nicht.
// Umschalter/Dropdown sind reine Anzeige-Steuerung im Frontend. KEIN 404-Fall: leerer
// Stand ist ein DATUM (leere Listen), kein Fehler -> ruhiger Leerzustand.
//
// Die zwei Grafiken (Tagesverlauf-Balken, Wochen-Heatmap) sind reines Inline-<svg>
// (kein neues Package). Nur bestehende Token-Variablen ueber CSS-Var/currentColor,
// NIE feste Farben. t NIEMALS in useEffect/useMemo-Deps (instabile Referenz -> Loop).

import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import {
  fetchBehaviorReport,
  fetchBehaviorReportPdf,
  fetchBehaviorReportTasks,
} from "../api/report.js";
import "./BehaviorReportView.css";

// Minuten-im-Tag -> "HH:MM" (zweistellig). Nur fuer nicht-null Slots aufrufen; der
// null-Fall (kein aktivster Slot) wird oben mit "—" abgefangen.
function hhmm(minuten) {
  const stunde = Math.floor(minuten / 60);
  const minute = minuten % 60;
  return `${String(stunde).padStart(2, "0")}:${String(minute).padStart(2, "0")}`;
}

export default function BehaviorReportView() {
  const { t } = useTranslation();

  // Aktiver Bezugsrahmen. Default "all" (Uebersicht ohne Vorauswahl).
  const [bezug, setBezug] = useState("all");
  // Waehlbare wiederkehrende Aufgaben fuers Dropdown (Bezug "single").
  const [tasks, setTasks] = useState([]);
  // Gewaehlte Aufgabe (null = noch keine Wahl -> Bericht-Bereich leer lassen).
  const [selectedTaskId, setSelectedTaskId] = useState(null);
  // Geladener Bericht (null = noch nicht geladen / kein Bezug gewaehlt).
  const [bericht, setBericht] = useState(null);
  const [ladeFehler, setLadeFehler] = useState(false);
  const [pdfFehler, setPdfFehler] = useState(false);

  // Die Wochentags-Kurzlabels (Mo..So) als Array. Ueber returnObjects gelesen; kein t
  // in Deps noetig, weil nur beim Rendern verwendet.
  const wochentage = t("report.behavior.wochentage", { returnObjects: true });

  // ── useEffect #1: waehlbare Aufgaben EINMALIG laden (Dropdown) ─────────────────
  // Fehler ist hier still: leere Liste -> das Dropdown zeigt den Leer-Hinweis (kein
  // harter Fehler). t NICHT in Deps.
  useEffect(() => {
    let abgebrochen = false;

    (async () => {
      try {
        const geladen = await fetchBehaviorReportTasks();
        if (!abgebrochen) {
          setTasks(geladen);
        }
      } catch {
        if (!abgebrochen) {
          setTasks([]);
        }
      }
    })();

    return () => {
      abgebrochen = true;
    };
  }, []);

  // ── useEffect #2: den Bericht je nach Bezug laden ─────────────────────────────
  // Bezug "all" -> fetchBehaviorReport(null). Bezug "single" -> nur laden, wenn eine
  // Aufgabe gewaehlt ist (sonst bericht=null, Bereich bleibt leer). ladeFehler bei
  // Fehler true, sonst false. abgebrochen-Flag: nach Abbruch nichts mehr setzen. t
  // BEWUSST NICHT in den Deps (neue Referenz je Render -> Loop).
  useEffect(() => {
    let abgebrochen = false;

    // Im Einzel-Bezug ohne Auswahl: nichts laden, Bericht leeren.
    if (bezug === "single" && !selectedTaskId) {
      setBericht(null);
      setLadeFehler(false);
      return () => {
        abgebrochen = true;
      };
    }

    (async () => {
      setLadeFehler(false);
      try {
        const geladen = await fetchBehaviorReport(
          bezug === "single" ? selectedTaskId : null,
        );
        if (!abgebrochen) {
          setBericht(geladen);
        }
      } catch {
        if (!abgebrochen) {
          setBericht(null);
          setLadeFehler(true);
        }
      }
    })();

    return () => {
      abgebrochen = true;
    };
  }, [bezug, selectedTaskId]);

  // PDF-Download anstossen (Bezug = aktuelle Auswahl). Fehler -> kurzer Hinweis; der
  // ladeFehler-State bleibt unberuehrt (Muster der DNS-Berichte).
  async function handlePdf() {
    setPdfFehler(false);
    try {
      await fetchBehaviorReportPdf(bezug === "single" ? selectedTaskId : null);
    } catch {
      setPdfFehler(true);
    }
  }

  // Ist gerade ein Bericht sichtbar? (PDF-Knopf nur dann anzeigen.) Im Einzel-Bezug
  // ohne Auswahl ist bericht null -> nichts sichtbar.
  const berichtSichtbar = Boolean(bericht);

  return (
    <div className="behavior-report">
      {/* Bezugsrahmen-Umschalter (Optik der DnsWatchScreen-Reiter). Im Druck weg. */}
      <div className="behavior-report__bezug-reiter" role="tablist">
        <button
          type="button"
          role="tab"
          aria-selected={bezug === "single"}
          className={
            bezug === "single"
              ? "behavior-report__bezug-knopf behavior-report__bezug-knopf--aktiv"
              : "behavior-report__bezug-knopf"
          }
          onClick={() => setBezug("single")}
        >
          {t("report.behavior.bezug.single")}
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={bezug === "all"}
          className={
            bezug === "all"
              ? "behavior-report__bezug-knopf behavior-report__bezug-knopf--aktiv"
              : "behavior-report__bezug-knopf"
          }
          onClick={() => setBezug("all")}
        >
          {t("report.behavior.bezug.all")}
        </button>
      </div>

      {/* Aufgaben-Dropdown nur im Einzel-Bezug. Leere Aufgabenliste -> Hinweis. */}
      {bezug === "single" ? (
        tasks.length > 0 ? (
          <div className="behavior-report__toolbar">
            <label className="behavior-report__aufgabe-label">
              <span>{t("report.behavior.aufgabeWahl")}</span>
              <select
                className="behavior-report__aufgabe-select"
                value={selectedTaskId ?? ""}
                onChange={(e) => setSelectedTaskId(e.target.value || null)}
              >
                <option value="">—</option>
                {tasks.map((task) => (
                  <option key={task.id} value={task.id}>
                    {task.label}
                  </option>
                ))}
              </select>
            </label>
          </div>
        ) : (
          <p className="behavior-report__leer">{t("report.behavior.keineAufgaben")}</p>
        )
      ) : null}

      {ladeFehler ? (
        <div className="behavior-report__fehler" role="note">
          {t("report.behavior.ladeFehler")}
        </div>
      ) : null}

      {/* Einzel-Bezug ohne Auswahl: dezenter Hinweis, Bereich leer. */}
      {bezug === "single" && !selectedTaskId && tasks.length > 0 ? (
        <p className="behavior-report__hinweis">{t("report.behavior.aufgabeHinweis")}</p>
      ) : null}

      {/* ── Bericht-Inhalt ────────────────────────────────────────────────────── */}
      {bericht && bericht.scope === "all" ? (
        <UebersichtsTabelle entries={bericht.entries} wochentage={wochentage} t={t} />
      ) : null}

      {bericht && bericht.scope === "single" && bericht.singleProfile ? (
        <EinzelProfil profil={bericht.singleProfile} wochentage={wochentage} t={t} />
      ) : null}

      {/* ── Aktionsleiste: Bericht als PDF herunterladen ──────────────────────── */}
      {berichtSichtbar ? (
        <div className="behavior-report__aktionen">
          <button
            type="button"
            className="behavior-report__pdf"
            onClick={handlePdf}
          >
            {t("report.behavior.pdf")}
          </button>
          {pdfFehler ? (
            <p className="behavior-report__pdf-fehler" role="alert">
              {t("report.behavior.pdfFehler")}
            </p>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

// ── scope==="all": Uebersichtstabelle je Aufgabe/Geraet ───────────────────────────
// Eine flache Tabelle: Geraet | Aufzeichnungstage | Genug Daten | Abweichungen |
// Aktivste Zeit | Aktivster Tag. Leere entries -> ruhiger Leer-Hinweis. Reihenfolge
// kommt sortiert vom Backend (unveraendert uebernehmen). t NIEMALS in Deps.
function UebersichtsTabelle({ entries, wochentage, t }) {
  if (entries.length === 0) {
    return <p className="behavior-report__leer">{t("report.behavior.keineAufgaben")}</p>;
  }

  return (
    <table className="behavior-report__tabelle">
      <thead>
        <tr>
          <th>{t("report.behavior.spalte.geraet")}</th>
          <th className="behavior-report__num">
            {t("report.behavior.spalte.aufzeichnungstage")}
          </th>
          <th>{t("report.behavior.spalte.genugDaten")}</th>
          <th className="behavior-report__num">
            {t("report.behavior.spalte.abweichungen")}
          </th>
          <th>{t("report.behavior.spalte.aktivsteZeit")}</th>
          <th>{t("report.behavior.spalte.aktivsterTag")}</th>
        </tr>
      </thead>
      <tbody>
        {entries.map((e, i) => (
          <tr key={`entry-${i}`} className="behavior-report__zeile">
            <td>{e.label}</td>
            <td className="behavior-report__num behavior-report__mono">
              {e.recordedDays}
            </td>
            <td>
              {e.hasEnoughData
                ? t("report.behavior.kennzahl.ja")
                : t("report.behavior.kennzahl.nein")}
            </td>
            <td className="behavior-report__num behavior-report__mono">
              {e.deviationCount}
            </td>
            <td className="behavior-report__mono">
              {e.busiestSlotStart === null ? "—" : hhmm(e.busiestSlotStart)}
            </td>
            <td>
              {e.busiestWeekday === null ? "—" : wochentage[e.busiestWeekday]}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

// ── scope==="single": Einzelprofil (Kennzahlen + zwei Grafiken) ───────────────────
// Kennzahlen-Zeile (Aufzeichnungstage / Genug Daten / Abweichungen) plus, sofern Daten
// vorhanden, zwei Inline-SVG-Grafiken: Tagesverlauf-Balken und Wochen-Heatmap. Sind
// beide Datenreihen leer -> ruhiger Hinweis. t NIEMALS in Deps.
function EinzelProfil({ profil, wochentage, t }) {
  const keineDaten = profil.dayBand.length === 0 && profil.weekHeatmap.length === 0;

  return (
    <>
      <div className="behavior-report__kennzahlen">
        <div className="behavior-report__kennzahl">
          <span className="behavior-report__kennzahl-wert behavior-report__mono">
            {profil.recordedDays}
          </span>
          <span className="behavior-report__kennzahl-label">
            {t("report.behavior.kennzahl.aufzeichnungstage")}
          </span>
        </div>
        <div className="behavior-report__kennzahl">
          <span className="behavior-report__kennzahl-wert">
            {profil.hasEnoughData
              ? t("report.behavior.kennzahl.ja")
              : t("report.behavior.kennzahl.nein")}
          </span>
          <span className="behavior-report__kennzahl-label">
            {t("report.behavior.kennzahl.genugDaten")}
          </span>
        </div>
        <div className="behavior-report__kennzahl">
          <span className="behavior-report__kennzahl-wert behavior-report__mono">
            {profil.deviationCount}
          </span>
          <span className="behavior-report__kennzahl-label">
            {t("report.behavior.kennzahl.abweichungen")}
          </span>
        </div>
      </div>

      {keineDaten ? (
        <p className="behavior-report__leer">{t("report.behavior.keineDaten")}</p>
      ) : (
        <>
          <TagesverlaufGrafik dayBand={profil.dayBand} t={t} />
          <WochenmusterGrafik
            weekHeatmap={profil.weekHeatmap}
            wochentage={wochentage}
            t={t}
          />
        </>
      )}
    </>
  );
}

// ── Tagesverlauf: vertikale Balken je Zeit-Slot ───────────────────────────────────
// dayBand nach slotStart sortiert, je Slot ein Balken; Hoehe = activityCount / max.
// isDeviation-Balken in der Akzentfarbe (var(--color-accent)), normale in einer
// dezenten Token-Farbe (var(--color-border)). Unter den Balken sparsame Stundenmarken
// (slotStart % 60 === 0). Reines <svg>, responsiv ueber viewBox. Nur Token-Farben.
function TagesverlaufGrafik({ dayBand, t }) {
  const slots = useMemo(
    () => [...dayBand].sort((a, b) => a.slotStart - b.slotStart),
    [dayBand],
  );
  const max = slots.reduce((m, s) => Math.max(m, s.activityCount), 0);

  // Geometrie in viewBox-Einheiten. Balkenbreite abhaengig von der Slot-Zahl.
  const breite = 720;
  const hoehe = 160;
  const grund = 130; // Basislinie der Balken (Platz darunter fuer Stundenmarken).
  const luecke = 2;
  const balkenBreite = slots.length > 0 ? (breite - luecke) / slots.length : 0;

  return (
    <section className="behavior-report__grafik">
      <h4 className="behavior-report__grafik-titel">
        {t("report.behavior.tagesverlauf")}
      </h4>
      <svg
        className="behavior-report__svg"
        viewBox={`0 0 ${breite} ${hoehe}`}
        role="img"
        aria-label={t("report.behavior.tagesverlauf")}
        preserveAspectRatio="none"
      >
        {slots.map((s, i) => {
          const anteil = max > 0 ? s.activityCount / max : 0;
          const balkenHoehe = anteil * (grund - 8);
          const x = i * balkenBreite + luecke / 2;
          const y = grund - balkenHoehe;
          return (
            <rect
              key={`bar-${i}`}
              x={x.toFixed(2)}
              y={y.toFixed(2)}
              width={Math.max(0, balkenBreite - luecke).toFixed(2)}
              height={balkenHoehe.toFixed(2)}
              fill={s.isDeviation ? "var(--color-accent)" : "var(--color-border)"}
            />
          );
        })}

        {/* Basislinie. */}
        <line
          x1="0"
          y1={grund}
          x2={breite}
          y2={grund}
          stroke="var(--color-border)"
          strokeWidth="1"
        />

        {/* Sparsame Stundenmarken (nur volle Stunden). */}
        {slots.map((s, i) => {
          if (s.slotStart % 60 !== 0) {
            return null;
          }
          const x = i * balkenBreite + balkenBreite / 2;
          return (
            <text
              key={`mark-${i}`}
              x={x.toFixed(2)}
              y={hoehe - 6}
              textAnchor="middle"
              fontSize="10"
              fill="currentColor"
              className="behavior-report__svg-mark"
            >
              {hhmm(s.slotStart)}
            </text>
          );
        })}
      </svg>
    </section>
  );
}

// ── Wochenmuster: Heatmap 7 Zeilen (Mo..So) x distinct slotStart ──────────────────
// weekHeatmap als Raster: Zeilen weekday 0..6 (Mo oben), Spalten die distinct slotStart
// (aufsteigend). Zellfarbe = Akzent mit Deckkraft activityCount / max (fill-opacity).
// isDeviation-Zellen zusaetzlich dezente Umrandung. Unten Stundenmarken. Reines <svg>,
// responsiv. Nur Token-Farben (var(--color-accent) mit Opacity).
function WochenmusterGrafik({ weekHeatmap, wochentage, t }) {
  // Distinct slotStart (aufsteigend) als Spalten; Zellen ueber (weekday, slotStart)
  // schnell auffindbar. Stabile Memo-Deps (kein t).
  const { spalten, zelleAt, max } = useMemo(() => {
    const distinct = Array.from(new Set(weekHeatmap.map((z) => z.slotStart))).sort(
      (a, b) => a - b,
    );
    const karte = new Map();
    let hoechst = 0;
    for (const z of weekHeatmap) {
      karte.set(`${z.weekday}:${z.slotStart}`, z);
      hoechst = Math.max(hoechst, z.activityCount);
    }
    return {
      spalten: distinct,
      zelleAt: (weekday, slotStart) => karte.get(`${weekday}:${slotStart}`) ?? null,
      max: hoechst,
    };
  }, [weekHeatmap]);

  // Geometrie in viewBox-Einheiten.
  const zeilen = 7; // Mo..So
  const labelBreite = 34;
  const zellHoehe = 22;
  const markHoehe = 18;
  const inhaltBreite = 686;
  const zellBreite = spalten.length > 0 ? inhaltBreite / spalten.length : 0;
  const breite = labelBreite + inhaltBreite;
  const hoehe = zeilen * zellHoehe + markHoehe;

  return (
    <section className="behavior-report__grafik">
      <h4 className="behavior-report__grafik-titel">
        {t("report.behavior.wochenmuster")}
      </h4>
      <svg
        className="behavior-report__svg"
        viewBox={`0 0 ${breite} ${hoehe}`}
        role="img"
        aria-label={t("report.behavior.wochenmuster")}
        preserveAspectRatio="none"
      >
        {Array.from({ length: zeilen }, (_, weekday) => {
          const y = weekday * zellHoehe;
          return (
            <g key={`row-${weekday}`}>
              {/* Zeilen-Label (Mo..So). */}
              <text
                x={labelBreite - 8}
                y={y + zellHoehe / 2 + 3}
                textAnchor="end"
                fontSize="10"
                fill="currentColor"
                className="behavior-report__svg-mark"
              >
                {wochentage[weekday]}
              </text>
              {spalten.map((slotStart, sp) => {
                const zelle = zelleAt(weekday, slotStart);
                const wert = zelle?.activityCount ?? 0;
                const deckkraft = max > 0 ? wert / max : 0;
                const x = labelBreite + sp * zellBreite;
                return (
                  <rect
                    key={`cell-${weekday}-${sp}`}
                    x={x.toFixed(2)}
                    y={y + 1}
                    width={Math.max(0, zellBreite - 1).toFixed(2)}
                    height={zellHoehe - 2}
                    fill="var(--color-accent)"
                    fillOpacity={deckkraft.toFixed(3)}
                    stroke={zelle?.isDeviation ? "var(--color-accent-strong)" : "none"}
                    strokeWidth={zelle?.isDeviation ? "1.5" : "0"}
                  />
                );
              })}
            </g>
          );
        })}

        {/* Stundenmarken unten (nur volle Stunden). */}
        {spalten.map((slotStart, sp) => {
          if (slotStart % 60 !== 0) {
            return null;
          }
          const x = labelBreite + sp * zellBreite + zellBreite / 2;
          return (
            <text
              key={`wmark-${sp}`}
              x={x.toFixed(2)}
              y={hoehe - 4}
              textAnchor="middle"
              fontSize="10"
              fill="currentColor"
              className="behavior-report__svg-mark"
            >
              {hhmm(slotStart)}
            </text>
          );
        })}
      </svg>
    </section>
  );
}
