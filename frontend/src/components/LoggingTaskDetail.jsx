// Detailansicht einer Logging-Aufgabe (CERNIS PRO 2.0)
//
// Klick auf "Bericht" an einer Aufgaben-Karte öffnet diese Ansicht. Sie zeigt zu
// EINER Task über einen wählbaren Zeitraum: Kopfdaten, SLA-Kennzahlen, einen
// umschaltbaren Verlaufsgraph (Verfügbarkeit % / Ø-RTT) und die Ereignis-Flanken,
// plus einen Export (PDF/CSV/JSON) desselben Ausschnitts.
//
// Der gewählte Zeitraum (feste Stufe oder freie von/bis-Wahl) steuert Chart UND
// Kennzahlen UND Export — alle bekommen denselben since/until-Ausschnitt. Feste
// Stufen: since = jetzt - N, until = null (offenes Ende = bis jetzt, am klarsten).
// Freie Wahl: beide aus den datetime-local-Feldern (in Unix-Sekunden umgerechnet).
//
// Datenquelle: api/monitoring.js (fetchLoggingTask + fetchLoggingSla +
// fetchLoggingEvents, downloadLoggingReport). Fehlertoleranz wie MonitorView/
// LoggingPanel: ein Ladefehler kippt die Ansicht NICHT (dezenter Hinweis statt
// Absturz); 404 -> "Aufgabe nicht gefunden" + Zurück. Alle Texte über i18n, alle
// Farben über Tokens (tokens.css), nie feste Farben.

import { ArrowLeft, FileText } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import {
  downloadLoggingReport,
  fetchLoggingEvents,
  fetchLoggingSla,
  fetchLoggingTask,
} from "../api/monitoring.js";
import { CODES, mitCode } from "../lib/fehlercodes.js";
import LoggingProfileView from "./LoggingProfileView.jsx";
import LoggingSeriesView from "./LoggingSeriesView.jsx";
import SlaChart from "./SlaChart.jsx";
import "./LoggingTaskDetail.css";

// Feste Zeitraum-Stufen: i18n-Schlüssel -> Fensterlänge in Sekunden. Reihenfolge
// verbindlich (so erscheinen die Knöpfe). "frei" ist KEINE Stufe hier (eigener Zweig).
const ZEITRAUM_STUFEN = [
  { key: "stunde", sekunden: 3600 },
  { key: "24h", sekunden: 86400 },
  { key: "7tage", sekunden: 604800 },
  { key: "30tage", sekunden: 2592000 },
];

// Default-Stufe beim Öffnen: letzte 24 h.
const DEFAULT_STUFE = "24h";

// Wandelt einen lokalen datetime-local-Eingabewert ("2026-06-18T14:30") in einen
// Unix-ts in SEKUNDEN (Backend-Zeitbasis). Leerer/ungültiger Wert -> null.
function lokalZuTs(wert) {
  if (!wert) {
    return null;
  }
  const ms = new Date(wert).getTime();
  return Number.isNaN(ms) ? null : ms / 1000;
}

// Unix-ts (Sekunden) -> lesbare lokale Zeit (sprachabhängig). null/keine Zahl -> "—".
function formatZeit(ts, sprache) {
  if (ts === null || ts === undefined || Number.isNaN(ts)) {
    return "—";
  }
  return new Date(ts * 1000).toLocaleString(sprache);
}

// RTT in ms auf eine Nachkommastelle ("8.0 ms"); null = ehrliche Lücke -> "—".
function formatRtt(rttMs) {
  if (rttMs === null || rttMs === undefined || Number.isNaN(rttMs)) {
    return "—";
  }
  return `${rttMs.toFixed(1)} ms`;
}

// Eine Kennzahl-Kachel (Wert prominent, Bezeichnung dezent darunter).
function Kennzahl({ wert, label }) {
  return (
    <div className="logging-detail__kennzahl">
      <span className="logging-detail__kennzahl-wert">{wert}</span>
      <span className="logging-detail__kennzahl-label">{label}</span>
    </div>
  );
}

// Props:
//   taskId    id der anzuzeigenden Aufgabe
//   onZurueck Callback zurück zur Liste
export default function LoggingTaskDetail({ taskId, onZurueck }) {
  const { t, i18n } = useTranslation();

  // Geladene Daten (null = noch nicht geladen / nicht vorhanden).
  const [task, setTask] = useState(null);
  const [sla, setSla] = useState(null);
  const [events, setEvents] = useState([]);

  // Zeitraum-Wahl: stufe ("stunde"|...|"30tage") ODER "frei". Bei "frei" tragen
  // freiVon/freiBis die datetime-local-Strings.
  const [stufe, setStufe] = useState(DEFAULT_STUFE);
  const [freiVon, setFreiVon] = useState("");
  const [freiBis, setFreiBis] = useState("");

  // Chart-Umschalter: "uptime" (Default) | "rtt".
  const [chartModus, setChartModus] = useState("uptime");

  // Ansichts-Umschalter: "bericht" (Default) | "serie" | "profil". Nur bei recurring
  // sichtbar (sonst bleibt es bei "bericht" wie heute). Steuert, ob der SLA/Chart/
  // Ereignis-Block, die Serien-Auswertung oder das Verhaltensprofil gezeigt wird.
  const [ansicht, setAnsicht] = useState("bericht");

  // Ladeflags / Fehlerzustände.
  const [laedt, setLaedt] = useState(false);
  const [nichtGefunden, setNichtGefunden] = useState(false);
  const [fehler, setFehler] = useState(null);

  // Export-Feedback: laufendes Format ("pdf"|...) oder null; Export-Fehlerhinweis.
  const [exportLaeuft, setExportLaeuft] = useState(null);
  const [exportFehler, setExportFehler] = useState(false);

  // Den aktuellen since/until-Ausschnitt aus der Zeitraum-Wahl ableiten. Feste
  // Stufe: since = jetzt - N, until = null (offenes Ende). Freie Wahl: beide aus
  // den Feldern (null bleibt null = offene Grenze). Memoisiert über die Wahl, damit
  // der Lade-Effekt eine stabile Abhängigkeit hat.
  const grenzenBerechnen = useCallback(() => {
    if (stufe === "frei") {
      return { since: lokalZuTs(freiVon), until: lokalZuTs(freiBis) };
    }
    const treffer = ZEITRAUM_STUFEN.find((s) => s.key === stufe);
    const fenster = treffer ? treffer.sekunden : ZEITRAUM_STUFEN[1].sekunden;
    return { since: Date.now() / 1000 - fenster, until: null };
  }, [stufe, freiVon, freiBis]);

  // Lädt Kopfdaten + SLA + Ereignisse für den aktuellen Ausschnitt. Bei Mount und
  // bei jeder Zeitraum-Änderung. Kopfdaten-404 -> "nicht gefunden" (+ Zurück); SLA/
  // Events tolerieren Fehler je für sich (leere Auswertung statt Absturz).
  useEffect(() => {
    let abgebrochen = false;
    const { since, until } = grenzenBerechnen();

    (async () => {
      setLaedt(true);
      setFehler(null);
      setNichtGefunden(false);

      // Kopfdaten: 404 ist der einzige "harte" Fall (Task existiert nicht).
      try {
        const geladen = await fetchLoggingTask(taskId);
        if (!abgebrochen) {
          setTask(geladen);
        }
      } catch (ladeFehler) {
        if (!abgebrochen) {
          if (ladeFehler?.status === 404) {
            setNichtGefunden(true);
          } else {
            setFehler(t("beobachten.logging.detailFehler"));
          }
        }
      }

      // SLA: Fehler -> keine Auswertung (null), kein Absturz.
      try {
        const geladen = await fetchLoggingSla(taskId, since, until);
        if (!abgebrochen) {
          setSla(geladen);
        }
      } catch {
        if (!abgebrochen) {
          setSla(null);
        }
      }

      // Ereignisse: Fehler -> leere Liste, kein Absturz.
      try {
        const geladen = await fetchLoggingEvents(taskId, since, until);
        if (!abgebrochen) {
          setEvents(geladen);
        }
      } catch {
        if (!abgebrochen) {
          setEvents([]);
        }
      }

      if (!abgebrochen) {
        setLaedt(false);
      }
    })();

    return () => {
      abgebrochen = true;
    };
  // t BEWUSST NICHT in den Deps: react-i18next liefert bei jedem Render eine neue
  // t-Referenz -> mit t in den Deps feuert der State-setzende Effekt endlos (Loop).
  // t wird hier nur fuer eine statische Fehlermeldung genutzt, keine Reaktivitaet noetig.
  }, [taskId, grenzenBerechnen]);

  // Export auslösen: den GEWÄHLTEN Ausschnitt (since/until) im gewünschten Format
  // herunterladen. Während des Downloads den jeweiligen Knopf deaktivieren; Fehler
  // -> dezenter Hinweis (kein Absturz).
  const handleExport = async (format) => {
    const { since, until } = grenzenBerechnen();
    setExportLaeuft(format);
    setExportFehler(false);
    try {
      await downloadLoggingReport(taskId, format, since, until);
    } catch {
      setExportFehler(true);
    } finally {
      setExportLaeuft(null);
    }
  };

  // 404: ruhige Meldung + Zurück (kein Rest-UI, die Task gibt es nicht).
  if (nichtGefunden) {
    return (
      <div className="logging-detail">
        <button type="button" className="logging-detail__zurueck" onClick={onZurueck}>
          <ArrowLeft size={15} />
          {t("beobachten.logging.zurueck")}
        </button>
        <p className="logging-detail__leer">{t("beobachten.logging.detailNichtGefunden")}</p>
      </div>
    );
  }

  // SLA-Werte aufbereiten (uptimePct === null -> "keine Auswertung").
  const hatAuswertung = sla !== null && sla.uptimePct !== null;
  const uptimeWert = hatAuswertung
    ? `${Number(sla.uptimePct).toLocaleString(i18n.language, { maximumFractionDigits: 1 })} %`
    : t("beobachten.logging.keineAuswertung");
  const rttWert =
    sla !== null && sla.avgRttMs !== null ? formatRtt(sla.avgRttMs) : "—";
  const downtimeWert =
    sla !== null && sla.downtimeMins !== null
      ? `${Number(sla.downtimeMins).toLocaleString(i18n.language, { maximumFractionDigits: 1 })} ${t("beobachten.logging.minuten")}`
      : "—";
  const messpunkteWert = sla !== null ? String(sla.samples ?? 0) : "—";

  const exportiert = exportLaeuft !== null;

  return (
    <div className="logging-detail">
      <button type="button" className="logging-detail__zurueck" onClick={onZurueck}>
        <ArrowLeft size={15} />
        {t("beobachten.logging.zurueck")}
      </button>

      {fehler && (
        <div className="logging-detail__fehler" role="note">
          {fehler}
        </div>
      )}

      {/* ── Kopf: Bezeichnung + Zweck/Ziel/Status/Modus ──────────────────────── */}
      <div className="logging-detail__kopf">
        <h2 className="logging-detail__titel">
          {task?.label ?? t("beobachten.logging.detailTitel")}
        </h2>
        {task && (
          <div className="logging-detail__kopf-meta">
            {task.purpose && (
              <span className="logging-detail__kopf-zweck">{task.purpose}</span>
            )}
            <span className="logging-detail__kopf-zeile">
              <span className="logging-detail__ziel">{task.targetId}</span>
              <span className="logging-detail__trenner" aria-hidden="true">·</span>
              <span>
                {t(`beobachten.logging.state.${task.state}`, { defaultValue: task.state })}
              </span>
              <span className="logging-detail__trenner" aria-hidden="true">·</span>
              <span>
                {t(`beobachten.logging.captureKurz.${task.captureMode}`, {
                  defaultValue: task.captureMode,
                })}
              </span>
            </span>
          </div>
        )}
      </div>

      {/* ── Zeitraumwahl: feste Stufen + frei ────────────────────────────────── */}
      <div className="logging-detail__zeitraum">
        <span className="logging-detail__zeitraum-label">
          {t("beobachten.logging.zeitraumLabel")}
        </span>
        <div className="logging-detail__zeitraum-knoepfe">
          {ZEITRAUM_STUFEN.map((s) => (
            <button
              key={s.key}
              type="button"
              className={
                stufe === s.key
                  ? "logging-detail__stufe logging-detail__stufe--aktiv"
                  : "logging-detail__stufe"
              }
              aria-pressed={stufe === s.key}
              onClick={() => setStufe(s.key)}
            >
              {t(`beobachten.logging.zeitraum.${s.key}`)}
            </button>
          ))}
          <button
            type="button"
            className={
              stufe === "frei"
                ? "logging-detail__stufe logging-detail__stufe--aktiv"
                : "logging-detail__stufe"
            }
            aria-pressed={stufe === "frei"}
            onClick={() => setStufe("frei")}
          >
            {t("beobachten.logging.zeitraum.frei")}
          </button>
        </div>
        {stufe === "frei" && (
          <div className="logging-detail__frei">
            <label className="logging-detail__frei-feld">
              <span>{t("beobachten.logging.zeitraumVon")}</span>
              <input
                type="datetime-local"
                value={freiVon}
                onChange={(e) => setFreiVon(e.target.value)}
              />
            </label>
            <label className="logging-detail__frei-feld">
              <span>{t("beobachten.logging.zeitraumBis")}</span>
              <input
                type="datetime-local"
                value={freiBis}
                onChange={(e) => setFreiBis(e.target.value)}
              />
            </label>
          </div>
        )}
      </div>

      {/* ── Ansichts-Umschalter: Bericht | Serien-Auswertung (nur recurring) ─── */}
      {task?.operationMode === "recurring" && (
        <div className="logging-detail__chart-tabs" role="tablist">
          <button
            type="button"
            role="tab"
            aria-selected={ansicht === "bericht"}
            className={
              ansicht === "bericht"
                ? "logging-detail__tab logging-detail__tab--aktiv"
                : "logging-detail__tab"
            }
            onClick={() => setAnsicht("bericht")}
          >
            {t("beobachten.logging.ansicht.bericht")}
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={ansicht === "serie"}
            className={
              ansicht === "serie"
                ? "logging-detail__tab logging-detail__tab--aktiv"
                : "logging-detail__tab"
            }
            onClick={() => setAnsicht("serie")}
          >
            {t("beobachten.logging.ansicht.serie")}
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={ansicht === "profil"}
            className={
              ansicht === "profil"
                ? "logging-detail__tab logging-detail__tab--aktiv"
                : "logging-detail__tab"
            }
            onClick={() => setAnsicht("profil")}
          >
            {t("beobachten.logging.ansicht.profil")}
          </button>
        </div>
      )}

      {ansicht === "serie" || ansicht === "profil" ? (
        (() => {
          // Einmal berechnen + destrukturieren (statt grenzenBerechnen() doppelt) —
          // Verhalten unveraendert, nur ein Aufruf. since/until wie bei "serie".
          const { since, until } = grenzenBerechnen();
          return ansicht === "profil" ? (
            <LoggingProfileView taskId={taskId} since={since} until={until} />
          ) : (
            <LoggingSeriesView taskId={taskId} since={since} until={until} />
          );
        })()
      ) : (
        <>
      {/* ── SLA-Kennzahlen ───────────────────────────────────────────────────── */}
      <div className="logging-detail__kennzahlen">
        <Kennzahl wert={uptimeWert} label={t("beobachten.logging.kennzahl.verfuegbarkeit")} />
        <Kennzahl wert={rttWert} label={t("beobachten.logging.kennzahl.rtt")} />
        <Kennzahl wert={downtimeWert} label={t("beobachten.logging.kennzahl.ausfallzeit")} />
        <Kennzahl wert={messpunkteWert} label={t("beobachten.logging.kennzahl.messpunkte")} />
      </div>

      {/* ── Chart: Tab-Umschalter + SlaChart ─────────────────────────────────── */}
      <div className="logging-detail__chart-tabs" role="tablist">
        <button
          type="button"
          role="tab"
          aria-selected={chartModus === "uptime"}
          className={
            chartModus === "uptime"
              ? "logging-detail__tab logging-detail__tab--aktiv"
              : "logging-detail__tab"
          }
          onClick={() => setChartModus("uptime")}
        >
          {t("beobachten.logging.chartTab.uptime")}
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={chartModus === "rtt"}
          className={
            chartModus === "rtt"
              ? "logging-detail__tab logging-detail__tab--aktiv"
              : "logging-detail__tab"
          }
          onClick={() => setChartModus("rtt")}
        >
          {t("beobachten.logging.chartTab.rtt")}
        </button>
      </div>
      <SlaChart buckets={sla?.chart ?? []} modus={chartModus} label={task?.label} />

      {/* ── Ereignis-Liste (neueste zuerst, wie das Monitor-Log) ─────────────── */}
      <div className="logging-detail__ereignisse-titel">
        {t("beobachten.logging.ereignisseTitel")}
      </div>
      {events.length === 0 ? (
        <p className="logging-detail__leer">{t("beobachten.logging.ereignisseLeer")}</p>
      ) : (
        <ul className="logging-detail__ereignisse">
          {[...events].reverse().map((ev, index) => (
            <li className="logging-detail__ereignis" key={`${ev.ts}-${index}`}>
              <span className="logging-detail__ereignis-zeit logging-detail__mono">
                {formatZeit(ev.ts, i18n.language)}
              </span>
              <span className="logging-detail__ereignis-typ">{ev.eventType}</span>
              <span className="logging-detail__ereignis-rtt logging-detail__mono">
                {formatRtt(ev.rttMs)}
              </span>
            </li>
          ))}
        </ul>
      )}
        </>
      )}

      {/* ── Export-Zeile (PDF/CSV/JSON) — nur im Bericht-Reiter ──────────────── */}
      {ansicht === "bericht" && (
      <div className="logging-detail__export">
        <span className="logging-detail__export-titel">
          <FileText size={15} aria-hidden="true" />
          {t("beobachten.logging.exportTitel")}
        </span>
        <div className="logging-detail__export-knoepfe">
          <button
            type="button"
            className="logging-detail__export-knopf"
            disabled={exportiert}
            onClick={() => handleExport("pdf")}
          >
            {exportLaeuft === "pdf"
              ? t("beobachten.logging.exportLaeuft")
              : t("beobachten.logging.exportPdf")}
          </button>
          <button
            type="button"
            className="logging-detail__export-knopf"
            disabled={exportiert}
            onClick={() => handleExport("csv")}
          >
            {exportLaeuft === "csv"
              ? t("beobachten.logging.exportLaeuft")
              : t("beobachten.logging.exportCsv")}
          </button>
          <button
            type="button"
            className="logging-detail__export-knopf"
            disabled={exportiert}
            onClick={() => handleExport("json")}
          >
            {exportLaeuft === "json"
              ? t("beobachten.logging.exportLaeuft")
              : t("beobachten.logging.exportJson")}
          </button>
        </div>
        {exportFehler && (
          <span className="logging-detail__export-fehler" role="note">
            {mitCode(t("beobachten.logging.exportFehler"), CODES.E_504)}
          </span>
        )}
      </div>
      )}

      {laedt && <div className="logging-detail__laedt" aria-hidden="true" />}
    </div>
  );
}
