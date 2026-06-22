// Logging-Aufgaben-Maske (CERNIS PRO 2.0)
//
// Gefuehrte Maske zum Anlegen + Steuern von Logging-Aufgaben auf dem fertigen
// B-Backend (REST unter /api/monitor/logging). Zwei Teile:
//   - oben die ANLAGE: Modus-Umschalter Assistent/Erweitert. Assistent fuehrt in
//     drei Schritten (Ziel & Zweck / Erfassung / Betriebsart), Erweitert zeigt
//     dieselben Felder kompakt auf einem Schirm. Beide erzeugen denselben
//     createLoggingTask-POST -- die Modus-Wahl ist reine UI (kein Backend).
//   - darunter die UEBERSICHT + PLAYER: je Task eine Karte mit Zustand (Pill),
//     Restzeit (rein clientseitig aus loggingTask.js) und Player-Knoepfen je nach
//     Zustand. Aktionen rufen die API und aktualisieren die Liste.
//
// NUR backendgestuetzte Felder. KEINE Enterprise-Funktionen (Mess-Intervall,
// Alarme, Wartungsfenster, Baseline, SLA, Export) -- die haben kein Backend und
// kommen als eigene Folge-Schnitte. KEINE toten/deaktivierten Attrappen-Schalter.
//
// Datenquelle: api/monitoring.js (Logging-REST + fetchMonitorStatus fuer die
// Ziel-Auswahl). Fehlertoleranz wie MonitorView: ein Ladefehler kippt die Ansicht
// NICHT (leere Liste + dezenter Hinweis). Alle Texte ueber i18n, alle Farben ueber
// Tokens (tokens.css), nie feste Farben.

import { FileText, Pause, Play, Plus, Square, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import {
  createLoggingTask,
  deleteLoggingTask,
  fetchLoggingSla,
  fetchLoggingTasks,
  fetchMonitorStatus,
  pauseLoggingTask,
  resumeLoggingTask,
  startLoggingTask,
  stopLoggingTask,
} from "../api/monitoring.js";
import {
  fortschrittAnteil,
  formatiereRestzeit,
  restSekunden,
  ZUSTAND,
} from "./loggingTask.js";
import LoggingTaskDetail from "./LoggingTaskDetail.jsx";
import "./LoggingPanel.css";

// Die drei vom Backend unterstuetzten Erfassungs-Modi (capture_mode-Vokabular).
// Reihenfolge ist verbindlich (so erscheinen die Kacheln/Optionen).
const CAPTURE_MODI = ["interface_status", "reachability", "reachability_latency"];

// Waehlbare Sofort-Dauern: i18n-Schluessel -> Sekunden. Reihenfolge verbindlich.
const DAUER_OPTIONEN = [
  { key: "30min", sekunden: 1800 },
  { key: "2h", sekunden: 7200 },
  { key: "6h", sekunden: 21600 },
  { key: "1d", sekunden: 86400 },
  { key: "1w", sekunden: 604800 },
];

// Waehlbare Mess-Intervall-Stufen (C-2): i18n-Schluessel -> Sekunden. Muss mit den
// Backend-Stufen {5,15,30,60,300} uebereinstimmen (sonst 422). Reihenfolge verbindlich.
// NUR im Erweitert-Modus sichtbar; der Assistent nutzt still den Default (5 s).
const INTERVALL_OPTIONEN = [
  { key: "5s", sekunden: 5 },
  { key: "15s", sekunden: 15 },
  { key: "30s", sekunden: 30 },
  { key: "60s", sekunden: 60 },
  { key: "300s", sekunden: 300 },
];

// Mess-Intervall in Sekunden -> i18n-Schluessel der Karten-Anzeige ("alle 30 s").
// Fremde Werte -> null (keine Anzeige, kein Absturz).
function intervallKarteKey(sekunden) {
  const treffer = INTERVALL_OPTIONEN.find((o) => o.sekunden === sekunden);
  return treffer ? treffer.key : null;
}

// Rundet eine Zahl auf ``stellen`` Dezimalstellen und formatiert sie sprachabhaengig
// (DE -> Komma, EN -> Punkt) ueber toLocaleString. ``null``/keine Zahl -> null (die
// Anzeige laesst den Wert dann weg). ``sprache`` ist i18n.language.
function formatiereZahl(wert, stellen, sprache) {
  if (wert === null || wert === undefined || Number.isNaN(wert)) {
    return null;
  }
  return Number(wert).toLocaleString(sprache, {
    minimumFractionDigits: stellen,
    maximumFractionDigits: stellen,
  });
}

// Wandelt einen lokalen datetime-local-Eingabewert ("2026-06-18T14:30") in einen
// Unix-ts in SEKUNDEN (Backend-Zeitbasis). Leerer Wert -> null (ehrliche Luecke).
function lokalZuTs(wert) {
  if (!wert) {
    return null;
  }
  const ms = new Date(wert).getTime();
  return Number.isNaN(ms) ? null : ms / 1000;
}

// Wiederkehrend (3b): Helfer hh:mm <-> Minuten seit Mitternacht. ``minutenZuHhmm``
// formatiert eine Minutenzahl (0..1440) als "HH:MM" fuer das time-Input; ungueltige
// Werte -> "" (kein Absturz). ``hhmmZuMinuten`` parst ein "HH:MM"-time-Input in Minuten
// seit Mitternacht; leer/ungueltig -> null (ehrliche Luecke).
function minutenZuHhmm(minuten) {
  if (minuten === null || minuten === undefined || Number.isNaN(minuten)) {
    return "";
  }
  const std = Math.floor(minuten / 60);
  const min = Math.floor(minuten % 60);
  return `${String(std).padStart(2, "0")}:${String(min).padStart(2, "0")}`;
}

function hhmmZuMinuten(wert) {
  if (!wert) {
    return null;
  }
  const [std, min] = wert.split(":").map((teil) => Number(teil));
  if (Number.isNaN(std) || Number.isNaN(min)) {
    return null;
  }
  return std * 60 + min;
}

// Wiederkehrend (3b): Helfer fuer das Zeitraum-Datum (date-Input "2026-06-18") <-> Unix-ts
// in SEKUNDEN. ``datumZuTs`` parst ein date-Input zu Mitternachts-ts; leer/ungueltig ->
// null. ``tsZuDatum`` formatiert einen Unix-ts als "YYYY-MM-DD" fuer das date-Input
// bzw. (lokalisiert in der Karte) -- hier die rohe ISO-Form; null -> "".
function datumZuTs(wert) {
  if (!wert) {
    return null;
  }
  const ms = new Date(wert).getTime();
  return Number.isNaN(ms) ? null : ms / 1000;
}

function tsZuDatum(ts) {
  if (ts === null || ts === undefined || Number.isNaN(ts)) {
    return "";
  }
  const d = new Date(ts * 1000);
  if (Number.isNaN(d.getTime())) {
    return "";
  }
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(
    d.getDate(),
  ).padStart(2, "0")}`;
}

// Wiederkehrend (3b): zaehlt die Tage im Zeitraum [von, bis], die auf einen der
// gewaehlten Wochentage fallen -- die Vorschau "Ergibt N Messlaeufe". Reine Frontend-
// Rechnung, defensiv: fehlt das von-Datum ODER ist die Wochentags-Liste leer, kann N
// nicht bestimmt werden (-> null). Leere Wochentags-Liste bedeutet zwar fachlich "alle
// Tage", aber die Vorschau soll dann nichts Konkretes versprechen (defensiv null). Ist
// das bis-Datum leer, signalisiert der Aufrufer "laeuft bis auf Weiteres" separat.
// JS getDay(): 0=So..6=Sa -> auf das Backend-Schema 0=Mo..6=So umgerechnet.
function zaehleMesslaeufe(vonTs, bisTs, weekdays) {
  if (vonTs === null || bisTs === null || !weekdays || weekdays.length === 0) {
    return null;
  }
  if (bisTs < vonTs) {
    return 0;
  }
  const aktiv = new Set(weekdays);
  let anzahl = 0;
  const tag = new Date(vonTs * 1000);
  tag.setHours(0, 0, 0, 0);
  const ende = new Date(bisTs * 1000);
  ende.setHours(0, 0, 0, 0);
  // Obergrenze gegen versehentliche Endlosschleifen bei kaputten Eingaben (defensiv).
  let schutz = 0;
  while (tag.getTime() <= ende.getTime() && schutz < 4000) {
    const backendTag = (tag.getDay() + 6) % 7; // So=0..Sa=6 -> Mo=0..So=6
    if (aktiv.has(backendTag)) {
      anzahl += 1;
    }
    tag.setDate(tag.getDate() + 1);
    schutz += 1;
  }
  return anzahl;
}

// CSS-Modifier-Klasse des Zustands-Pills je Backend-Zustand (aktiv gruen /
// pausiert lila / angelegt grau / beendet gedaempft). Unbekannte Zustaende ->
// gedaempft (kein Absturz).
function pillKlasse(state) {
  switch (state) {
    case ZUSTAND.ACTIVE:
      return "logging-pill logging-pill--aktiv";
    case ZUSTAND.PAUSED:
      return "logging-pill logging-pill--pausiert";
    case ZUSTAND.CREATED:
      return "logging-pill logging-pill--angelegt";
    default:
      return "logging-pill logging-pill--beendet";
  }
}

// Ein Player-Knopf je Task-Karte. Ruft onClick; Icon + Label uebergeben.
function PlayerKnopf({ icon: Icon, label, onClick, variante }) {
  return (
    <button
      type="button"
      className={`logging-player__knopf logging-player__knopf--${variante}`}
      onClick={onClick}
      title={label}
      aria-label={label}
    >
      <Icon size={14} />
      <span>{label}</span>
    </button>
  );
}

// Eine Aufgaben-Karte: Label, Ziel, Erfassungsmodus, Zustands-Pill, Restzeit, bei
// aktiven ein Fortschrittsbalken, plus die zustandsabhaengigen Player-Knoepfe.
// jetzt wird von oben durchgereicht (ein gemeinsamer Tick fuer alle Karten).
function AufgabenKarte({ task, jetzt, sla, onAktion }) {
  const { t, i18n } = useTranslation();

  const rest = restSekunden(task, jetzt);
  const restText = formatiereRestzeit(rest, t, "beobachten.logging.rest");
  const anteil = fortschrittAnteil(task, jetzt);
  const zustandText = t(`beobachten.logging.state.${task.state}`, {
    defaultValue: task.state,
  });
  const captureText = t(`beobachten.logging.captureKurz.${task.captureMode}`, {
    defaultValue: task.captureMode,
  });
  // Mess-Intervall (C-2) NUR bei "Erreichbarkeit + Latenz" zeigen (nur dieser Modus
  // erzeugt die dichten RTT-Punkte, die das Intervall ausduennt). Fremde/fehlende Werte
  // -> keine Anzeige (intervallKarteKey -> null).
  const intervallKey =
    task.captureMode === "reachability_latency" ? intervallKarteKey(task.intervalS) : null;
  const intervallText = intervallKey
    ? t(`beobachten.logging.intervallKarte.${intervallKey}`)
    : null;

  // Schwellwert-Alarm (Schnitt 5): bei gesetztem threshold (nicht null) eine dezente
  // Meta-Zeile. Zwei Varianten je condition -- "latency_above" zeigt Grenzwert + N,
  // "unreachable" nur N. i18n-Text mit Platzhaltern (keine zusammengebauten Strings);
  // fremde condition -> keine Anzeige (kein Absturz).
  const thr = task.threshold;
  const schwellwertText = !thr
    ? null
    : thr.condition === "latency_above"
      ? t("beobachten.logging.schwellwertKarte.latency", {
          limit: thr.limitMs,
          n: thr.consecutiveN,
        })
      : thr.condition === "unreachable"
        ? t("beobachten.logging.schwellwertKarte.unreachable", { n: thr.consecutiveN })
        : null;

  // SLA-Kennzahlen (C-3) NUR bei "Erreichbarkeit + Latenz" (nur dieser Modus erzeugt
  // die dichten RTT-Punkte, aus denen die Verfuegbarkeit gerechnet wird). ``sla`` ist
  // das geladene { uptimePct, downtimeMins, avgRttMs, samples } oder undefined (noch
  // nicht geladen / Ladefehler -> Zeile still weglassen, kein Absturz). uptimePct ===
  // null heisst "noch keine Auswertung" (zu wenig/keine Daten -> dezenter Hinweis).
  // Wiederkehrend (3b): bei operationMode "recurring" statt der einmaligen Restzeit eine
  // eigene Meta-Zeile "Wiederkehrend · <HH:MM>-<HH:MM> · <Wochentage-Kurz>" und, wenn ein
  // Ende-Datum gesetzt ist, "· bis <Datum>". Defensiv: fehlende Felder lassen den
  // jeweiligen Teil weg (kein Absturz). Die Wochentags-Kurzform aus diskreten i18n-Tokens
  // (kein zusammengebauter Satz) -- leere Liste = alle Tage (-> kein Tage-Teil).
  const istWiederkehrend = task.operationMode === "recurring";
  const wochentageKurz =
    istWiederkehrend && Array.isArray(task.recurWeekdays)
      ? task.recurWeekdays
          .map((tag) => t(`beobachten.logging.recurWochentag.${tag}`, { defaultValue: "" }))
          .filter(Boolean)
          .join(", ")
      : "";
  const wiederkehrendText = istWiederkehrend
    ? t("beobachten.logging.wiederkehrendKarte", {
        von: minutenZuHhmm(task.recurStartMinute),
        bis: minutenZuHhmm(task.recurEndMinute),
        tage: wochentageKurz,
      })
    : null;
  const wiederkehrendBisText =
    istWiederkehrend && task.recurUntil
      ? t("beobachten.logging.wiederkehrendKarteBis", {
          datum: new Date(task.recurUntil * 1000).toLocaleDateString(i18n.language),
        })
      : null;

  const zeigtSla = task.captureMode === "reachability_latency" && sla !== undefined;
  const hatAuswertung = zeigtSla && sla.uptimePct !== null;
  const uptimeText = hatAuswertung ? formatiereZahl(sla.uptimePct, 1, i18n.language) : null;
  const avgRttText = hatAuswertung ? formatiereZahl(sla.avgRttMs, 1, i18n.language) : null;
  const downtimeText = hatAuswertung ? formatiereZahl(sla.downtimeMins, 1, i18n.language) : null;

  return (
    <div className="logging-karte">
      <div className="logging-karte__kopf">
        <span className={pillKlasse(task.state)}>
          {task.state === ZUSTAND.ACTIVE && (
            <span className="logging-pill__punkt" aria-hidden="true" />
          )}
          {zustandText}
        </span>
        <span className="logging-karte__label">{task.label}</span>
      </div>

      <div className="logging-karte__meta">
        <span className="logging-karte__ziel">{task.targetId}</span>
        <span className="logging-karte__trenner" aria-hidden="true">
          ·
        </span>
        <span className="logging-karte__capture">{captureText}</span>
        {intervallText && (
          <>
            <span className="logging-karte__trenner" aria-hidden="true">
              ·
            </span>
            <span className="logging-karte__intervall">{intervallText}</span>
          </>
        )}
        {schwellwertText && (
          <>
            <span className="logging-karte__trenner" aria-hidden="true">
              ·
            </span>
            <span className="logging-karte__schwellwert">{schwellwertText}</span>
          </>
        )}
        {wiederkehrendText && (
          <>
            <span className="logging-karte__trenner" aria-hidden="true">
              ·
            </span>
            <span className="logging-karte__wiederkehrend">{wiederkehrendText}</span>
            {wiederkehrendBisText && (
              <>
                <span className="logging-karte__trenner" aria-hidden="true">
                  ·
                </span>
                <span className="logging-karte__wiederkehrend-bis">{wiederkehrendBisText}</span>
              </>
            )}
          </>
        )}
        {restText && (
          <>
            <span className="logging-karte__trenner" aria-hidden="true">
              ·
            </span>
            <span className="logging-karte__rest">{restText}</span>
          </>
        )}
      </div>

      {/* SLA-Kennzahlen (C-3): Verfuegbarkeit prominent, Ø-RTT + ca.-Downtime dezent.
          Nur bei reachability_latency mit geladenen Daten. uptimePct null -> Hinweis. */}
      {zeigtSla &&
        (hatAuswertung ? (
          <div className="logging-karte__sla">
            <span className="logging-karte__sla-uptime">
              {t("beobachten.logging.sla.verfuegbarkeit", { wert: uptimeText })}
            </span>
            <span className="logging-karte__sla-detail">
              {t("beobachten.logging.sla.avgRtt", { wert: avgRttText })}
            </span>
            <span className="logging-karte__sla-detail">
              {t("beobachten.logging.sla.downtime", { wert: downtimeText })}
            </span>
          </div>
        ) : (
          <div className="logging-karte__sla logging-karte__sla--leer">
            {t("beobachten.logging.sla.keineAuswertung")}
          </div>
        ))}

      {/* Fortschrittsbalken nur bei aktiven Aufgaben mit bestimmbarem Anteil. */}
      {task.state === ZUSTAND.ACTIVE && anteil !== null && (
        <div className="logging-karte__balken" aria-hidden="true">
          <div
            className="logging-karte__balken-fill"
            style={{ width: `${Math.round(anteil * 100)}%` }}
          />
        </div>
      )}

      <div className="logging-player">
        {/* Bericht/Detail-Knopf: ein eigener Knopf statt die ganze Karte klickbar zu
            machen (die Karte traegt schon die Player-Knoepfe -- ein klarer eigener
            Knopf ist eindeutiger). Loest onAktion("detail", task) aus. Immer sichtbar
            (ein Bericht ist in jedem Zustand sinnvoll). */}
        <PlayerKnopf
          icon={FileText}
          label={t("beobachten.logging.aktion.detail")}
          variante="detail"
          onClick={() => onAktion("detail", task)}
        />
        {task.state === ZUSTAND.CREATED && (
          <PlayerKnopf
            icon={Play}
            label={t("beobachten.logging.aktion.start")}
            variante="start"
            onClick={() => onAktion("start", task)}
          />
        )}
        {task.state === ZUSTAND.ACTIVE && (
          <>
            <PlayerKnopf
              icon={Pause}
              label={t("beobachten.logging.aktion.pause")}
              variante="pause"
              onClick={() => onAktion("pause", task)}
            />
            <PlayerKnopf
              icon={Square}
              label={t("beobachten.logging.aktion.stop")}
              variante="stop"
              onClick={() => onAktion("stop", task)}
            />
          </>
        )}
        {task.state === ZUSTAND.PAUSED && (
          <>
            <PlayerKnopf
              icon={Play}
              label={t("beobachten.logging.aktion.resume")}
              variante="start"
              onClick={() => onAktion("resume", task)}
            />
            <PlayerKnopf
              icon={Square}
              label={t("beobachten.logging.aktion.stop")}
              variante="stop"
              onClick={() => onAktion("stop", task)}
            />
          </>
        )}
        {task.state === ZUSTAND.FINISHED && (
          <PlayerKnopf
            icon={Trash2}
            label={t("beobachten.logging.aktion.delete")}
            variante="delete"
            onClick={() => onAktion("delete", task)}
          />
        )}
      </div>
    </div>
  );
}

// Der gemeinsame Eingabe-Zustand der Maske. Beide Modi (Assistent/Erweitert)
// schreiben in DIESELBEN Felder; nur die Darstellung unterscheidet sich.
const LEERE_EINGABE = {
  targetId: "",
  label: "",
  purpose: "",
  captureMode: "reachability_latency",
  operationMode: "immediate",
  maxDurationS: 7200,
  plannedStart: "",
  plannedEnd: "",
  // Mess-Intervall in Sekunden (C-2). Default 5 = heutiges dichtes Verhalten. Im
  // Assistent-Modus unsichtbar (wird nicht in den Payload gereicht -> Backend-Default);
  // nur der Erweitert-Modus zeigt das Feld und reicht es mit.
  intervalS: 5,
  // Wiederkehrendes Tagesfenster (3b). Nur fuer operationMode "recurring" relevant.
  // recurStartMinute/recurEndMinute sind Minuten seit Mitternacht (600/660 = 10:00-11:00
  // als sinnvolle Vorbelegung); recurWeekdays als Array 0..6 (Mo-Fr vorbelegt); recurFrom/
  // recurUntil sind leere Strings (date-Inputs, leer = ab sofort / unbegrenzt).
  recurStartMinute: 600,
  recurEndMinute: 660,
  recurWeekdays: [0, 1, 2, 3, 4],
  recurFrom: "",
  recurUntil: "",
  // Schwellwert-Alarm (Schnitt 5). Verschachteltes Objekt mit eigenem aktiv-Flag:
  // aktiv=false bedeutet KEIN Schwellwert (nichts in den Payload). Die Default-Werte
  // sind sinnvoll vorbelegt (Latenz > 100 ms, 3 Messungen in Folge, Desktop an,
  // E-Mail aus -- passend zu den Domaenen-Defaults). NUR im Erweitert-Modus sichtbar.
  threshold: {
    aktiv: false,
    condition: "latency_above",
    limitMs: 100,
    consecutiveN: 3,
    notifyDesktop: true,
    notifyEmail: false,
  },
};

// onDetailChange (optional): meldet dem Eltern-Bereich, ob die Detailansicht offen
// ist (true wenn eine Task-id gewaehlt, false zurueck zur Liste). Damit kann der
// Bereich z. B. seinen eigenen Zurück-Knopf ausblenden, solange das Detail offen ist.
// Optional (optional chaining) -- ohne das Prop funktioniert das Panel unveraendert.
export default function LoggingPanel({ onDetailChange }) {
  const { t } = useTranslation();

  // Anlage-Modus (reine UI): "assistent" | "erweitert".
  const [modus, setModus] = useState("assistent");
  // Aktiver Assistenten-Schritt (1..3). Im Erweitert-Modus ohne Bedeutung.
  const [schritt, setSchritt] = useState(1);
  // Gemeinsame Eingabefelder der Maske.
  const [eingabe, setEingabe] = useState(LEERE_EINGABE);

  // Verfuegbare Ziele (aus fetchMonitorStatus): [{ targetId, label }].
  const [ziele, setZiele] = useState([]);
  // Angelegte Aufgaben (aus fetchLoggingTasks), gemappt.
  const [aufgaben, setAufgaben] = useState([]);
  // SLA-Kennzahlen je Task-id (C-3): { [taskId]: { uptimePct, downtimeMins, avgRttMs,
  // samples } }. Einmalig pro Listen-Reload befuellt (KEIN Dauer-Poll) -- nur fuer
  // reachability_latency-Tasks. Fehlt ein Eintrag (Ladefehler), zeigt die Karte keine
  // SLA-Zeile (still weggelassen).
  const [slaMap, setSlaMap] = useState({});
  // Dezenter Fehlerhinweis oben (Anlage/Aktion/Laden) oder null.
  const [fehler, setFehler] = useState(null);
  // Gemeinsamer Sekunden-Tick fuer die Restzeit-Anzeige aller Karten.
  const [jetzt, setJetzt] = useState(() => Date.now() / 1000);
  // Detail-Navigation (Schnitt 1b/1c): null = Liste/Maske, gesetzt = Detailansicht
  // dieser Task-id. Reine View-Navigation (kein Backend).
  const [detailTaskId, setDetailTaskId] = useState(null);

  // Ein Feld der Eingabe setzen (immutabel).
  const setFeld = (feld, wert) => setEingabe((v) => ({ ...v, [feld]: wert }));

  // Ein Feld INNERHALB des verschachtelten threshold-Objekts setzen (immutabel, Schnitt
  // 5). Analog setFeld, aber tief: schreibt in eingabe.threshold[feld] ohne die uebrigen
  // Schwellwert-Felder zu verlieren.
  const setThresholdFeld = (feld, wert) =>
    setEingabe((v) => ({ ...v, threshold: { ...v.threshold, [feld]: wert } }));

  // Beim Mount: Ziele (fuer die Auswahl) und vorhandene Aufgaben laden. Fehler
  // werden toleriert (leere Liste, dezenter Hinweis erst bei Aktionsfehlern).
  useEffect(() => {
    let abgebrochen = false;
    (async () => {
      try {
        const liste = await fetchMonitorStatus();
        if (!abgebrochen) {
          setZiele(liste.map((z) => ({ targetId: z.targetId, label: z.label })));
        }
      } catch {
        // Keine Ziele erreichbar: leere Auswahl, kein Hinweis.
      }
      await ladeAufgaben(abgebrochen);
    })();
    return () => {
      abgebrochen = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Restzeit-Tick: einmal pro Sekunde die Wanduhr aktualisieren, damit die
  // Karten-Restzeit live mitlaeuft. Reine Anzeige (kein Backend-Poll).
  useEffect(() => {
    const id = setInterval(() => setJetzt(Date.now() / 1000), 1000);
    return () => clearInterval(id);
  }, []);

  // Detail-Zustand nach aussen melden (Schnitt 1c): wann immer detailTaskId zwischen
  // null (Liste) und gesetzt (Detail) wechselt, den Eltern-Bereich informieren -- damit
  // der z. B. seinen eigenen Zurück-Knopf ausblenden kann. Optional (optional chaining):
  // ohne onDetailChange-Prop ist das ein No-op.
  useEffect(() => {
    onDetailChange?.(detailTaskId !== null);
  }, [detailTaskId, onDetailChange]);

  // Aufgaben-Liste neu laden. Fehler -> dezenter Lade-Hinweis (kein Absturz). Im
  // Anschluss EINMALIG die SLA-Kennzahlen der reachability_latency-Tasks nachladen
  // (kein Dauer-Poll -- nur beim Listen-Reload).
  const ladeAufgaben = async (abgebrochen = false) => {
    try {
      const liste = await fetchLoggingTasks();
      if (!abgebrochen) {
        setAufgaben(liste);
        ladeSla(liste, abgebrochen);
      }
    } catch {
      if (!abgebrochen) {
        setFehler(t("beobachten.logging.ladeFehler"));
      }
    }
  };

  // SLA-Kennzahlen je reachability_latency-Task laden (C-3). Pro Task ein einzelner
  // fetchLoggingSla; ein Fehler an EINEM Task laesst nur dessen SLA-Zeile weg (kein
  // Eintrag in der Map), die Liste bleibt stehen. EINMALIG pro Reload (kein Poll).
  const ladeSla = async (liste, abgebrochen = false) => {
    const slaTasks = liste.filter((t2) => t2.captureMode === "reachability_latency");
    const ergebnisse = await Promise.all(
      slaTasks.map(async (t2) => {
        try {
          return [t2.id, await fetchLoggingSla(t2.id)];
        } catch {
          // 404/Netz: kein Eintrag -> die Karte laesst die SLA-Zeile still weg.
          return null;
        }
      }),
    );
    if (!abgebrochen) {
      setSlaMap(Object.fromEntries(ergebnisse.filter(Boolean)));
    }
  };

  // Baut aus den Eingabefeldern den Create-Payload (nur die modus-gueltigen
  // Zeitfelder). SCHEDULED -> plannedStart/plannedEnd; IMMEDIATE -> maxDurationS.
  const bauePayload = () => {
    const basis = {
      targetId: eingabe.targetId,
      label: eingabe.label.trim(),
      purpose: eingabe.purpose.trim(),
      captureMode: eingabe.captureMode,
      operationMode: eingabe.operationMode,
    };
    // Mess-Intervall (C-2) NUR im Erweitert-Modus mitgeben -- der Assistent laesst es
    // weg, dann greift still der Backend-Default (5 s). "Erweitert kann mehr".
    if (modus === "erweitert") {
      basis.intervalS = eingabe.intervalS;
    }
    // Schwellwert-Alarm (Schnitt 5) NUR im Erweitert-Modus und NUR wenn aktiv. Das
    // aktiv-Flag ist reine UI und wandert NICHT in den Payload. Bei "unreachable" spielt
    // der Grenzwert keine Rolle -> wir senden limitMs konsistent als 0 (das Backend
    // ignoriert ihn dort, 0 ist erlaubt) statt einen UI-Restwert mitzuschleppen.
    if (modus === "erweitert" && eingabe.threshold.aktiv) {
      const t = eingabe.threshold;
      basis.threshold = {
        condition: t.condition,
        limitMs: t.condition === "latency_above" ? t.limitMs : 0,
        consecutiveN: t.consecutiveN,
        notifyDesktop: t.notifyDesktop,
        notifyEmail: t.notifyEmail,
      };
    }
    if (eingabe.operationMode === "scheduled") {
      return {
        ...basis,
        plannedStart: lokalZuTs(eingabe.plannedStart),
        plannedEnd: lokalZuTs(eingabe.plannedEnd),
      };
    }
    // Wiederkehrend (3b): Tagesfenster (Minuten), Wochentage (Array 0..6) und der optionale
    // Gesamtzeitraum (recurFrom/recurUntil als Unix-ts oder null -> der API-Client laesst
    // null-Grenzen weg). Das Tagesfenster ist hier durch eingabeGueltig garantiert gesetzt.
    if (eingabe.operationMode === "recurring") {
      return {
        ...basis,
        recurStartMinute: eingabe.recurStartMinute,
        recurEndMinute: eingabe.recurEndMinute,
        recurWeekdays: eingabe.recurWeekdays,
        recurFrom: datumZuTs(eingabe.recurFrom),
        recurUntil: datumZuTs(eingabe.recurUntil),
      };
    }
    return { ...basis, maxDurationS: eingabe.maxDurationS };
  };

  // Pruefung am Rand wie das Backend erwartet (verhindert die 422 vorab): Ziel +
  // Label noetig; SCHEDULED braucht beide Zeiten, IMMEDIATE eine Dauer.
  const eingabeGueltig = () => {
    if (!eingabe.targetId || eingabe.label.trim() === "") {
      return false;
    }
    if (eingabe.operationMode === "scheduled") {
      return (
        lokalZuTs(eingabe.plannedStart) !== null &&
        lokalZuTs(eingabe.plannedEnd) !== null
      );
    }
    // Wiederkehrend (3b): das Tagesfenster muss vollstaendig + sinnvoll sein (von < bis).
    // Wochentage/Zeitraum sind optional (leere Wochentage = alle Tage; leerer Zeitraum =
    // ab sofort/unbegrenzt) -- darum hier nicht erzwungen.
    if (eingabe.operationMode === "recurring") {
      return (
        eingabe.recurStartMinute !== null &&
        eingabe.recurEndMinute !== null &&
        eingabe.recurEndMinute > eingabe.recurStartMinute
      );
    }
    return eingabe.maxDurationS !== null;
  };

  // Anlegen (optional sofort starten). Bei Erfolg Felder zuruecksetzen, Liste neu
  // laden. Fehler (z. B. 422/Netz) -> dezenter Hinweis (kein Absturz).
  const handleAnlegen = async (sofortStarten) => {
    if (!eingabeGueltig()) {
      return;
    }
    try {
      const task = await createLoggingTask(bauePayload());
      if (sofortStarten) {
        try {
          await startLoggingTask(task.id);
        } catch (startFehler) {
          // Anlegen ging, Start kollidiert (z. B. Ziel belegt): den detail-Text
          // zeigen, die Aufgabe bleibt aber angelegt (CREATED).
          setFehler(startFehler?.message ?? t("beobachten.logging.aktionFehler"));
        }
      }
      setEingabe(LEERE_EINGABE);
      setSchritt(1);
      setFehler(null);
      await ladeAufgaben();
    } catch (anlegeFehler) {
      setFehler(anlegeFehler?.message ?? t("beobachten.logging.anlegenFehler"));
    }
  };

  // Player-Aktion auf einer Karte. Ruft die passende API, laedt die Liste neu.
  // Bei 409 (Ziel belegt / falscher Zustand) zeigt der ApiError.message-Text die
  // Backend-detail-Meldung -- freundlich oben anzeigen, kein Absturz.
  const handleAktion = async (aktion, task) => {
    // Detail/Bericht ist reine View-Navigation -- kein API-Aufruf, kein Reload.
    if (aktion === "detail") {
      setDetailTaskId(task.id);
      return;
    }
    try {
      if (aktion === "start") {
        await startLoggingTask(task.id);
      } else if (aktion === "pause") {
        await pauseLoggingTask(task.id);
      } else if (aktion === "resume") {
        await resumeLoggingTask(task.id);
      } else if (aktion === "stop") {
        await stopLoggingTask(task.id);
      } else if (aktion === "delete") {
        await deleteLoggingTask(task.id);
      }
      setFehler(null);
      await ladeAufgaben();
    } catch (aktionFehler) {
      setFehler(aktionFehler?.message ?? t("beobachten.logging.aktionFehler"));
    }
  };

  const gueltig = eingabeGueltig();

  // Detailansicht: ersetzt Maske + Liste, solange eine Task-id gewaehlt ist. Zurueck
  // setzt detailTaskId auf null -> der bestehende Inhalt erscheint wieder. (Der Rest
  // von LoggingPanel bleibt unveraendert.)
  if (detailTaskId !== null) {
    return (
      <div className="logging">
        <LoggingTaskDetail
          taskId={detailTaskId}
          onZurueck={() => setDetailTaskId(null)}
        />
      </div>
    );
  }

  return (
    <div className="logging">
      {fehler && (
        <div className="logging__fehler" role="note">
          {fehler}
        </div>
      )}

      {/* ── Anlage-Maske ─────────────────────────────────────────────────── */}
      <div className="logging__maske">
        <div className="logging__maske-kopf">
          <span className="logging__maske-titel">
            {t("beobachten.logging.neueAufgabe")}
          </span>
          {/* Segment-Control: Anlage-Modus (reine UI). */}
          <div className="logging__segment" role="tablist">
            <button
              type="button"
              role="tab"
              aria-selected={modus === "assistent"}
              className={
                modus === "assistent"
                  ? "logging__segment-knopf logging__segment-knopf--aktiv"
                  : "logging__segment-knopf"
              }
              onClick={() => setModus("assistent")}
            >
              {t("beobachten.logging.modusAssistent")}
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={modus === "erweitert"}
              className={
                modus === "erweitert"
                  ? "logging__segment-knopf logging__segment-knopf--aktiv"
                  : "logging__segment-knopf"
              }
              onClick={() => setModus("erweitert")}
            >
              {t("beobachten.logging.modusErweitert")}
            </button>
          </div>
        </div>

        {modus === "assistent" ? (
          <AssistentMaske
            eingabe={eingabe}
            setFeld={setFeld}
            ziele={ziele}
            schritt={schritt}
            setSchritt={setSchritt}
            gueltig={gueltig}
            onAnlegen={handleAnlegen}
          />
        ) : (
          <ErweitertMaske
            eingabe={eingabe}
            setFeld={setFeld}
            setThresholdFeld={setThresholdFeld}
            ziele={ziele}
            gueltig={gueltig}
            onAnlegen={handleAnlegen}
          />
        )}
      </div>

      {/* ── Aufgaben-Uebersicht + Player ─────────────────────────────────── */}
      <div className="logging__listeTitel">{t("beobachten.logging.listeTitel")}</div>
      {aufgaben.length === 0 ? (
        <p className="logging__leer">{t("beobachten.logging.listeLeer")}</p>
      ) : (
        <div className="logging__liste">
          {aufgaben.map((task) => (
            <AufgabenKarte
              key={task.id}
              task={task}
              jetzt={jetzt}
              sla={slaMap[task.id]}
              onAktion={handleAktion}
            />
          ))}
        </div>
      )}
    </div>
  );
}

// ── Gemeinsame Feld-Bausteine (in beiden Modi genutzt) ───────────────────────

// Ziel-Auswahlliste (Quelle: fetchMonitorStatus). Leere Liste -> Hinweis-Option.
function ZielAuswahl({ eingabe, setFeld, ziele }) {
  const { t } = useTranslation();
  return (
    <label className="logging-feld">
      <span className="logging-feld__label">{t("beobachten.logging.zielLabel")}</span>
      <select
        className="logging-feld__select"
        value={eingabe.targetId}
        onChange={(e) => setFeld("targetId", e.target.value)}
      >
        <option value="" disabled>
          {ziele.length === 0
            ? t("beobachten.logging.zielLeer")
            : t("beobachten.logging.zielPlaceholder")}
        </option>
        {ziele.map((z) => (
          <option key={z.targetId} value={z.targetId}>
            {z.label}
          </option>
        ))}
      </select>
    </label>
  );
}

// Betriebsart-Felder (Sofort: Dauer-Auswahl; Geplant: Start/Ende). In beiden Modi
// gleich (nur der Container-Stil unterscheidet sich uebers CSS der Eltern).
function BetriebFelder({ eingabe, setFeld }) {
  const { t } = useTranslation();
  return (
    <>
      <div className="logging-feld">
        <span className="logging-feld__label">{t("beobachten.logging.betriebLabel")}</span>
        <div className="logging__radiozeile">
          <label className="logging__radio">
            <input
              type="radio"
              name="betrieb"
              checked={eingabe.operationMode === "immediate"}
              onChange={() => setFeld("operationMode", "immediate")}
            />
            {t("beobachten.logging.betriebSofort")}
          </label>
          <label className="logging__radio">
            <input
              type="radio"
              name="betrieb"
              checked={eingabe.operationMode === "scheduled"}
              onChange={() => setFeld("operationMode", "scheduled")}
            />
            {t("beobachten.logging.betriebGeplant")}
          </label>
          <label className="logging__radio">
            <input
              type="radio"
              name="betrieb"
              checked={eingabe.operationMode === "recurring"}
              onChange={() => setFeld("operationMode", "recurring")}
            />
            {t("beobachten.logging.betriebWiederkehrend")}
          </label>
        </div>
      </div>

      {eingabe.operationMode === "recurring" ? (
        <WiederkehrendFelder eingabe={eingabe} setFeld={setFeld} />
      ) : eingabe.operationMode === "immediate" ? (
        <label className="logging-feld">
          <span className="logging-feld__label">{t("beobachten.logging.dauerLabel")}</span>
          <select
            className="logging-feld__select"
            value={eingabe.maxDurationS}
            onChange={(e) => setFeld("maxDurationS", Number(e.target.value))}
          >
            {DAUER_OPTIONEN.map((d) => (
              <option key={d.key} value={d.sekunden}>
                {t(`beobachten.logging.dauer.${d.key}`)}
              </option>
            ))}
          </select>
        </label>
      ) : (
        <div className="logging__zeitzeile">
          <label className="logging-feld">
            <span className="logging-feld__label">{t("beobachten.logging.startLabel")}</span>
            <input
              type="datetime-local"
              className="logging-feld__input"
              value={eingabe.plannedStart}
              onChange={(e) => setFeld("plannedStart", e.target.value)}
            />
          </label>
          <label className="logging-feld">
            <span className="logging-feld__label">{t("beobachten.logging.endeLabel")}</span>
            <input
              type="datetime-local"
              className="logging-feld__input"
              value={eingabe.plannedEnd}
              onChange={(e) => setFeld("plannedEnd", e.target.value)}
            />
          </label>
        </div>
      )}
    </>
  );
}

// Wochentage in Anzeige-Reihenfolge (Mo..So) -- die Werte sind das Backend-Schema 0..6
// (0=Mo). Verbindliche Reihenfolge der Chips.
const WOCHENTAGE = [0, 1, 2, 3, 4, 5, 6];

// Wiederkehrend-Felder (3b) -- nur bei operationMode "recurring" gerendert (in derselben
// Zeile/Gruppe wie Start/Ende bei "geplant"). Drei Bloecke: Tagesfenster (zwei HH:MM-
// Eingaben -> intern Minuten seit Mitternacht, von < bis), Wochentage (sieben umschaltbare
// Chips Mo..So) und Zeitraum (zwei Datums-Eingaben -> Unix-ts; bis optional = unbegrenzt).
// Plus eine Vorschau-Zeile "Ergibt N Messlaeufe" (defensiv, kein Absturz bei leeren Feldern).
function WiederkehrendFelder({ eingabe, setFeld }) {
  const { t } = useTranslation();

  // Einen Wochentag umschalten (Array bleibt sortiert fuer eine stabile Anzeige/Payload).
  const toggleWochentag = (tag) => {
    const aktiv = eingabe.recurWeekdays.includes(tag);
    const neu = aktiv
      ? eingabe.recurWeekdays.filter((w) => w !== tag)
      : [...eingabe.recurWeekdays, tag].sort((a, b) => a - b);
    setFeld("recurWeekdays", neu);
  };

  // Vorschau: N Messlaeufe im Zeitraum auf den gewaehlten Wochentagen. Leeres bis-Datum ->
  // "laeuft bis auf Weiteres" (kein N). Sonst die Frontend-Rechnung (null -> nichts zeigen).
  const vonTs = datumZuTs(eingabe.recurFrom);
  const bisTs = datumZuTs(eingabe.recurUntil);
  const unbegrenzt = eingabe.recurUntil === "";
  const anzahl = unbegrenzt ? null : zaehleMesslaeufe(vonTs, bisTs, eingabe.recurWeekdays);

  return (
    <>
      <div className="logging-feld">
        <span className="logging-feld__label">
          {t("beobachten.logging.recurTagesfensterLabel")}
        </span>
        <div className="logging__zeitzeile logging__zeitzeile--kompakt">
          <label className="logging-feld logging-feld--inline">
            <span className="logging-feld__sublabel">{t("beobachten.logging.recurVon")}</span>
            <input
              type="time"
              className="logging-feld__input"
              value={minutenZuHhmm(eingabe.recurStartMinute)}
              onChange={(e) => setFeld("recurStartMinute", hhmmZuMinuten(e.target.value))}
            />
          </label>
          <label className="logging-feld logging-feld--inline">
            <span className="logging-feld__sublabel">{t("beobachten.logging.recurBis")}</span>
            <input
              type="time"
              className="logging-feld__input"
              value={minutenZuHhmm(eingabe.recurEndMinute)}
              onChange={(e) => setFeld("recurEndMinute", hhmmZuMinuten(e.target.value))}
            />
          </label>
        </div>
      </div>

      <div className="logging-feld">
        <span className="logging-feld__label">
          {t("beobachten.logging.recurWochentageLabel")}
        </span>
        <div className="logging__wochentage">
          {WOCHENTAGE.map((tag) => {
            const aktiv = eingabe.recurWeekdays.includes(tag);
            return (
              <button
                key={tag}
                type="button"
                className={
                  aktiv
                    ? "logging-chip logging-chip--aktiv"
                    : "logging-chip"
                }
                aria-pressed={aktiv}
                onClick={() => toggleWochentag(tag)}
              >
                {t(`beobachten.logging.recurWochentag.${tag}`)}
              </button>
            );
          })}
        </div>
      </div>

      <div className="logging-feld">
        <span className="logging-feld__label">
          {t("beobachten.logging.recurZeitraumLabel")}
        </span>
        <div className="logging__zeitzeile logging__zeitzeile--kompakt">
          <label className="logging-feld logging-feld--inline">
            <span className="logging-feld__sublabel">
              {t("beobachten.logging.recurZeitraumVon")}
            </span>
            <input
              type="date"
              className="logging-feld__input"
              value={eingabe.recurFrom}
              onChange={(e) => setFeld("recurFrom", e.target.value)}
            />
          </label>
          <label className="logging-feld logging-feld--inline">
            <span className="logging-feld__sublabel">
              {t("beobachten.logging.recurZeitraumBis")}
            </span>
            <input
              type="date"
              className="logging-feld__input"
              value={eingabe.recurUntil}
              onChange={(e) => setFeld("recurUntil", e.target.value)}
            />
          </label>
        </div>
      </div>

      <div className="logging__vorschau" role="note">
        {unbegrenzt
          ? t("beobachten.logging.recurVorschauUnbegrenzt")
          : anzahl !== null
            ? t("beobachten.logging.recurVorschau", { n: anzahl })
            : null}
      </div>
    </>
  );
}

// Abschluss-Knoepfe (Anlegen / Anlegen & starten). In beiden Modi identisch.
function AbschlussKnoepfe({ gueltig, onAnlegen, recurring = false }) {
  const { t } = useTranslation();
  // Bei "recurring" (3b) heisst der Haupt-Aktionsknopf "Planen" und legt den Task an +
  // startet ihn anschliessend (derselbe create->start-Pfad wie "Anlegen & starten", damit
  // der Task ACTIVE/scharf ist). Der sekundaere "Anlegen"-Knopf entfaellt dann (ein blosses
  // CREATED ohne Start ergibt fuer eine geplante Wiederkehr keinen Sinn). Bei sofort/geplant
  // bleiben beide Knoepfe unveraendert.
  if (recurring) {
    return (
      <div className="logging__abschluss">
        <button
          type="button"
          className="logging__knopf logging__knopf--primaer"
          disabled={!gueltig}
          onClick={() => onAnlegen(true)}
        >
          <Plus size={15} />
          {t("beobachten.logging.planen")}
        </button>
      </div>
    );
  }
  return (
    <div className="logging__abschluss">
      <button
        type="button"
        className="logging__knopf logging__knopf--sekundaer"
        disabled={!gueltig}
        onClick={() => onAnlegen(false)}
      >
        {t("beobachten.logging.anlegen")}
      </button>
      <button
        type="button"
        className="logging__knopf logging__knopf--primaer"
        disabled={!gueltig}
        onClick={() => onAnlegen(true)}
      >
        <Plus size={15} />
        {t("beobachten.logging.anlegenStarten")}
      </button>
    </div>
  );
}

// ── Assistent: drei gefuehrte Schritte mit Fortschrittsbalken ───────────────
function AssistentMaske({
  eingabe,
  setFeld,
  ziele,
  schritt,
  setSchritt,
  gueltig,
  onAnlegen,
}) {
  const { t } = useTranslation();
  const GESAMT = 3;

  // Schritt 1 ist erst weiter-bar mit Ziel + Label; Schritt 2 immer (Default
  // gesetzt). Schritt 3 schliesst ab (Knoepfe statt "Weiter").
  const schritt1Ok = eingabe.targetId !== "" && eingabe.label.trim() !== "";

  return (
    <div className="logging-assistent">
      <div className="logging-assistent__fortschritt" aria-hidden="true">
        <div
          className="logging-assistent__fortschritt-fill"
          style={{ width: `${(schritt / GESAMT) * 100}%` }}
        />
      </div>
      <div className="logging-assistent__schritt-info">
        {t("beobachten.logging.schrittVon", { aktuell: schritt, gesamt: GESAMT })}
      </div>

      {schritt === 1 && (
        <div className="logging-assistent__feldgruppe">
          <span className="logging-assistent__titel">
            {t("beobachten.logging.schritt1Titel")}
          </span>
          <ZielAuswahl eingabe={eingabe} setFeld={setFeld} ziele={ziele} />
          <label className="logging-feld">
            <span className="logging-feld__label">
              {t("beobachten.logging.bezeichnungLabel")}
            </span>
            <input
              type="text"
              className="logging-feld__input"
              value={eingabe.label}
              placeholder={t("beobachten.logging.bezeichnungPlaceholder")}
              onChange={(e) => setFeld("label", e.target.value)}
            />
          </label>
          <label className="logging-feld">
            <span className="logging-feld__label">
              {t("beobachten.logging.zweckLabel")}
            </span>
            <input
              type="text"
              className="logging-feld__input"
              value={eingabe.purpose}
              placeholder={t("beobachten.logging.zweckPlaceholder")}
              onChange={(e) => setFeld("purpose", e.target.value)}
            />
          </label>
        </div>
      )}

      {schritt === 2 && (
        <div className="logging-assistent__feldgruppe">
          <span className="logging-assistent__titel">
            {t("beobachten.logging.schritt2Titel")}
          </span>
          <div className="logging__kacheln">
            {CAPTURE_MODI.map((m) => {
              const aktiv = eingabe.captureMode === m;
              return (
                <button
                  key={m}
                  type="button"
                  className={
                    aktiv
                      ? "logging-kachel logging-kachel--aktiv"
                      : "logging-kachel"
                  }
                  aria-pressed={aktiv}
                  onClick={() => setFeld("captureMode", m)}
                >
                  <span className="logging-kachel__titel">
                    {t(`beobachten.logging.capture.${m}.titel`)}
                  </span>
                  <span className="logging-kachel__text">
                    {t(`beobachten.logging.capture.${m}.text`)}
                  </span>
                  {m === "reachability_latency" && (
                    <span className="logging-kachel__menge">
                      {t("beobachten.logging.capture.reachability_latency.mengeHinweis")}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        </div>
      )}

      {schritt === 3 && (
        <div className="logging-assistent__feldgruppe">
          <span className="logging-assistent__titel">
            {t("beobachten.logging.schritt3Titel")}
          </span>
          <BetriebFelder eingabe={eingabe} setFeld={setFeld} />
        </div>
      )}

      {/* Navigation: Zurueck links, Weiter/Abschluss rechts. */}
      <div className="logging-assistent__nav">
        <button
          type="button"
          className="logging__knopf logging__knopf--sekundaer"
          disabled={schritt === 1}
          onClick={() => setSchritt((s) => Math.max(1, s - 1))}
        >
          {t("beobachten.logging.zurueck")}
        </button>
        {schritt < GESAMT ? (
          <button
            type="button"
            className="logging__knopf logging__knopf--primaer"
            disabled={schritt === 1 && !schritt1Ok}
            onClick={() => setSchritt((s) => Math.min(GESAMT, s + 1))}
          >
            {t("beobachten.logging.weiter")}
          </button>
        ) : (
          <AbschlussKnoepfe
            gueltig={gueltig}
            onAnlegen={onAnlegen}
            recurring={eingabe.operationMode === "recurring"}
          />
        )}
      </div>
    </div>
  );
}

// ── Erweitert: dieselben Felder kompakt auf EINEM Schirm ────────────────────
function ErweitertMaske({ eingabe, setFeld, setThresholdFeld, ziele, gueltig, onAnlegen }) {
  const { t } = useTranslation();
  return (
    <div className="logging-erweitert">
      <div className="logging-erweitert__raster">
        <ZielAuswahl eingabe={eingabe} setFeld={setFeld} ziele={ziele} />
        <label className="logging-feld">
          <span className="logging-feld__label">
            {t("beobachten.logging.bezeichnungLabel")}
          </span>
          <input
            type="text"
            className="logging-feld__input"
            value={eingabe.label}
            placeholder={t("beobachten.logging.bezeichnungPlaceholder")}
            onChange={(e) => setFeld("label", e.target.value)}
          />
        </label>
        <label className="logging-feld">
          <span className="logging-feld__label">{t("beobachten.logging.zweckLabel")}</span>
          <input
            type="text"
            className="logging-feld__input"
            value={eingabe.purpose}
            placeholder={t("beobachten.logging.zweckPlaceholder")}
            onChange={(e) => setFeld("purpose", e.target.value)}
          />
        </label>
        <label className="logging-feld">
          <span className="logging-feld__label">{t("beobachten.logging.captureLabel")}</span>
          <select
            className="logging-feld__select"
            value={eingabe.captureMode}
            onChange={(e) => setFeld("captureMode", e.target.value)}
          >
            {CAPTURE_MODI.map((m) => (
              <option key={m} value={m}>
                {t(`beobachten.logging.captureKurz.${m}`)}
              </option>
            ))}
          </select>
        </label>
        <BetriebFelder eingabe={eingabe} setFeld={setFeld} />
        <IntervallFeld eingabe={eingabe} setFeld={setFeld} />
      </div>
      <SchwellwertFeld eingabe={eingabe} setThresholdFeld={setThresholdFeld} />
      <AbschlussKnoepfe
        gueltig={gueltig}
        onAnlegen={onAnlegen}
        recurring={eingabe.operationMode === "recurring"}
      />
    </div>
  );
}

// Mess-Intervall-Feld (C-2) -- NUR im Erweitert-Modus gerendert (der Assistent zeigt
// es nicht, nutzt still den Default 5 s). Dropdown ueber die erlaubten Stufen; der
// Wert ist die Sekundenzahl (deckt sich mit den Backend-Stufen). Fachlich relevant ist
// es fuer "Erreichbarkeit + Latenz" (nur dieser Modus erzeugt dichte RTT-Punkte) --
// darum ein dezenter Hinweis, kein Verstecken (das Feld bleibt fuer alle Modi bedienbar,
// der Backend-Sink duennt ohnehin nur reachability_latency aus).
function IntervallFeld({ eingabe, setFeld }) {
  const { t } = useTranslation();
  return (
    <label className="logging-feld">
      <span className="logging-feld__label">{t("beobachten.logging.intervallLabel")}</span>
      <select
        className="logging-feld__select"
        value={eingabe.intervalS}
        onChange={(e) => setFeld("intervalS", Number(e.target.value))}
      >
        {INTERVALL_OPTIONEN.map((o) => (
          <option key={o.key} value={o.sekunden}>
            {t(`beobachten.logging.intervall.${o.key}`)}
          </option>
        ))}
      </select>
      {eingabe.captureMode === "reachability_latency" && (
        <span className="logging-feld__hinweis">
          {t("beobachten.logging.intervallHinweis")}
        </span>
      )}
    </label>
  );
}

// Schwellwert-Alarm-Feld (Schnitt 5) -- NUR im Erweitert-Modus gerendert (der Assistent
// zeigt es nicht: "Erweitert kann mehr"). Ein An/Aus-Schalter blendet die Detailfelder
// ein. Bei "unreachable" entfaellt der Grenzwert (spielt fachlich keine Rolle). Schreibt
// ueber setThresholdFeld tief in eingabe.threshold; das aktiv-Flag ist reine UI (nur
// bauePayload entscheidet, ob ueberhaupt ein threshold gesendet wird).
function SchwellwertFeld({ eingabe, setThresholdFeld }) {
  const { t } = useTranslation();
  const thr = eingabe.threshold;
  return (
    <div className="logging-schwellwert">
      <label className="logging-schwellwert__schalter">
        <input
          type="checkbox"
          checked={thr.aktiv}
          onChange={(e) => setThresholdFeld("aktiv", e.target.checked)}
        />
        <span className="logging-schwellwert__schalter-label">
          {t("beobachten.logging.schwellwertLabel")}
        </span>
      </label>
      <span className="logging-feld__hinweis">
        {t("beobachten.logging.schwellwertHinweis")}
      </span>

      {thr.aktiv && (
        <div className="logging-schwellwert__felder">
          <label className="logging-feld">
            <span className="logging-feld__label">
              {t("beobachten.logging.schwellwertBedingungLabel")}
            </span>
            <select
              className="logging-feld__select"
              value={thr.condition}
              onChange={(e) => setThresholdFeld("condition", e.target.value)}
            >
              <option value="latency_above">
                {t("beobachten.logging.schwellwertBedingung.latency_above")}
              </option>
              <option value="unreachable">
                {t("beobachten.logging.schwellwertBedingung.unreachable")}
              </option>
            </select>
          </label>

          {/* Grenzwert nur bei "latency_above" -- bei "unreachable" ohne Bedeutung. */}
          {thr.condition === "latency_above" && (
            <label className="logging-feld">
              <span className="logging-feld__label">
                {t("beobachten.logging.schwellwertGrenzwertLabel")}
              </span>
              <input
                type="number"
                min="0"
                className="logging-feld__input"
                value={thr.limitMs}
                onChange={(e) => setThresholdFeld("limitMs", Number(e.target.value))}
              />
            </label>
          )}

          <label className="logging-feld">
            <span className="logging-feld__label">
              {t("beobachten.logging.schwellwertEmpfindlichkeitLabel")}
            </span>
            <input
              type="number"
              min="1"
              className="logging-feld__input"
              value={thr.consecutiveN}
              onChange={(e) => setThresholdFeld("consecutiveN", Number(e.target.value))}
            />
            <span className="logging-feld__hinweis">
              {t("beobachten.logging.schwellwertEmpfindlichkeitHinweis")}
            </span>
          </label>

          <div className="logging-schwellwert__benachrichtigung">
            <label className="logging__radio">
              <input
                type="checkbox"
                checked={thr.notifyDesktop}
                onChange={(e) => setThresholdFeld("notifyDesktop", e.target.checked)}
              />
              {t("beobachten.logging.schwellwertDesktop")}
            </label>
            <label className="logging__radio">
              <input
                type="checkbox"
                checked={thr.notifyEmail}
                onChange={(e) => setThresholdFeld("notifyEmail", e.target.checked)}
              />
              {t("beobachten.logging.schwellwertEmail")}
            </label>
          </div>
        </div>
      )}
    </div>
  );
}
