// Aussenkontakte-Aufzeichnung: Leiste + aufklappbare Verwaltung (CERNIS PRO 2.0)
//
// Integriert in die Aussenkontakte-Ansicht (OutboundView), KEINE eigene
// Beobachten-Kachel mehr. Aufbau (Variante 2 "Aufzeichnungs-Leiste"):
//   (LEISTE) immer sichtbar, ueber der OutboundView-Steuerleiste.
//     - RUHE (keine active): neutrale Leiste, Text + Knopf "Aufzeichnungen".
//     - AKTIV (eine active): dieselbe Leiste GELB (Warnton-Tokens --sev-med-*,
//       analog zur roten LivePill ueber --sev-high-*), zeigt "Aufzeichnung
//       laeuft -- <label>" + Pause/Stopp + den "Aufzeichnungen"-Knopf.
//   (VERWALTUNG) ueber den "Aufzeichnungen"-Knopf auf-/zuklappbar (Default ZU):
//     (A) ANLEGEN (Karte, einklappbar): Bezeichnung/Zweck, Modus (detail/
//         aggregate) + Tiefe (anonymous/app_resolved) als Segmented Control mit je
//         einem ruhigen Hinweis-Fliesstext, Intervall-Wahl NUR bei detail.
//     (B) AUFZEICHNUNGS-LISTE: je Recording eine Karte mit Modus-/Tiefe-Badges,
//         Zustands-Pille und zustandsabhaengigen Player-Knoepfen. Loeschen ueber
//         einen Inline-Zweistufen-Knopf (KEIN window.confirm). Bei start/resume
//         mit 409 ein RUHIGER Konflikt-Hinweis ueber der Liste.
//
// Die BEFUND-Ansicht (aggregate/detail) kommt in E5b -- hier nur ein selectedId-
// State + Platzhalter-Sektion. Muster bewusst wie LoggingPanel.jsx (useState/
// useEffect, useTranslation, KEIN t/i18n im State-setzenden useEffect-Dep-Array --
// Render-Loop-Falle). Alle Texte ueber i18n, alle Farben ueber Tokens.

import { CircleDot, Pause, Play, Square, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import {
  createRecording,
  deleteRecording,
  fetchRecordings,
  pauseRecording,
  resumeRecording,
  startRecording,
  stopRecording,
} from "../api/outboundLog.js";
import "./OutboundRecordingPanel.css";

// Waehlbare Mess-Intervall-Stufen (nur bei mode==detail): i18n-Schluessel ->
// Sekunden. Muss mit den Backend-Stufen {30,60,300} uebereinstimmen. Default 60.
const INTERVALL_OPTIONEN = [
  { key: "30s", sekunden: 30 },
  { key: "60s", sekunden: 60 },
  { key: "300s", sekunden: 300 },
];

// Feste Dauer-Stufen (nur bei mode==detail): i18n-Schluessel -> Stunden. Default
// 24 h (deckt sich mit dem Backend-Default 86400 s und der harten 24h-Deckelung).
const DAUER_STUFEN = [
  { key: "1h", stunden: 1 },
  { key: "6h", stunden: 6 },
  { key: "12h", stunden: 12 },
  { key: "24h", stunden: 24 },
];

// Erlaubter Stunden-Bereich der Dauer-Wahl (Backend deckelt detail hart auf 24 h).
// Ganzzahlige Stunden -- keine Minuten/Dezimalstellen (bewusst klar gehalten).
const DAUER_MIN_STUNDEN = 1;
const DAUER_MAX_STUNDEN = 24;

// Die leere Anlage-Eingabe. Default-Modus detail, Default-Tiefe anonymous,
// Default-Intervall 60 s (deckt sich mit dem Backend-Default). purpose leer.
// Dauer: Default-Stufe 24 h (durationModus "stufe"). Bei "custom" traegt
// durationCustom den freien Stunden-Wert (als String, damit das Zahlenfeld auch
// leer/ungueltig sein darf -- erst beim Anlegen validiert).
const LEERE_EINGABE = {
  label: "",
  purpose: "",
  mode: "detail",
  depth: "anonymous",
  intervalS: 60,
  durationModus: "stufe",
  durationStunden: 24,
  durationCustom: "",
};

// CSS-Modifier-Klasse des Zustands-Pills je Backend-Zustand (active gruen /
// paused lila / created grau / finished gedaempft). Unbekannte Zustaende ->
// gedaempft (kein Absturz). Muster pillKlasse aus LoggingPanel.
function pillKlasse(state) {
  switch (state) {
    case "active":
      return "outboundlog-pill outboundlog-pill--aktiv";
    case "paused":
      return "outboundlog-pill outboundlog-pill--pausiert";
    case "created":
      return "outboundlog-pill outboundlog-pill--angelegt";
    default:
      return "outboundlog-pill outboundlog-pill--beendet";
  }
}

// Unix-Sekunden (float) -> lokale, gut lesbare Datum-Zeit-Zeichenkette. Kein
// projektweiter Helfer vorhanden (jede Komponente formatiert lokal mit
// toLocaleString -- Muster LoggingTaskDetail/SecurityReportView), darum hier ein
// kleiner lokaler Helfer im selben Stil. Bei null/ungueltig -> null (S3-ehrlich,
// die "Erstellt am"-Zeile entfaellt dann ganz). createdAt ist in SEKUNDEN -> *1000.
function formatiereZeitpunkt(unixSekunden, sprache) {
  if (unixSekunden === null || unixSekunden === undefined) {
    return null;
  }
  const datum = new Date(unixSekunden * 1000);
  if (Number.isNaN(datum.getTime())) {
    return null;
  }
  return datum.toLocaleString(sprache);
}

// Ein Player-Knopf je Karte. Ruft onClick; Icon + Label uebergeben. Muster
// PlayerKnopf aus LoggingPanel.
function PlayerKnopf({ icon: Icon, label, onClick, variante }) {
  return (
    <button
      type="button"
      className={`outboundlog-player__knopf outboundlog-player__knopf--${variante}`}
      onClick={onClick}
      title={label}
      aria-label={label}
    >
      <Icon size={14} />
      <span>{label}</span>
    </button>
  );
}

// Eine Aufzeichnungs-Karte: Bezeichnung, Modus-/Tiefe-Badges, Zustands-Pille, bei
// aktiven Detail-Aufzeichnungen der 24h-Hinweis, plus die zustandsabhaengigen
// Player-Knoepfe. Loeschen ueber einen Inline-Zweistufen-Knopf (loeschBereit:
// erster Klick fragt, zweiter loescht; ein Klick daneben bricht ab -- onAbbruch).
function AufzeichnungsKarte({
  recording,
  ausgewaehlt,
  loeschBereit,
  onWaehlen,
  onAktion,
  onLoeschBereit,
  onLoeschAbbruch,
}) {
  const { t, i18n } = useTranslation();

  const zustandText = t(`beobachten.outboundlog.state.${recording.state}`, {
    defaultValue: recording.state,
  });
  const modusText = t(`beobachten.outboundlog.modus.${recording.mode}`, {
    defaultValue: recording.mode,
  });
  const tiefeKey = recording.depth === "app_resolved" ? "appResolved" : "anonymous";
  const tiefeText = t(`beobachten.outboundlog.tiefe.${tiefeKey}`, {
    defaultValue: recording.depth,
  });

  // 24h-Hinweis NUR bei aktiver Detail-Aufzeichnung (aggregate ist zeitlich
  // unbegrenzt). Statischer Hinweis -- die Restzeit-Berechnung kommt in E5b.
  const zeigt24hHinweis = recording.mode === "detail" && recording.state === "active";

  // "Erstellt am"-Zeitpunkt (lokal formatiert). Bei fehlendem createdAt -> null,
  // die Zeile entfaellt dann ganz (kein erfundenes "unbekannt").
  const erstelltText = formatiereZeitpunkt(recording.createdAt, i18n.language);

  // Aufzeichnungs-Dauer als ruhige Zusatzinfo NUR bei detail-Karten mit gesetztem
  // maxDurationS (aggregate traegt null -> weglassen). maxDurationS in Sekunden ->
  // ganze Stunden.
  const dauerStunden =
    recording.mode === "detail" && recording.maxDurationS !== null
      ? Math.round(recording.maxDurationS / 3600)
      : null;

  return (
    <div
      className={
        ausgewaehlt
          ? "outboundlog-karte outboundlog-karte--ausgewaehlt"
          : "outboundlog-karte"
      }
      onClick={() => onWaehlen(recording.id)}
    >
      <div className="outboundlog-karte__kopf">
        <span className={pillKlasse(recording.state)}>
          {recording.state === "active" && (
            <span className="outboundlog-pill__punkt" aria-hidden="true" />
          )}
          {zustandText}
        </span>
        <span className="outboundlog-karte__label">{recording.label}</span>
      </div>

      <div className="outboundlog-karte__meta">
        <span className="outboundlog-badge outboundlog-badge--modus">{modusText}</span>
        <span className="outboundlog-badge outboundlog-badge--tiefe">{tiefeText}</span>
        {dauerStunden !== null && (
          <span className="outboundlog-karte__dauer">
            {t("beobachten.outboundlog.dauerKarte", { stunden: dauerStunden })}
          </span>
        )}
        {recording.purpose && (
          <span className="outboundlog-karte__zweck">{recording.purpose}</span>
        )}
      </div>

      {/* "Erstellt am"-Zeile: dezent, gedaempft. Entfaellt ganz, wenn createdAt
          fehlt (kein erfundenes "unbekannt"). */}
      {erstelltText !== null && (
        <div className="outboundlog-karte__erstellt">
          {t("beobachten.outboundlog.erstelltAm", { datum: erstelltText })}
        </div>
      )}

      {zeigt24hHinweis && (
        <div className="outboundlog-karte__detailhinweis" role="note">
          {t("beobachten.outboundlog.detailHinweis")}
        </div>
      )}

      {/* Player-Knoepfe. stopPropagation, damit ein Knopf-Klick die Karte nicht
          zugleich aus-/abwaehlt. created->Start; active->Pause+Stop; paused->
          Fortsetzen+Stop; finished->nur Loeschen. Loeschen ist immer verfuegbar
          (Inline-Zweistufen statt window.confirm). */}
      <div className="outboundlog-player" onClick={(e) => e.stopPropagation()}>
        {recording.state === "created" && (
          <PlayerKnopf
            icon={Play}
            label={t("beobachten.outboundlog.aktion.start")}
            variante="start"
            onClick={() => onAktion("start", recording)}
          />
        )}
        {recording.state === "active" && (
          <>
            <PlayerKnopf
              icon={Pause}
              label={t("beobachten.outboundlog.aktion.pause")}
              variante="pause"
              onClick={() => onAktion("pause", recording)}
            />
            <PlayerKnopf
              icon={Square}
              label={t("beobachten.outboundlog.aktion.stop")}
              variante="stop"
              onClick={() => onAktion("stop", recording)}
            />
          </>
        )}
        {recording.state === "paused" && (
          <>
            <PlayerKnopf
              icon={Play}
              label={t("beobachten.outboundlog.aktion.resume")}
              variante="start"
              onClick={() => onAktion("resume", recording)}
            />
            <PlayerKnopf
              icon={Square}
              label={t("beobachten.outboundlog.aktion.stop")}
              variante="stop"
              onClick={() => onAktion("stop", recording)}
            />
          </>
        )}

        {/* Loeschen-Zweistufer: ungefragt nur "Loeschen"; nach dem ersten Klick
            zwei Knoepfe (Bestaetigen / Abbrechen). Kein window.confirm. */}
        {loeschBereit ? (
          <div className="outboundlog-loeschen">
            <span className="outboundlog-loeschen__frage">
              {t("beobachten.outboundlog.aktion.loeschenFrage")}
            </span>
            <button
              type="button"
              className="outboundlog-player__knopf outboundlog-player__knopf--delete"
              onClick={() => onAktion("delete", recording)}
            >
              {t("beobachten.outboundlog.aktion.loeschenBestaetigen")}
            </button>
            <button
              type="button"
              className="outboundlog-player__knopf outboundlog-player__knopf--abbrechen"
              onClick={() => onLoeschAbbruch()}
            >
              {t("beobachten.outboundlog.aktion.loeschenAbbrechen")}
            </button>
          </div>
        ) : (
          <PlayerKnopf
            icon={Trash2}
            label={t("beobachten.outboundlog.aktion.loeschen")}
            variante="delete"
            onClick={() => onLoeschBereit(recording.id)}
          />
        )}
      </div>
    </div>
  );
}

// Die integrierte Aufzeichnungs-Komponente: schlanke Leiste (Ruhe/Aktiv) plus
// aufklappbare Verwaltung (Anlegen + Liste). Wird von OutboundView ueber der
// Live-Liste eingebunden. Datenquelle bleibt api/outboundLog.js.
// onAktivCount(anzahl): optionaler Callback, ueber den die Komponente die Anzahl
// host-weit gerade laufender Aufzeichnungen (state==="active") nach oben meldet --
// OutboundView nutzt das fuer den ruhigen Banner-Hinweis, OHNE einen zweiten
// Voll-Poll. Default ein No-Op, damit die Komponente eigenstaendig bleibt.
export default function OutboundRecordingPanel({ onAktivCount = () => {} }) {
  const { t } = useTranslation();

  // Angelegte Aufzeichnungen (aus fetchRecordings), gemappt.
  const [recordings, setRecordings] = useState([]);
  // Gemeinsame Eingabefelder der Anlage-Maske.
  const [eingabe, setEingabe] = useState(LEERE_EINGABE);
  // Ob die Anlage-Karte aufgeklappt ist (Muster einklappbarer Panels).
  const [anlegenOffen, setAnlegenOffen] = useState(true);
  // Ob der aufklappbare Verwaltungs-Bereich (Anlegen + Liste) offen ist. Default
  // ZU: im Ruhezustand zeigt die Leiste nur den "Aufzeichnungen"-Knopf.
  const [verwaltungOffen, setVerwaltungOffen] = useState(false);
  // Dezenter Fehlerhinweis (Anlage/Aktion/Laden) oder null.
  const [fehler, setFehler] = useState(null);
  // Ruhiger Konflikt-Hinweis (start/resume mit 409) oder false. Getrennt vom
  // normalen Fehler: kein roter Banner, sondern ein ruhiger Hinweis ueber der Liste.
  const [konflikt, setKonflikt] = useState(false);
  // Gewaehlte Karte (Klick) -- die BEFUND-Ansicht dazu kommt in E5b. Hier nur der
  // State + eine Platzhalter-Sektion.
  const [selectedId, setSelectedId] = useState(null);
  // id der Karte, deren Loeschen gerade nachgefragt wird (Inline-Zweistufer), oder null.
  const [loeschId, setLoeschId] = useState(null);

  // Ein Feld der Eingabe setzen (immutabel).
  const setFeld = (feld, wert) => setEingabe((v) => ({ ...v, [feld]: wert }));

  // Liste laden. Fehler -> dezenter Lade-Hinweis (kein Absturz). abgebrochen
  // schuetzt vor setState nach Unmount.
  const ladeRecordings = async (abgebrochen = false) => {
    try {
      const liste = await fetchRecordings();
      if (!abgebrochen) {
        setRecordings(liste);
      }
    } catch {
      if (!abgebrochen) {
        setFehler(t("beobachten.outboundlog.ladeFehler"));
      }
    }
  };

  // Beim Mount die vorhandenen Aufzeichnungen laden. KEIN t im Dep-Array
  // (Render-Loop-Falle) -- die Mount-Logik laeuft genau einmal.
  useEffect(() => {
    let abgebrochen = false;
    ladeRecordings(abgebrochen);
    return () => {
      abgebrochen = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Effektive Dauer-Stunden je nach durationModus: feste Stufe -> durationStunden,
  // custom -> der freie Wert (durationCustom als getrimmter String). Nur bei detail
  // relevant. Bei aggregate gibt es kein Dauer-Feld (Sammlung zeitlich unbegrenzt).
  const customRoh = eingabe.durationCustom.trim();
  const customStunden =
    customRoh === "" || !/^\d+$/.test(customRoh) ? NaN : Number.parseInt(customRoh, 10);
  const dauerStunden =
    eingabe.durationModus === "custom" ? customStunden : eingabe.durationStunden;

  // Die Dauer-Wahl ist nur im custom-Modus ueberhaupt fehleranfaellig (die festen
  // Stufen sind per Konstruktion gueltig). Gueltig sind ganze Stunden im Bereich
  // DAUER_MIN_STUNDEN..DAUER_MAX_STUNDEN. Bei aggregate ist die Dauer irrelevant.
  const dauerGueltig =
    eingabe.mode !== "detail" ||
    (Number.isInteger(dauerStunden) &&
      dauerStunden >= DAUER_MIN_STUNDEN &&
      dauerStunden <= DAUER_MAX_STUNDEN);

  // Anzahl host-weit gerade laufender Aufzeichnungen (state==="active"). Backend
  // erlaubt hoechstens EINE -- die Zahl bleibt also 0 oder 1; als count gehalten,
  // damit OutboundView sauber pluralisieren kann.
  const aktivAnzahl = recordings.filter((r) => r.state === "active").length;

  // Die aktive Anzahl nach oben melden, sobald sie sich aendert. KEIN onAktivCount
  // im Dep-Array (waere bei jedem Render eine neue Funktion -> Render-Loop); nur
  // aktivAnzahl. onAktivCount ist stabil genug fuer diesen Zweck.
  useEffect(() => {
    onAktivCount(aktivAnzahl);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [aktivAnzahl]);

  // Clientseitige Mindest-Pruefung: label nicht leer UND (falls custom-Dauer) gueltig.
  const eingabeGueltig = eingabe.label.trim() !== "" && dauerGueltig;

  // Host-weit hoechstens EINE active -- die aus recordings mit state==="active".
  // Treibt den Leisten-Zustand (Ruhe vs. Aktiv) und die Pause/Stopp-Knoepfe.
  const aktiveAufzeichnung = recordings.find((r) => r.state === "active") ?? null;

  // Anlegen. Bei mode==detail KEIN max_duration_s senden (Backend defaultet auf
  // 86400/24h); das Intervall wird NUR bei detail mitgegeben (bei aggregate weniger
  // kritisch -- der Backend-Default 60 greift). purpose nur senden, wenn gesetzt.
  // Nach Erfolg: Formular zuruecksetzen + Liste neu laden. Fehler (z. B. 422/Netz)
  // -> dezenter Hinweis (kein Absturz).
  const handleAnlegen = async () => {
    if (!eingabeGueltig) {
      return;
    }
    const purpose = eingabe.purpose.trim();
    const payload = {
      label: eingabe.label.trim(),
      mode: eingabe.mode,
      depth: eingabe.depth,
    };
    if (purpose !== "") {
      payload.purpose = purpose;
    }
    // Intervall + Dauer nur im Detail-Modus mitgeben (aggregate nutzt still den
    // Default beim Intervall und ist zeitlich unbegrenzt -- KEIN maxDurationS).
    // maxDurationS immer explizit aus den gewaehlten Stunden berechnet (auch bei
    // der Default-Stufe 24h -> 86400), damit der Sendepfad konsistent ist.
    if (eingabe.mode === "detail") {
      payload.intervalS = eingabe.intervalS;
      payload.maxDurationS = dauerStunden * 3600;
    }
    try {
      await createRecording(payload);
      setEingabe(LEERE_EINGABE);
      setFehler(null);
      await ladeRecordings();
    } catch (anlegeFehler) {
      setFehler(anlegeFehler?.message ?? t("beobachten.outboundlog.anlegenFehler"));
    }
  };

  // Player-Aktion auf einer Karte. Ruft die passende API, laedt die Liste neu. Bei
  // 409 (host-weit schon eine active / unzulaessige Transition) den RUHIGEN
  // Konflikt-Hinweis setzen (kein roter Fehler); andere Fehler (Netz/500) als
  // normaler dezenter Fehlertext. delete: nach Erfolg den Loesch-Zweistufer schliessen.
  const handleAktion = async (aktion, recording) => {
    try {
      if (aktion === "start") {
        await startRecording(recording.id);
      } else if (aktion === "pause") {
        await pauseRecording(recording.id);
      } else if (aktion === "resume") {
        await resumeRecording(recording.id);
      } else if (aktion === "stop") {
        await stopRecording(recording.id);
      } else if (aktion === "delete") {
        await deleteRecording(recording.id);
        setLoeschId(null);
        // War die geloeschte Karte ausgewaehlt, die Auswahl aufheben.
        if (selectedId === recording.id) {
          setSelectedId(null);
        }
      }
      setFehler(null);
      setKonflikt(false);
      await ladeRecordings();
    } catch (aktionFehler) {
      // 409 = host-weit schon eine active: ruhiger Konflikt-Hinweis statt Fehler.
      if (aktionFehler?.status === 409) {
        setKonflikt(true);
      } else {
        setFehler(aktionFehler?.message ?? t("beobachten.outboundlog.aktionFehler"));
      }
    }
  };

  // Karte waehlen (E5b-Befund). Erneuter Klick auf dieselbe hebt die Auswahl auf.
  const handleWaehlen = (id) => {
    setSelectedId((aktuell) => (aktuell === id ? null : id));
  };

  const ausgewaehlt = recordings.find((r) => r.id === selectedId) ?? null;

  return (
    <div className="outboundrec">
      {/* ── LEISTE: immer sichtbar. Ruhe neutral, Aktiv GELB (Warnton-Tokens). ── */}
      {aktiveAufzeichnung ? (
        <div className="outboundrec__leiste outboundrec__leiste--aktiv">
          <span className="outboundrec__leiste-status">
            <span className="outboundrec__leiste-punkt" aria-hidden="true" />
            <span className="outboundrec__leiste-text">
              {t("beobachten.outboundlog.leiste.titelAktiv", {
                label: aktiveAufzeichnung.label,
              })}
            </span>
          </span>
          <span className="outboundrec__leiste-knoepfe">
            <PlayerKnopf
              icon={Pause}
              label={t("beobachten.outboundlog.aktion.pause")}
              variante="pause"
              onClick={() => handleAktion("pause", aktiveAufzeichnung)}
            />
            <PlayerKnopf
              icon={Square}
              label={t("beobachten.outboundlog.aktion.stop")}
              variante="stop"
              onClick={() => handleAktion("stop", aktiveAufzeichnung)}
            />
            <button
              type="button"
              className="outboundrec__verwaltung-knopf"
              aria-expanded={verwaltungOffen}
              onClick={() => setVerwaltungOffen((o) => !o)}
            >
              {t("beobachten.outboundlog.leiste.knopfVerwaltung")}
            </button>
          </span>
        </div>
      ) : (
        <div className="outboundrec__leiste">
          <span className="outboundrec__leiste-status">
            <CircleDot size={15} aria-hidden="true" />
            <span className="outboundrec__leiste-text">
              {t("beobachten.outboundlog.leiste.titelRuhe")}
            </span>
          </span>
          <button
            type="button"
            className="outboundrec__verwaltung-knopf"
            aria-expanded={verwaltungOffen}
            onClick={() => setVerwaltungOffen((o) => !o)}
          >
            {t("beobachten.outboundlog.leiste.knopfVerwaltung")}
          </button>
        </div>
      )}

      {/* ── VERWALTUNG: aufklappbar (Default ZU). Anlegen + Liste + Befund. ── */}
      {verwaltungOffen && (
        <div className="outboundrec__verwaltung">
          {/* Ruhiger Konflikt-Hinweis (start/resume mit 409): ueber der Liste, kein
              roter Banner -- ein freundlicher Hinweis (nur EINE darf host-weit aktiv sein). */}
          {konflikt && (
            <div className="outboundlog__konflikt" role="note">
              {t("beobachten.outboundlog.konfliktHinweis")}
            </div>
          )}

          {/* Dezenter Fehlerhinweis (Anlage/Aktion/Laden). Warnton, kein Alarm. */}
          {fehler && (
            <div className="outboundlog__fehler" role="note">
              {fehler}
            </div>
          )}

          {/* ── (A) Anlegen ──────────────────────────────────────────────── */}
          <div className="outboundlog__maske">
            <button
              type="button"
              className="outboundlog__maske-kopf"
              aria-expanded={anlegenOffen}
              onClick={() => setAnlegenOffen((o) => !o)}
            >
              <span className="outboundlog__maske-titel">
                {t("beobachten.outboundlog.neueAufzeichnung")}
              </span>
              <span className="outboundlog__maske-toggle" aria-hidden="true">
                {anlegenOffen ? "−" : "+"}
              </span>
            </button>

            {anlegenOffen && (
              <div className="outboundlog__maske-inhalt">
                <label className="outboundlog-feld">
                  <span className="outboundlog-feld__label">
                    {t("beobachten.outboundlog.bezeichnungLabel")}
                  </span>
                  <input
                    type="text"
                    className="outboundlog-feld__input"
                    value={eingabe.label}
                    placeholder={t("beobachten.outboundlog.bezeichnungPlaceholder")}
                    onChange={(e) => setFeld("label", e.target.value)}
                  />
                </label>

                <label className="outboundlog-feld">
                  <span className="outboundlog-feld__label">
                    {t("beobachten.outboundlog.zweckLabel")}
                  </span>
                  <input
                    type="text"
                    className="outboundlog-feld__input"
                    value={eingabe.purpose}
                    placeholder={t("beobachten.outboundlog.zweckPlaceholder")}
                    onChange={(e) => setFeld("purpose", e.target.value)}
                  />
                </label>

                {/* Modus: Segmented Control (Muster TopologyView). Darunter ein
                    ruhiger Hinweis-Fliesstext je Wahl. */}
                <div className="outboundlog-feld">
                  <span className="outboundlog-feld__label">
                    {t("beobachten.outboundlog.modusLabel")}
                  </span>
                  <div className="outboundlog-segment" role="tablist">
                    <button
                      type="button"
                      role="tab"
                      aria-selected={eingabe.mode === "detail"}
                      className={
                        eingabe.mode === "detail"
                          ? "outboundlog-segment__knopf outboundlog-segment__knopf--aktiv"
                          : "outboundlog-segment__knopf"
                      }
                      onClick={() => setFeld("mode", "detail")}
                    >
                      {t("beobachten.outboundlog.modus.detail")}
                    </button>
                    <button
                      type="button"
                      role="tab"
                      aria-selected={eingabe.mode === "aggregate"}
                      className={
                        eingabe.mode === "aggregate"
                          ? "outboundlog-segment__knopf outboundlog-segment__knopf--aktiv"
                          : "outboundlog-segment__knopf"
                      }
                      onClick={() => setFeld("mode", "aggregate")}
                    >
                      {t("beobachten.outboundlog.modus.aggregate")}
                    </button>
                  </div>
                  <p className="outboundlog-feld__hinweis">
                    {eingabe.mode === "detail"
                      ? t("beobachten.outboundlog.modusHinweis.detail")
                      : t("beobachten.outboundlog.modusHinweis.aggregate")}
                  </p>
                </div>

                {/* Tiefe: Segmented Control + ruhiger Hinweis-Fliesstext je Wahl. */}
                <div className="outboundlog-feld">
                  <span className="outboundlog-feld__label">
                    {t("beobachten.outboundlog.tiefeLabel")}
                  </span>
                  <div className="outboundlog-segment" role="tablist">
                    <button
                      type="button"
                      role="tab"
                      aria-selected={eingabe.depth === "anonymous"}
                      className={
                        eingabe.depth === "anonymous"
                          ? "outboundlog-segment__knopf outboundlog-segment__knopf--aktiv"
                          : "outboundlog-segment__knopf"
                      }
                      onClick={() => setFeld("depth", "anonymous")}
                    >
                      {t("beobachten.outboundlog.tiefe.anonymous")}
                    </button>
                    <button
                      type="button"
                      role="tab"
                      aria-selected={eingabe.depth === "app_resolved"}
                      className={
                        eingabe.depth === "app_resolved"
                          ? "outboundlog-segment__knopf outboundlog-segment__knopf--aktiv"
                          : "outboundlog-segment__knopf"
                      }
                      onClick={() => setFeld("depth", "app_resolved")}
                    >
                      {t("beobachten.outboundlog.tiefe.appResolved")}
                    </button>
                  </div>
                  <p className="outboundlog-feld__hinweis">
                    {eingabe.depth === "app_resolved"
                      ? t("beobachten.outboundlog.tiefeHinweis.appResolved")
                      : t("beobachten.outboundlog.tiefeHinweis.anonymous")}
                  </p>
                </div>

                {/* Intervall NUR bei mode==detail (bei aggregate ausgeblendet). */}
                {eingabe.mode === "detail" && (
                  <label className="outboundlog-feld">
                    <span className="outboundlog-feld__label">
                      {t("beobachten.outboundlog.intervallLabel")}
                    </span>
                    <select
                      className="outboundlog-feld__select"
                      value={eingabe.intervalS}
                      onChange={(e) => setFeld("intervalS", Number(e.target.value))}
                    >
                      {INTERVALL_OPTIONEN.map((o) => (
                        <option key={o.key} value={o.sekunden}>
                          {t(`beobachten.outboundlog.intervall.${o.key}`)}
                        </option>
                      ))}
                    </select>
                  </label>
                )}

                {/* Dauer-Wahl NUR bei mode==detail (bei aggregate ausgeblendet --
                    Sammlung ist zeitlich unbegrenzt, kein maxDurationS). Feste Stufen
                    als Segmented Control (Muster Modus/Tiefe) + Option
                    "benutzerdefiniert"; bei custom erscheint darunter ein Zahlenfeld
                    (1..24 Stunden) mit ruhigem Validierungs-Hinweis. */}
                {eingabe.mode === "detail" && (
                  <div className="outboundlog-feld">
                    <span className="outboundlog-feld__label">
                      {t("beobachten.outboundlog.dauerLabel")}
                    </span>
                    <div className="outboundlog-segment" role="tablist">
                      {DAUER_STUFEN.map((stufe) => {
                        const aktiv =
                          eingabe.durationModus === "stufe" &&
                          eingabe.durationStunden === stufe.stunden;
                        return (
                          <button
                            key={stufe.key}
                            type="button"
                            role="tab"
                            aria-selected={aktiv}
                            className={
                              aktiv
                                ? "outboundlog-segment__knopf outboundlog-segment__knopf--aktiv"
                                : "outboundlog-segment__knopf"
                            }
                            onClick={() =>
                              setEingabe((v) => ({
                                ...v,
                                durationModus: "stufe",
                                durationStunden: stufe.stunden,
                              }))
                            }
                          >
                            {t(`beobachten.outboundlog.dauer.${stufe.key}`)}
                          </button>
                        );
                      })}
                      <button
                        type="button"
                        role="tab"
                        aria-selected={eingabe.durationModus === "custom"}
                        className={
                          eingabe.durationModus === "custom"
                            ? "outboundlog-segment__knopf outboundlog-segment__knopf--aktiv"
                            : "outboundlog-segment__knopf"
                        }
                        onClick={() => setFeld("durationModus", "custom")}
                      >
                        {t("beobachten.outboundlog.dauer.custom")}
                      </button>
                    </div>

                    {eingabe.durationModus === "custom" && (
                      <label className="outboundlog-feld outboundlog-feld--custom">
                        <span className="outboundlog-feld__label">
                          {t("beobachten.outboundlog.dauerCustomLabel")}
                        </span>
                        <input
                          type="number"
                          min={DAUER_MIN_STUNDEN}
                          max={DAUER_MAX_STUNDEN}
                          step={1}
                          inputMode="numeric"
                          className="outboundlog-feld__input"
                          value={eingabe.durationCustom}
                          onChange={(e) => setFeld("durationCustom", e.target.value)}
                          aria-invalid={!dauerGueltig}
                        />
                        {!dauerGueltig && (
                          <span className="outboundlog-feld__hinweis" role="note">
                            {t("beobachten.outboundlog.dauerCustomHinweis")}
                          </span>
                        )}
                      </label>
                    )}
                  </div>
                )}

                <div className="outboundlog__abschluss">
                  <button
                    type="button"
                    className="outboundlog__knopf outboundlog__knopf--primaer"
                    disabled={!eingabeGueltig}
                    onClick={handleAnlegen}
                  >
                    {t("beobachten.outboundlog.anlegen")}
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* ── (B) Aufzeichnungs-Liste ──────────────────────────────────── */}
          <div className="outboundlog__listeTitel">
            {t("beobachten.outboundlog.listeTitel")}
          </div>
          {recordings.length === 0 ? (
            <p className="outboundlog__leer">{t("beobachten.outboundlog.listeLeer")}</p>
          ) : (
            <div className="outboundlog__liste">
              {recordings.map((recording) => (
                <AufzeichnungsKarte
                  key={recording.id}
                  recording={recording}
                  ausgewaehlt={selectedId === recording.id}
                  loeschBereit={loeschId === recording.id}
                  onWaehlen={handleWaehlen}
                  onAktion={handleAktion}
                  onLoeschBereit={(id) => setLoeschId(id)}
                  onLoeschAbbruch={() => setLoeschId(null)}
                />
              ))}
            </div>
          )}

          {/* ── (C) Befund-Platzhalter (E5b) ─────────────────────────────── */}
          {ausgewaehlt && (
            <div className="outboundlog__befund" role="note">
              {t("beobachten.outboundlog.befundFolgt", { label: ausgewaehlt.label })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
