// Aussenkontakte-Aufzeichnung: selbsterklaerende Karte + Modals (CERNIS PRO 2.0)
//
// Integriert in die Aussenkontakte-Ansicht (OutboundView), KEINE eigene
// Beobachten-Kachel mehr. Aufbau (Layout-Finale "Aufzeichnungs-Karte"):
//   EINE selbsterklaerende Karte (outboundrec-karte) statt der frueheren Leiste:
//     - Kopf: Icon + Titel "Aufzeichnungen". Laeuft eine Aufzeichnung (state
//       active), wechselt der Kopf in einen RUHIGEN Aktiv-Zustand (Warnton-Tokens
//       --sev-med-*, KEIN Alarm): Punkt + "Zeichnet auf: <label>" + Pause/Stopp.
//       Laeuft keine: ein sprechender Status-Satz ("Keine Aufzeichnung aktiv.").
//     - Knopf "Neue Aufzeichnung" (Plus) -> oeffnet das ERSTELLEN-MODAL.
//     - Darunter die Liste: pro Eintrag eine kompakte Zeile (Name + zustands-
//       abhaengige Player-Icons + ein Zahnrad, das das DETAIL-MODAL oeffnet). Bei
//       mehreren Eintraegen 2-spaltig (grid auto-fill), sonst 1-spaltig.
//   Das DETAIL-MODAL (selectedId) zeigt zunaechst NUR LESEND (AufzeichnungsKarte +
//   Player + Loeschen-Zweistufer) + einen Knopf "Aendern". "Aendern" schaltet in
//   den BEARBEITEN-MODUS: label/purpose IMMER editierbar; Modus/Tiefe/Intervall/
//   Dauer NUR im Zustand "created" (sonst ruhiger gesperrt-Hinweis mit Schloss +
//   Nur-Lese-Werten). Speichern ruft updateRecording.
//
// Muster bewusst wie LoggingPanel.jsx (useState/useEffect, useTranslation, KEIN
// t/i18n im State-setzenden useEffect-Dep-Array -- Render-Loop-Falle). Alle Texte
// ueber i18n, alle Farben ueber Tokens.

import {
  CircleDot,
  Lock,
  Pause,
  Play,
  Plus,
  Settings,
  Square,
  Trash2,
  X,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import {
  createRecording,
  deleteRecording,
  fetchRecordings,
  pauseRecording,
  resumeRecording,
  startRecording,
  stopRecording,
  updateRecording,
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

// Eine vorhandene Aufzeichnung in den Eingabe-Shape (LEERE_EINGABE) uebersetzen --
// fuer den Bearbeiten-Modus, damit dasselbe Felder-Markup vorbefuellt erscheint.
// purpose null -> leerer String (das Feld bleibt editierbar leer). intervalS null
// (aggregate) -> Default 60 (irrelevant, weil das Intervall-Feld bei aggregate
// nicht gezeigt wird). maxDurationS -> volle Stunden; deckt sich der Wert mit einer
// festen Stufe, wird diese gewaehlt (durationModus "stufe"), sonst "custom" mit dem
// Stunden-Wert als String.
function recordingZuEingabe(recording) {
  const stunden =
    recording.maxDurationS !== null && recording.maxDurationS !== undefined
      ? Math.round(recording.maxDurationS / 3600)
      : 24;
  const trefferStufe = DAUER_STUFEN.find((s) => s.stunden === stunden) ?? null;
  return {
    label: recording.label ?? "",
    purpose: recording.purpose ?? "",
    mode: recording.mode,
    depth: recording.depth,
    intervalS: recording.intervalS ?? 60,
    durationModus: trefferStufe ? "stufe" : "custom",
    durationStunden: trefferStufe ? trefferStufe.stunden : 24,
    durationCustom: trefferStufe ? "" : String(stunden),
  };
}

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

// ── Wiederverwendbare Felder-Bausteine (Erstellen- UND Bearbeiten-Modus) ──────

// Bezeichnung (label) + Zweck (purpose): in JEDEM Zustand editierbar. Bekommt die
// gemeinsame eingabe + setFeld, damit Erstellen- und Bearbeiten-Modus dasselbe
// Markup teilen.
function LabelZweckFelder({ eingabe, setFeld }) {
  const { t } = useTranslation();
  return (
    <>
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
    </>
  );
}

// Modus/Tiefe/Intervall/Dauer als EINGABE: Segmented Controls + Hinweise + (bei
// detail) Intervall-Select und Dauer-Wahl. Wird im Erstellen-Modal IMMER gezeigt,
// im Bearbeiten-Modus NUR bei state==="created". setFeld/setEingabe + die
// abgeleiteten Dauer-Werte kommen vom Aufrufer (geteilte Validierung).
function KonfigEingabeFelder({ eingabe, setFeld, setEingabe, dauerGueltig }) {
  const { t } = useTranslation();
  return (
    <>
      {/* Modus: Segmented Control (Muster TopologyView). Darunter ein ruhiger
          Hinweis-Fliesstext je Wahl. */}
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

      {/* Dauer-Wahl NUR bei mode==detail (bei aggregate ausgeblendet -- Sammlung
          ist zeitlich unbegrenzt, kein maxDurationS). Feste Stufen als Segmented
          Control + Option "benutzerdefiniert"; bei custom erscheint darunter ein
          Zahlenfeld (1..24 Stunden) mit ruhigem Validierungs-Hinweis. */}
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
    </>
  );
}

// Modus/Tiefe/Intervall/Dauer als RUHIGER GESPERRT-HINWEIS (state !== "created"):
// Schloss-Icon + Erklaer-Satz, darunter die aktuellen Werte als Nur-Lese-Text. So
// sieht der Nutzer WARUM die Konfig nicht editierbar ist.
function KonfigGesperrt({ recording }) {
  const { t } = useTranslation();

  const modusText = t(`beobachten.outboundlog.modus.${recording.mode}`, {
    defaultValue: recording.mode,
  });
  const tiefeKey =
    recording.depth === "app_resolved" ? "appResolved" : "anonymous";
  const tiefeText = t(`beobachten.outboundlog.tiefe.${tiefeKey}`, {
    defaultValue: recording.depth,
  });
  // Intervall/Dauer nur bei detail (aggregate traegt kein Intervall/keine Dauer).
  const istDetail = recording.mode === "detail";
  const intervallText =
    istDetail && recording.intervalS !== null
      ? t(`beobachten.outboundlog.intervall.${recording.intervalS}s`, {
          defaultValue: `${recording.intervalS} s`,
        })
      : null;
  const dauerStunden =
    istDetail && recording.maxDurationS !== null
      ? Math.round(recording.maxDurationS / 3600)
      : null;

  return (
    <div className="outboundlog-gesperrt" role="note">
      <div className="outboundlog-gesperrt__kopf">
        <Lock size={14} aria-hidden="true" />
        <span className="outboundlog-gesperrt__titel">
          {t("beobachten.outboundlog.gesperrtTitel")}
        </span>
      </div>
      <p className="outboundlog-gesperrt__text">
        {t("beobachten.outboundlog.gesperrtHinweis")}
      </p>
      <dl className="outboundlog-gesperrt__werte">
        <div className="outboundlog-gesperrt__zeile">
          <dt>{t("beobachten.outboundlog.modusLabel")}</dt>
          <dd>{modusText}</dd>
        </div>
        <div className="outboundlog-gesperrt__zeile">
          <dt>{t("beobachten.outboundlog.tiefeLabel")}</dt>
          <dd>{tiefeText}</dd>
        </div>
        {intervallText !== null && (
          <div className="outboundlog-gesperrt__zeile">
            <dt>{t("beobachten.outboundlog.intervallLabel")}</dt>
            <dd>{intervallText}</dd>
          </div>
        )}
        {dauerStunden !== null && (
          <div className="outboundlog-gesperrt__zeile">
            <dt>{t("beobachten.outboundlog.dauerLabel")}</dt>
            <dd>{t("beobachten.outboundlog.dauerKarte", { stunden: dauerStunden })}</dd>
          </div>
        )}
      </dl>
    </div>
  );
}

// Eine Aufzeichnungs-Karte: Bezeichnung, Modus-/Tiefe-Badges, Zustands-Pille, bei
// aktiven Detail-Aufzeichnungen der 24h-Hinweis, plus die zustandsabhaengigen
// Player-Knoepfe. Loeschen ueber einen normalen roten Knopf (onLoeschen), der ein
// eigenes kleines Bestaetigungs-Modal oeffnet (kein Inline-Zweistufer mehr).
// Im Detail-Modal zusaetzlich ein "Aendern"-Knopf (onAendern), der in den
// Bearbeiten-Modus schaltet -- nur gezeigt, wenn onAendern uebergeben wird.
function AufzeichnungsKarte({
  recording,
  ausgewaehlt,
  onWaehlen,
  onAktion,
  onLoeschen,
  onAendern,
}) {
  const { t, i18n } = useTranslation();

  const zustandText = t(`beobachten.outboundlog.state.${recording.state}`, {
    defaultValue: recording.state,
  });
  const modusText = t(`beobachten.outboundlog.modus.${recording.mode}`, {
    defaultValue: recording.mode,
  });
  const tiefeKey =
    recording.depth === "app_resolved" ? "appResolved" : "anonymous";
  const tiefeText = t(`beobachten.outboundlog.tiefe.${tiefeKey}`, {
    defaultValue: recording.depth,
  });

  // 24h-Hinweis NUR bei aktiver Detail-Aufzeichnung (aggregate ist zeitlich
  // unbegrenzt). Statischer Hinweis -- die Restzeit-Berechnung kommt in E5b.
  const zeigt24hHinweis =
    recording.mode === "detail" && recording.state === "active";

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
        <span className="outboundlog-badge outboundlog-badge--modus">
          {modusText}
        </span>
        <span className="outboundlog-badge outboundlog-badge--tiefe">
          {tiefeText}
        </span>
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
          (oeffnet ueber onLoeschen das Bestaetigungs-Modal). "Aendern" (falls
          onAendern) oeffnet den Bearbeiten-Modus. */}
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

        {/* "Aendern": nur im Detail-Modal (onAendern uebergeben). Oeffnet den
            Bearbeiten-Modus. */}
        {onAendern && (
          <PlayerKnopf
            icon={Settings}
            label={t("beobachten.outboundlog.aendern")}
            variante="aendern"
            onClick={() => onAendern(recording)}
          />
        )}

        {/* Loeschen: normaler roter Knopf, oeffnet das Bestaetigungs-Modal. */}
        <PlayerKnopf
          icon={Trash2}
          label={t("beobachten.outboundlog.aktion.loeschen")}
          variante="delete"
          onClick={() => onLoeschen(recording)}
        />
      </div>
    </div>
  );
}

// Ein kompakter Icon-Player-Knopf fuer die Karten-Liste: NUR Icon, das Label bleibt
// als title/aria-label erhalten (Barrierefreiheit). stopPropagation im Aufrufer,
// damit ein Knopf-Klick nicht zugleich die Zeile waehlt.
function IconKnopf({ icon: Icon, label, onClick, variante }) {
  return (
    <button
      type="button"
      className={`outboundrec-kompakt__knopf outboundrec-kompakt__knopf--${variante}`}
      onClick={onClick}
      title={label}
      aria-label={label}
    >
      <Icon size={14} />
    </button>
  );
}

// Eine KOMPAKTE Zeile der Karten-Liste: NUR Name (bei Ueberlaenge als langsame,
// dauerhafte Laufschrift, nicht abschneidend) + die zustandsabhaengigen Player-Icons + ein
// Zahnrad-Icon, das das Detail-Modal oeffnet. Play startet direkt, Zahnrad oeffnet
// Details -- die beiden NICHT vermischen (stopPropagation pro Knopf). Klick auf die
// Zeile selbst (nicht auf einen Knopf) oeffnet ebenfalls die Details.
//
// Der NAME ist die Identitaet der Zeile (mehrere "angelegte" haben alle denselben
// Zustand -- nur der Name unterscheidet sie). Der Zustand erscheint daher NICHT
// mehr als Pille, sondern -- nur bei active/paused -- als dezenter farbiger Punkt
// VOR dem Namen (Warnton bei active, ruhiger neutraler Punkt bei paused). Der Punkt
// traegt title/aria-label mit dem Zustandstext, damit die Info barrierefrei bleibt.
function KompakteKarte({ recording, onWaehlen, onAktion }) {
  const { t } = useTranslation();

  const zustandText = t(`beobachten.outboundlog.state.${recording.state}`, {
    defaultValue: recording.state,
  });

  // Echter-Ueberlauf-Messung: reines CSS kann "passt der Name rein?" nicht
  // beantworten. Refs auf den Viewport (outboundrec-kompakt__name) und den inneren
  // Span; nach dem Render messen, ob der Inhalt breiter ist als der Viewport. Nur
  // dann laeuft die Laufschrift -- sonst steht der Name still.
  const nameViewportRef = useRef(null);
  const nameInnerRef = useRef(null);
  const [ueberlaeuft, setUeberlaeuft] = useState(false);

  // Messen bei Mount + jeder label-Aenderung. KEIN t im Dep-Array (Render-Loop-
  // Falle, Muster wie die State-setzenden Effekte oben). Der label-Wert genuegt als
  // Trigger -- ResizeObserver waere die Kuer, ist hier aber bewusst nicht noetig.
  useEffect(() => {
    const viewport = nameViewportRef.current;
    const inner = nameInnerRef.current;
    if (!viewport || !inner) {
      return;
    }
    // +1px Toleranz gegen subpixel-Rundung (sonst flackert die Laufschrift bei
    // Namen, die exakt passen).
    setUeberlaeuft(inner.scrollWidth > viewport.clientWidth + 1);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [recording.label]);

  // Zustands-Punkt nur bei active/paused; created/finished bleiben ohne Punkt
  // (der Name allein genuegt). active -> Warnton, paused -> neutral gedaempft.
  const punktKlasse =
    recording.state === "active"
      ? "outboundrec-kompakt__punkt outboundrec-kompakt__punkt--aktiv"
      : recording.state === "paused"
        ? "outboundrec-kompakt__punkt outboundrec-kompakt__punkt--pausiert"
        : null;

  return (
    <div
      className="outboundrec-kompakt"
      onClick={() => onWaehlen(recording.id)}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onWaehlen(recording.id);
        }
      }}
    >
      {/* Zustands-Punkt (nur active/paused): dezent, mit title/aria-label fuer die
          Barrierefreiheit -- die Zustands-Info geht ohne Pille nicht verloren. */}
      {punktKlasse && (
        <span
          className={punktKlasse}
          role="img"
          aria-label={zustandText}
          title={zustandText}
        />
      )}
      {/* Name: Viewport (overflow hidden, nowrap). Der innere Span laeuft NUR bei
          echtem Ueberlauf (JS-Messung oben -> ueberlaeuft) als zuegige Laufschrift;
          passt der Name rein, bleibt er still (keine Animation). prefers-reduced-
          motion -> statisch mit Ellipse (CSS). */}
      <span className="outboundrec-kompakt__name" ref={nameViewportRef}>
        <span
          ref={nameInnerRef}
          className={
            ueberlaeuft
              ? "outboundrec-kompakt__name-inner outboundrec-kompakt__name-inner--laeuft"
              : "outboundrec-kompakt__name-inner"
          }
        >
          {recording.label}
        </span>
      </span>

      {/* Player-Icons + Zahnrad. stopPropagation, damit der Knopf-Klick die Zeile
          nicht zugleich oeffnet. created->Start; active->Pause+Stop; paused->
          Fortsetzen+Stop. Zahnrad oeffnet IMMER die Details (handleWaehlen). */}
      <span
        className="outboundrec-kompakt__knoepfe"
        onClick={(e) => e.stopPropagation()}
      >
        {recording.state === "created" && (
          <IconKnopf
            icon={Play}
            label={t("beobachten.outboundlog.aktion.start")}
            variante="start"
            onClick={() => onAktion("start", recording)}
          />
        )}
        {recording.state === "active" && (
          <>
            <IconKnopf
              icon={Pause}
              label={t("beobachten.outboundlog.aktion.pause")}
              variante="pause"
              onClick={() => onAktion("pause", recording)}
            />
            <IconKnopf
              icon={Square}
              label={t("beobachten.outboundlog.aktion.stop")}
              variante="stop"
              onClick={() => onAktion("stop", recording)}
            />
          </>
        )}
        {recording.state === "paused" && (
          <>
            <IconKnopf
              icon={Play}
              label={t("beobachten.outboundlog.aktion.resume")}
              variante="start"
              onClick={() => onAktion("resume", recording)}
            />
            <IconKnopf
              icon={Square}
              label={t("beobachten.outboundlog.aktion.stop")}
              variante="stop"
              onClick={() => onAktion("stop", recording)}
            />
          </>
        )}

        {/* Zahnrad: oeffnet die Details (Detail-Modal). Bewusst getrennt vom
            Play-Knopf -- Play startet, Zahnrad zeigt/aendert. */}
        <IconKnopf
          icon={Settings}
          label={t("beobachten.outboundlog.details")}
          variante="details"
          onClick={() => onWaehlen(recording.id)}
        />
      </span>
    </div>
  );
}

// Modal-Rahmen nach Vorbild OutboundConsentDialog (Overlay + zentrierter Dialog).
// Schliessen per X-Knopf UND Klick auf den Overlay-Hintergrund (nicht auf den
// Dialog selbst -> stopPropagation). titel = Ueberschrift, kinder = Inhalt.
function ModalRahmen({ titel, onClose, children }) {
  const { t } = useTranslation();
  return (
    <div className="outboundrec-modal-overlay" onClick={onClose}>
      <div
        className="outboundrec-modal"
        role="dialog"
        aria-modal="true"
        aria-label={titel}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="outboundrec-modal__kopf">
          <h2 className="outboundrec-modal__titel">{titel}</h2>
          <button
            type="button"
            className="outboundrec-modal__schliessen"
            onClick={onClose}
            title={t("beobachten.outboundlog.schliessen")}
            aria-label={t("beobachten.outboundlog.schliessen")}
          >
            <X size={18} />
          </button>
        </div>
        <div className="outboundrec-modal__inhalt">{children}</div>
      </div>
    </div>
  );
}

// Die integrierte Aufzeichnungs-Komponente: EINE selbsterklaerende Karte (Kopf +
// "Neue Aufzeichnung"-Knopf + Liste) plus Erstellen-/Detail-Modal. Wird von
// OutboundView ueber der Live-Liste eingebunden. Datenquelle bleibt
// api/outboundLog.js.
// onAktivCount(anzahl): optionaler Callback, ueber den die Komponente die Anzahl
// host-weit gerade laufender Aufzeichnungen (state==="active") nach oben meldet --
// OutboundView nutzt das fuer den ruhigen Banner-Hinweis, OHNE einen zweiten
// Voll-Poll. Default ein No-Op, damit die Komponente eigenstaendig bleibt.
export default function OutboundRecordingPanel({ onAktivCount = () => {} }) {
  const { t } = useTranslation();

  // Angelegte Aufzeichnungen (aus fetchRecordings), gemappt.
  const [recordings, setRecordings] = useState([]);
  // Gemeinsame Eingabefelder der ANLAGE-Maske (Erstellen-Modal).
  const [eingabe, setEingabe] = useState(LEERE_EINGABE);
  // Ob das ERSTELLEN-MODAL offen ist (oeffnet ueber den Karten-Knopf).
  const [erstellenOffen, setErstellenOffen] = useState(false);
  // Dezenter Fehlerhinweis (Anlage/Aktion/Laden) oder null.
  const [fehler, setFehler] = useState(null);
  // Ruhiger Konflikt-Hinweis (start/resume mit 409) oder false. Getrennt vom
  // normalen Fehler: kein roter Banner, sondern ein ruhiger Hinweis ueber der Liste.
  const [konflikt, setKonflikt] = useState(false);
  // Gewaehlte Karte (Klick/Zahnrad) -> oeffnet das Detail-Modal, oder null.
  const [selectedId, setSelectedId] = useState(null);
  // Aufzeichnung, deren Loeschen gerade im Bestaetigungs-Modal nachgefragt wird,
  // oder null. Haelt das ganze recording-Objekt (fuer label im Modal-Text).
  const [loeschBestaetigung, setLoeschBestaetigung] = useState(null);

  // ── Bearbeiten-Modus im Detail-Modal ──────────────────────────────────────
  // Ob der Bearbeiten-Modus offen ist (sonst: Anzeige-Modus, nur lesend).
  const [editOffen, setEditOffen] = useState(false);
  // Vorbefuellte Eingabefelder fuer das Aendern (Shape wie LEERE_EINGABE).
  const [editEingabe, setEditEingabe] = useState(LEERE_EINGABE);
  // Ruhiger Fehlerhinweis im Bearbeiten-Modus (409/422/Netz) oder null.
  const [editFehler, setEditFehler] = useState(null);

  // Ein Feld der ANLAGE-Eingabe setzen (immutabel).
  const setFeld = (feld, wert) => setEingabe((v) => ({ ...v, [feld]: wert }));
  // Ein Feld der EDIT-Eingabe setzen (immutabel).
  const setEditFeld = (feld, wert) =>
    setEditEingabe((v) => ({ ...v, [feld]: wert }));

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

  // Abgeleitete Dauer-Werte der ANLAGE-Eingabe (Erstellen-Modal).
  const customRoh = eingabe.durationCustom.trim();
  const customStunden =
    customRoh === "" || !/^\d+$/.test(customRoh)
      ? NaN
      : Number.parseInt(customRoh, 10);
  const dauerStunden =
    eingabe.durationModus === "custom" ? customStunden : eingabe.durationStunden;
  const dauerGueltig =
    eingabe.mode !== "detail" ||
    (Number.isInteger(dauerStunden) &&
      dauerStunden >= DAUER_MIN_STUNDEN &&
      dauerStunden <= DAUER_MAX_STUNDEN);

  // Abgeleitete Dauer-Werte der EDIT-Eingabe (Bearbeiten-Modus).
  const editCustomRoh = editEingabe.durationCustom.trim();
  const editCustomStunden =
    editCustomRoh === "" || !/^\d+$/.test(editCustomRoh)
      ? NaN
      : Number.parseInt(editCustomRoh, 10);
  const editDauerStunden =
    editEingabe.durationModus === "custom"
      ? editCustomStunden
      : editEingabe.durationStunden;
  const editDauerGueltig =
    editEingabe.mode !== "detail" ||
    (Number.isInteger(editDauerStunden) &&
      editDauerStunden >= DAUER_MIN_STUNDEN &&
      editDauerStunden <= DAUER_MAX_STUNDEN);

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

  // Clientseitige Mindest-Pruefung Anlage: label nicht leer UND (falls custom) gueltig.
  const eingabeGueltig = eingabe.label.trim() !== "" && dauerGueltig;
  // Clientseitige Mindest-Pruefung Aenderung: label nicht leer UND Dauer gueltig.
  const editGueltig = editEingabe.label.trim() !== "" && editDauerGueltig;

  // Host-weit hoechstens EINE active -- treibt den Karten-Kopf (Ruhe vs. Aktiv) und
  // die Pause/Stopp-Knoepfe im Kopf.
  const aktiveAufzeichnung =
    recordings.find((r) => r.state === "active") ?? null;

  // Anlegen. Bei mode==detail Intervall + Dauer mitgeben; purpose nur wenn gesetzt.
  // Nach Erfolg: Formular zuruecksetzen + Modal schliessen + Liste neu laden.
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
    if (eingabe.mode === "detail") {
      payload.intervalS = eingabe.intervalS;
      payload.maxDurationS = dauerStunden * 3600;
    }
    try {
      await createRecording(payload);
      setEingabe(LEERE_EINGABE);
      setFehler(null);
      setKonflikt(false);
      setErstellenOffen(false);
      await ladeRecordings();
    } catch (anlegeFehler) {
      // 409 = Name schon vergeben (Backend RecordingNameTaken). Der Erstellen-Pfad
      // laeuft ueber apiPost, das den Backend-detail-Text verwirft -> eigenen i18n-
      // Hinweis bevorzugen. Andere Fehler (422/Netz) wie bisher generisch.
      if (anlegeFehler?.status === 409) {
        setFehler(t("beobachten.outboundlog.nameVergeben"));
      } else {
        setFehler(
          anlegeFehler?.message ?? t("beobachten.outboundlog.anlegenFehler"),
        );
      }
    }
  };

  // Player-Aktion auf einer Karte. Ruft die passende API, laedt die Liste neu. Bei
  // 409 (host-weit schon eine active / unzulaessige Transition) den RUHIGEN
  // Konflikt-Hinweis setzen (kein roter Fehler); andere Fehler (Netz/500) als
  // normaler dezenter Fehlertext. delete: nach Erfolg das Bestaetigungs-Modal schliessen.
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
        setLoeschBestaetigung(null);
        // War die geloeschte Karte ausgewaehlt, die Auswahl aufheben (schliesst
        // das Detail-Modal) und den Bearbeiten-Modus zuruecksetzen.
        if (selectedId === recording.id) {
          setSelectedId(null);
          setEditOffen(false);
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
        setFehler(
          aktionFehler?.message ?? t("beobachten.outboundlog.aktionFehler"),
        );
      }
    }
  };

  // Karte/Zahnrad waehlen -> oeffnet das Detail-Modal (selectedId !== null) im
  // Anzeige-Modus. Erneuter Klick auf dieselbe hebt die Auswahl auf (schliesst das
  // Modal). Beim Oeffnen/Schliessen den Bearbeiten-Modus zuruecksetzen. Signatur
  // unveraendert.
  const handleWaehlen = (id) => {
    setEditOffen(false);
    setEditFehler(null);
    setSelectedId((aktuell) => (aktuell === id ? null : id));
  };

  // "Aendern" im Detail-Modal: in den Bearbeiten-Modus schalten und die Felder aus
  // der ausgewaehlten Aufzeichnung vorbefuellen.
  const handleAendernStart = (recording) => {
    setEditEingabe(recordingZuEingabe(recording));
    setEditFehler(null);
    setEditOffen(true);
  };

  // "Abbrechen" im Bearbeiten-Modus: zurueck in den Anzeige-Modus (Modal bleibt
  // offen mit den unveraenderten Werten).
  const handleAendernAbbrechen = () => {
    setEditOffen(false);
    setEditFehler(null);
  };

  // "Speichern" im Bearbeiten-Modus: updateRecording mit den aktuellen Formwerten.
  // Bei created mit allen Feldern; bei nicht-created reicht label/purpose plus die
  // UNVERAENDERTEN Konfig-Werte (das Backend akzeptiert unveraenderte Konfig in
  // jedem Zustand; nur eine ABWEICHUNG loest 409 aus). Erfolg -> zurueck in den
  // Anzeige-Modus + Liste neu laden + selectedId behalten (Modal bleibt offen mit
  // frischen Werten). Fehler (409/422/Netz) -> ruhiger Hinweis im Modal.
  const handleAendernSpeichern = async (recording) => {
    if (!editGueltig) {
      return;
    }
    const purpose = editEingabe.purpose.trim();
    // label/purpose immer; Konfig: bei created aus dem Formular, sonst die
    // unveraenderten Werte der Aufzeichnung (so loest das Backend kein 409 aus).
    // purpose IMMER mitgeben (auch leer ""), damit ein geleerter Zweck den alten
    // Wert ueberschreibt -- updateRecording verwirft nur undefined/null, "" geht
    // durch.
    const payload = { label: editEingabe.label.trim(), purpose };
    if (recording.state === "created") {
      payload.mode = editEingabe.mode;
      payload.depth = editEingabe.depth;
      if (editEingabe.mode === "detail") {
        payload.intervalS = editEingabe.intervalS;
        payload.maxDurationS = editDauerStunden * 3600;
      } else {
        // aggregate: kein Intervall/keine Dauer (Sammlung zeitlich unbegrenzt).
        payload.intervalS = editEingabe.intervalS;
      }
    } else {
      // Konfig gesperrt: die unveraenderten Werte der Aufzeichnung mitgeben.
      payload.mode = recording.mode;
      payload.depth = recording.depth;
      payload.intervalS = recording.intervalS ?? 60;
      if (recording.maxDurationS !== null && recording.maxDurationS !== undefined) {
        payload.maxDurationS = recording.maxDurationS;
      }
    }
    try {
      await updateRecording(recording.id, payload);
      setEditOffen(false);
      setEditFehler(null);
      await ladeRecordings();
    } catch (aenderFehler) {
      // 409 = Name schon vergeben (Backend RecordingNameTaken; RecordingConfigLocked
      // sollte durch die UI-Sperre normal nicht auftreten) -> eigenen i18n-Hinweis
      // bevorzugen, konsistent zum Erstellen-Pfad. 422 / Netz: generisch.
      if (aenderFehler?.status === 409) {
        setEditFehler(t("beobachten.outboundlog.nameVergeben"));
      } else {
        setEditFehler(
          aenderFehler?.message ?? t("beobachten.outboundlog.aenderungFehler"),
        );
      }
    }
  };

  const ausgewaehlt = recordings.find((r) => r.id === selectedId) ?? null;

  // CSS-Modifier der Karten-Liste: 2-spaltig (auto-fill) ab zwei Eintraegen,
  // einspaltig (volle Breite) bei genau einem.
  const listeKlasse =
    recordings.length > 1
      ? "outboundrec-karte__liste outboundrec-karte__liste--grid"
      : "outboundrec-karte__liste";

  return (
    <div className="outboundrec">
      {/* ── Aufzeichnungs-KARTE: Kopf (Ruhe/Aktiv) + "Neue Aufzeichnung" + Liste ── */}
      <div className="outboundrec-karte">
        <div
          className={
            aktiveAufzeichnung
              ? "outboundrec-karte__kopf outboundrec-karte__kopf--aktiv"
              : "outboundrec-karte__kopf"
          }
        >
          {aktiveAufzeichnung ? (
            <>
              <span className="outboundrec-karte__status">
                <span
                  className="outboundrec-karte__punkt"
                  aria-hidden="true"
                />
                <span className="outboundrec-karte__statustext">
                  {t("beobachten.outboundlog.karte.statusAktiv", {
                    label: aktiveAufzeichnung.label,
                  })}
                </span>
              </span>
              <span className="outboundrec-karte__kopf-knoepfe">
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
              </span>
            </>
          ) : (
            <span className="outboundrec-karte__status">
              <CircleDot size={16} aria-hidden="true" />
              <span className="outboundrec-karte__titel">
                {t("beobachten.outboundlog.karte.titel")}
              </span>
              <span className="outboundrec-karte__statustext">
                {t("beobachten.outboundlog.karte.statusRuhe")}
              </span>
            </span>
          )}

          <button
            type="button"
            className="outboundrec-karte__neu"
            onClick={() => setErstellenOffen(true)}
          >
            <Plus size={15} aria-hidden="true" />
            <span>{t("beobachten.outboundlog.neueAufzeichnung")}</span>
          </button>
        </div>

        {/* Liste der Aufzeichnungen. Leer -> ruhiger Hinweis. */}
        {recordings.length === 0 ? (
          <p className="outboundlog__leer">
            {t("beobachten.outboundlog.listeLeer")}
          </p>
        ) : (
          <div className={listeKlasse}>
            {recordings.map((recording) => (
              <KompakteKarte
                key={recording.id}
                recording={recording}
                onWaehlen={handleWaehlen}
                onAktion={handleAktion}
              />
            ))}
          </div>
        )}
      </div>

      {/* ── ERSTELLEN-MODAL: Overlay nach Consent-Vorbild, komplette Maske. ── */}
      {erstellenOffen && (
        <ModalRahmen
          titel={t("beobachten.outboundlog.neueAufzeichnung")}
          onClose={() => setErstellenOffen(false)}
        >
          {/* Ruhiger Konflikt-Hinweis (start/resume mit 409). */}
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

          <div className="outboundlog__maske-inhalt">
            <LabelZweckFelder eingabe={eingabe} setFeld={setFeld} />
            <KonfigEingabeFelder
              eingabe={eingabe}
              setFeld={setFeld}
              setEingabe={setEingabe}
              dauerGueltig={dauerGueltig}
            />

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
        </ModalRahmen>
      )}

      {/* ── DETAIL-MODAL (bei selectedId !== null): Anzeige-Modus (nur lesend +
          Player + Loeschen + "Aendern") ODER Bearbeiten-Modus (Formular). ── */}
      {ausgewaehlt && (
        <ModalRahmen
          titel={t("beobachten.outboundlog.detailTitel")}
          onClose={() => {
            setSelectedId(null);
            setEditOffen(false);
            setEditFehler(null);
          }}
        >
          {editOffen ? (
            <div className="outboundlog__maske-inhalt">
              {/* Ruhiger Aenderungs-Fehler (409/422/Netz). */}
              {editFehler && (
                <div className="outboundlog__fehler" role="note">
                  {editFehler}
                </div>
              )}

              {/* label/purpose IMMER editierbar. */}
              <LabelZweckFelder eingabe={editEingabe} setFeld={setEditFeld} />

              {/* Konfig: bei created editierbar, sonst ruhiger gesperrt-Hinweis. */}
              {ausgewaehlt.state === "created" ? (
                <KonfigEingabeFelder
                  eingabe={editEingabe}
                  setFeld={setEditFeld}
                  setEingabe={setEditEingabe}
                  dauerGueltig={editDauerGueltig}
                />
              ) : (
                <KonfigGesperrt recording={ausgewaehlt} />
              )}

              <div className="outboundlog__abschluss">
                <button
                  type="button"
                  className="outboundlog__knopf outboundlog__knopf--abbrechen"
                  onClick={handleAendernAbbrechen}
                >
                  {t("beobachten.outboundlog.abbrechen")}
                </button>
                <button
                  type="button"
                  className="outboundlog__knopf outboundlog__knopf--primaer"
                  disabled={!editGueltig}
                  onClick={() => handleAendernSpeichern(ausgewaehlt)}
                >
                  {t("beobachten.outboundlog.speichern")}
                </button>
              </div>
            </div>
          ) : (
            <AufzeichnungsKarte
              recording={ausgewaehlt}
              ausgewaehlt={false}
              onWaehlen={() => {}}
              onAktion={handleAktion}
              onLoeschen={(recording) => setLoeschBestaetigung(recording)}
              onAendern={handleAendernStart}
            />
          )}
        </ModalRahmen>
      )}

      {/* ── LOESCHEN-BESTAETIGUNG: eigenes kleines Overlay UEBER dem Detail-Modal
          (z-index 95 > 90, < 100 Consent). Klick auf den Backdrop = Abbrechen. ── */}
      {loeschBestaetigung && (
        <div
          className="outboundrec-loeschmodal-overlay"
          onClick={() => setLoeschBestaetigung(null)}
        >
          <div
            className="outboundrec-loeschmodal"
            role="alertdialog"
            aria-modal="true"
            aria-label={t("beobachten.outboundlog.aktion.loeschen")}
            onClick={(e) => e.stopPropagation()}
          >
            <p className="outboundrec-loeschmodal__text">
              {t("beobachten.outboundlog.aktion.loeschenModalText", {
                label: loeschBestaetigung.label,
              })}
            </p>
            <div className="outboundrec-loeschmodal__knoepfe">
              <button
                type="button"
                className="outboundlog__knopf outboundlog__knopf--abbrechen"
                onClick={() => setLoeschBestaetigung(null)}
              >
                {t("beobachten.outboundlog.aktion.loeschenAbbrechen")}
              </button>
              <button
                type="button"
                className="outboundlog__knopf outboundlog__knopf--loeschen"
                onClick={() => handleAktion("delete", loeschBestaetigung)}
              >
                {t("beobachten.outboundlog.aktion.loeschenBestaetigen")}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
