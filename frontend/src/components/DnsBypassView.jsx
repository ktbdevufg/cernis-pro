// Netzweiter DNS-Umgehungs-Waechter (CERNIS PRO 2.0, E5) -- Reiter 2 "Umgehung im Netz".
//
// Lese-/Steuer-Ansicht der NETZWEITEN DNS-Umgehung: welche Geraete IM NETZ (nicht
// nur dieser Rechner) den erwarteten DNS umgehen -- Port 53 zu einem fremden
// Resolver (hart erkannt) oder eine moegliche DoH-Verbindung (heuristisch). Reines
// Frontend gegen die 4b-Routen GET /api/dns-bypass (+ /status + /start + /stop),
// gemappt in api/dnsBypass.js.
//
// CERNIS ist PASSIV: hier wird NICHTS erlaubt/blockiert, nur sichtbar gemacht.
// Anders als der host-lokale Reiter braucht die netzweite Sicht eine LAUFENDE
// Aufzeichnung (der Recorder liest den Netzverkehr passiv mit). Steuerung im Muster
// OutboundRecordingPanel, aber REDUZIERT: genau EINE Aufzeichnung, nur start/stop/
// status (keine Modi/Intervalle/Modals). Vor dem ERSTEN Start ein Einwilligungs-
// Dialog (Muster OutboundConsentDialog).
//
// KEINE Quittierung: die 4b-Routen kennen keine Ack-Route -> hier wird bewusst
// KEINE gebaut. Orange (Severity) NUR fuer offene Umgehungs-Befunde; das DoH-Badge
// ist NEUTRAL (heuristisch). t NIEMALS in useEffect/useMemo-Deps (Render-Loop-Falle).

import { CircleDot, Play, Square } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import {
  fetchDnsBypass,
  fetchDnsBypassStatus,
  startDnsBypass,
  stopDnsBypass,
} from "../api/dnsBypass.js";
import { fetchSettings, updateSetting } from "../api/settings.js";
import DnsBypassConsentDialog from "./DnsBypassConsentDialog.jsx";
import NpcapDialog from "./NpcapDialog.jsx";
import "./DnsBypassView.css";

// Marker der Sniff-Verfuegbarkeit aus dem Backend (permission_error, siehe
// sniffd_unavailable_reason). Es gibt genau EINEN: fehlt Npcap, ist die ganze
// Sniff-Familie auf dieser Plattform nicht nutzbar -- dann Ausgrau-Hinweis statt
// Start-Knopf. Ist Npcap erkannt, liefert das Backend gar keinen Marker.
//
// Bewusst derselbe Vergleich wie in OutboundView/TrafficView: exakt gegen den
// Marker-String, nicht gegen Textbestandteile. Der DNS-Waechter war die einzige
// Ansicht der Familie, die ihn nicht las -- er zeigte deshalb den Rohtext der
// Erfassungsschicht, wo die anderen beiden die Ursache benennen (Befund 52).
const NPCAP_MARKER = "NPCAP_MISSING";

function istNpcapMarker(marker) {
  return marker === NPCAP_MARKER;
}

// Anzeigereihenfolge der drei Kennzahlen: "Umgeher" zuerst (dort lohnt der Blick),
// dann "Anfragen gesamt", dann "erwartungsgemaess". key zeigt auf das Feld der
// Sicht, labelKey auf den i18n-Text, ton steuert die Optik (offen = Orange).
const KENNZAHLEN = [
  { key: "bypassTotal", labelKey: "countBypass", ton: "offen" },
  { key: "queriesTotal", labelKey: "countQueries", ton: "neutral" },
  { key: "expectedTotal", labelKey: "countExpected", ton: "neutral" },
];

// Eine ruhige Kennzahl-Karte: grosse Zahl + Label darunter. ton="offen" hebt die
// Zahl im Severity-Orange hervor, alles andere bleibt neutral. Muster wie
// DnsWatchView.KennzahlKarte.
function KennzahlKarte({ wert, label, ton }) {
  const klasse =
    ton === "offen"
      ? "dnsbypass-kennzahl dnsbypass-kennzahl--offen"
      : "dnsbypass-kennzahl";
  return (
    <div className={klasse}>
      <span className="dnsbypass-kennzahl__zahl">{wert}</span>
      <span className="dnsbypass-kennzahl__label">{label}</span>
    </div>
  );
}

// Eine Umgeher-Zeile: Titel (deviceName, sonst srcIp), darunter klein die
// Quell-IP (nur wenn der Titel der Name war, sonst stuende sie doppelt) + Ziel-IP
// + "×queryCount" + ggf. DoH-Badge. Rechts ein paar Beispiel-Qnames (best-effort,
// gedaempft). KEINE Quittier-Aktion (keine Ack-Route). Zeilen-Ton: offene
// Umgehung -> Orange-Akzent; ist der Befund als DoH bewertet, bleibt die ganze
// Zeile NEUTRAL (heuristisch, kein harter Befund).
function UmgeherZeile({ befund }) {
  const { t } = useTranslation();

  const titel = befund.deviceName ?? befund.srcIp;
  const zeigeIpUnten = befund.deviceName !== null;

  // Untertitel-Teile: nur vorhandene Felder, fehlende weglassen (S3-ehrlich).
  const subTeile = [];
  if (zeigeIpUnten) {
    subTeile.push(befund.srcIp);
  }
  // Ziel-Resolver: rohe IP IMMER sichtbar; der best-effort Name ergaenzt sie in
  // Klammern, wenn aufloesbar (kein Platzhalter, wenn er fehlt).
  const ziel = befund.resolverName
    ? `${befund.dstIp} (${befund.resolverName})`
    : befund.dstIp;
  subTeile.push(t("beobachten.dnsbypass.toTarget", { ziel }));
  subTeile.push(
    t("beobachten.dnsbypass.queriesSuffix", { count: befund.queryCount }),
  );

  // Zeilen-Ton: DoH -> neutral (heuristisch); sonst offene Umgehung -> Orange.
  const tonKlasse = befund.isDoh
    ? "dnsbypass-zeile"
    : "dnsbypass-zeile dnsbypass-zeile--offen";

  // Beispiel-Qnames: kompakt, gedaempft; nur wenn welche da sind.
  const beispiele = befund.sampleQnames.slice(0, 3);

  return (
    <li className={tonKlasse}>
      <div className="dnsbypass-zeile__main">
        <div className="dnsbypass-zeile__kopf">
          <span className="dnsbypass-zeile__title dnsbypass-mono">{titel}</span>
          {befund.isSelf && (
            <span className="dnsbypass-badge dnsbypass-badge--self">
              {t("beobachten.dnsbypass.selfBadge")}
            </span>
          )}
          {befund.isDoh && (
            <span className="dnsbypass-badge dnsbypass-badge--doh">
              {befund.dohSourceName
                ? t("beobachten.dnsbypass.dohBadgeNamed", {
                    quelle: befund.dohSourceName,
                  })
                : t("beobachten.dnsbypass.dohBadge")}
            </span>
          )}
        </div>
        <span className="dnsbypass-zeile__sub dnsbypass-mono">
          {subTeile.join(" · ")}
        </span>
        {beispiele.length > 0 && (
          <span className="dnsbypass-zeile__qnames dnsbypass-mono">
            {beispiele.join(", ")}
          </span>
        )}
      </div>
    </li>
  );
}

export default function DnsBypassView() {
  const { t } = useTranslation();

  // Verdichtete Sicht (findings + Zaehler + recording).
  const [sicht, setSicht] = useState(null);
  // Billiger Status-Poll (recording + collectedQueries + permissionError) --
  // treibt die Steuer-Karte UND die Ausgrau-Entscheidung.
  const [status, setStatus] = useState({
    recording: false,
    collectedQueries: 0,
    permissionError: null,
  });
  // Ob der NpcapDialog offen ist. Der Dialog kennt nur EINEN Fall (Npcap fehlt),
  // darum genuegt ein Ja/Nein -- Muster OutboundView.
  const [zeigeNpcapDialog, setZeigeNpcapDialog] = useState(false);
  // Ruhiger Hinweis-Streifen bei Lade-/Steuerfehler (kein Absturz).
  const [ladeFehler, setLadeFehler] = useState(false);
  // Ehrlicher Start-Fehlertext (aus {ok:false, error}) oder null.
  const [startFehler, setStartFehler] = useState(null);
  // Ob der Einwilligungs-Dialog offen ist (vor dem Start, wenn nicht erteilt).
  const [consentOffen, setConsentOffen] = useState(false);
  // Persistierte Einwilligung ins netzweite Mitlesen: "granted"|"denied"|
  // null(=unset)|"loading"(=Startwert, bis das Settings-Lesen durch ist). Muster
  // OutboundView.consent -- ueber das Setting dns_bypass_consent abgelegt, kein
  // sitzungslokaler State mehr (ein Neustart merkt die Entscheidung).
  const [consent, setConsent] = useState("loading");
  // Ob die Sicht schon mindestens einmal (mit laufender Aufzeichnung) geladen
  // wurde -- treibt den PROMINENTEN Leerzustand nur NACH einer Aufzeichnung.
  const [schonGeladen, setSchonGeladen] = useState(false);

  // Verdichtete Sicht laden und State setzen. Wird nach Start/Stop und beim Mount
  // aufgerufen. Fehler tolerieren (ruhiger Hinweis-Streifen).
  async function ladeSicht() {
    try {
      const ergebnis = await fetchDnsBypass();
      setSicht(ergebnis);
      setStatus((s) => ({ ...s, recording: ergebnis.recording }));
      setSchonGeladen(true);
      setLadeFehler(false);
    } catch {
      setLadeFehler(true);
    }
  }

  // Billiger Status-Poll (recording + collectedQueries). Getrennt von der teuren
  // Sicht, damit die Steuer-Karte guenstig aktuell bleibt.
  async function ladeStatus() {
    try {
      const ergebnis = await fetchDnsBypassStatus();
      setStatus(ergebnis);
      setLadeFehler(false);
    } catch {
      setLadeFehler(true);
    }
  }

  // Beim Mount: einmal Sicht + Status laden. t NIEMALS in dep-Array (react-i18next-
  // Regel) -- leeres dep-Array. Fehler tolerieren, kein Absturz.
  useEffect(() => {
    let abgebrochen = false;
    (async () => {
      try {
        const [sichtErgebnis, statusErgebnis] = await Promise.all([
          fetchDnsBypass(),
          fetchDnsBypassStatus(),
        ]);
        if (abgebrochen) {
          return;
        }
        setSicht(sichtErgebnis);
        setStatus(statusErgebnis);
        setSchonGeladen(true);
        setLadeFehler(false);
      } catch {
        if (!abgebrochen) {
          setLadeFehler(true);
        }
      }
    })();
    return () => {
      abgebrochen = true;
    };
  }, []);

  // Einwilligung beim Mount aus den Settings laden (Muster OutboundView). t NICHT
  // im dep-Array (react-i18next-Regel) -- leeres dep-Array, einmal beim Mount.
  // Fehlt/faellt das Lesen aus, bleibt consent null (dann fragt der Start-Knopf).
  useEffect(() => {
    let abgebrochen = false;
    (async () => {
      try {
        const settings = await fetchSettings();
        if (abgebrochen) {
          return;
        }
        setConsent(settings["dns_bypass_consent"] ?? null);
      } catch {
        if (!abgebrochen) {
          setConsent(null);
        }
      }
    })();
    return () => {
      abgebrochen = true;
    };
  }, []);

  // Aufzeichnung starten. Ist die Einwilligung erteilt ("granted"), direkt
  // starten. Sonst (denied/null/loading) den Consent-Dialog oeffnen und HIER
  // stoppen -- der eigentliche Start laeuft dann erst nach onGrant.
  const handleStart = async () => {
    if (consent !== "granted") {
      setConsentOffen(true);
      return;
    }
    await starteJetzt();
  };

  // Der eigentliche Start-Aufruf (nach erteilter Einwilligung). Das Backend reicht
  // einen legitimen Start-Fehler als {ok:false, error} durch (S3) -> ehrlich als
  // startFehler-Text zeigen, kein roter Alarm. Erfolg -> Status/Sicht neu laden.
  const starteJetzt = async () => {
    try {
      const antwort = await startDnsBypass(null);
      if (antwort && antwort.ok === false) {
        // Der Marker kann auch HIER herauskommen (die Vorpruefung des Backends
        // gibt ihn als Fehlertext zurueck). Dann NICHT als Rohtext anzeigen,
        // sondern in den Ausgrau-Zustand kippen -- derselbe Block, dieselbe
        // Ursache. Der Statuswert ist die eine Wahrheit, an der die Ansicht
        // haengt; er wird darum gesetzt, nicht ein zweiter Zustand daneben.
        if (istNpcapMarker(antwort.error)) {
          setStartFehler(null);
          setStatus((s) => ({ ...s, permissionError: antwort.error }));
          return;
        }
        setStartFehler(antwort.error ?? t("beobachten.dnsbypass.startFehler"));
        return;
      }
      setStartFehler(null);
      await ladeStatus();
      await ladeSicht();
    } catch {
      setLadeFehler(true);
    }
  };

  // Einwilligung erteilt: dauerhaft als "granted" persistieren (fehlertolerant --
  // UI laeuft auch bei Schreibfehler weiter), Dialog schliessen und sofort starten.
  // dontAsk wird beim Zustimmen nicht gesondert gebraucht (Zustimmen persistiert
  // ohnehin) -- Muster OutboundView.handleGrant.
  const handleConsentGrant = async (dontAsk) => {
    void dontAsk;
    try {
      await updateSetting("dns_bypass_consent", "granted");
    } catch (fehler) {
      console.error("Einwilligung speichern fehlgeschlagen", fehler);
    }
    setConsent("granted");
    setConsentOffen(false);
    await starteJetzt();
  };

  // Einwilligung abgelehnt: nur bei "Nicht mehr fragen" dauerhaft als "denied"
  // persistieren (fehlertolerant); sonst unset lassen (consent=null) -- dann fragt
  // der Start-Knopf beim naechsten Mal erneut. Dialog schliessen, NICHT starten
  // (Muster OutboundView.handleDeny).
  const handleConsentDeny = async (dontAsk) => {
    if (dontAsk) {
      try {
        await updateSetting("dns_bypass_consent", "denied");
      } catch (fehler) {
        console.error("Ablehnung speichern fehlgeschlagen", fehler);
      }
      setConsent("denied");
    } else {
      setConsent(null);
    }
    setConsentOffen(false);
  };

  // Aufzeichnung stoppen. Danach Status/Sicht neu laden (die Sicht bleibt mit den
  // bis dahin gesammelten Befunden stehen).
  const handleStop = async () => {
    try {
      await stopDnsBypass();
      setStartFehler(null);
      await ladeStatus();
      await ladeSicht();
    } catch {
      setLadeFehler(true);
    }
  };

  const findings = sicht?.findings ?? [];
  const expectedServers = sicht?.expectedServers ?? [];
  const recording = status.recording;

  // Liegt der Marker an, ist die Erfassung auf dieser Plattform gar nicht
  // moeglich. Dann ersetzt der Ausgrau-Block die Steuer-Karte -- ein Start-Knopf
  // waere eine Sackgasse, er koennte nur scheitern.
  const npcapFehlt = istNpcapMarker(status.permissionError);

  // PROMINENTER Leerzustand NUR nach einer Aufzeichnung ohne Befunde: schon
  // geladen, NICHT (mehr) am Aufzeichnen und keine Befunde. Sonst bleibt der
  // Voraussetzungs-Hinweis dezent (siehe unten).
  //
  // Bei anliegendem Marker entfaellt er: "Keine Umgehung erfasst" liest sich als
  // Befund ("es wurde geschaut, es war nichts"), obwohl gar nichts erfasst werden
  // KONNTE. Der Ausgrau-Block sagt die Wahrheit an seiner Stelle.
  const prominenterLeerzustand =
    schonGeladen && !recording && findings.length === 0 && !npcapFehlt;

  // Schliesst den NpcapDialog und liest den Status neu: hat der Nutzer Npcap
  // inzwischen eingerichtet, faellt der Marker weg und die Ansicht wird nutzbar,
  // ohne dass er das Programm neu starten muss (Muster OutboundView).
  const handleNpcapDialogSchliessen = () => {
    setZeigeNpcapDialog(false);
    void ladeStatus();
  };

  return (
    <div className="dnsbypass">
      {/* Ruhiger Hinweis-Streifen bei Lade-/Steuerfehler (Stil dnswatch__hinweis). */}
      {ladeFehler && (
        <div className="dnsbypass__hinweis" role="note">
          <span className="dnsbypass__hinweis-title">
            {t("beobachten.dnsbypass.hinweisTitel")}
          </span>
          <span className="dnsbypass__hinweis-text">
            {t("beobachten.dnsbypass.loadError")}
          </span>
        </div>
      )}

      {/* Npcap-Ausgrau-Block: traegt der Status den Marker, ist die Erfassung auf
          dieser Plattform nicht moeglich. Dann STATT der Steuer-Karte ein
          ehrlicher Hinweis mit dem Knopf zum NpcapDialog -- derselbe Text
          (npcap.inlineHint) und derselbe Weg, die Aussenkontakte und Per-App-
          Verkehr schon anbieten. Kein neuer Wortlaut, keine eigene Diagnose. */}
      {npcapFehlt && (
        <div className="dnsbypass__hinweis" role="note">
          <span className="dnsbypass__hinweis-text">{t("npcap.inlineHint")}</span>
          <button
            type="button"
            className="dnsbypass__hinweis-button"
            onClick={() => setZeigeNpcapDialog(true)}
          >
            {t("npcap.installBtn")}
          </button>
        </div>
      )}

      {/* ── Steuer-Karte: EINE Aufzeichnung, nur start/stop/status. Entfaellt bei
          anliegendem Marker -- der Start koennte dort nur scheitern. ── */}
      {!npcapFehlt && (
      <div
        className={
          recording
            ? "dnsbypass-karte dnsbypass-karte--aktiv"
            : "dnsbypass-karte"
        }
      >
        <span className="dnsbypass-karte__status">
          {recording ? (
            <span className="dnsbypass-karte__punkt" aria-hidden="true" />
          ) : (
            <CircleDot size={16} aria-hidden="true" />
          )}
          <span className="dnsbypass-karte__statustext">
            {recording
              ? t("beobachten.dnsbypass.statusAktiv", {
                  count: status.collectedQueries,
                })
              : t("beobachten.dnsbypass.statusRuhe")}
          </span>
        </span>

        {recording ? (
          <button
            type="button"
            className="dnsbypass-karte__knopf dnsbypass-karte__knopf--stop"
            onClick={handleStop}
          >
            <Square size={15} aria-hidden="true" />
            <span>{t("beobachten.dnsbypass.stop")}</span>
          </button>
        ) : (
          <button
            type="button"
            className="dnsbypass-karte__knopf dnsbypass-karte__knopf--start"
            onClick={handleStart}
          >
            <Play size={15} aria-hidden="true" />
            <span>{t("beobachten.dnsbypass.start")}</span>
          </button>
        )}
      </div>
      )}

      {/* Ehrlicher Start-Fehlertext (aus {ok:false, error}). Warnton, kein Alarm.
          Entfaellt bei anliegendem Marker: dort ERSETZT der Ausgrau-Block ihn --
          sonst staende der Rohtext der Erfassungsschicht daneben und benannte
          dieselbe Ursache ein zweites Mal, schlechter. */}
      {startFehler && !npcapFehlt && (
        <div className="dnsbypass__fehler" role="note">
          {startFehler}
        </div>
      )}

      {/* Drei Kennzahlen: Umgeher (orange) / Anfragen gesamt / erwartungsgemaess. */}
      <div className="dnsbypass__kennzahlen">
        {KENNZAHLEN.map((k) => (
          <KennzahlKarte
            key={k.key}
            wert={sicht ? sicht[k.key] : 0}
            label={t(`beobachten.dnsbypass.${k.labelKey}`)}
            ton={k.ton}
          />
        ))}
      </div>

      {/* Liste der Umgeher ODER Leerzustand. Der PROMINENTE Leerzustand (nach einer
          Aufzeichnung ohne Befunde) benennt die Netz-Voraussetzung deutlich; sonst
          ein ruhiger Standard-Leerzustand. */}
      {findings.length === 0 ? (
        prominenterLeerzustand ? (
          <div className="dnsbypass__leer-prominent" role="note">
            <span className="dnsbypass__leer-titel">
              {t("beobachten.dnsbypass.emptyProminentTitle")}
            </span>
            <span className="dnsbypass__leer-text">
              {t("beobachten.dnsbypass.emptyProminentText")}
            </span>
          </div>
        ) : (
          <p className="dnsbypass__empty">
            {recording
              ? t("beobachten.dnsbypass.emptyRecording")
              : t("beobachten.dnsbypass.emptyIdle")}
          </p>
        )
      ) : (
        <ul className="dnsbypass__liste">
          {findings.map((befund) => (
            <UmgeherZeile
              key={`${befund.srcIp}:${befund.dstIp}`}
              befund={befund}
            />
          ))}
        </ul>
      )}

      {/* Dezenter, DAUERHAFTER Voraussetzungs-Hinweis (Netz sichtbar noetig). */}
      <div className="dnsbypass__voraussetzung" role="note">
        {t("beobachten.dnsbypass.prereqHint")}
      </div>

      {/* Fusszeile: erwartete DNS-Server + Einstellungs-Hinweis (nur Text). */}
      <div className="dnsbypass__footer">
        <span className="dnsbypass__footer-servers dnsbypass-mono">
          {t("beobachten.dnsbypass.footerExpected", {
            servers:
              expectedServers.length > 0 ? expectedServers.join(", ") : "—",
          })}
        </span>
        <span className="dnsbypass__footer-hint">
          {t("beobachten.dnsbypass.settingsHint")}
        </span>
      </div>

      {/* Einwilligungs-Dialog vor dem ERSTEN Start. */}
      {consentOffen && (
        <DnsBypassConsentDialog
          onGrant={handleConsentGrant}
          onDeny={handleConsentDeny}
        />
      )}

      {/* NpcapDialog: Erklaer-/Download-Dialog bei fehlendem Npcap. Beim
          Schliessen wird der Status neu gelesen -- eine zwischenzeitliche
          Einrichtung wirkt sofort, ohne Neustart. */}
      {zeigeNpcapDialog && (
        <NpcapDialog onClose={handleNpcapDialogSchliessen} />
      )}
    </div>
  );
}
