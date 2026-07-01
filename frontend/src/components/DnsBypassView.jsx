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
import DnsBypassConsentDialog from "./DnsBypassConsentDialog.jsx";
import "./DnsBypassView.css";

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
  subTeile.push(t("beobachten.dnsbypass.toTarget", { ziel: befund.dstIp }));
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
  // Billiger Status-Poll (recording + collectedQueries) -- treibt die Steuer-Karte.
  const [status, setStatus] = useState({ recording: false, collectedQueries: 0 });
  // Ruhiger Hinweis-Streifen bei Lade-/Steuerfehler (kein Absturz).
  const [ladeFehler, setLadeFehler] = useState(false);
  // Ehrlicher Start-Fehlertext (aus {ok:false, error}) oder null.
  const [startFehler, setStartFehler] = useState(null);
  // Ob der Einwilligungs-Dialog offen ist (nur vor dem ERSTEN Start).
  const [consentOffen, setConsentOffen] = useState(false);
  // Sitzungslokale Einwilligung: einmal erteilt, kein wiederkehrender Dialog.
  const [consentErteilt, setConsentErteilt] = useState(false);
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

  // Aufzeichnung starten. Vor dem ERSTEN Start (Einwilligung noch nicht erteilt)
  // den Consent-Dialog oeffnen und HIER stoppen -- der eigentliche Start laeuft
  // dann erst nach onGrant. Ist die Einwilligung schon da, direkt starten.
  const handleStart = async () => {
    if (!consentErteilt) {
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

  // Einwilligung erteilt: Dialog schliessen, sitzungslokal merken und sofort
  // starten. Ablehnen: nur den Dialog schliessen (nicht starten).
  const handleConsentGrant = async () => {
    setConsentOffen(false);
    setConsentErteilt(true);
    await starteJetzt();
  };
  const handleConsentDeny = () => {
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

  // PROMINENTER Leerzustand NUR nach einer Aufzeichnung ohne Befunde: schon
  // geladen, NICHT (mehr) am Aufzeichnen und keine Befunde. Sonst bleibt der
  // Voraussetzungs-Hinweis dezent (siehe unten).
  const prominenterLeerzustand =
    schonGeladen && !recording && findings.length === 0;

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

      {/* ── Steuer-Karte: EINE Aufzeichnung, nur start/stop/status. ── */}
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

      {/* Ehrlicher Start-Fehlertext (aus {ok:false, error}). Warnton, kein Alarm. */}
      {startFehler && (
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
    </div>
  );
}
