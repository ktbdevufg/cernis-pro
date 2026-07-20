// Einstellungs-Ansicht (CERNIS PRO 2.0)
// Eigener Modus (kein Reiter), erreichbar über das Zahnrad in der Kopfzeile.
// Nutzt das function-shell-Muster der übrigen Bereiche: Zurück-Weg + Titel
// über dem Inhalt. Aufgebaut aus benannten Sektionen, sodass weitere Optionen
// später einfach als zusätzliche Sektionen/Zeilen dazukommen.
//
// Die View hält keinen eigenen State und keine localStorage-Logik. Die Sprache
// kommt als Prop (lang) und wird über onLangChange zurückgemeldet — die
// Persistenz bleibt in App.jsx (single source of truth).

import { Trash2, Upload } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { fetchAllRules, lookupService, parsePortliste } from "../api/analysis.js";
import {
  CAPTURE_ACCESS_REVOKE_OUTCOME,
  CAPTURE_ACCESS_STATE,
  fetchCaptureAccess,
  revokeCaptureAccess,
} from "../api/captureAccess.js";
import {
  fetchDefaultCredsState,
  armDefaultCreds,
} from "../api/security.js";
import {
  fetchSettings,
  updateSetting,
  updateSecret,
  secretGesetzt,
} from "../api/settings.js";
import { CODES, mitCode } from "../lib/fehlercodes.js";
import { FunctionShell } from "../components/AreaShell.jsx";
import DefaultCredsConsentDialog from "../components/DefaultCredsConsentDialog.jsx";
import DefaultCredsListeSektion from "../components/DefaultCredsListeSektion.jsx";
import "./SettingsView.css";

// Default-Portmengen der Auffälligkeits-Engine. SPIEGELT bewusst die Backend-
// Defaults aus backend/domain/analysis/rules.py (Regeln host_remote_access_port
// bzw. host_backdoor_port). Doppelquelle ist gewollt und dokumentiert: das
// Backend liefert bei frischer DB KEINEN Setting-Wert (dann greift dort der
// Built-in-Default), das Frontend würde sonst leere Tabellen zeigen. Hier nur die
// Zahlen-Defaults — die Regel-Liste selbst kommt live aus GET /api/analysis/rules/all.
const DEFAULT_AUFFAELLIGE_PORTS = [
  21, 23, 139, 445, 2049, 3306, 3389, 5432, 5800, 5900, 5984, 6379, 8080, 8443,
  9200, 27017,
];
const DEFAULT_KRITISCHE_PORTS = [
  1243, 1337, 6670, 6711, 6712, 6713, 6771, 12345, 12346, 20034, 27374, 27444,
  27665, 30303, 31335, 31337, 31338, 32768, 54283, 65000,
];

// Auswahlwerte des Schwellen-Dropdowns „Viele hohe Ports". Default-Anzeige 10
// (entspricht dem Backend-Default threshold der Regel host_many_high_ports).
const PORT_COUNT_OPTIONEN = [5, 8, 10, 12, 15, 20];
const DEFAULT_PORT_COUNT = 10;

// Obergrenze für den Portlisten-Upload (Schnitt 7). Eine .txt mit Portnummern
// ist winzig; alles über 1 MB wird abgelehnt, statt den Browser zu blockieren.
const UPLOAD_MAX_BYTES = 1024 * 1024;

// Settings-Keys der zwei editierbaren DNS-Wächter-Listen (JSON-Arrays von
// IP-Strings). SPIEGELT bewusst die Modulkonstanten aus backend/api/dns_watch.py
// (DNS_EXPECTED_SERVERS_KEY / DNS_DOH_PROVIDERS_KEY) — normale Listen-Settings,
// leeres Array zulässig (dann greift der Backend-Default, z. B. Gateway).
const DNS_EXPECTED_SERVERS_KEY = "dns_expected_servers";
const DNS_DOH_PROVIDERS_KEY = "dns_doh_providers";

// Grobe IP-Prüfung ohne Library (analog OutboundView.istLokaleIp): IPv4 als vier
// 0–255-Oktette ODER ein IPv6-Kandidat (enthält ":" und nur Hex/Doppelpunkt).
// Bewusst pragmatisch — die Listen sind editierbare Hinweise, keine sicherheits-
// kritische Eingabe; offensichtlicher Müll wird abgewiesen, nicht jeder Edge-Case.
function istGueltigeIp(roh) {
  const ip = String(roh).trim();
  if (ip === "") {
    return false;
  }
  // IPv4: vier Oktette 0–255.
  const v4 = ip.split(".");
  if (v4.length === 4) {
    return v4.every((teil) => {
      if (!/^\d{1,3}$/.test(teil)) {
        return false;
      }
      const zahl = Number(teil);
      return zahl >= 0 && zahl <= 255;
    });
  }
  // IPv6: grob — enthält ":" und besteht nur aus Hex-Ziffern/Doppelpunkten.
  if (ip.includes(":")) {
    return /^[0-9a-fA-F:]+$/.test(ip) && ip.length >= 2;
  }
  return false;
}

// Eine Settings-Zeile: Label links, Bedienelement rechts.
function SettingsZeile({ label, children }) {
  return (
    <div className="settings__row">
      <span className="settings__row-label">{label}</span>
      <div className="settings__row-control">{children}</div>
    </div>
  );
}

// Eine benannte Sektion mit Überschrift und Zeilen.
function SettingsSektion({ title, children }) {
  return (
    <section className="settings__section">
      <h3 className="settings__section-title">{title}</h3>
      <div className="settings__section-body">{children}</div>
    </section>
  );
}

// Setting-Key der Startseiten-Bereichsschalter. Wert ist ein JSON-Objekt mit
// Booleans; fehlt der Key -> alle Defaults true. SPIEGELT bewusst OverviewView
// (SECTIONS_KEY / SECTION_DEFAULTS): OverviewView liest, diese Sektion schreibt.
const STARTSEITE_KEY = "overview_sections";

// Default-Sichtbarkeit aller Startseiten-Bereiche (alle true). Identisch zu
// OverviewView.SECTION_DEFAULTS — fehlt ein einzelner Schalter, gilt sein Default.
const STARTSEITE_DEFAULTS = {
  status: true,
  schnellzugriff: true,
  beachtenswert: true,
  cve: true,
  kennzahlen: true,
  status_monitoring: true,
};

// Liest `overview_sections` aus dem rohen Settings-Dict und mischt es über die
// Defaults. Toleriert Objekt UND JSON-String (Backend-Settings tragen Werte teils
// als String) — exakt OverviewView.leseSektionen. Nur echte Booleans werden
// übernommen, alles andere fällt auf den Default true zurück; unparsbar -> Defaults.
function leseStartseite(settings) {
  const roh = settings?.[STARTSEITE_KEY];
  let obj = null;
  if (roh && typeof roh === "object") {
    obj = roh;
  } else if (typeof roh === "string" && roh.length > 0) {
    try {
      const geparst = JSON.parse(roh);
      if (geparst && typeof geparst === "object") {
        obj = geparst;
      }
    } catch {
      obj = null;
    }
  }
  if (!obj) {
    return { ...STARTSEITE_DEFAULTS };
  }
  const ergebnis = { ...STARTSEITE_DEFAULTS };
  for (const key of Object.keys(STARTSEITE_DEFAULTS)) {
    if (typeof obj[key] === "boolean") {
      ergebnis[key] = obj[key];
    }
  }
  return ergebnis;
}

// Startseiten-Sektion: eigener Daten-State analog FritzBoxSektion/Auffaelligkeit-
// Sektion (laden beim Mount, schreiben pro Änderung gegen die Settings-API).
// onGespeichert ist das gemeinsame zeigeGespeichert-Feedback aus SettingsView.
//
// Pro Bereich ein Toggle im auffaelligkeit__rule/__switch-Stil. status_monitoring
// ist ein Detail der Status-Zeile -> eingerückt und deaktiviert, solange status aus
// ist (nicht versteckt, damit der Nutzer es kennt).
function OverviewSektion({ onGespeichert }) {
  const { t } = useTranslation();

  const [sektionen, setSektionen] = useState(STARTSEITE_DEFAULTS);
  const [ladeStatus, setLadeStatus] = useState("laedt"); // laedt | bereit | fehler
  const [speicherFehler, setSpeicherFehler] = useState(false);

  // Einmal beim Mount laden, über die Defaults mischen. Fehler nicht verschlucken
  // (console.error) und in den Lade-Fehlerzustand gehen.
  useEffect(() => {
    let aktiv = true;
    (async () => {
      try {
        const settings = await fetchSettings();
        if (!aktiv) {
          return;
        }
        setSektionen(leseStartseite(settings));
        setLadeStatus("bereit");
      } catch (fehler) {
        if (!aktiv) {
          return;
        }
        console.error("Startseiten-Einstellungen laden fehlgeschlagen:", fehler);
        setLadeStatus("fehler");
      }
    })();
    return () => {
      aktiv = false;
    };
  }, []);

  // Einen Bereich umschalten: lokal spiegeln, dann das KOMPLETTE Objekt schreiben
  // (updateSetting serialisiert wie bei den anderen Objekt-Settings). Bei Fehler
  // den Speicher-Fehlerzustand setzen, lokalen Zustand belassen.
  const handleToggle = async (key, an) => {
    setSpeicherFehler(false);
    const naechste = { ...sektionen, [key]: an };
    setSektionen(naechste);
    try {
      await updateSetting(STARTSEITE_KEY, naechste);
      onGespeichert();
    } catch (fehler) {
      console.error("overview_sections speichern fehlgeschlagen:", fehler);
      setSpeicherFehler(true);
    }
  };

  if (ladeStatus === "laedt") {
    return (
      <SettingsSektion title={t("settings.startseite.title")}>
        <div className="settings__row">
          <span className="settings__hint">
            {t("settings.startseite.loading")}
          </span>
        </div>
      </SettingsSektion>
    );
  }

  if (ladeStatus === "fehler") {
    return (
      <SettingsSektion title={t("settings.startseite.title")}>
        <div className="settings__row">
          <span className="settings__hint settings__hint--error">
            {t("settings.startseite.loadError")}
          </span>
        </div>
      </SettingsSektion>
    );
  }

  // Reihenfolge laut Briefing. status_monitoring folgt direkt auf status, optisch
  // als dessen Unterpunkt.
  return (
    <SettingsSektion title={t("settings.startseite.title")}>
      {/* Teil B — Bereichs-Schalter als abgesetzte Boxen (Text-Box + Kästchen-Box).
          status_monitoring ist Detail der Status-Zeile: eingerückt und deaktiviert,
          solange status aus ist. Datengetrieben, Reihenfolge laut Briefing.
          Im auffaelligkeit__block, damit die Schalter denselben seitlichen
          Innenabstand wie Port- und Regel-Zeilen haben (nicht am Rand kleben). */}
      <div className="auffaelligkeit__block">
        <ul className="auffaelligkeit__rules">
        {[
          { key: "status", sub: false, disabled: false },
          { key: "statusMonitoring", schalter: "status_monitoring", sub: true },
          { key: "schnellzugriff", sub: false },
          { key: "beachtenswert", sub: false },
          { key: "cve", sub: false },
          { key: "kennzahlen", sub: false },
        ].map((eintrag) => {
          const schalter = eintrag.schalter ?? eintrag.key;
          const istDeaktiviert = schalter === "status_monitoring" && !sektionen.status;
          return (
            <li
              key={schalter}
              className={
                eintrag.sub
                  ? "auffaelligkeit__rule startseite__rule--sub"
                  : "auffaelligkeit__rule"
              }
            >
              <span className="auffaelligkeit__rule-label">
                <span className="auffaelligkeit__rule-title">
                  {t(`settings.startseite.${eintrag.key}`)}
                </span>
              </span>
              <span className="auffaelligkeit__rule-switchbox">
                <input
                  type="checkbox"
                  className="auffaelligkeit__switch"
                  checked={sektionen[schalter]}
                  disabled={istDeaktiviert}
                  onChange={(e) => handleToggle(schalter, e.target.checked)}
                />
              </span>
            </li>
          );
        })}
        </ul>
      </div>

      <p className="settings__hint">{t("settings.startseite.hint")}</p>

      {speicherFehler ? (
        <span className="settings__hint settings__hint--error">
          {mitCode(t("settings.startseite.saveError"), CODES.E_501)}
        </span>
      ) : null}
    </SettingsSektion>
  );
}

// FritzBox-Sektion: einzige Sektion mit eigenem Daten-State (laden + schreiben
// gegen die Settings-API). onGespeichert ist das vorhandene zeigeGespeichert
// aus SettingsView — gemeinsames Feedback-Muster, nicht neu erfunden.
//
// Klartext-Passwörter kommen NIE vom Server: passwortWert startet leer und wird
// nur beim Tippen befüllt; ist es beim Speichern leer, bleibt ein gesetztes
// Secret unangetastet.
function FritzBoxSektion({ onGespeichert }) {
  const { t } = useTranslation();

  const [hostWert, setHostWert] = useState("");
  const [userWert, setUserWert] = useState("");
  const [passwortWert, setPasswortWert] = useState("");
  const [passwortGesetzt, setPasswortGesetzt] = useState(false);
  const [ladeStatus, setLadeStatus] = useState("laedt"); // laedt | bereit | fehler
  const [speicherStatus, setSpeicherStatus] = useState("idle"); // idle | speichert | fehler

  // Einmal beim Mount laden. Fehler nicht verschlucken (console.error) und in
  // den Lade-Fehlerzustand gehen.
  useEffect(() => {
    let aktiv = true;
    (async () => {
      try {
        const settings = await fetchSettings();
        if (!aktiv) {
          return;
        }
        setHostWert(String(settings.fritz_host ?? ""));
        setUserWert(String(settings.fritz_user ?? ""));
        setPasswortGesetzt(secretGesetzt(settings, "fritz_password"));
        setLadeStatus("bereit");
      } catch (fehler) {
        if (!aktiv) {
          return;
        }
        console.error("FritzBox-Einstellungen laden fehlgeschlagen:", fehler);
        setLadeStatus("fehler");
      }
    })();
    return () => {
      aktiv = false;
    };
  }, []);

  // Passwort entfernen: leerer Wert löscht das Secret serverseitig (idempotent).
  const handlePasswortEntfernen = async () => {
    setSpeicherStatus("speichert");
    try {
      await updateSecret("fritz_password", "");
      setPasswortGesetzt(false);
      setPasswortWert("");
      setSpeicherStatus("idle");
      onGespeichert();
    } catch (fehler) {
      console.error("FritzBox-Passwort entfernen fehlgeschlagen:", fehler);
      setSpeicherStatus("fehler");
    }
  };

  // Sektion speichern: Host/User immer, Passwort nur wenn etwas getippt wurde.
  // Bei Fehler abbrechen (try/catch ums Ganze).
  const handleSpeichern = async () => {
    setSpeicherStatus("speichert");
    try {
      await updateSetting("fritz_host", hostWert);
      await updateSetting("fritz_user", userWert);
      if (passwortWert !== "") {
        await updateSecret("fritz_password", passwortWert);
        setPasswortGesetzt(true);
        setPasswortWert("");
      }
      setSpeicherStatus("idle");
      onGespeichert();
    } catch (fehler) {
      console.error("FritzBox-Einstellungen speichern fehlgeschlagen:", fehler);
      setSpeicherStatus("fehler");
    }
  };

  if (ladeStatus === "laedt") {
    return (
      <SettingsSektion title={t("settings.fritzbox.title")}>
        <div className="settings__row">
          <span className="settings__hint">{t("settings.fritzbox.loading")}</span>
        </div>
      </SettingsSektion>
    );
  }

  if (ladeStatus === "fehler") {
    return (
      <SettingsSektion title={t("settings.fritzbox.title")}>
        <div className="settings__row">
          <span className="settings__hint settings__hint--error">
            {t("settings.fritzbox.loadError")}
          </span>
        </div>
      </SettingsSektion>
    );
  }

  return (
    <SettingsSektion title={t("settings.fritzbox.title")}>
      <SettingsZeile label={t("settings.fritzbox.host")}>
        <input
          className="settings__input"
          type="text"
          value={hostWert}
          onChange={(e) => setHostWert(e.target.value)}
          placeholder={t("settings.fritzbox.hostPlaceholder")}
        />
      </SettingsZeile>

      <SettingsZeile label={t("settings.fritzbox.user")}>
        <input
          className="settings__input"
          type="text"
          value={userWert}
          onChange={(e) => setUserWert(e.target.value)}
          placeholder={t("settings.fritzbox.userPlaceholder")}
        />
      </SettingsZeile>

      <SettingsZeile label={t("settings.fritzbox.password")}>
        <div className="settings__field">
          <input
            className="settings__input"
            type="password"
            value={passwortWert}
            onChange={(e) => setPasswortWert(e.target.value)}
            autoComplete="new-password"
          />
          {passwortGesetzt && passwortWert === "" ? (
            <span className="settings__hint">
              {t("settings.fritzbox.passwordIsSet")}
            </span>
          ) : null}
          {passwortGesetzt ? (
            <button
              type="button"
              className="settings__link-button"
              onClick={handlePasswortEntfernen}
              disabled={speicherStatus === "speichert"}
            >
              {t("settings.fritzbox.passwordRemove")}
            </button>
          ) : null}
        </div>
      </SettingsZeile>

      <div className="settings__row settings__row--actions">
        {speicherStatus === "fehler" ? (
          <span className="settings__hint settings__hint--error">
            {mitCode(t("settings.fritzbox.saveError"), CODES.E_501)}
          </span>
        ) : (
          <span />
        )}
        <button
          type="button"
          className="settings__button"
          onClick={handleSpeichern}
          disabled={speicherStatus === "speichert"}
        >
          {t("settings.fritzbox.save")}
        </button>
      </div>
    </SettingsSektion>
  );
}

// Service-Name zu einem gelisteten Port: zeigt den gecachten Namen oder lädt ihn
// einmalig per GET /api/analysis/service nach. Der Cache liegt in der Sektion
// (über beide Tabellen geteilt), damit ein Port nur einmal aufgelöst wird. Ein
// fehlgeschlagener Lookup oder ein unbekannter Port -> „—", kein Crash.
function ServiceZelle({ port, serviceCache, onServiceGeladen }) {
  const { t } = useTranslation();
  const eintragVorhanden = Object.prototype.hasOwnProperty.call(
    serviceCache,
    port,
  );

  useEffect(() => {
    if (eintragVorhanden) {
      return undefined;
    }
    let aktiv = true;
    (async () => {
      try {
        const name = await lookupService(port);
        if (aktiv) {
          onServiceGeladen(port, name);
        }
      } catch (ursache) {
        console.error("Service-Lookup fehlgeschlagen:", ursache);
        if (aktiv) {
          onServiceGeladen(port, null);
        }
      }
    })();
    return () => {
      aktiv = false;
    };
  }, [port, eintragVorhanden, onServiceGeladen]);

  const service = serviceCache[port];
  return <>{service ?? t("settings.auffaelligkeit.serviceUnknown")}</>;
}

// Eine Port→Service-Liste (auffällig ODER kritisch) im Box-Schema. Stateless bzgl.
// Persistenz: aktive und abgewählte Ports kommen als Props, jede Änderung meldet
// die Sektion über die Handler zurück (sie hält das Speichern). variante steuert
// nur die Optik ("auffaellig"|"kritisch") über die severity-Tokens. Der
// serviceCache wird über beide Listen geteilt (siehe ServiceZelle).
//
// Anzeige-Liste = Vereinigung aus aktivePorts (angehakt) + disabledPorts
// (abgewählt), sortiert nach Portnummer. Das Kästchen schaltet einen Port zwischen
// aktiv/abgewählt; der Mülleimer entfernt ihn endgültig aus BEIDEN Listen.
function PortTabelle({
  variante,
  titel,
  aktivePorts,
  disabledPorts,
  standardPorts,
  onToggle,
  onRemove,
  onAdd,
  onReset,
  serviceCache,
  onServiceGeladen,
}) {
  const { t } = useTranslation();

  const [eingabe, setEingabe] = useState("");
  const [service, setService] = useState(null); // Auto-Lookup-Ergebnis (oder null)
  const [fehler, setFehler] = useState(""); // dezente Inline-Meldung (i18n-Key)

  // Anzeige-Liste: Vereinigung beider Listen, dedupliziert + sortiert. Ein Set der
  // aktiven Ports steuert das Kästchen; ein Set ALLER Ports verhindert Duplikate
  // beim Hinzufügen (ein abgewählter Port zählt als vorhanden).
  const aktivSet = new Set(aktivePorts);
  const alleSet = new Set([...aktivePorts, ...disabledPorts]);
  const anzeigePorts = [...alleSet].sort((a, b) => a - b);

  // Standard-Ports der Rubrik (aus konfig.defaults durchgereicht): nur SELBST
  // hinzugefügte Ports (nicht in dieser Menge) bekommen den Mülleimer. Standard-
  // Ports behalten ihr Kästchen, aber kein Entfernen.
  const standardSet = new Set(standardPorts);

  // Auto-Lookup beim Tippen, entprellt (~300ms). Eine leere/ungültige Eingabe
  // löst keinen Aufruf aus; ein fehlgeschlagener Lookup ist „—", kein Crash.
  useEffect(() => {
    const roh = eingabe.trim();
    if (roh === "") {
      setService(null);
      return undefined;
    }
    const port = Number(roh);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      setService(null);
      return undefined;
    }
    let aktiv = true;
    const handle = setTimeout(async () => {
      try {
        const name = await lookupService(port);
        if (aktiv) {
          setService(name);
        }
      } catch (ursache) {
        // Lookup fehlgeschlagen -> Leer-Zustand „—", nicht crashen.
        console.error("Service-Lookup fehlgeschlagen:", ursache);
        if (aktiv) {
          setService(null);
        }
      }
    }, 300);
    return () => {
      aktiv = false;
      clearTimeout(handle);
    };
  }, [eingabe]);

  // Port hinzufügen: Range 1–65535 erzwingen (ungültig -> Inline-Meldung, kein
  // Eintrag), Duplikate gegen die GESAMTE Anzeige-Liste verhindern (aktiv ODER
  // abgewählt). Der neue Port kommt aktiv (angehakt) hinzu — das übernimmt onAdd.
  const handleHinzufuegen = () => {
    const port = Number(eingabe.trim());
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      setFehler("portInvalid");
      return;
    }
    if (alleSet.has(port)) {
      setFehler("portDuplicate");
      return;
    }
    onAdd(port);
    setEingabe("");
    setService(null);
    setFehler("");
  };

  const handleEingabe = (wert) => {
    setEingabe(wert);
    if (fehler !== "") {
      setFehler("");
    }
  };

  const klasse = `auffaelligkeit__table auffaelligkeit__table--${variante}`;

  return (
    <div className={klasse}>
      <div className="auffaelligkeit__table-head">
        <span className="auffaelligkeit__badge">{titel}</span>
        <button
          type="button"
          className="settings__link-button"
          onClick={onReset}
        >
          {t("settings.auffaelligkeit.reset")}
        </button>
      </div>

      {/* Teil E — oranger Hinweis, nur wenn abgewählte Ports existieren. */}
      {disabledPorts.length > 0 ? (
        <span className="auffaelligkeit__disabled-hint">
          {t("settings.auffaelligkeit.disabledHint", {
            count: disabledPorts.length,
          })}
        </span>
      ) : null}

      {/* Box-Schema: pro Zeile vier abgesetzte Boxen, Einträge untereinander. */}
      {anzeigePorts.length === 0 ? (
        <span className="auffaelligkeit__empty">
          {t("settings.auffaelligkeit.empty")}
        </span>
      ) : (
        <ul className="auffaelligkeit__portlist">
          {anzeigePorts.map((port) => {
            const aktiv = aktivSet.has(port);
            const istStandard = standardSet.has(port);
            const zeilenKlasse = aktiv
              ? "auffaelligkeit__portrow"
              : "auffaelligkeit__portrow auffaelligkeit__portrow--inaktiv";
            return (
              <li key={port} className={zeilenKlasse}>
                <span className="auffaelligkeit__port-box">{port}</span>
                <span className="auffaelligkeit__port-service">
                  <ServiceZelle
                    port={port}
                    serviceCache={serviceCache}
                    onServiceGeladen={onServiceGeladen}
                  />
                </span>
                <span className="auffaelligkeit__port-toggle">
                  <input
                    type="checkbox"
                    className="auffaelligkeit__switch"
                    checked={aktiv}
                    aria-label={t(
                      aktiv
                        ? "settings.auffaelligkeit.portActive"
                        : "settings.auffaelligkeit.portInactive",
                    )}
                    onChange={(e) => onToggle(port, e.target.checked)}
                  />
                </span>
                {/* Mülleimer nur bei selbst hinzugefügten Ports. Standard-Ports
                    (in der defaults-Liste) bekommen an gleicher Stelle einen
                    leeren Platzhalter, damit die Spalten bündig bleiben. */}
                {istStandard ? (
                  <span
                    className="auffaelligkeit__port-remove auffaelligkeit__port-remove--leer"
                    aria-hidden="true"
                  />
                ) : (
                  <span className="auffaelligkeit__port-remove">
                    <button
                      type="button"
                      className="auffaelligkeit__remove"
                      aria-label={t("settings.auffaelligkeit.remove")}
                      title={t("settings.auffaelligkeit.remove")}
                      onClick={() => onRemove(port)}
                    >
                      <Trash2 size={14} aria-hidden="true" />
                    </button>
                  </span>
                )}
              </li>
            );
          })}
        </ul>
      )}

      <div className="auffaelligkeit__add">
        <input
          className="settings__input auffaelligkeit__add-input"
          type="number"
          min={1}
          max={65535}
          inputMode="numeric"
          value={eingabe}
          onChange={(e) => handleEingabe(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              handleHinzufuegen();
            }
          }}
          placeholder={t("settings.auffaelligkeit.addPortPlaceholder")}
        />
        <span className="auffaelligkeit__add-service">
          {service ?? t("settings.auffaelligkeit.serviceUnknown")}
        </span>
        <button
          type="button"
          className="settings__button"
          onClick={handleHinzufuegen}
        >
          {t("settings.auffaelligkeit.add")}
        </button>
      </div>
      {fehler !== "" ? (
        <span className="settings__hint settings__hint--error">
          {t(`settings.auffaelligkeit.${fehler}`)}
        </span>
      ) : null}
    </div>
  );
}

// Portlisten-Upload (Schnitt 7, Konzept §3.2) für EINE Liste (auffällig ODER
// kritisch), eingebettet direkt unter der jeweiligen PortTabelle. Liest clientseitig
// eine .txt per FileReader, parst sie über die reine parsePortliste, zeigt eine
// inline-Vorschau (Chips mit Service-Name, ungültig-Zähler, Überschneidung mit der
// bestehenden Liste) und schreibt erst beim Klick auf „Ergänzen"/„Ersetzen" — über
// den GLEICHEN onChange-Pfad wie die Tabelle (schreibePortliste). Die rohe Datei
// verlässt das Frontend NIE; nur das validierte Array geht ans Backend.
//
// variante steuert (wie bei PortTabelle) nur die Optik über die severity-Tokens.
// bestehendePorts ist die aktuelle Liste (für Union beim Ergänzen + Überschneidungs-
// Hinweis). serviceCache/onServiceGeladen werden mit den Tabellen geteilt, damit ein
// schon bekannter Port nicht erneut nachgeschlagen wird.
function PortUpload({
  variante,
  bestehendePorts,
  onErsetzen,
  onErgaenzen,
  serviceCache,
  onServiceGeladen,
}) {
  const { t } = useTranslation();
  const dateiInputRef = useRef(null);

  // Vorschau-Zustand: null = keine Datei gewählt. Sonst das Parse-Ergebnis plus der
  // Dateiname (rein informativ in der Vorschau).
  const [vorschau, setVorschau] = useState(null); // { name, gueltig, ungueltig, gesamt }
  const [fehler, setFehler] = useState(""); // dezenter Inline-Fehler (i18n-Key) oder ""

  const bestehendSet = new Set(bestehendePorts);

  const handleDatei = (datei) => {
    if (!datei) {
      return;
    }
    setFehler("");
    setVorschau(null);
    // Größengrenze VOR dem Lesen prüfen — eine Portliste ist winzig.
    if (datei.size > UPLOAD_MAX_BYTES) {
      setFehler("uploadTooLarge");
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      const text = typeof reader.result === "string" ? reader.result : "";
      const ergebnis = parsePortliste(text);
      setVorschau({ name: datei.name, ...ergebnis });
    };
    reader.onerror = () => {
      console.error("Datei lesen fehlgeschlagen:", reader.error);
      setFehler("uploadReadError");
    };
    reader.readAsText(datei);
  };

  // Nach Schreiben (oder Abbrechen) die Vorschau verwerfen und das File-Input
  // zurücksetzen, damit dieselbe Datei erneut gewählt werden kann.
  const verwerfen = () => {
    setVorschau(null);
    setFehler("");
    if (dateiInputRef.current) {
      dateiInputRef.current.value = "";
    }
  };

  const klasse = `auffaelligkeit__upload auffaelligkeit__upload--${variante}`;

  // Vorschau-Kennzahlen.
  const gueltig = vorschau ? vorschau.gueltig : [];
  const bereitsVorhanden = gueltig.filter((p) => bestehendSet.has(p)).length;
  const leer = gueltig.length === 0;

  return (
    <div className={klasse}>
      <div className="auffaelligkeit__upload-trigger">
        <input
          ref={dateiInputRef}
          type="file"
          accept=".txt,text/plain"
          className="auffaelligkeit__upload-input"
          onChange={(e) => handleDatei(e.target.files?.[0] ?? null)}
        />
        <button
          type="button"
          className="settings__button auffaelligkeit__upload-button"
          onClick={() => dateiInputRef.current?.click()}
        >
          <Upload size={14} aria-hidden="true" />
          {t("settings.auffaelligkeit.upload")}
        </button>
        <span className="settings__hint auffaelligkeit__upload-hint">
          {t("settings.auffaelligkeit.uploadHint")}
        </span>
      </div>

      {fehler !== "" ? (
        <span className="settings__hint settings__hint--error">
          {t(`settings.auffaelligkeit.${fehler}`)}
        </span>
      ) : null}

      {vorschau ? (
        <div className="auffaelligkeit__preview">
          <div className="auffaelligkeit__preview-head">
            <span className="auffaelligkeit__badge">
              {t("settings.auffaelligkeit.previewTitle")}
            </span>
            <span className="auffaelligkeit__preview-file">{vorschau.name}</span>
          </div>

          <span className="settings__hint">
            {t("settings.auffaelligkeit.previewValidCount", {
              count: gueltig.length,
            })}
          </span>

          {leer ? (
            <span className="auffaelligkeit__preview-empty">
              {t("settings.auffaelligkeit.previewNone")}
            </span>
          ) : (
            <div className="auffaelligkeit__chips">
              {gueltig.map((port) => (
                <span key={port} className="auffaelligkeit__chip">
                  <span className="auffaelligkeit__chip-port">{port}</span>
                  <span className="auffaelligkeit__chip-service">
                    <ServiceZelle
                      port={port}
                      serviceCache={serviceCache}
                      onServiceGeladen={onServiceGeladen}
                    />
                  </span>
                </span>
              ))}
            </div>
          )}

          {vorschau.ungueltig > 0 ? (
            <span className="settings__hint auffaelligkeit__preview-invalid">
              {t("settings.auffaelligkeit.previewInvalidLines", {
                count: vorschau.ungueltig,
              })}
            </span>
          ) : null}

          {bereitsVorhanden > 0 ? (
            <span className="settings__hint">
              {t("settings.auffaelligkeit.previewAlreadyPresent", {
                count: bereitsVorhanden,
              })}
            </span>
          ) : null}

          <div className="auffaelligkeit__preview-actions">
            <button
              type="button"
              className="settings__button"
              disabled={leer}
              onClick={() => {
                // Ergänzen: Union mit der bestehenden Liste, dedupliziert + sortiert.
                const vereint = [
                  ...new Set([...bestehendePorts, ...gueltig]),
                ].sort((a, b) => a - b);
                onErgaenzen(vereint);
                verwerfen();
              }}
            >
              {t("settings.auffaelligkeit.previewAdd")}
            </button>
            <button
              type="button"
              className="settings__button"
              disabled={leer}
              onClick={() => {
                // Ersetzen: die hochgeladene Liste ersetzt die bestehende komplett.
                onErsetzen([...gueltig]);
                verwerfen();
              }}
            >
              {t("settings.auffaelligkeit.previewReplace")}
            </button>
            <button
              type="button"
              className="settings__link-button"
              onClick={verwerfen}
            >
              {t("settings.auffaelligkeit.previewCancel")}
            </button>
          </div>

          {leer ? (
            <span className="settings__hint auffaelligkeit__preview-empty-hint">
              {t("settings.auffaelligkeit.previewEmptyHint")}
            </span>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

// Sektion „Was ist auffällig?": eigener Daten-State analog FritzBoxSektion (laden
// beim Mount, schreiben pro Änderung gegen die Settings-/analysis-API).
// onGespeichert ist das gemeinsame zeigeGespeichert-Feedback aus SettingsView.
//
// Vier Blöcke: (1) zwei Port→Service-Tabellen, (2) Schwellen-Dropdown, (3) Regel-
// An/Aus, (4) Ehrlichkeits-Hinweis.
function AuffaelligkeitSektion({ onGespeichert }) {
  const { t } = useTranslation();

  const [auffaelligePorts, setAuffaelligePorts] = useState([]);
  const [kritischePorts, setKritischePorts] = useState([]);
  // Abgewählte Ports je Liste (Teil D): reine Frontend-Keys, additiv. Sie ändern
  // NICHT, was das Backend auswertet — dort steht nur die jeweils aktive Liste.
  const [auffaelligDisabled, setAuffaelligDisabled] = useState([]);
  const [kritischDisabled, setKritischDisabled] = useState([]);
  const [portCount, setPortCount] = useState(DEFAULT_PORT_COUNT);
  const [regeln, setRegeln] = useState([]); // [{ id, title, severity, disabled }]
  const [serviceCache, setServiceCache] = useState({}); // port -> name|null
  const [ladeStatus, setLadeStatus] = useState("laedt"); // laedt | bereit | fehler
  const [speicherFehler, setSpeicherFehler] = useState(false);

  // Cache-Schreiber für die ServiceZelle. useCallback, damit der useEffect der
  // Zelle nicht bei jedem Render neu feuert.
  const merkeService = useCallback((port, name) => {
    setServiceCache((vorher) => ({ ...vorher, [port]: name }));
  }, []);

  // Einmal beim Mount laden: Settings (Portlisten/Schwelle/Deaktivierungen) und
  // die Regel-Liste. Fehlt ein Port-Listen-Key (frische DB), greift im Backend der
  // Built-in-Default und das Frontend sieht KEINEN Wert -> dann die Default-
  // Konstanten zeigen. Fehler nicht verschlucken; in den Lade-Fehlerzustand gehen.
  useEffect(() => {
    let aktiv = true;
    (async () => {
      try {
        const [settings, alleRegeln] = await Promise.all([
          fetchSettings(),
          fetchAllRules(),
        ]);
        if (!aktiv) {
          return;
        }
        setAuffaelligePorts(
          Array.isArray(settings.analysis_suspicious_ports)
            ? [...settings.analysis_suspicious_ports].sort((a, b) => a - b)
            : DEFAULT_AUFFAELLIGE_PORTS,
        );
        setKritischePorts(
          Array.isArray(settings.analysis_critical_ports)
            ? [...settings.analysis_critical_ports].sort((a, b) => a - b)
            : DEFAULT_KRITISCHE_PORTS,
        );
        // Disabled-Listen: fehlt der Key (alte DB), als leeres Array behandeln.
        setAuffaelligDisabled(
          Array.isArray(settings.analysis_suspicious_ports_disabled)
            ? [...settings.analysis_suspicious_ports_disabled].sort(
                (a, b) => a - b,
              )
            : [],
        );
        setKritischDisabled(
          Array.isArray(settings.analysis_critical_ports_disabled)
            ? [...settings.analysis_critical_ports_disabled].sort(
                (a, b) => a - b,
              )
            : [],
        );
        setPortCount(
          Number.isInteger(settings.analysis_port_count_threshold)
            ? settings.analysis_port_count_threshold
            : DEFAULT_PORT_COUNT,
        );
        setRegeln(
          alleRegeln.map((r) => ({
            id: r.id,
            title: r.title,
            severity: r.severity,
            disabled: Boolean(r.disabled),
          })),
        );
        setLadeStatus("bereit");
      } catch (fehler) {
        if (!aktiv) {
          return;
        }
        console.error("Auffälligkeits-Einstellungen laden fehlgeschlagen:", fehler);
        setLadeStatus("fehler");
      }
    })();
    return () => {
      aktiv = false;
    };
  }, []);

  // Block 1: eine Portliste schreiben (auffällig/kritisch). Erst lokal spiegeln,
  // dann persistieren; bei Fehler den Speicher-Fehlerzustand setzen.
  const schreibePortliste = async (key, setLocal, neueListe) => {
    setSpeicherFehler(false);
    setLocal(neueListe);
    try {
      await updateSetting(key, neueListe);
      onGespeichert();
    } catch (fehler) {
      console.error(`${key} speichern fehlgeschlagen:`, fehler);
      setSpeicherFehler(true);
    }
  };

  // Schreibt BEIDE Listen einer Rubrik (aktiv + disabled) atomar gegen die API.
  // Erst lokal spiegeln, dann zwei updateSetting-Aufrufe; bei Fehler den
  // Speicher-Fehlerzustand setzen. Genutzt von Kästchen-Toggle und Mülleimer.
  const schreibeListenpaar = async (konfig, neuAktiv, neuDisabled) => {
    setSpeicherFehler(false);
    konfig.setAktiv(neuAktiv);
    konfig.setDisabled(neuDisabled);
    try {
      await updateSetting(konfig.aktivKey, neuAktiv);
      await updateSetting(konfig.disabledKey, neuDisabled);
      onGespeichert();
    } catch (fehler) {
      console.error(`${konfig.aktivKey} speichern fehlgeschlagen:`, fehler);
      setSpeicherFehler(true);
    }
  };

  // Kästchen umschalten (Teil D). Anhaken: Port aus disabled raus, in aktiv rein.
  // Abwählen: Port aus aktiv raus, in disabled rein. Beide Listen sortiert.
  const handlePortToggle = (konfig, port, anhaken) => {
    if (anhaken) {
      const neuAktiv = [...konfig.aktiv, port].sort((a, b) => a - b);
      const neuDisabled = konfig.disabled.filter((p) => p !== port);
      schreibeListenpaar(konfig, neuAktiv, neuDisabled);
    } else {
      const neuAktiv = konfig.aktiv.filter((p) => p !== port);
      const neuDisabled = [...konfig.disabled, port].sort((a, b) => a - b);
      schreibeListenpaar(konfig, neuAktiv, neuDisabled);
    }
  };

  // Mülleimer (Teil D): Port endgültig aus BEIDEN Listen entfernen.
  const handlePortRemove = (konfig, port) => {
    const neuAktiv = konfig.aktiv.filter((p) => p !== port);
    const neuDisabled = konfig.disabled.filter((p) => p !== port);
    schreibeListenpaar(konfig, neuAktiv, neuDisabled);
  };

  // „Hinzufügen" (Teil D): neuer Port kommt aktiv (angehakt) hinzu, disabled bleibt.
  const handlePortAdd = (konfig, port) => {
    const neuAktiv = [...konfig.aktiv, port].sort((a, b) => a - b);
    schreibePortliste(konfig.aktivKey, konfig.setAktiv, neuAktiv);
  };

  // „Auf Standard zurücksetzen" (Teil D): aktive Liste auf die Standard-Ports,
  // disabled-Liste leeren — alle Standard-Ports also wieder aktiv.
  const handlePortReset = (konfig) => {
    schreibeListenpaar(konfig, [...konfig.defaults], []);
  };

  // Upload-Pfad (Schnitt 7): geschriebene Liste ist die aktive Liste; die darin
  // enthaltenen Ports werden aus disabled entfernt (sonst Doppelung aktiv+disabled).
  const handlePortUpload = (konfig, neueAktiv) => {
    const aktivSet = new Set(neueAktiv);
    const neuDisabled = konfig.disabled.filter((p) => !aktivSet.has(p));
    schreibeListenpaar(konfig, neueAktiv, neuDisabled);
  };

  // Block 2: die Schwelle schreiben.
  const handlePortCount = async (wert) => {
    const zahl = Number(wert);
    setSpeicherFehler(false);
    setPortCount(zahl);
    try {
      await updateSetting("analysis_port_count_threshold", zahl);
      onGespeichert();
    } catch (fehler) {
      console.error("analysis_port_count_threshold speichern fehlgeschlagen:", fehler);
      setSpeicherFehler(true);
    }
  };

  // Block 3: eine Regel an-/ausschalten. Schalter aus -> id ins
  // analysis_disabled_rules-Array; Schalter an -> id raus. Nach dem Schreiben
  // lokal spiegeln (konsistenter Zustand ohne erneuten Roundtrip).
  const handleRegelToggle = async (regelId, neuDisabled) => {
    setSpeicherFehler(false);
    const naechste = regeln.map((r) =>
      r.id === regelId ? { ...r, disabled: neuDisabled } : r,
    );
    setRegeln(naechste);
    const disabledIds = naechste.filter((r) => r.disabled).map((r) => r.id);
    try {
      await updateSetting("analysis_disabled_rules", disabledIds);
      onGespeichert();
    } catch (fehler) {
      console.error("analysis_disabled_rules speichern fehlgeschlagen:", fehler);
      setSpeicherFehler(true);
    }
  };

  if (ladeStatus === "laedt") {
    return (
      <SettingsSektion title={t("settings.auffaelligkeit.title")}>
        <div className="settings__row">
          <span className="settings__hint">
            {t("settings.auffaelligkeit.loading")}
          </span>
        </div>
      </SettingsSektion>
    );
  }

  if (ladeStatus === "fehler") {
    return (
      <SettingsSektion title={t("settings.auffaelligkeit.title")}>
        <div className="settings__row">
          <span className="settings__hint settings__hint--error">
            {t("settings.auffaelligkeit.loadError")}
          </span>
        </div>
      </SettingsSektion>
    );
  }

  // Listen-Konfigurationen: bündeln je Rubrik die beiden Settings-Keys, die
  // Standard-Ports und die State-Setter. Die Handler oben arbeiten generisch
  // darauf, sodass auffällig/kritisch denselben Pfad teilen.
  const auffaelligKonfig = {
    aktivKey: "analysis_suspicious_ports",
    disabledKey: "analysis_suspicious_ports_disabled",
    defaults: DEFAULT_AUFFAELLIGE_PORTS,
    aktiv: auffaelligePorts,
    disabled: auffaelligDisabled,
    setAktiv: setAuffaelligePorts,
    setDisabled: setAuffaelligDisabled,
  };
  const kritischKonfig = {
    aktivKey: "analysis_critical_ports",
    disabledKey: "analysis_critical_ports_disabled",
    defaults: DEFAULT_KRITISCHE_PORTS,
    aktiv: kritischePorts,
    disabled: kritischDisabled,
    setAktiv: setKritischePorts,
    setDisabled: setKritischDisabled,
  };

  return (
    <SettingsSektion title={t("settings.auffaelligkeit.title")}>
      {/* Block 1 — zwei getrennte Port-Listen, je mit Upload darunter. */}
      <div className="auffaelligkeit__block">
        <div className="auffaelligkeit__listengruppe">
          <PortTabelle
            variante="auffaellig"
            titel={t("settings.auffaelligkeit.suspiciousTitle")}
            aktivePorts={auffaelligePorts}
            disabledPorts={auffaelligDisabled}
            standardPorts={auffaelligKonfig.defaults}
            serviceCache={serviceCache}
            onServiceGeladen={merkeService}
            onToggle={(port, anhaken) =>
              handlePortToggle(auffaelligKonfig, port, anhaken)
            }
            onRemove={(port) => handlePortRemove(auffaelligKonfig, port)}
            onAdd={(port) => handlePortAdd(auffaelligKonfig, port)}
            onReset={() => handlePortReset(auffaelligKonfig)}
          />
          <PortUpload
            variante="auffaellig"
            bestehendePorts={auffaelligePorts}
            serviceCache={serviceCache}
            onServiceGeladen={merkeService}
            onErgaenzen={(neu) => handlePortUpload(auffaelligKonfig, neu)}
            onErsetzen={(neu) => handlePortUpload(auffaelligKonfig, neu)}
          />
        </div>
        <div className="auffaelligkeit__listengruppe">
          <PortTabelle
            variante="kritisch"
            titel={t("settings.auffaelligkeit.criticalTitle")}
            aktivePorts={kritischePorts}
            disabledPorts={kritischDisabled}
            standardPorts={kritischKonfig.defaults}
            serviceCache={serviceCache}
            onServiceGeladen={merkeService}
            onToggle={(port, anhaken) =>
              handlePortToggle(kritischKonfig, port, anhaken)
            }
            onRemove={(port) => handlePortRemove(kritischKonfig, port)}
            onAdd={(port) => handlePortAdd(kritischKonfig, port)}
            onReset={() => handlePortReset(kritischKonfig)}
          />
          <PortUpload
            variante="kritisch"
            bestehendePorts={kritischePorts}
            serviceCache={serviceCache}
            onServiceGeladen={merkeService}
            onErgaenzen={(neu) => handlePortUpload(kritischKonfig, neu)}
            onErsetzen={(neu) => handlePortUpload(kritischKonfig, neu)}
          />
        </div>
      </div>

      {/* Block 2 — Schwellen-Dropdown „Viele hohe Ports". */}
      <div className="auffaelligkeit__block">
        <span className="auffaelligkeit__badge auffaelligkeit__badge--neutral">
          {t("settings.auffaelligkeit.thresholdTitle")}
        </span>
        <div className="auffaelligkeit__threshold">
          <span className="settings__row-label">
            {t("settings.auffaelligkeit.thresholdLabel")}
          </span>
          <select
            className="settings__select"
            value={portCount}
            onChange={(e) => handlePortCount(e.target.value)}
          >
            {PORT_COUNT_OPTIONEN.map((wert) => (
              <option key={wert} value={wert}>
                {wert}
              </option>
            ))}
          </select>
          <span className="settings__row-label">
            {t("settings.auffaelligkeit.thresholdUnit")}
          </span>
        </div>
        <span className="settings__hint">
          {t("settings.auffaelligkeit.thresholdHint")}
        </span>
      </div>

      {/* Block 3 — Regel-An/Aus. */}
      <div className="auffaelligkeit__block">
        <span className="auffaelligkeit__badge auffaelligkeit__badge--neutral">
          {t("settings.auffaelligkeit.rulesTitle")}
        </span>
        <span className="settings__hint">
          {t("settings.auffaelligkeit.rulesHint")}
        </span>
        {regeln.length === 0 ? (
          <span className="settings__hint">
            {t("settings.auffaelligkeit.rulesEmpty")}
          </span>
        ) : (
          <ul className="auffaelligkeit__rules">
            {regeln.map((regel) => {
              const dotVariante =
                regel.severity === "critical"
                  ? "kritisch"
                  : regel.severity === "notable"
                    ? "auffaellig"
                    : "neutral";
              return (
                <li key={regel.id} className="auffaelligkeit__rule">
                  {/* Severity-Böppel als eigenes abgesetztes Kästchen ganz links. */}
                  <span className="auffaelligkeit__rule-sevbox">
                    <span
                      className={`auffaelligkeit__dot auffaelligkeit__dot--${dotVariante}`}
                      aria-hidden="true"
                    />
                  </span>
                  {/* Breite Text-Box mit der Bezeichnung. */}
                  <span className="auffaelligkeit__rule-label">
                    <span className="auffaelligkeit__rule-title">
                      {regel.title}
                    </span>
                  </span>
                  {/* Separate Box mit dem Kästchen rechts. */}
                  <span className="auffaelligkeit__rule-switchbox">
                    <input
                      type="checkbox"
                      className="auffaelligkeit__switch"
                      checked={!regel.disabled}
                      onChange={(e) =>
                        handleRegelToggle(regel.id, !e.target.checked)
                      }
                    />
                  </span>
                </li>
              );
            })}
          </ul>
        )}
      </div>

      {/* Block 4 — Ehrlichkeits-Hinweis. */}
      <div className="auffaelligkeit__block auffaelligkeit__honesty">
        <span className="auffaelligkeit__badge auffaelligkeit__badge--neutral">
          {t("settings.auffaelligkeit.honestyTitle")}
        </span>
        <p className="settings__hint">
          {t("settings.auffaelligkeit.honestyText")}
        </p>
      </div>

      {speicherFehler ? (
        <span className="settings__hint settings__hint--error">
          {mitCode(t("settings.auffaelligkeit.saveError"), CODES.E_501)}
        </span>
      ) : null}
    </SettingsSektion>
  );
}

// Eine editierbare IP-Liste (DNS-Wächter): Liste der IP-Strings mit Mülleimer je
// Eintrag + Eingabefeld zum Hinzufügen. Stateless bzgl. Persistenz — die aktuelle
// Liste kommt als Prop, jede Änderung meldet die Sektion über onChange zurück (sie
// hält das Speichern). Leeres Array ist zulässig (dann greift der Backend-Default).
// Validierung über istGueltigeIp; Duplikate werden abgewiesen (Inline-Meldung).
function IpListe({ titel, hinweis, ips, onChange }) {
  const { t } = useTranslation();

  const [eingabe, setEingabe] = useState("");
  const [fehler, setFehler] = useState(""); // dezente Inline-Meldung (i18n-Key) oder ""

  const handleHinzufuegen = () => {
    const ip = eingabe.trim();
    if (!istGueltigeIp(ip)) {
      setFehler("ipInvalid");
      return;
    }
    if (ips.includes(ip)) {
      setFehler("ipDuplicate");
      return;
    }
    onChange([...ips, ip]);
    setEingabe("");
    setFehler("");
  };

  const handleEingabe = (wert) => {
    setEingabe(wert);
    if (fehler !== "") {
      setFehler("");
    }
  };

  const handleEntfernen = (ip) => {
    onChange(ips.filter((eintrag) => eintrag !== ip));
  };

  return (
    <div className="auffaelligkeit__block">
      <span className="auffaelligkeit__badge auffaelligkeit__badge--neutral">
        {titel}
      </span>
      <span className="settings__hint">{hinweis}</span>

      {ips.length === 0 ? (
        <span className="auffaelligkeit__empty">
          {t("settings.dnswatch.listEmpty")}
        </span>
      ) : (
        <ul className="dnsip__list">
          {ips.map((ip) => (
            <li key={ip} className="dnsip__row">
              <span className="dnsip__box">{ip}</span>
              <span className="auffaelligkeit__port-remove">
                <button
                  type="button"
                  className="auffaelligkeit__remove"
                  aria-label={t("settings.dnswatch.remove")}
                  title={t("settings.dnswatch.remove")}
                  onClick={() => handleEntfernen(ip)}
                >
                  <Trash2 size={14} aria-hidden="true" />
                </button>
              </span>
            </li>
          ))}
        </ul>
      )}

      <div className="auffaelligkeit__add">
        <input
          className="settings__input auffaelligkeit__add-input"
          type="text"
          value={eingabe}
          onChange={(e) => handleEingabe(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              handleHinzufuegen();
            }
          }}
          placeholder={t("settings.dnswatch.addPlaceholder")}
        />
        <button
          type="button"
          className="settings__button"
          onClick={handleHinzufuegen}
        >
          {t("settings.dnswatch.add")}
        </button>
      </div>
      {fehler !== "" ? (
        <span className="settings__hint settings__hint--error">
          {t(`settings.dnswatch.${fehler}`)}
        </span>
      ) : null}
    </div>
  );
}

// DNS-Wächter-Sektion: zwei editierbare IP-Listen (erwartete DNS-Server + bekannte
// DoH-Anbieter). Eigener Daten-State analog AuffaelligkeitSektion (laden beim Mount,
// schreiben pro Änderung gegen die Settings-API). onGespeichert ist das gemeinsame
// zeigeGespeichert-Feedback aus SettingsView. Fehlt ein Key (frische DB), gilt das
// leere Array — dann greift im Backend der Default (z. B. Gateway als DNS-Server).
function DnsWatchSektion({ onGespeichert }) {
  const { t } = useTranslation();

  const [expectedServers, setExpectedServers] = useState([]);
  const [dohProviders, setDohProviders] = useState([]);
  const [ladeStatus, setLadeStatus] = useState("laedt"); // laedt | bereit | fehler
  const [speicherFehler, setSpeicherFehler] = useState(false);

  // Einmal beim Mount laden. Nur valide String-Arrays übernehmen; sonst leeres
  // Array (Backend-Default greift). Fehler nicht verschlucken; Lade-Fehlerzustand.
  useEffect(() => {
    let aktiv = true;
    (async () => {
      try {
        const settings = await fetchSettings();
        if (!aktiv) {
          return;
        }
        setExpectedServers(
          Array.isArray(settings[DNS_EXPECTED_SERVERS_KEY])
            ? settings[DNS_EXPECTED_SERVERS_KEY].filter(
                (eintrag) => typeof eintrag === "string",
              )
            : [],
        );
        setDohProviders(
          Array.isArray(settings[DNS_DOH_PROVIDERS_KEY])
            ? settings[DNS_DOH_PROVIDERS_KEY].filter(
                (eintrag) => typeof eintrag === "string",
              )
            : [],
        );
        setLadeStatus("bereit");
      } catch (fehler) {
        if (!aktiv) {
          return;
        }
        console.error("DNS-Wächter-Einstellungen laden fehlgeschlagen:", fehler);
        setLadeStatus("fehler");
      }
    })();
    return () => {
      aktiv = false;
    };
  }, []);

  // Eine Liste schreiben: erst lokal spiegeln, dann persistieren; bei Fehler den
  // Speicher-Fehlerzustand setzen (Muster wie AuffaelligkeitSektion.schreibePortliste).
  const schreibeListe = async (key, setLocal, neueListe) => {
    setSpeicherFehler(false);
    setLocal(neueListe);
    try {
      await updateSetting(key, neueListe);
      onGespeichert();
    } catch (fehler) {
      console.error(`${key} speichern fehlgeschlagen:`, fehler);
      setSpeicherFehler(true);
    }
  };

  if (ladeStatus === "laedt") {
    return (
      <SettingsSektion title={t("settings.dnswatch.title")}>
        <div className="settings__row">
          <span className="settings__hint">{t("settings.dnswatch.loading")}</span>
        </div>
      </SettingsSektion>
    );
  }

  if (ladeStatus === "fehler") {
    return (
      <SettingsSektion title={t("settings.dnswatch.title")}>
        <div className="settings__row">
          <span className="settings__hint settings__hint--error">
            {t("settings.dnswatch.loadError")}
          </span>
        </div>
      </SettingsSektion>
    );
  }

  return (
    <SettingsSektion title={t("settings.dnswatch.title")}>
      <IpListe
        titel={t("settings.dnswatch.expectedTitle")}
        hinweis={t("settings.dnswatch.expectedHint")}
        ips={expectedServers}
        onChange={(neu) =>
          schreibeListe(DNS_EXPECTED_SERVERS_KEY, setExpectedServers, neu)
        }
      />
      <IpListe
        titel={t("settings.dnswatch.dohTitle")}
        hinweis={t("settings.dnswatch.dohHint")}
        ips={dohProviders}
        onChange={(neu) =>
          schreibeListe(DNS_DOH_PROVIDERS_KEY, setDohProviders, neu)
        }
      />

      {speicherFehler ? (
        <span className="settings__hint settings__hint--error">
          {mitCode(t("settings.dnswatch.saveError"), CODES.E_501)}
        </span>
      ) : null}
    </SettingsSektion>
  );
}

// Standardzugangs-Sektion (Etappe 2): scharfer Session-Schalter für die Opt-in-
// Sonderfunktion „Standardzugänge prüfen". Anders als die übrigen Sektionen
// schreibt sie NICHT gegen die Settings-API, sondern liest/setzt den sitzungs-
// weiten Freischalt-Zustand über den Security-Endpunkt. Der Zustand ist NICHT
// persistent (kein localStorage) — beim Mount wird er gelesen und der Schalter
// danach gesetzt.
//
// Einschalten (aus -> an) verlangt ZUERST einen Bestätigungs-Dialog (aktiver
// Login-Versuch, nur Sitzung). Erst nach Bestätigung armDefaultCreds(true) und
// Schalter an. Abbrechen -> nichts passiert. Ausschalten (an -> aus) braucht
// KEINE Bestätigung: direkt armDefaultCreds(false). Fehler (Backend nicht
// erreichbar) werden ruhig behandelt: der Schalter bleibt im letzten sicheren
// Zustand, eine kurze Meldung erscheint, kein Absturz.
function DefaultCredsSektion({ onGespeichert }) {
  const { t } = useTranslation();

  const [armed, setArmed] = useState(false);
  const [ladeStatus, setLadeStatus] = useState("laedt"); // laedt | bereit | fehler
  const [dialogOffen, setDialogOffen] = useState(false);
  const [fehler, setFehler] = useState(false); // Schreibfehler beim arm

  // Einmal beim Mount den sitzungsweiten Zustand lesen. Fehler nicht verschlucken
  // (console.error) und in den Lade-Fehlerzustand gehen — KEIN stiller Fallback
  // auf „armed".
  useEffect(() => {
    let aktiv = true;
    (async () => {
      try {
        const zustand = await fetchDefaultCredsState();
        if (!aktiv) {
          return;
        }
        setArmed(Boolean(zustand?.armed));
        setLadeStatus("bereit");
      } catch (ursache) {
        if (!aktiv) {
          return;
        }
        console.error("Standardzugangs-Zustand laden fehlgeschlagen:", ursache);
        setLadeStatus("fehler");
      }
    })();
    return () => {
      aktiv = false;
    };
  }, []);

  // Schalter-Änderung: Einschalten öffnet erst den Dialog; Ausschalten läuft
  // direkt. Der Schalter selbst wird NICHT sofort umgelegt — er folgt dem
  // tatsächlichen Backend-Zustand (nach Bestätigung bzw. nach dem arm-Aufruf).
  const handleToggle = (an) => {
    if (an) {
      setDialogOffen(true);
    } else {
      setzeArmed(false);
    }
  };

  // armDefaultCreds aufrufen und den Schalter dem Ergebnis folgen lassen. Bei
  // Fehler bleibt der Schalter im letzten sicheren Zustand und eine Meldung
  // erscheint (kein stiller Fallback).
  const setzeArmed = async (an) => {
    setFehler(false);
    try {
      const zustand = await armDefaultCreds(an);
      setArmed(Boolean(zustand?.armed));
      onGespeichert();
    } catch (ursache) {
      console.error("Standardzugangs-Zustand setzen fehlgeschlagen:", ursache);
      setFehler(true);
    }
  };

  // Dialog bestätigt: schließen, dann freischalten.
  const handleBestaetigen = () => {
    setDialogOffen(false);
    setzeArmed(true);
  };

  // Dialog abgebrochen: nur schließen, nichts passiert (Schalter bleibt aus).
  const handleAbbrechen = () => {
    setDialogOffen(false);
  };

  if (ladeStatus === "laedt") {
    return (
      <SettingsSektion title={t("settings.defaultCreds.title")}>
        <div className="settings__row">
          <span className="settings__hint">
            {t("settings.defaultCreds.loading")}
          </span>
        </div>
      </SettingsSektion>
    );
  }

  if (ladeStatus === "fehler") {
    return (
      <SettingsSektion title={t("settings.defaultCreds.title")}>
        <div className="settings__row">
          <span className="settings__hint settings__hint--error">
            {t("settings.defaultCreds.loadError")}
          </span>
        </div>
      </SettingsSektion>
    );
  }

  return (
    <SettingsSektion title={t("settings.defaultCreds.title")}>
      {/* Ruhiger Warn-/Erklärungsabsatz. */}
      <p className="settings__hint">{t("settings.defaultCreds.warn")}</p>

      {/* Session-Schalter im auffaelligkeit__switch-Stil (bestehendes Toggle-
          Muster der View), eingerückt im auffaelligkeit__block. */}
      <div className="auffaelligkeit__block">
        <ul className="auffaelligkeit__rules">
          <li className="auffaelligkeit__rule">
            <span className="auffaelligkeit__rule-label">
              <span className="auffaelligkeit__rule-title">
                {t("settings.defaultCreds.toggleLabel")}
              </span>
            </span>
            <span className="auffaelligkeit__rule-switchbox">
              <input
                type="checkbox"
                className="auffaelligkeit__switch"
                checked={armed}
                onChange={(e) => handleToggle(e.target.checked)}
              />
            </span>
          </li>
        </ul>
      </div>

      {fehler ? (
        <span className="settings__hint settings__hint--error">
          {mitCode(t("settings.defaultCreds.saveError"), CODES.E_501)}
        </span>
      ) : null}

      {dialogOffen ? (
        <DefaultCredsConsentDialog
          onConfirm={handleBestaetigen}
          onCancel={handleAbbrechen}
        />
      ) : null}
    </SettingsSektion>
  );
}

// Widerrufs-Sektion des Mitschnitt-Zugriffs (Etappe 3). Gegenstück zur Einrichtung
// in OutboundView: dort wird erteilt, hier zurückgenommen — die Zusage „jederzeit
// widerrufbar" aus dem Einwilligungs-Dialog wird damit einlösbar.
//
// Die Sektion erscheint NUR, wenn der Zugriff tatsächlich eingerichtet ist (state
// granted). Bei „missing" gibt es nichts zu widerrufen, bei „not_applicable" (Linux)
// gibt es diese Einrichtung gar nicht — beides zeigt keinen Abschnitt, statt einen
// wirkungslosen Knopf anzubieten.
//
// Der Klick auf „Widerrufen" öffnet ZUERST eine Bestätigung und NICHT sofort den
// Systemdialog: ein unangekündigtes Passwortfenster wäre für eine zerstörende
// Aktion die falsche Reihenfolge (dasselbe Prinzip wie CaptureAccessDialog vor dem
// Einrichten).
//
// Die Bestätigung unterscheidet zwei Fälle anhand von members. Grund: die
// Mitschnitt-Geräte und der Systemdienst sind SYSTEMWEITE Ressourcen, die sich alle
// macOS-Konten der Maschine teilen. Ein vollständiges Abräumen nimmt allen anderen
// Mitgliedern den Zugriff — das darf nicht unbemerkt passieren.
//   genau ein Mitglied  -> Alleinbesitz: eine einfache Bestätigung, vollständig.
//   mehrere Mitglieder  -> die anderen Namen werden genannt, und es gibt ZWEI
//                          getrennte Aktionen (nur eigener Zugriff / vollständig).
// Den eigenen Login-Namen liefert das Backend bewusst nicht; die Länge der Liste
// genügt für diese Unterscheidung.
function CaptureAccessSektion({ status, onNeuLaden }) {
  const { t } = useTranslation();

  // ruhe | bestaetigung | laeuft | erfolg | fehler — bewusst EIN Zustand statt
  // mehrerer Booleans, damit unmögliche Kombinationen gar nicht darstellbar sind.
  const [phase, setPhase] = useState("ruhe");
  const [fehlerGrund, setFehlerGrund] = useState("");

  const members = status?.members ?? [];
  // Mehr als ein Eintrag heißt: weitere Konten teilen sich diese Einrichtung.
  const geteilt = members.length > 1;

  // Widerruf ausführen. Der Aufruf DAUERT, solange der Systemdialog offen ist.
  // Die drei Ausgänge bleiben getrennt: „cancelled" führt kommentarlos in den
  // Ausgangszustand zurück (KEINE Fehleroptik — der Nutzer hat sich legitim anders
  // entschieden), „failed" zeigt die Begründung im Klartext.
  const widerrufen = async (nurMitgliedschaft) => {
    setFehlerGrund("");
    setPhase("laeuft");
    try {
      const ergebnis = await revokeCaptureAccess(nurMitgliedschaft);
      if (ergebnis.outcome === CAPTURE_ACCESS_REVOKE_OUTCOME.REVOKED) {
        setPhase("erfolg");
        onNeuLaden();
        return;
      }
      if (ergebnis.outcome === CAPTURE_ACCESS_REVOKE_OUTCOME.CANCELLED) {
        setPhase("ruhe");
        return;
      }
      // failed und not_applicable: beide tragen eine Begründung aus dem Backend.
      setFehlerGrund(ergebnis.reason ?? "");
      setPhase("fehler");
    } catch (ursache) {
      // Transportfehler (Backend nicht erreichbar) — nicht verschlucken.
      console.error("Widerruf des Mitschnitt-Zugriffs fehlgeschlagen:", ursache);
      setFehlerGrund("");
      setPhase("fehler");
    }
  };

  // Nach geglücktem Widerruf ERSETZT die Erfolgsmeldung den Abschnitt, statt ihn
  // zu ergänzen: Einleitung, Was-Liste und Knopf beschreiben eine Einrichtung, die
  // es nicht mehr gibt. Stünden sie weiter da, widersprächen sich zwei Aussagen auf
  // demselben Bildschirm („Eingerichtet ist: …" neben „Der Zugriff wurde
  // widerrufen"). Früher Return statt zusätzlicher Bedingungen an jedem Element —
  // so ist der Endzustand an einer Stelle beschrieben und kann nicht auseinander-
  // laufen. Nur der Erfolg räumt ab; bei „laeuft" und „fehler" ist der
  // Zustandstext weiterhin richtig (es wurde ja nichts entfernt).
  if (phase === "erfolg") {
    return (
      <SettingsSektion title={t("settings.captureAccess.title")}>
        <span className="settings__hint" role="status" aria-live="polite">
          {t("settings.captureAccess.erfolg")}
        </span>
      </SettingsSektion>
    );
  }

  return (
    <SettingsSektion title={t("settings.captureAccess.title")}>
      <p className="settings__hint">{t("settings.captureAccess.intro")}</p>

      {/* Was eingerichtet ist — kurz und in nicht-technischer Sprache, damit vor
          dem Widerruf klar ist, was verschwindet. */}
      <p className="settings__hint">{t("settings.captureAccess.whatTitle")}</p>
      <ul className="settings__liste">
        <li>{t("settings.captureAccess.whatGroup")}</li>
        <li>{t("settings.captureAccess.whatDaemon")}</li>
        <li>{t("settings.captureAccess.whatDevices")}</li>
      </ul>

      {phase === "ruhe" ? (
        <div className="settings__row settings__row--actions">
          <span className="settings__hint" />
          <button
            type="button"
            className="settings__button"
            onClick={() => setPhase("bestaetigung")}
          >
            {t("settings.captureAccess.revokeButton")}
          </button>
        </div>
      ) : null}

      {phase === "bestaetigung" ? (
        <div className="settings__widerruf">
          <p className="settings__widerruf-titel">
            {geteilt
              ? t("settings.captureAccess.confirmSharedTitle")
              : t("settings.captureAccess.confirmTitle")}
          </p>
          <p className="settings__hint">
            {geteilt
              ? t("settings.captureAccess.confirmSharedBody")
              : t("settings.captureAccess.confirmSoloBody")}
          </p>

          {/* Nur wenn andere betroffen sind: die Namen beim Namen nennen. */}
          {geteilt ? (
            <>
              <p className="settings__hint">
                {t("settings.captureAccess.confirmSharedMembers")}
              </p>
              <ul className="settings__liste">
                {members.map((name) => (
                  <li key={name}>{name}</li>
                ))}
              </ul>
            </>
          ) : null}

          <p className="settings__hint">
            {t("settings.captureAccess.hinweisAnmeldung")}
          </p>

          {/* Geteilter Fall: ZWEI getrennte Aktionen, damit die schonende Variante
              gleichwertig danebensteht und nicht in einem Menü versteckt ist.
              Alleinbesitz: eine einzige Bestätigung, vollständig. */}
          <div className="settings__row settings__row--actions">
            <button
              type="button"
              className="settings__link-button"
              onClick={() => setPhase("ruhe")}
            >
              {t("settings.captureAccess.cancel")}
            </button>
            <span className="settings__widerruf-aktionen">
              {geteilt ? (
                <>
                  <button
                    type="button"
                    className="settings__button"
                    onClick={() => widerrufen(true)}
                  >
                    {t("settings.captureAccess.actionMembershipOnly")}
                  </button>
                  <button
                    type="button"
                    className="settings__button"
                    onClick={() => widerrufen(false)}
                  >
                    {t("settings.captureAccess.actionFull")}
                  </button>
                </>
              ) : (
                <button
                  type="button"
                  className="settings__button"
                  onClick={() => widerrufen(false)}
                >
                  {t("settings.captureAccess.confirm")}
                </button>
              )}
            </span>
          </div>
        </div>
      ) : null}

      {phase === "laeuft" ? (
        <span className="settings__hint" role="status" aria-live="polite">
          {t("settings.captureAccess.laeuft")}
        </span>
      ) : null}

      {/* Der Erfolgsfall kommt hier NICHT vor — er wird oben als eigener Rückgabe-
          zweig behandelt und ersetzt den gesamten Abschnitt. */}

      {/* Fehlschlag: die Begründung aus dem Backend im Klartext, nicht verschluckt. */}
      {phase === "fehler" ? (
        <span className="settings__hint settings__hint--error">
          {mitCode(t("settings.captureAccess.fehler"), CODES.E_501)}
          {fehlerGrund ? ` ${fehlerGrund}` : ""}
        </span>
      ) : null}
    </SettingsSektion>
  );
}

export default function SettingsView({ lang, onLangChange, onClose, onOpenManual }) {
  const { t } = useTranslation();

  // Dezentes "Gespeichert"-Feedback (rein visuell). Die Persistenz selbst bleibt
  // in App.jsx; hier wird nach jeder Änderung kurz eine Bestätigung gezeigt, die
  // nach ~1,5 s wieder verschwindet (Muster wie der Copy-Haken im LookupPanel).
  const [gespeichert, setGespeichert] = useState(false);
  const speicherTimeout = useRef(null);

  const zeigeGespeichert = () => {
    setGespeichert(true);
    if (speicherTimeout.current !== null) {
      clearTimeout(speicherTimeout.current);
    }
    speicherTimeout.current = setTimeout(() => {
      setGespeichert(false);
      speicherTimeout.current = null;
    }, 1500);
  };

  // Wrapper um die echten Handler: erst persistieren (App.jsx), dann Feedback.
  const handleLang = (wert) => {
    onLangChange(wert);
    zeigeGespeichert();
  };

  // Zustand des Mitschnitt-Zugriffs. Er entscheidet, ob die Widerrufs-Rubrik
  // überhaupt angeboten wird — darum liegt er HIER und nicht in der Sektion: die
  // Navigation braucht ihn genauso wie der Inhalt (eine Quelle, kein zweites Laden).
  // null heißt „noch nicht geladen bzw. nicht ermittelbar" — dann keine Rubrik.
  const [captureAccess, setCaptureAccess] = useState(null);

  const ladeCaptureAccess = useCallback(async () => {
    try {
      setCaptureAccess(await fetchCaptureAccess());
    } catch (ursache) {
      // Ruhig behandeln: der Zugriffs-Status ist eine Zusatzauskunft. Fehlt er,
      // entfällt die Rubrik — die übrigen Einstellungen bleiben benutzbar.
      console.error("Status des Mitschnitt-Zugriffs laden fehlgeschlagen:", ursache);
      setCaptureAccess(null);
    }
  }, []);

  useEffect(() => {
    ladeCaptureAccess();
  }, [ladeCaptureAccess]);

  // Nur bei „granted" gibt es etwas zu widerrufen (siehe CaptureAccessSektion).
  const captureAccessWiderrufbar =
    captureAccess?.state === CAPTURE_ACCESS_STATE.GRANTED;

  // Teil A — Navigation links, Inhalt rechts. Eine Rubrik zur Zeit sichtbar; der
  // State bleibt lokal (kein Routing). Default ist die erste Rubrik.
  const [rubrik, setRubrik] = useState("general");
  const rubriken = [
    { id: "general", label: t("settings.nav.general") },
    { id: "startseite", label: t("settings.nav.startseite") },
    { id: "fritzbox", label: t("settings.nav.fritzbox") },
    { id: "auffaelligkeit", label: t("settings.nav.auffaelligkeit") },
    { id: "dnswatch", label: t("settings.nav.dnswatch") },
    { id: "defaultcreds", label: t("settings.nav.defaultcreds") },
    { id: "defaultcredsList", label: t("settings.nav.defaultcredsList") },
    ...(captureAccessWiderrufbar
      ? [{ id: "captureAccess", label: t("settings.nav.captureAccess") }]
      : []),
  ];

  return (
    <FunctionShell
      title={t("settings.title")}
      onBack={onClose}
      helpId="help.settings.uebersicht"
      onOpenManual={onOpenManual}
    >
      <div className="settings settings--layout">
        {/* Linke Navigations-Spalte: Rubriken-Liste, aktive dezent hervorgehoben. */}
        <nav className="settings__nav" aria-label={t("settings.title")}>
          {rubriken.map((eintrag) => (
            <button
              key={eintrag.id}
              type="button"
              className={
                rubrik === eintrag.id
                  ? "settings__nav-item settings__nav-item--aktiv"
                  : "settings__nav-item"
              }
              aria-current={rubrik === eintrag.id ? "page" : undefined}
              onClick={() => setRubrik(eintrag.id)}
            >
              {eintrag.label}
            </button>
          ))}
        </nav>

        {/* Rechter Inhaltsbereich: zeigt die aktive Rubrik. */}
        <div className="settings__content">
          {/* Dezente Bestätigungszeile; aria-live für Screenreader. Reserviert
              keinen festen Platz — sie erscheint nur kurz nach einer Änderung. */}
          <span
            className={
              gespeichert
                ? "settings__saved settings__saved--shown"
                : "settings__saved"
            }
            role="status"
            aria-live="polite"
          >
            {gespeichert ? t("settings.saved") : ""}
          </span>

          {rubrik === "general" ? (
            <SettingsSektion title={t("settings.sectionGeneral")}>
              <SettingsZeile label={t("settings.language")}>
                {/* Sprachnamen in ihrer eigenen Schreibweise — Konvention bei
                    Sprachwahl, daher nicht übersetzt. */}
                <select
                  className="settings__select"
                  value={lang}
                  onChange={(e) => handleLang(e.target.value)}
                >
                  <option value="de">Deutsch</option>
                  <option value="en">English</option>
                </select>
              </SettingsZeile>
            </SettingsSektion>
          ) : null}

          {rubrik === "startseite" ? (
            <OverviewSektion onGespeichert={zeigeGespeichert} />
          ) : null}

          {rubrik === "fritzbox" ? (
            <FritzBoxSektion onGespeichert={zeigeGespeichert} />
          ) : null}

          {rubrik === "auffaelligkeit" ? (
            <AuffaelligkeitSektion onGespeichert={zeigeGespeichert} />
          ) : null}

          {rubrik === "dnswatch" ? (
            <DnsWatchSektion onGespeichert={zeigeGespeichert} />
          ) : null}

          {rubrik === "defaultcreds" ? (
            <DefaultCredsSektion onGespeichert={zeigeGespeichert} />
          ) : null}

          {rubrik === "defaultcredsList" ? (
            <DefaultCredsListeSektion onGespeichert={zeigeGespeichert} />
          ) : null}

          {/* Nach einem geglückten Widerruf meldet der Status nicht mehr „granted";
              die Rubrik verschwindet dann aus der Navigation. Der Inhalt bleibt so
              lange stehen, bis der Nutzer selbst weiterklickt — die Erfolgsmeldung
              soll nicht unter ihm wegspringen. */}
          {rubrik === "captureAccess" && captureAccess !== null ? (
            <CaptureAccessSektion
              status={captureAccess}
              onNeuLaden={ladeCaptureAccess}
            />
          ) : null}
        </div>
      </div>
    </FunctionShell>
  );
}
