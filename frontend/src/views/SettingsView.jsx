// Einstellungs-Ansicht (CERNIS PRO 2.0)
// Eigener Modus (kein Reiter), erreichbar über das Zahnrad in der Kopfzeile.
// Nutzt das function-shell-Muster der übrigen Bereiche: Zurück-Weg + Titel
// über dem Inhalt. Aufgebaut aus benannten Sektionen, sodass weitere Optionen
// später einfach als zusätzliche Sektionen/Zeilen dazukommen.
//
// Die View hält keinen eigenen State und keine localStorage-Logik. Die Sprache
// kommt als Prop (lang) und wird über onLangChange zurückgemeldet — die
// Persistenz bleibt in App.jsx (single source of truth).

import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import {
  fetchSettings,
  updateSetting,
  updateSecret,
  secretGesetzt,
} from "../api/settings.js";
import { FunctionShell } from "../components/AreaShell.jsx";
import "./SettingsView.css";

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
            {t("settings.fritzbox.saveError")}
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

export default function SettingsView({ lang, onLangChange, onClose }) {
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

  return (
    <FunctionShell title={t("settings.title")} onBack={onClose}>
      <div className="settings">
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
        <FritzBoxSektion onGespeichert={zeigeGespeichert} />
      </div>
    </FunctionShell>
  );
}
