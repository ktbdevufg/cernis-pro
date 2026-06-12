// Einstellungs-Ansicht (CERNIS PRO 2.0)
// Eigener Modus (kein Reiter), erreichbar über das Zahnrad in der Kopfzeile.
// Nutzt das function-shell-Muster der übrigen Bereiche: Zurück-Weg + Titel
// über dem Inhalt. Aufgebaut aus benannten Sektionen, sodass weitere Optionen
// später einfach als zusätzliche Sektionen/Zeilen dazukommen.
//
// Die View hält keinen eigenen State und keine localStorage-Logik. Die Sprache
// kommt als Prop (lang) und wird über onLangChange zurückgemeldet — die
// Persistenz bleibt in App.jsx (single source of truth).

import { useTranslation } from "react-i18next";

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

export default function SettingsView({ lang, onLangChange, onClose }) {
  const { t } = useTranslation();

  return (
    <FunctionShell title={t("settings.title")} onBack={onClose}>
      <div className="settings">
        <SettingsSektion title={t("settings.sectionGeneral")}>
          <SettingsZeile label={t("settings.language")}>
            {/* Sprachnamen in ihrer eigenen Schreibweise — Konvention bei
                Sprachwahl, daher nicht übersetzt. */}
            <select
              className="settings__select"
              value={lang}
              onChange={(e) => onLangChange(e.target.value)}
            >
              <option value="de">Deutsch</option>
              <option value="en">English</option>
            </select>
          </SettingsZeile>
        </SettingsSektion>
      </div>
    </FunctionShell>
  );
}
