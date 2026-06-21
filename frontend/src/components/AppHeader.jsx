// Kopfzeile (CERNIS PRO 2.0)
// Auf jeder Seite identisch. Links Logo + Version, rechts Bedienelemente.
// Bekommt theme nebst Setter als Props; das Zahnrad meldet sich über
// onOpenSettings. Die Sprach-Auswahl wohnt jetzt im Einstellungs-Bereich.

import { BookOpen, Settings } from "lucide-react";
import { useTranslation } from "react-i18next";

import LivePill from "./LivePill.jsx";
import ThemeToggle from "./ThemeToggle.jsx";
import "./AppHeader.css";

export default function AppHeader({ theme, onThemeChange, onOpenSettings, onOpenManual, onGoToLogging, onGoHome }) {
  const { t } = useTranslation();

  return (
    <header className="app-header">
      <button
        type="button"
        className="app-header__brand app-header__brand--button"
        onClick={onGoHome}
        aria-label={t("header.home")}
        title={t("header.home")}
      >
        <img
          className="app-header__logo"
          src="/cernis-logo.png"
          alt="CERNIS PRO"
        />
        <span className="app-header__wordmark">
          {/* Wortmarke ist fester Markenname, wird nicht übersetzt. */}
          CERNIS PRO
          <span className="app-header__version">{t("app.version")}</span>
        </span>
      </button>

      {/* Live-Monitoring-Pill: nur sichtbar, wenn eine Logging-Aufgabe aktiv ist
          (datengetrieben, eigener Poll). Klick fuehrt zur Logging-Ansicht. */}
      <LivePill onOeffnen={onGoToLogging} />

      <div className="app-header__controls">
        <ThemeToggle theme={theme} onChange={onThemeChange} />
        <button
          type="button"
          className="control-button"
          onClick={onOpenManual}
        >
          <BookOpen size={16} />
          <span>{t("header.manual")}</span>
        </button>
        <button
          type="button"
          className="icon-button"
          onClick={onOpenSettings}
          aria-label={t("header.settings")}
          title={t("header.settings")}
        >
          <Settings size={22} />
        </button>
      </div>
    </header>
  );
}
