// Kopfzeile (CERNIS PRO 2.0)
// Auf jeder Seite identisch. Links Logo + Version, rechts Bedienelemente.
// Bekommt theme/lang nebst Settern als Props.

import { BookOpen } from "lucide-react";
import { useTranslation } from "react-i18next";

import LanguageToggle from "./LanguageToggle.jsx";
import ThemeToggle from "./ThemeToggle.jsx";
import "./AppHeader.css";

export default function AppHeader({ theme, onThemeChange, lang, onLangChange }) {
  const { t } = useTranslation();

  return (
    <header className="app-header">
      <div className="app-header__brand">
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
      </div>

      <div className="app-header__controls">
        <LanguageToggle lang={lang} onChange={onLangChange} />
        <ThemeToggle theme={theme} onChange={onThemeChange} />
        <button type="button" className="control-button">
          <BookOpen size={16} />
          <span>{t("header.manual")}</span>
        </button>
      </div>
    </header>
  );
}
