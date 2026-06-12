// App-Wurzel (CERNIS PRO 2.0)
// Layout: fixe Kopfzeile, darunter Reiterleiste, darunter scrollbarer Inhalt.
// Hält State: aktiver Reiter, Theme, Sprache. Theme + Sprache in localStorage.

import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import AppHeader from "./components/AppHeader.jsx";
import TabNav, { REITER } from "./components/TabNav.jsx";
import ExportView from "./views/ExportView.jsx";
import InvestigateView from "./views/InvestigateView.jsx";
import ObserveView from "./views/ObserveView.jsx";
import OverviewView from "./views/OverviewView.jsx";
import SettingsView from "./views/SettingsView.jsx";
import "./App.css";

const THEME_KEY = "cernis_theme";
const LANG_KEY = "cernis_lang";

function ermittleStartTheme() {
  const gespeichert = localStorage.getItem(THEME_KEY);
  return gespeichert === "dark" || gespeichert === "light" ? gespeichert : "light";
}

function ermittleStartSprache() {
  const gespeichert = localStorage.getItem(LANG_KEY);
  return gespeichert === "de" || gespeichert === "en" ? gespeichert : "de";
}

export default function App() {
  const { i18n } = useTranslation();

  const [activeTab, setActiveTab] = useState(REITER[0].id);
  const [theme, setTheme] = useState(ermittleStartTheme);
  const [lang, setLang] = useState(ermittleStartSprache);
  // Einstellungs-Bereich ist ein eigener Modus (kein Reiter): überlagert den
  // View-Bereich. Schließen kehrt zum vorher aktiven Reiter zurück.
  const [settingsOffen, setSettingsOffen] = useState(false);

  // Theme am <html> setzen und persistieren.
  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem(THEME_KEY, theme);
  }, [theme]);

  // Sprache in i18n übernehmen und persistieren.
  useEffect(() => {
    if (i18n.language !== lang) {
      i18n.changeLanguage(lang);
    }
    localStorage.setItem(LANG_KEY, lang);
  }, [lang, i18n]);

  return (
    <div className="app">
      <AppHeader
        theme={theme}
        onThemeChange={setTheme}
        onOpenSettings={() => setSettingsOffen(true)}
      />
      {/* Einstellungen ist kein Reiter: bei offenem Modus bleibt kein Reiter
          aktiv markiert, daher blenden wir die Reiterleiste aus. */}
      {!settingsOffen && <TabNav active={activeTab} onChange={setActiveTab} />}

      <main className="app__content">
        {settingsOffen ? (
          <SettingsView
            lang={lang}
            onLangChange={setLang}
            onClose={() => setSettingsOffen(false)}
          />
        ) : (
          <>
            {activeTab === "overview" && <OverviewView />}
            {activeTab === "observe" && <ObserveView />}
            {activeTab === "investigate" && <InvestigateView />}
            {activeTab === "export" && <ExportView />}
          </>
        )}
      </main>
    </div>
  );
}
