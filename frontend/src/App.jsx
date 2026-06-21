// App-Wurzel (CERNIS PRO 2.0)
// Layout: fixe Kopfzeile, darunter Reiterleiste, darunter scrollbarer Inhalt.
// Hält State: aktiver Reiter, Theme, Sprache. Theme + Sprache in localStorage.

import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import AppHeader from "./components/AppHeader.jsx";
import TabNav, { REITER } from "./components/TabNav.jsx";
import DevicesView from "./views/DevicesView.jsx";
import ExportView from "./views/ExportView.jsx";
import InvestigateView from "./views/InvestigateView.jsx";
import ManualView from "./views/ManualView.jsx";
import ObserveView from "./views/ObserveView.jsx";
import OverviewView from "./views/OverviewView.jsx";
import SettingsView from "./views/SettingsView.jsx";
import "./App.css";

const THEME_KEY = "cernis_theme";
const LANG_KEY = "cernis_lang";
const REFRESH_KEY = "cernis_traffic_refresh";

// Erlaubte Auto-Refresh-Intervalle in Sekunden (0 = aus).
const REFRESH_WERTE = [0, 5, 10, 30, 60];

function ermittleStartTheme() {
  const gespeichert = localStorage.getItem(THEME_KEY);
  return gespeichert === "dark" || gespeichert === "light" ? gespeichert : "light";
}

function ermittleStartSprache() {
  const gespeichert = localStorage.getItem(LANG_KEY);
  return gespeichert === "de" || gespeichert === "en" ? gespeichert : "de";
}

// Auto-Refresh-Intervall aus localStorage; nur erlaubte Werte, sonst 0 (aus).
function ermittleStartRefresh() {
  const gespeichert = Number(localStorage.getItem(REFRESH_KEY));
  return REFRESH_WERTE.includes(gespeichert) ? gespeichert : 0;
}

export default function App() {
  const { i18n } = useTranslation();

  const [activeTab, setActiveTab] = useState(REITER[0].id);
  const [theme, setTheme] = useState(ermittleStartTheme);
  const [lang, setLang] = useState(ermittleStartSprache);
  // Auto-Refresh-Intervall für den Per-App-Verkehr (Sekunden; 0 = aus).
  const [refreshInterval, setRefreshInterval] = useState(ermittleStartRefresh);
  // Einstellungs-Bereich ist ein eigener Modus (kein Reiter): überlagert den
  // View-Bereich. Schließen kehrt zum vorher aktiven Reiter zurück.
  const [settingsOffen, setSettingsOffen] = useState(false);
  // Benutzerhandbuch ist ebenfalls ein eigener Modus (kein Reiter) und schließt
  // sich mit den Einstellungen gegenseitig aus: immer nur einer ist offen.
  const [handbuchOffen, setHandbuchOffen] = useState(false);
  // Wunsch-Funktion im Beobachten-Bereich (z. B. vom Kopfzeilen-Live-Pill). Wird
  // EINMAL als initiale Funktion an ObserveView gereicht; danach von ObserveView
  // quittiert (onFunktionGeoeffnet -> null), damit der Nutzer dort frei navigiert.
  const [observeFunktion, setObserveFunktion] = useState(null);

  // Vom Kopfzeilen-Pill: zur Logging-Ansicht springen. Reiter auf "observe" und
  // die logging-Funktion vormerken; ein offener Einstellungs-Modus wird verlassen.
  const goToLogging = () => {
    setSettingsOffen(false);
    setHandbuchOffen(false);
    setActiveTab("observe");
    setObserveFunktion("logging");
  };

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

  // Auto-Refresh-Intervall persistieren (gleiches Muster wie Theme/Sprache).
  useEffect(() => {
    localStorage.setItem(REFRESH_KEY, String(refreshInterval));
  }, [refreshInterval]);

  return (
    <div className="app">
      <AppHeader
        theme={theme}
        onThemeChange={setTheme}
        onOpenSettings={() => {
          setHandbuchOffen(false);
          setSettingsOffen(true);
        }}
        onOpenManual={() => {
          setSettingsOffen(false);
          setHandbuchOffen(true);
        }}
        onGoToLogging={goToLogging}
        onGoHome={() => {
          setSettingsOffen(false);
          setHandbuchOffen(false);
          setActiveTab("overview");
        }}
      />
      {/* Einstellungen UND Handbuch sind kein Reiter: bei einem offenen Modus
          bleibt kein Reiter aktiv markiert, daher blenden wir die Reiterleiste
          aus. */}
      {!settingsOffen && !handbuchOffen && (
        <TabNav active={activeTab} onChange={setActiveTab} />
      )}

      <main className="app__content">
        {handbuchOffen ? (
          <ManualView onClose={() => setHandbuchOffen(false)} />
        ) : settingsOffen ? (
          <SettingsView
            lang={lang}
            onLangChange={setLang}
            onClose={() => setSettingsOffen(false)}
          />
        ) : (
          <>
            {activeTab === "overview" && (
              <OverviewView onNavigate={(tab) => setActiveTab(tab)} />
            )}
            {activeTab === "observe" && (
              <ObserveView
                refreshInterval={refreshInterval}
                onRefreshIntervalChange={setRefreshInterval}
                initialFunction={observeFunktion}
                onFunktionGeoeffnet={() => setObserveFunktion(null)}
              />
            )}
            {activeTab === "investigate" && <InvestigateView />}
            {activeTab === "export" && <ExportView />}
            {activeTab === "devices" && <DevicesView />}
          </>
        )}
      </main>
    </div>
  );
}
