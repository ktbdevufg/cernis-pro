// Kopfzeile (CERNIS PRO 2.0)
// Auf jeder Seite identisch. Links Logo + Version, rechts Bedienelemente.
// Bekommt theme nebst Setter als Props; das Zahnrad meldet sich über
// onOpenSettings. Die Sprach-Auswahl wohnt jetzt im Einstellungs-Bereich.

import { BookOpen, Info, Settings } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { fetchSystemInfo } from "../api/system.js";
import DnsBypassRecordingPill from "./DnsBypassRecordingPill.jsx";
import LivePill from "./LivePill.jsx";
import OutboundRecordingPill from "./OutboundRecordingPill.jsx";
import ThemeToggle from "./ThemeToggle.jsx";
import "./AppHeader.css";

export default function AppHeader({ theme, onThemeChange, onOpenSettings, onOpenManual, onOpenUeber, onGoToLogging, onGoToOutbound, onGoToDnsWatch, onGoHome }) {
  const { t } = useTranslation();

  // Echte Build-Version vom Backend (bereits Anzeige-Form, z. B. "2.0.0-x64.<sha>").
  // Einmalig beim Mount geladen. Solange nichts geladen ist ODER der Aufruf
  // fehlschlaegt, bleibt version null und die Anzeige faellt unten auf den
  // i18n-Text t("app.version") zurueck (kein leerer/springender Zustand).
  const [version, setVersion] = useState(null);

  useEffect(() => {
    let aktiv = true;
    fetchSystemInfo()
      .then((info) => {
        if (aktiv && info?.version) {
          setVersion(info.version);
        }
      })
      .catch(() => {
        // Backend nicht erreichbar o. Ae.: still schlucken, Fallback greift.
      });
    return () => {
      aktiv = false;
    };
  }, []);

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
          {/* Wortmarke ist fester Markenname, wird nicht übersetzt. "PRO" steht in
              einem eigenen Element, um es farblich/im Gewicht vom Markenton
              abzusetzen; den Abstand setzt der Flex-gap der Wortmarke. */}
          <span className="app-header__marke">CERNIS</span>
          <span className="app-header__pro">PRO</span>
          <span className="app-header__version">{version ?? t("app.version")}</span>
        </span>
      </button>

      {/* Kopfzeilen-Pills: jeweils nur sichtbar, wenn etwas aktiv ist
          (datengetrieben, eigener Poll). Rot = Live-Monitoring (Logging-Ansicht),
          Gelb = Aussenkontakte-Aufzeichnung. Beide koennen gleichzeitig sichtbar
          sein -- ein Wrapper haelt sie mit Abstand nebeneinander, ohne dass das
          Header-space-between sie auseinanderdrueckt. */}
      <div className="app-header__pills">
        <LivePill onOeffnen={onGoToLogging} />
        <OutboundRecordingPill onOeffnen={onGoToOutbound} />
        <DnsBypassRecordingPill onOeffnen={onGoToDnsWatch} />
      </div>

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
        {/* "Über CERNIS PRO" (Lizenzaufstellung): dritter eigener Modus neben
            Handbuch und Einstellungen, an derselben Stelle und im selben Stil. */}
        <button
          type="button"
          className="icon-button"
          onClick={onOpenUeber}
          aria-label={t("header.ueber")}
          title={t("header.ueber")}
        >
          <Info size={22} />
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
