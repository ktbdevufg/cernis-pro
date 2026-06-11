// Überblick-Ansicht (CERNIS PRO 2.0)
// Zeigt das Lagebild des Netzwerks in zwei Zuständen:
//   A) leer  — noch nichts beobachtet (Einladung zum ersten Scan)
//   B) Daten — Auffälliges zuerst, darunter verdichtete Kennzahlen
//
// Datenquelle ist ausschließlich der Import aus mockData/overviewMock.
// Die View weiß nicht, ob die Daten echt oder Platzhalter sind. Bei echter
// Anbindung wird nur dieser Import ausgetauscht.

import {
  ChevronRight,
  Globe,
  Radar,
  Smartphone,
} from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import overviewMock from "../mockData/overviewMock.js";
import "./OverviewView.css";

// Abbildung der Mock-Icon-Schlüssel auf lucide-Komponenten.
// Hält den Mock frei von Komponenten-Referenzen.
const FINDING_ICONS = {
  smartphone: Smartphone,
  globe: Globe,
};

// Lage-Block: Hinweis-Balken + "Auffälliges zuerst" + Kennzahlen-Grid.
function Lagebild({ daten }) {
  const { t } = useTranslation();
  const { auffaelligkeiten, kennzahlen } = daten;

  return (
    <div className="overview">
      {auffaelligkeiten.length > 0 && (
        <div className="overview__banner" role="status">
          {t("overview.situation.attention", { count: auffaelligkeiten.length })}
        </div>
      )}

      <section className="overview__section">
        <h2 className="overview__heading">{t("overview.findingsHeading")}</h2>
        <ul className="overview__findings">
          {auffaelligkeiten.map((eintrag) => {
            const Icon = FINDING_ICONS[eintrag.icon] ?? Radar;
            return (
              <li key={eintrag.id}>
                {/* Klick vorerst ohne Funktion (Platzhalter, kein API-Call). */}
                <button type="button" className="overview__finding">
                  <span className="overview__finding-icon" aria-hidden="true">
                    <Icon size={20} />
                  </span>
                  <span className="overview__finding-text">
                    <span className="overview__finding-title">
                      {t(`overview.findings.${eintrag.i18nKey}.title`)}
                    </span>
                    <span className="overview__finding-subtitle">
                      {t(`overview.findings.${eintrag.i18nKey}.subtitle`)}
                    </span>
                  </span>
                  <ChevronRight
                    size={18}
                    className="overview__finding-chevron"
                    aria-hidden="true"
                  />
                </button>
              </li>
            );
          })}
        </ul>
      </section>

      <section className="overview__section">
        <div className="overview__metrics">
          {kennzahlen.map((kennzahl) => (
            <div key={kennzahl.id} className="overview__metric">
              <span className="overview__metric-value">{kennzahl.value}</span>
              <span className="overview__metric-label">
                {t(`overview.metrics.${kennzahl.i18nKey}`)}
              </span>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

// Leerzustand: dezentes Icon, Überschrift, erklärender Satz, Akzent-Button.
function Leerzustand() {
  const { t } = useTranslation();

  return (
    <div className="overview overview--empty">
      <Radar size={48} className="overview__empty-icon" aria-hidden="true" />
      <h2 className="overview__empty-title">{t("overview.empty.title")}</h2>
      <p className="overview__empty-text">{t("overview.empty.text")}</p>
      {/* Button löst vorerst nichts aus (Platzhalter, kein API-Call). */}
      <button type="button" className="overview__empty-button">
        {t("overview.empty.startScan")}
      </button>
    </div>
  );
}

export default function OverviewView() {
  const { t } = useTranslation();

  // TEMP: Zustand-Umschalter nur fürs Bauen — entfällt mit echter
  // Datenanbindung (Zustand ergibt sich dann aus den Daten).
  const [zeigeDaten, setZeigeDaten] = useState(true);

  return (
    <div className="overview-view">
      {/* TEMP: Zustand-Umschalter nur fürs Bauen — entfällt mit echter
          Datenanbindung (Zustand ergibt sich dann aus den Daten). */}
      <div className="overview-view__switch">
        <span className="overview-view__switch-label">
          {t("overview.stateToggle.label")}
        </span>
        <div className="overview-view__switch-buttons">
          <button
            type="button"
            className={
              zeigeDaten
                ? "overview-view__switch-btn"
                : "overview-view__switch-btn overview-view__switch-btn--active"
            }
            onClick={() => setZeigeDaten(false)}
          >
            {t("overview.stateToggle.empty")}
          </button>
          <button
            type="button"
            className={
              zeigeDaten
                ? "overview-view__switch-btn overview-view__switch-btn--active"
                : "overview-view__switch-btn"
            }
            onClick={() => setZeigeDaten(true)}
          >
            {t("overview.stateToggle.data")}
          </button>
        </div>
      </div>

      {zeigeDaten ? <Lagebild daten={overviewMock} /> : <Leerzustand />}
    </div>
  );
}
