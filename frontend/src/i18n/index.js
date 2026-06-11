// i18n-Initialisierung (CERNIS PRO 2.0)
// Sprache aus localStorage (Key cernis_lang), Fallback de.

import i18n from "i18next";
import { initReactI18next } from "react-i18next";

import de from "./de.json";
import en from "./en.json";

export const SPRACHEN = ["de", "en"];
const STORAGE_KEY = "cernis_lang";

function ermittleStartsprache() {
  if (typeof localStorage === "undefined") {
    return "de";
  }
  const gespeichert = localStorage.getItem(STORAGE_KEY);
  return SPRACHEN.includes(gespeichert) ? gespeichert : "de";
}

i18n.use(initReactI18next).init({
  resources: {
    de: { translation: de },
    en: { translation: en },
  },
  lng: ermittleStartsprache(),
  fallbackLng: "de",
  interpolation: {
    escapeValue: false,
  },
});

export default i18n;
