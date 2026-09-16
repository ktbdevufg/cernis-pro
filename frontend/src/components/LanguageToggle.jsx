// DE/EN-Umschalter (CERNIS PRO 2.0)
// Bekommt aktuelle Sprache + Setter als Props.

import { Languages } from "lucide-react";

import "./ControlButton.css";

export default function LanguageToggle({ lang, onChange }) {
  const naechste = lang === "de" ? "en" : "de";

  return (
    <button
      type="button"
      className="control-button"
      onClick={() => onChange(naechste)}
      aria-label={naechste.toUpperCase()}
      title={naechste.toUpperCase()}
    >
      <Languages size={16} />
      <span>{lang.toUpperCase()}</span>
    </button>
  );
}
