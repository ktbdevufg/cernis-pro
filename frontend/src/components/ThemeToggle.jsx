// Hell/Dunkel-Schalter (CERNIS PRO 2.0)
// Bekommt aktuelles Theme + Setter als Props.

import { Moon, Sun } from "lucide-react";
import { useTranslation } from "react-i18next";

import "./ControlButton.css";

export default function ThemeToggle({ theme, onChange }) {
  const { t } = useTranslation();
  const istHell = theme === "light";
  const naechstes = istHell ? "dark" : "light";

  return (
    <button
      type="button"
      className="control-button"
      onClick={() => onChange(naechstes)}
      aria-label={istHell ? t("theme.dark") : t("theme.light")}
      title={istHell ? t("theme.dark") : t("theme.light")}
    >
      {istHell ? <Moon size={16} /> : <Sun size={16} />}
      <span>{istHell ? t("theme.dark") : t("theme.light")}</span>
    </button>
  );
}
