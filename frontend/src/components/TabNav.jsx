// Reiterleiste (CERNIS PRO 2.0)
// Vier Gruppen mit lucide-Icons. Aktiver Reiter türkis unterstrichen.
// Bekommt aktiven Reiter + onChange als Props.

import { Activity, FileOutput, LayoutDashboard, Search } from "lucide-react";
import { useTranslation } from "react-i18next";

import "./TabNav.css";

// Reiter-Definition: Schlüssel + Icon. Reihenfolge ist verbindlich.
export const REITER = [
  { id: "overview", icon: LayoutDashboard },
  { id: "observe", icon: Activity },
  { id: "investigate", icon: Search },
  { id: "export", icon: FileOutput },
];

export default function TabNav({ active, onChange }) {
  const { t } = useTranslation();

  return (
    <nav className="tab-nav">
      {REITER.map(({ id, icon: Icon }) => {
        const istAktiv = id === active;
        return (
          <button
            key={id}
            type="button"
            className={istAktiv ? "tab-nav__tab tab-nav__tab--active" : "tab-nav__tab"}
            aria-current={istAktiv ? "page" : undefined}
            onClick={() => onChange(id)}
          >
            <Icon size={18} />
            <span>{t(`nav.${id}`)}</span>
          </button>
        );
      })}
    </nav>
  );
}
