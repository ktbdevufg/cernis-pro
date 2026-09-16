// Reiterleiste (CERNIS PRO 2.0)
// Vier Gruppen mit lucide-Icons. Nackte Reiter; der aktive trägt als einziges
// Markierungselement die "Wanne": eine an beiden Enden nach oben gebogene,
// spitz auslaufende Unterlinie in Akzentfarbe (gefüllter SVG-Pfad).
// Bekommt aktiven Reiter + onChange als Props.

import { Activity, FileBarChart, LayoutDashboard, Router, Search, Wrench } from "lucide-react";
import { useTranslation } from "react-i18next";

import "./TabNav.css";

// Reiter-Definition: Schlüssel + Icon. Reihenfolge ist verbindlich. Der letzte
// Reiter „verwaltung" steht optisch nach rechts abgesetzt (margin-left:auto, s.u.).
export const REITER = [
  { id: "overview", icon: LayoutDashboard },
  { id: "observe", icon: Activity },
  { id: "investigate", icon: Search },
  { id: "reporting", icon: FileBarChart },
  { id: "devices", icon: Router },
  { id: "verwaltung", icon: Wrench },
];

export default function TabNav({ active, onChange }) {
  const { t } = useTranslation();

  return (
    <nav className="tab-nav">
      {REITER.map(({ id, icon: Icon }) => {
        const istAktiv = id === active;
        // Der Verwaltungs-Reiter wird nach ganz rechts abgesetzt (margin-left:auto).
        const klassen = ["tab-nav__tab"];
        if (istAktiv) {
          klassen.push("tab-nav__tab--active");
        }
        if (id === "verwaltung") {
          klassen.push("tab-nav__tab--rechts");
        }
        return (
          <button
            key={id}
            type="button"
            className={klassen.join(" ")}
            aria-current={istAktiv ? "page" : undefined}
            onClick={() => onChange(id)}
          >
            <Icon size={18} />
            <span>{t(`nav.${id}`)}</span>
            {istAktiv && (
              <span className="tab-nav__wanne" aria-hidden="true">
                <svg viewBox="0 0 200 11" preserveAspectRatio="none">
                  <path d="M2,0 C2,7 5,9 12,9.6 L188,9.6 C195,9 198,7 198,0 C197.2,6.4 194.4,8.2 188,8.4 L12,8.4 C5.6,8.2 2.8,6.4 2,0 Z" />
                </svg>
              </span>
            )}
          </button>
        );
      })}
    </nav>
  );
}
