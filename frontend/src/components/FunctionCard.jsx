// Funktions-Kachel (CERNIS PRO 2.0)
// Gemeinsame Kachel für die Bereichs-Übersichten (Observe/Investigate/Export).
// Zeigt Icon, Titel, Untertitel und unten einen "Öffnen"-Hinweis. Gesperrte
// Kacheln sind ausgegraut, nicht klickbar und nennen einen Sperrgrund.
//
// Props:
//   icon         lucide-Komponente (oben links)
//   title        Kachel-Titel
//   subtitle     kurzer neutraler Untertitel
//   locked       bool — true sperrt die Kachel
//   lockedReason Begründungstext bei gesperrter Kachel
//   onOpen       Klick-Handler (nur aktive Kachel)
//   onInfo       Klick-Handler des Info-Icons oben rechts (Platzhalter)

import { ArrowRight, Info, Lock } from "lucide-react";
import { useTranslation } from "react-i18next";

import "./FunctionCard.css";

export default function FunctionCard({
  icon: Icon,
  title,
  subtitle,
  locked = false,
  lockedReason,
  onOpen,
  onInfo,
}) {
  const { t } = useTranslation();

  // Info-Icon nicht den Karten-Klick auslösen lassen.
  const handleInfo = (event) => {
    event.stopPropagation();
    if (onInfo) onInfo();
  };

  return (
    <div
      className={
        locked ? "function-card function-card--locked" : "function-card"
      }
      role={locked ? undefined : "button"}
      tabIndex={locked ? undefined : 0}
      aria-disabled={locked ? true : undefined}
      onClick={locked ? undefined : onOpen}
      onKeyDown={
        locked
          ? undefined
          : (event) => {
              if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                onOpen?.();
              }
            }
      }
    >
      <div className="function-card__head">
        <span className="function-card__icon">
          <Icon size={23} />
        </span>
        <button
          type="button"
          className="function-card__info"
          aria-label={t("cards.infoLabel")}
          onClick={handleInfo}
        >
          <Info size={16} />
        </button>
      </div>

      <h3 className="function-card__title">{title}</h3>
      <p className="function-card__subtitle">{subtitle}</p>

      {locked ? (
        <div className="function-card__locked-row">
          <Lock size={14} />
          <span>{lockedReason}</span>
        </div>
      ) : (
        <div className="function-card__open-row">
          <span>{t("cards.open")}</span>
          <ArrowRight size={15} />
        </div>
      )}
    </div>
  );
}
