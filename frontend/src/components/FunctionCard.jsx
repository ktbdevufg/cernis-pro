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
//   aktiv        bool — true zeigt ein ruhiges grünes "aktiv"-Kennzeichen neben dem
//                Icon (Default false -> kein Kennzeichen; andere Views bleiben so
//                völlig unverändert, da sie die Prop nicht setzen)
//   onOpen       Klick-Handler (nur aktive Kachel)
//   helpId       help_content.json-Schlüssel; gesetzt -> "?"-HelpDot-Popup oben
//                rechts. Ohne helpId wird kein Knopf gerendert.
//   onOpenManual onOpenManual(helpId) für den HelpDot ("Mehr im Handbuch")

import { ArrowRight, Lock } from "lucide-react";
import { useTranslation } from "react-i18next";

import HelpDot from "./HelpDot.jsx";
import "./FunctionCard.css";

export default function FunctionCard({
  icon: Icon,
  title,
  subtitle,
  locked = false,
  lockedReason,
  aktiv = false,
  onOpen,
  helpId,
  onOpenManual,
}) {
  const { t } = useTranslation();

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
        <span className="function-card__head-left">
          <span className="function-card__icon">
            <Icon size={23} />
          </span>
          {aktiv && (
            <span className="function-card__aktiv">
              <span
                className="function-card__aktiv-punkt"
                aria-hidden="true"
              />
              {t("cards.aktiv")}
            </span>
          )}
        </span>
        {helpId ? (
          // HelpDot-Klick darf den Karten-Klick (onOpen) nicht auslösen.
          <span onClick={(event) => event.stopPropagation()}>
            <HelpDot helpId={helpId} onOpenManual={onOpenManual} />
          </span>
        ) : null}
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
