// Bereichs-Hülle (CERNIS PRO 2.0)
// Gemeinsames Gerüst für Bereiche mit Kachel-Übersicht (Observe/Investigate/
// Export): zeigt entweder das Kachel-Gitter (CardGrid) oder eine geöffnete
// Funktion mit "Zurück"-Weg zur Übersicht (FunctionShell).
//
// Beide sind reine Layout-Hüllen ohne eigenen State — der Bereich entscheidet,
// welche Funktion geöffnet ist, und gibt onBack mit.

import { ArrowLeft } from "lucide-react";
import { useTranslation } from "react-i18next";

import HelpDot from "./HelpDot.jsx";
import "./AreaShell.css";

// Kachel-Gitter für die Bereichs-Übersicht.
export function CardGrid({ children }) {
  return <div className="card-grid">{children}</div>;
}

// Geöffnete Funktion: Zurück-Leiste mit Titel über dem Funktionsinhalt.
//
// zurueckVerbergen (Default false): blendet NUR den Zurück-Knopf aus, der Titel
// bleibt stehen. Hintergrund: hat der Funktionsinhalt selbst eine Detailansicht
// mit eigenem Zurück (z. B. die Logging-Detailansicht), wäre der Shell-Zurück
// darüber redundant + verwirrend. Default false -> alle bestehenden Aufrufer
// (scan/traffic/monitor) unverändert.
export function FunctionShell({
  title,
  onBack,
  children,
  zurueckVerbergen = false,
  helpId,
  onOpenManual,
}) {
  const { t } = useTranslation();

  return (
    <div className="function-shell">
      <div className="function-shell__bar">
        {!zurueckVerbergen && (
          <button
            type="button"
            className="function-shell__back"
            onClick={onBack}
          >
            <ArrowLeft size={16} />
            <span>{t("cards.back")}</span>
          </button>
        )}
        <h2 className="function-shell__title">{title}</h2>
        {helpId ? (
          <HelpDot helpId={helpId} onOpenManual={onOpenManual} />
        ) : null}
      </div>

      <div className="function-shell__body">{children}</div>
    </div>
  );
}

// Neutraler "in Arbeit"-Platzhalter für noch nicht gebaute Funktionsinhalte.
export function InProgress() {
  const { t } = useTranslation();
  return <p className="function-shell__wip">{t("placeholder.inProgress")}</p>;
}
