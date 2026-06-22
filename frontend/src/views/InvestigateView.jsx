// Untersuchen-Ansicht (CERNIS PRO 2.0)
// Kachel-Übersicht der Untersuchungs-Funktionen. Klick auf eine aktive Kachel
// öffnet vorerst einen "in Arbeit"-Platzhalter mit Zurück-Weg.
//
// Funktionen:
//   "diagnose"  Diagnose (aktiv: zeigt die Route-zum-Ziel-Ansicht, ADR 0036)
//   "analysis"  Analyse (gesperrt: braucht gesammelte Daten)
//   "cve"       CVE-Abgleich (aktiv: zeigt die CVE-Befund-Ansicht, ADR 0037)

import { Activity, ScanSearch, ShieldAlert } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import {
  CardGrid,
  FunctionShell,
  InProgress,
} from "../components/AreaShell.jsx";
import CveView from "../components/CveView.jsx";
import FunctionCard from "../components/FunctionCard.jsx";
import RouteView from "../components/RouteView.jsx";

// Kachel-Definition: Schlüssel, Icon, Sperrstatus. Reihenfolge ist verbindlich.
const FUNKTIONEN = [
  { id: "diagnose", icon: Activity, locked: false },
  { id: "analysis", icon: ScanSearch, locked: true },
  { id: "cve", icon: ShieldAlert, locked: false },
];

export default function InvestigateView({
  initialFunction = null,
  onFunktionGeoeffnet,
}) {
  const { t } = useTranslation();
  // null -> Kachel-Übersicht; sonst die geöffnete Funktion. Eine von aussen
  // gewuenschte Funktion (initialFunction, z. B. von der Startseiten-Kachel)
  // wird initial uebernommen.
  const [openFunction, setOpenFunction] = useState(initialFunction);

  // Wechselt initialFunction (z. B. erneuter Kachel-Klick bei bereits offenem
  // Untersuchen-Bereich), die gewuenschte Funktion oeffnen und beim Eltern-State
  // quittieren, damit der Nutzer danach frei zur Uebersicht zurueck kann.
  useEffect(() => {
    if (initialFunction) {
      setOpenFunction(initialFunction);
      onFunktionGeoeffnet?.();
    }
  }, [initialFunction, onFunktionGeoeffnet]);

  if (openFunction) {
    // "diagnose" zeigt die Route-zum-Ziel-Ansicht (ADR 0036), "cve" die
    // CVE-Befund-Ansicht (ADR 0037); die übrigen Funktionen sind Platzhalter.
    return (
      <FunctionShell
        title={t(`untersuchen.cards.${openFunction}.title`)}
        onBack={() => setOpenFunction(null)}
      >
        {openFunction === "diagnose" ? (
          <RouteView />
        ) : openFunction === "cve" ? (
          <CveView />
        ) : (
          <InProgress />
        )}
      </FunctionShell>
    );
  }

  return (
    <CardGrid>
      {FUNKTIONEN.map(({ id, icon, locked }) => (
        <FunctionCard
          key={id}
          icon={icon}
          title={t(`untersuchen.cards.${id}.title`)}
          subtitle={t(`untersuchen.cards.${id}.subtitle`)}
          locked={locked}
          lockedReason={locked ? t(`untersuchen.cards.${id}.locked`) : undefined}
          onOpen={() => setOpenFunction(id)}
        />
      ))}
    </CardGrid>
  );
}
