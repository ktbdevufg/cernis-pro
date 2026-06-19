// Untersuchen-Ansicht (CERNIS PRO 2.0)
// Kachel-Übersicht der Untersuchungs-Funktionen. Klick auf eine aktive Kachel
// öffnet vorerst einen "in Arbeit"-Platzhalter mit Zurück-Weg.
//
// Funktionen:
//   "analysis"  Analyse (gesperrt: braucht gesammelte Daten)
//   "diagnose"  Diagnose (aktiv: zeigt die Route-zum-Ziel-Ansicht, ADR 0036)
//   "cve"       CVE-Abgleich (aktiv: zeigt die CVE-Befund-Ansicht, ADR 0037)

import { Activity, ScanSearch, ShieldAlert } from "lucide-react";
import { useState } from "react";
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
  { id: "analysis", icon: ScanSearch, locked: true },
  { id: "diagnose", icon: Activity, locked: false },
  { id: "cve", icon: ShieldAlert, locked: false },
];

export default function InvestigateView() {
  const { t } = useTranslation();
  // null -> Kachel-Übersicht; sonst die geöffnete Funktion.
  const [openFunction, setOpenFunction] = useState(null);

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
