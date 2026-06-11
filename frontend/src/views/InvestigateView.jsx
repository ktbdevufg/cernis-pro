// Untersuchen-Ansicht (CERNIS PRO 2.0)
// Kachel-Übersicht der Untersuchungs-Funktionen. Klick auf eine aktive Kachel
// öffnet vorerst einen "in Arbeit"-Platzhalter mit Zurück-Weg.
//
// Funktionen:
//   "analysis"  Analyse (gesperrt: braucht gesammelte Daten)
//   "diagnose"  Diagnose (aktiv, Inhalt vorerst Platzhalter)
//   "cve"       CVE-Abgleich (aktiv, Inhalt vorerst Platzhalter)

import { Activity, ScanSearch, ShieldAlert } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import {
  CardGrid,
  FunctionShell,
  InProgress,
} from "../components/AreaShell.jsx";
import FunctionCard from "../components/FunctionCard.jsx";

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
    return (
      <FunctionShell
        title={t(`untersuchen.cards.${openFunction}.title`)}
        onBack={() => setOpenFunction(null)}
      >
        <InProgress />
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
