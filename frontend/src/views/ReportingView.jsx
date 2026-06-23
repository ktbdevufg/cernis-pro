// Reporting-Ansicht (CERNIS PRO 2.0)
// Kachel-Übersicht der Reporting-Funktionen. Klick auf eine aktive Kachel öffnet
// vorerst einen "in Arbeit"-Platzhalter mit Zurück-Weg.
//
// Funktionen:
//   "report"  Bericht erstellen (aktiv, Inhalt vorerst Platzhalter)

import { FileText } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import {
  CardGrid,
  FunctionShell,
  InProgress,
} from "../components/AreaShell.jsx";
import FunctionCard from "../components/FunctionCard.jsx";

// Kachel-Definition: Schlüssel, Icon, Sperrstatus. Reihenfolge ist verbindlich.
const FUNKTIONEN = [{ id: "report", icon: FileText, locked: false }];

export default function ReportingView() {
  const { t } = useTranslation();
  // null -> Kachel-Übersicht; sonst die geöffnete Funktion.
  const [openFunction, setOpenFunction] = useState(null);

  if (openFunction) {
    return (
      <FunctionShell
        title={t(`reporting.cards.${openFunction}.title`)}
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
          title={t(`reporting.cards.${id}.title`)}
          subtitle={t(`reporting.cards.${id}.subtitle`)}
          locked={locked}
          lockedReason={locked ? t(`reporting.cards.${id}.locked`) : undefined}
          onOpen={() => setOpenFunction(id)}
        />
      ))}
    </CardGrid>
  );
}
