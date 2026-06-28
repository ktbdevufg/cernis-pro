// Reporting-Ansicht (CERNIS PRO 2.0)
// Kachel-Übersicht der Reporting-Funktionen. Jede Bericht-Art ist eine eigene
// Kachel; Klick auf eine aktive Kachel öffnet die zugehörige Berichts-Ansicht.
//
// Funktionen:
//   "security"  Netzwerk-Sicherheitsbericht (aktiv)
//   weitere Berichte folgen als eigene Kacheln (zusätzlicher FUNKTIONEN-Eintrag
//   mit eigener id + Eintrag in KOMPONENTEN_JE_ID).

import { Boxes, ShieldAlert, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import {
  CardGrid,
  FunctionShell,
} from "../components/AreaShell.jsx";
import FunctionCard from "../components/FunctionCard.jsx";
import CveReportView from "../components/CveReportView.jsx";
import InventoryReportView from "../components/InventoryReportView.jsx";
import SecurityReportView from "../components/SecurityReportView.jsx";

// Kachel-Definition: Schlüssel, Icon, Sperrstatus. Reihenfolge ist verbindlich.
const FUNKTIONEN = [
  { id: "security", icon: ShieldCheck, locked: false },
  { id: "inventory", icon: Boxes, locked: false },
  { id: "cve", icon: ShieldAlert, locked: false },
];

// Mapping id -> geöffnete Berichts-Komponente. Ein weiterer Bericht braucht nur
// einen FUNKTIONEN-Eintrag oben und einen Eintrag hier.
const KOMPONENTEN_JE_ID = {
  security: SecurityReportView,
  inventory: InventoryReportView,
  cve: CveReportView,
};

export default function ReportingView() {
  const { t } = useTranslation();
  // null -> Kachel-Übersicht; sonst die geöffnete Funktion.
  const [openFunction, setOpenFunction] = useState(null);

  if (openFunction) {
    const Bericht = KOMPONENTEN_JE_ID[openFunction];
    return (
      <FunctionShell
        title={t(`reporting.cards.${openFunction}.title`)}
        onBack={() => setOpenFunction(null)}
      >
        {Bericht ? <Bericht /> : null}
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
