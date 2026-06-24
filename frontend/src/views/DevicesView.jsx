// Geräte-Ansicht (CERNIS PRO 2.0)
// Kachel-Übersicht der Geräte-Funktionen. Aufbau EXAKT nach InvestigateView.jsx
// (CardGrid + FunctionCard + openFunction-State -> FunctionShell). Erste und
// vorerst einzige Kachel: die FRITZ!Box.
//
// Funktionen:
//   "verwaltung" Geräteverwaltung (aktiv) -> DeviceManagementPanel im FunctionShell.
//   "fritzbox"   FRITZ!Box (aktiv) -> FritzBoxPanel im FunctionShell.

import { ListChecks, Router } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { CardGrid, FunctionShell } from "../components/AreaShell.jsx";
import DeviceManagementPanel from "../components/DeviceManagementPanel.jsx";
import FritzBoxPanel from "../components/FritzBoxPanel.jsx";
import FunctionCard from "../components/FunctionCard.jsx";

// Kachel-Definition: Schlüssel, Icon, Sperrstatus. Reihenfolge ist verbindlich.
// Die Geräteverwaltung ist die zentrale Funktion und steht daher zuerst.
const FUNKTIONEN = [
  { id: "verwaltung", icon: ListChecks, locked: false },
  { id: "fritzbox", icon: Router, locked: false },
];

export default function DevicesView() {
  const { t } = useTranslation();
  // null -> Kachel-Übersicht; sonst die geöffnete Funktion.
  const [openFunction, setOpenFunction] = useState(null);

  if (openFunction === "verwaltung") {
    return (
      <FunctionShell
        title={t("geraete.cards.verwaltung.title")}
        onBack={() => setOpenFunction(null)}
      >
        <DeviceManagementPanel />
      </FunctionShell>
    );
  }

  if (openFunction === "fritzbox") {
    return (
      <FunctionShell
        title={t("geraete.cards.fritzbox.title")}
        onBack={() => setOpenFunction(null)}
      >
        <FritzBoxPanel />
      </FunctionShell>
    );
  }

  return (
    <CardGrid>
      {FUNKTIONEN.map(({ id, icon, locked }) => (
        <FunctionCard
          key={id}
          icon={icon}
          title={t(`geraete.cards.${id}.title`)}
          subtitle={t(`geraete.cards.${id}.subtitle`)}
          locked={locked}
          onOpen={() => setOpenFunction(id)}
        />
      ))}
    </CardGrid>
  );
}
