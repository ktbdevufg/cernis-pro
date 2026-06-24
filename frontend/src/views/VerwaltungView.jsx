// Verwaltungs-Ansicht (CERNIS PRO 2.0)
// Kachel-Übersicht der Verwaltungs-Funktionen. Aufbau EXAKT nach DevicesView.jsx
// (CardGrid + FunctionCard + openFunction-State -> FunctionShell). Bündelt die
// Geräteverwaltung und die Wartung („Daten löschen").
//
// Funktionen:
//   "geraeteverwaltung" Geräteverwaltung (aktiv) -> DeviceManagementPanel.
//   "wartung"           Daten löschen (aktiv) -> WartungPanel.

import { ListChecks, Trash2 } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { CardGrid, FunctionShell } from "../components/AreaShell.jsx";
import DeviceManagementPanel from "../components/DeviceManagementPanel.jsx";
import FunctionCard from "../components/FunctionCard.jsx";
import WartungPanel from "../components/WartungPanel.jsx";

// Kachel-Definition: Schlüssel, Icon, Sperrstatus. Reihenfolge ist verbindlich.
const FUNKTIONEN = [
  { id: "geraeteverwaltung", icon: ListChecks, locked: false },
  { id: "wartung", icon: Trash2, locked: false },
];

export default function VerwaltungView() {
  const { t } = useTranslation();
  // null -> Kachel-Übersicht; sonst die geöffnete Funktion.
  const [openFunction, setOpenFunction] = useState(null);

  if (openFunction === "geraeteverwaltung") {
    return (
      <FunctionShell
        title={t("verwaltung.cards.geraeteverwaltung.title")}
        onBack={() => setOpenFunction(null)}
      >
        <DeviceManagementPanel />
      </FunctionShell>
    );
  }

  if (openFunction === "wartung") {
    return (
      <FunctionShell
        title={t("verwaltung.cards.wartung.title")}
        onBack={() => setOpenFunction(null)}
      >
        <WartungPanel />
      </FunctionShell>
    );
  }

  return (
    <CardGrid>
      {FUNKTIONEN.map(({ id, icon, locked }) => (
        <FunctionCard
          key={id}
          icon={icon}
          title={t(`verwaltung.cards.${id}.title`)}
          subtitle={t(`verwaltung.cards.${id}.subtitle`)}
          locked={locked}
          onOpen={() => setOpenFunction(id)}
        />
      ))}
    </CardGrid>
  );
}
