// Geräte-Ansicht (CERNIS PRO 2.0)
// Kachel-Übersicht der Geräte-Funktionen. Aufbau EXAKT nach InvestigateView.jsx
// (CardGrid + FunctionCard + openFunction-State -> FunctionShell). Erste und
// vorerst einzige Kachel: die FRITZ!Box.
//
// Funktionen:
//   "fritzbox"   FRITZ!Box (aktiv) -> FritzBoxPanel im FunctionShell.

import { Router } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { CardGrid, FunctionShell } from "../components/AreaShell.jsx";
import FritzBoxPanel from "../components/FritzBoxPanel.jsx";
import FunctionCard from "../components/FunctionCard.jsx";

// Kachel-Definition: Schlüssel, Icon, Sperrstatus. Reihenfolge ist verbindlich.
const FUNKTIONEN = [
  { id: "fritzbox", icon: Router, locked: false, helpId: "help.fritzbox.detail" },
];

export default function DevicesView({ onOpenManual }) {
  const { t } = useTranslation();
  // null -> Kachel-Übersicht; sonst die geöffnete Funktion.
  const [openFunction, setOpenFunction] = useState(null);

  if (openFunction === "fritzbox") {
    return (
      <FunctionShell
        title={t("geraete.cards.fritzbox.title")}
        onBack={() => setOpenFunction(null)}
        helpId="help.fritzbox.detail"
        onOpenManual={onOpenManual}
      >
        <FritzBoxPanel />
      </FunctionShell>
    );
  }

  return (
    <CardGrid>
      {FUNKTIONEN.map(({ id, icon, locked, helpId }) => (
        <FunctionCard
          key={id}
          icon={icon}
          title={t(`geraete.cards.${id}.title`)}
          subtitle={t(`geraete.cards.${id}.subtitle`)}
          locked={locked}
          onOpen={() => setOpenFunction(id)}
          helpId={helpId}
          onOpenManual={onOpenManual}
        />
      ))}
    </CardGrid>
  );
}
