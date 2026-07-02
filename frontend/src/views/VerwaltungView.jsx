// Verwaltungs-Ansicht (CERNIS PRO 2.0)
// Kachel-Übersicht der Verwaltungs-Funktionen. Aufbau EXAKT nach DevicesView.jsx
// (CardGrid + FunctionCard + openFunction-State -> FunctionShell). Bündelt die
// Geräteverwaltung und die Wartung („Daten löschen").
//
// Funktionen:
//   "geraeteverwaltung" Geräteverwaltung (aktiv) -> DeviceManagementPanel.
//   "wartung"           Daten löschen (aktiv) -> WartungPanel.
//   "listen"            Listen-Verwaltung (aktiv) -> BlocklistPanel.
//   "dnsvertrauen"      DNS-Server & Vertrauen (aktiv) -> DnsTrustPanel.

import { ListChecks, ShieldAlert, ShieldCheck, Trash2 } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { CardGrid, FunctionShell } from "../components/AreaShell.jsx";
import BlocklistPanel from "../components/BlocklistPanel.jsx";
import DeviceManagementPanel from "../components/DeviceManagementPanel.jsx";
import DnsTrustPanel from "../components/DnsTrustPanel.jsx";
import FunctionCard from "../components/FunctionCard.jsx";
import WartungPanel from "../components/WartungPanel.jsx";

// Kachel-Definition: Schlüssel, Icon, Sperrstatus. Reihenfolge ist verbindlich.
const FUNKTIONEN = [
  { id: "geraeteverwaltung", icon: ListChecks, locked: false, helpId: "help.geraete.verwaltung" },
  { id: "wartung", icon: Trash2, locked: false, helpId: "help.wartung" },
  { id: "listen", icon: ShieldAlert, locked: false, helpId: "help.listen" },
  { id: "dnsvertrauen", icon: ShieldCheck, locked: false, helpId: "help.dnsvertrauen" },
];

export default function VerwaltungView({ onOpenManual }) {
  const { t } = useTranslation();
  // null -> Kachel-Übersicht; sonst die geöffnete Funktion.
  const [openFunction, setOpenFunction] = useState(null);

  if (openFunction === "geraeteverwaltung") {
    return (
      <FunctionShell
        title={t("verwaltung.cards.geraeteverwaltung.title")}
        onBack={() => setOpenFunction(null)}
        helpId="help.geraete.verwaltung"
        onOpenManual={onOpenManual}
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
        helpId="help.wartung"
        onOpenManual={onOpenManual}
      >
        <WartungPanel />
      </FunctionShell>
    );
  }

  if (openFunction === "listen") {
    return (
      <FunctionShell
        title={t("verwaltung.cards.listen.title")}
        onBack={() => setOpenFunction(null)}
        helpId="help.listen"
        onOpenManual={onOpenManual}
      >
        <BlocklistPanel />
      </FunctionShell>
    );
  }

  if (openFunction === "dnsvertrauen") {
    return (
      <FunctionShell
        title={t("verwaltung.cards.dnsvertrauen.title")}
        onBack={() => setOpenFunction(null)}
        helpId="help.dnsvertrauen"
        onOpenManual={onOpenManual}
      >
        <DnsTrustPanel />
      </FunctionShell>
    );
  }

  return (
    <CardGrid>
      {FUNKTIONEN.map(({ id, icon, locked, helpId }) => (
        <FunctionCard
          key={id}
          icon={icon}
          title={t(`verwaltung.cards.${id}.title`)}
          subtitle={t(`verwaltung.cards.${id}.subtitle`)}
          locked={locked}
          onOpen={() => setOpenFunction(id)}
          helpId={helpId}
          onOpenManual={onOpenManual}
        />
      ))}
    </CardGrid>
  );
}
