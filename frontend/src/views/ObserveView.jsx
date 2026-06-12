// Beobachten-Ansicht (CERNIS PRO 2.0)
// Zeigt zuerst eine Kachel-Übersicht der Funktionen. Klick auf eine aktive
// Kachel öffnet die zugehörige Funktion in derselben Fläche, mit Zurück-Weg.
//
// Funktionen:
//   "scan"     Netzwerk-Scan (aktiv) -> bestehende Scan-Tabelle
//   "traffic"  Per-App-Verkehr (aktiv) -> App-Liste + Verbindungs-Detail
//   "processes" Prozesse (gesperrt bis Beobachtung läuft)
//
// Datenquelle der Tabelle ist ausschließlich der Import aus mockData/scanMock.
// Die View weiß nicht, ob die Daten echt oder Platzhalter sind. Bei echter
// Anbindung wird nur dieser Import ausgetauscht.

import { ListTree, Radar, Repeat } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { CardGrid, FunctionShell } from "../components/AreaShell.jsx";
import FunctionCard from "../components/FunctionCard.jsx";
import ScanDetailPanel from "../components/ScanDetailPanel.jsx";
import ScanTable from "../components/ScanTable.jsx";
import TrafficView from "../components/TrafficView.jsx";
import scanMock from "../mockData/scanMock.js";
import "./ObserveView.css";

// Kachel-Definition: Schlüssel, Icon, Sperrstatus. Reihenfolge ist verbindlich.
const FUNKTIONEN = [
  { id: "scan", icon: Radar, locked: false },
  { id: "traffic", icon: Repeat, locked: false },
  { id: "processes", icon: ListTree, locked: true },
];

// Scan-Inhalt: Kopf-Leiste (Anzahl + "Scan starten") über der Tabelle.
// Hält die Auswahl (welches Gerät) und zeigt rechts das Detail-Panel an,
// sobald eine Zeile gewählt ist.
function ScanInhalt() {
  const { t } = useTranslation();
  const { geraete } = scanMock;

  // Gewähltes Gerät über die MAC (eindeutiger Schlüssel im Mock); null = keins.
  const [gewaehlteMac, setGewaehlteMac] = useState(null);

  // Klick auf eine Zeile: wählt das Gerät; erneuter Klick auf dieselbe löscht.
  const handleSelect = (geraet) => {
    setGewaehlteMac((aktuell) =>
      aktuell === geraet.mac ? null : geraet.mac,
    );
  };

  const gewaehltesGeraet =
    geraete.find((g) => g.mac === gewaehlteMac) ?? null;

  return (
    <div className="observe__scan">
      <div className="observe__toolbar">
        <span className="observe__count">
          {t("beobachten.scan.deviceCount", { count: geraete.length })}
        </span>
        {/* Button löst vorerst nichts aus (Platzhalter, kein API-Call). */}
        <button type="button" className="observe__scan-button">
          {t("beobachten.scan.startScan")}
        </button>
      </div>

      {/* Zwei-Spalten-Layout: Tabelle links, Panel rechts (nur bei Auswahl). */}
      <div className="observe__split">
        <ScanTable
          geraete={geraete}
          onSelect={handleSelect}
          selectedMac={gewaehlteMac}
        />
        {gewaehltesGeraet && (
          <ScanDetailPanel
            key={gewaehltesGeraet.mac}
            geraet={gewaehltesGeraet}
            onClose={() => setGewaehlteMac(null)}
          />
        )}
      </div>
    </div>
  );
}

export default function ObserveView() {
  const { t } = useTranslation();
  // null -> Kachel-Übersicht; sonst die geöffnete Funktion.
  const [openFunction, setOpenFunction] = useState(null);

  if (openFunction === "scan") {
    return (
      <FunctionShell
        title={t("beobachten.cards.scan.title")}
        onBack={() => setOpenFunction(null)}
      >
        <ScanInhalt />
      </FunctionShell>
    );
  }

  if (openFunction === "traffic") {
    return (
      <FunctionShell
        title={t("beobachten.cards.traffic.title")}
        onBack={() => setOpenFunction(null)}
      >
        <TrafficView />
      </FunctionShell>
    );
  }

  return (
    <CardGrid>
      {FUNKTIONEN.map(({ id, icon, locked }) => (
        <FunctionCard
          key={id}
          icon={icon}
          title={t(`beobachten.cards.${id}.title`)}
          subtitle={t(`beobachten.cards.${id}.subtitle`)}
          locked={locked}
          lockedReason={locked ? t(`beobachten.cards.${id}.locked`) : undefined}
          onOpen={() => setOpenFunction(id)}
        />
      ))}
    </CardGrid>
  );
}
