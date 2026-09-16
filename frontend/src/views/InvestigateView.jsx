// Untersuchen-Ansicht (CERNIS PRO 2.0)
// Kachel-Übersicht der Untersuchungs-Funktionen. Klick auf eine aktive Kachel
// öffnet vorerst einen "in Arbeit"-Platzhalter mit Zurück-Weg.
//
// Funktionen:
//   "diagnose"     Diagnose (aktiv: zeigt die Route-zum-Ziel-Ansicht, ADR 0036)
//   "analysis"     Analyse (gesperrt: braucht gesammelte Daten)
//   "cve"          CVE-Abgleich (aktiv: zeigt die CVE-Befund-Ansicht, ADR 0037)
//   "defaultcreds" Standardzugänge (Etappe 2, scharfer Opt-in): gesperrt, solange
//                  die Sonderfunktion nicht für die Sitzung freigeschaltet ist —
//                  Freischaltung in den Einstellungen. Entsperrt zeigt sie die
//                  Standardzugangs-Prüfansicht.

import { Activity, KeyRound, ScanSearch, ShieldAlert } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { fetchDefaultCredsState } from "../api/security.js";
import {
  CardGrid,
  FunctionShell,
  InProgress,
} from "../components/AreaShell.jsx";
import CveView from "../components/CveView.jsx";
import DefaultCredsView from "../components/DefaultCredsView.jsx";
import FunctionCard from "../components/FunctionCard.jsx";
import RouteView from "../components/RouteView.jsx";

// Kachel-Definition: Schlüssel, Icon, Sperrstatus. Reihenfolge ist verbindlich.
// Die statischen locked-Flags gelten unverändert; "defaultcreds" trägt hier
// KEIN festes locked — sein Sperrstatus hängt sitzungsweit vom Freischalt-Zustand
// ab und wird beim Rendern aus `armed` abgeleitet.
const FUNKTIONEN = [
  { id: "diagnose", icon: Activity, locked: false, helpId: "help.diagnostics.route_geo" },
  { id: "analysis", icon: ScanSearch, locked: true, helpId: "help.analysis.regeln" },
  { id: "cve", icon: ShieldAlert, locked: false, helpId: "help.cve.uebersicht" },
  { id: "defaultcreds", icon: KeyRound, helpId: "help.security.default_creds" },
];

export default function InvestigateView({
  initialFunction = null,
  onFunktionGeoeffnet,
  onOpenManual,
}) {
  const { t } = useTranslation();
  // null -> Kachel-Übersicht; sonst die geöffnete Funktion. Eine von aussen
  // gewuenschte Funktion (initialFunction, z. B. von der Startseiten-Kachel)
  // wird initial uebernommen.
  const [openFunction, setOpenFunction] = useState(initialFunction);
  // Sitzungsweiter Freischalt-Zustand der Standardzugangs-Sonderfunktion. Steuert
  // die Sperrung der "defaultcreds"-Kachel (locked = !armed). NICHT persistent —
  // nur gelesen. Fehler -> als „nicht freigeschaltet" behandeln (sichere Seite:
  // Kachel bleibt gesperrt), kein Absturz.
  const [armed, setArmed] = useState(false);

  // Wechselt initialFunction (z. B. erneuter Kachel-Klick bei bereits offenem
  // Untersuchen-Bereich), die gewuenschte Funktion oeffnen und beim Eltern-State
  // quittieren, damit der Nutzer danach frei zur Uebersicht zurueck kann.
  useEffect(() => {
    if (initialFunction) {
      setOpenFunction(initialFunction);
      onFunktionGeoeffnet?.();
    }
  }, [initialFunction, onFunktionGeoeffnet]);

  // Freischalt-Zustand beim Mount UND bei jeder Rückkehr zur Übersicht lesen
  // (openFunction === null): so spiegelt die Kachel eine gerade in den
  // Einstellungen erfolgte Freischaltung/Abschaltung wider. Fehler still auf der
  // sicheren Seite (armed bleibt false -> Kachel gesperrt).
  useEffect(() => {
    if (openFunction !== null) {
      return undefined;
    }
    let aktiv = true;
    fetchDefaultCredsState()
      .then((zustand) => {
        if (aktiv) {
          setArmed(Boolean(zustand?.armed));
        }
      })
      .catch(() => {
        // Zustand nicht lesbar -> auf der sicheren Seite gesperrt lassen.
        if (aktiv) {
          setArmed(false);
        }
      });
    return () => {
      aktiv = false;
    };
  }, [openFunction]);

  // Sperrstatus je Kachel: statisches locked ODER, für "defaultcreds", der
  // abgeleitete Freischalt-Zustand.
  const istGesperrt = (funktion) =>
    funktion.id === "defaultcreds" ? !armed : Boolean(funktion.locked);

  if (openFunction) {
    // "diagnose" zeigt die Route-zum-Ziel-Ansicht (ADR 0036), "cve" die
    // CVE-Befund-Ansicht (ADR 0037), "defaultcreds" die Standardzugangs-Prüf-
    // ansicht (Etappe 2); die übrigen Funktionen sind Platzhalter.
    return (
      <FunctionShell
        title={t(`untersuchen.cards.${openFunction}.title`)}
        onBack={() => setOpenFunction(null)}
        helpId={FUNKTIONEN.find((f) => f.id === openFunction)?.helpId}
        onOpenManual={onOpenManual}
      >
        {openFunction === "diagnose" ? (
          <RouteView />
        ) : openFunction === "cve" ? (
          <CveView />
        ) : openFunction === "defaultcreds" ? (
          <DefaultCredsView />
        ) : (
          <InProgress />
        )}
      </FunctionShell>
    );
  }

  return (
    <CardGrid>
      {FUNKTIONEN.map((funktion) => {
        const { id, icon, helpId } = funktion;
        const locked = istGesperrt(funktion);
        return (
          <FunctionCard
            key={id}
            icon={icon}
            title={t(`untersuchen.cards.${id}.title`)}
            subtitle={t(`untersuchen.cards.${id}.subtitle`)}
            locked={locked}
            lockedReason={locked ? t(`untersuchen.cards.${id}.locked`) : undefined}
            onOpen={() => setOpenFunction(id)}
            helpId={helpId}
            onOpenManual={onOpenManual}
          />
        );
      })}
    </CardGrid>
  );
}
