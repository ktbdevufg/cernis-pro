// Wartungs-Panel (CERNIS PRO 2.0)
// Eigenständiges Panel für „Daten löschen": ein ruhiger Erklär-Abschnitt + Knopf
// „Optionen anzeigen", der den zweistufigen Bestätigungs-Dialog öffnet. Der
// Backend-Aufruf läuft hier; das „erledigt"-Feedback zeigt das Panel selbst
// (kein onGespeichert von außen).
//
// Verschoben aus SettingsView.WartungSektion — Logik unverändert, nur ohne das
// SettingsSektion/SettingsZeile-Markup. Nutzt weiter die vorhandenen i18n-Keys
// settings.wartung.* (Texte bleiben inhaltlich gleich).
//
// Nach erfolgreichem Werkszustand sind alle Einstellungen (inkl. Sprache) weg —
// dafür ein eigener, ruhiger Hinweis. KEIN automatischer Reload (nur der Hinweis).

import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { factoryReset, resetSelected } from "../api/maintenance.js";
import MaintenanceDialog from "./MaintenanceDialog.jsx";
import "./WartungPanel.css";

export default function WartungPanel() {
  const { t } = useTranslation();

  const [dialogOffen, setDialogOffen] = useState(false);
  // null = kein Hinweis; "selected" | "factory" = welche „erledigt"-Meldung zeigen.
  const [erledigt, setErledigt] = useState(null);
  const erledigtTimeout = useRef(null);

  useEffect(() => {
    return () => {
      if (erledigtTimeout.current !== null) {
        clearTimeout(erledigtTimeout.current);
      }
    };
  }, []);

  // Den ruhigen „erledigt"-Hinweis kurz zeigen. Werkszustand bleibt etwas länger
  // stehen, da der Hinweis dort auch das Settings-Reset erklärt.
  const zeigeErledigt = (stufe) => {
    setErledigt(stufe);
    if (erledigtTimeout.current !== null) {
      clearTimeout(erledigtTimeout.current);
    }
    const dauer = stufe === "factory" ? 6000 : 3000;
    erledigtTimeout.current = setTimeout(() => {
      setErledigt(null);
      erledigtTimeout.current = null;
    }, dauer);
  };

  // Wird vom Dialog auf „Endgültig löschen" gerufen. Wirft bei Fehler weiter (der
  // Dialog fängt ihn und bleibt offen); bei Erfolg Dialog schließen + Hinweis.
  // Zwei Fälle: "factory" -> Werkszustand; "selected" -> granularer Baukasten mit
  // der effektiven Item-Liste (Wire-Strings; erzwungene Posten schon enthalten).
  const handleBestaetigt = async (stufe, { items, secretsEntfernen }) => {
    if (stufe === "factory") {
      await factoryReset(secretsEntfernen);
    } else {
      await resetSelected(items);
    }
    setDialogOffen(false);
    zeigeErledigt(stufe);
  };

  return (
    <div className="wp-panel">
      <section className="wp-section">
        <p className="wp-section__desc">{t("settings.wartung.rowDescription")}</p>
        <div className="wp-section__actions">
          <button
            type="button"
            className="wp-button"
            onClick={() => setDialogOffen(true)}
          >
            {t("settings.wartung.openButton")}
          </button>
        </div>
        {erledigt ? (
          <span className="wp-done" role="status" aria-live="polite">
            {erledigt === "factory"
              ? t("settings.wartung.doneFactory")
              : t("settings.wartung.doneSelected")}
          </span>
        ) : null}
      </section>

      {dialogOffen ? (
        <MaintenanceDialog
          onSchliessen={() => setDialogOffen(false)}
          onBestaetigt={handleBestaetigt}
        />
      ) : null}
    </div>
  );
}
