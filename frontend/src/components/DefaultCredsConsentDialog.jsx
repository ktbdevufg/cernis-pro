// Warndialog vor dem Freischalten der Standardzugangs-Prüfung (CERNIS PRO 2.0, E2)
//
// Reiner Präsentations-Dialog, Muster OutboundConsentDialog/DnsBypassConsentDialog
// (Variante B, strukturiert): erklärt, was die scharfe Opt-in-Sonderfunktion tut,
// BEVOR sie für die Sitzung freigeschaltet wird. KEIN eigenes Settings-/Hook-
// Wissen — die Entscheidung (Bestätigen/Abbrechen) reicht er über
// onConfirm/onCancel nach oben; der Aufrufer ruft danach armDefaultCreds(true).
// Nur CSS-Tokens; die Optik teilt er sich mit OutboundConsentDialog (dieselben
// outbound-consent-*-Klassen), darum KEINE eigene CSS-Datei.
//
// Drei Punkte machen die Eigenschaften ehrlich explizit:
//   Aktiver Login-Versuch (KeyRound) — greift aktiv an, kann Geräte-Logs/Sperren
//                                       auslösen; nur eigene Geräte.
//   Nur eigenes Netz (Network)       — das Backend prüft nur Ziele im privaten
//                                       Netz, fremde Ziele werden abgelehnt.
//   Nur diese Sitzung (Clock)        — die Freischaltung gilt NUR für die aktuelle
//                                       CERNIS-Sitzung, sie ist nicht persistent.
//
// Anders als die Aufzeichnungs-Consent-Dialoge OHNE „Nicht mehr fragen": die
// Freischaltung gilt bewusst nur sitzungsweit, ein dauerhaftes Merken widerspräche
// dem scharfen Opt-in-Charakter. Escape = Abbrechen (Muster MaintenanceDialog).

import { KeyRound, Network, Clock } from "lucide-react";
import { useEffect } from "react";
import { useTranslation } from "react-i18next";

import "./OutboundConsentDialog.css";

export default function DefaultCredsConsentDialog({ onConfirm, onCancel }) {
  const { t } = useTranslation();

  // Escape schließt den Dialog als Abbruch (Standard-Overlay-Verhalten, Muster
  // MaintenanceDialog). onCancel bewusst in den Dependencies, damit ein neuer
  // Handler nie auf einen veralteten Callback zeigt.
  useEffect(() => {
    const handler = (e) => {
      if (e.key === "Escape") {
        onCancel();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onCancel]);

  return (
    <div className="outbound-consent-overlay">
      <div
        className="outbound-consent-dialog"
        role="dialog"
        aria-modal="true"
        aria-label={t("settings.defaultCreds.dialogTitle")}
      >
        {/* Titel-Zeile: Schlüssel-Icon + Überschrift. */}
        <div className="outbound-consent-titel">
          <KeyRound size={20} aria-hidden="true" />
          <h2 className="outbound-consent-h">
            {t("settings.defaultCreds.dialogTitle")}
          </h2>
        </div>

        {/* Intro-Absatz: was die Freischaltung bedeutet. */}
        <p className="outbound-consent-intro">
          {t("settings.defaultCreds.dialogBody")}
        </p>

        {/* Drei Eigenschaften-Zeilen: Icon + <strong>Titel</strong> + Text. */}
        <div className="outbound-consent-point">
          <KeyRound size={18} aria-hidden="true" />
          <span className="outbound-consent-point-text">
            <strong>{t("settings.defaultCreds.dialogActiveTitle")}</strong>{" "}
            {t("settings.defaultCreds.dialogActiveText")}
          </span>
        </div>
        <div className="outbound-consent-point">
          <Network size={18} aria-hidden="true" />
          <span className="outbound-consent-point-text">
            <strong>{t("settings.defaultCreds.dialogOwnNetTitle")}</strong>{" "}
            {t("settings.defaultCreds.dialogOwnNetText")}
          </span>
        </div>
        <div className="outbound-consent-point">
          <Clock size={18} aria-hidden="true" />
          <span className="outbound-consent-point-text">
            <strong>{t("settings.defaultCreds.dialogSessionTitle")}</strong>{" "}
            {t("settings.defaultCreds.dialogSessionText")}
          </span>
        </div>

        {/* Knopfzeile, rechtsbündig: Abbrechen + Bestätigen. */}
        <div className="outbound-consent-actions">
          <button
            type="button"
            className="outbound-consent-button"
            onClick={onCancel}
          >
            {t("settings.defaultCreds.cancel")}
          </button>
          <button
            type="button"
            className="outbound-consent-button outbound-consent-button--grant"
            onClick={onConfirm}
          >
            {t("settings.defaultCreds.confirm")}
          </button>
        </div>
      </div>
    </div>
  );
}
