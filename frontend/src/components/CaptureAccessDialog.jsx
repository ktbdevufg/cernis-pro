// Erklär-Dialog vor der Rechteeinrichtung (CERNIS PRO 2.0, Etappe 2)
//
// Reiner Präsentations-Dialog: erklärt in nicht-technischer Sprache, was gleich
// eingerichtet wird, BEVOR das native Systemfenster nach dem Passwort fragt. Ohne
// diesen Schritt erschiene der Passwortdialog unangekündigt — das soll er nicht.
//
// Kein eigenes API-/Settings-Wissen: die Entscheidung reicht er über
// onConfirm/onDismiss nach oben. Stil und CSS bewusst wie OutboundConsentDialog
// (zentrierter Overlay-Dialog, nur CSS-Tokens, keine hartkodierten Farben) — die
// Klassennamen werden mitbenutzt, damit beide Dialoge identisch aussehen.
//
// Drei Punkte machen die Einrichtung greifbar:
//   Einmalig (KeyRound)     — die Systemabfrage kommt einmal, nicht bei jedem Start.
//   Begrenzt (ShieldCheck)  — nur Lesezugriff auf die Mitschnitt-Geräte, kein Root.
//   Widerrufbar (RotateCcw) — jederzeit rückgängig zu machen.

import { KeyRound, RotateCcw, ShieldCheck } from "lucide-react";
import { useTranslation } from "react-i18next";

import "./OutboundConsentDialog.css";

export default function CaptureAccessDialog({ onConfirm, onDismiss }) {
  const { t } = useTranslation();

  return (
    <div className="outbound-consent-overlay">
      <div
        className="outbound-consent-dialog"
        role="dialog"
        aria-modal="true"
        aria-label={t("beobachten.outbound.access.title")}
      >
        {/* Titel-Zeile: Schlüssel-Icon + Überschrift. */}
        <div className="outbound-consent-titel">
          <KeyRound size={20} aria-hidden="true" />
          <h2 className="outbound-consent-h">
            {t("beobachten.outbound.access.title")}
          </h2>
        </div>

        {/* Intro: was eingerichtet wird und warum überhaupt gefragt wird. */}
        <p className="outbound-consent-intro">
          {t("beobachten.outbound.access.intro")}
        </p>

        {/* Drei Eigenschaften-Zeilen: Icon + <strong>Titel</strong> + Text. */}
        <div className="outbound-consent-point">
          <KeyRound size={18} aria-hidden="true" />
          <span className="outbound-consent-point-text">
            <strong>{t("beobachten.outbound.access.onceTitle")}</strong>{" "}
            {t("beobachten.outbound.access.onceText")}
          </span>
        </div>
        <div className="outbound-consent-point">
          <ShieldCheck size={18} aria-hidden="true" />
          <span className="outbound-consent-point-text">
            <strong>{t("beobachten.outbound.access.limitedTitle")}</strong>{" "}
            {t("beobachten.outbound.access.limitedText")}
          </span>
        </div>
        <div className="outbound-consent-point">
          <RotateCcw size={18} aria-hidden="true" />
          <span className="outbound-consent-point-text">
            <strong>{t("beobachten.outbound.access.revocableTitle")}</strong>{" "}
            {t("beobachten.outbound.access.revocableText")}
          </span>
        </div>

        {/* Ankündigung des nächsten Schritts: das Systemfenster kommt gleich. */}
        <p className="outbound-consent-intro">
          {t("beobachten.outbound.access.nextStep")}
        </p>

        {/* Knopfzeile, rechtsbündig: Später + Einrichten. */}
        <div className="outbound-consent-actions">
          <button
            type="button"
            className="outbound-consent-button"
            onClick={onDismiss}
          >
            {t("beobachten.outbound.access.later")}
          </button>
          <button
            type="button"
            className="outbound-consent-button outbound-consent-button--grant"
            onClick={onConfirm}
          >
            {t("beobachten.outbound.access.confirm")}
          </button>
        </div>
      </div>
    </div>
  );
}
