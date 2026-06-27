// Einwilligungs-Dialog für echte Domainnamen (CERNIS PRO 2.0)
//
// Reiner Präsentations-Dialog (Variante B, strukturiert): erklärt, was die
// passive SNI-Beobachtung tut, bevor sie startet. KEIN eigenes Settings-/Hook-
// Wissen — die Entscheidung (Zustimmen/Ablehnen) reicht er über onGrant/onDeny
// nach oben; der Aufrufer persistiert ggf. Stil bewusst wie MaintenanceDialog
// (zentrierter Overlay-Dialog, nur CSS-Tokens, keine hartkodierten Farben).
//
// Drei Punkte machen die Eigenschaften der Beobachtung explizit:
//   Passiv (Eye)         — liest nur mit, greift nie in den Verkehr ein.
//   Flüchtig (Clock)     — nur solange die Ansicht offen ist, nichts gespeichert.
//   Erhöhte Rechte (ShieldCheck) — einmal eingerichtet, kein wiederkehrender Dialog.
//
// Das „Nicht mehr fragen"-Kästchen (dontAsk) wird an die Callbacks durchgereicht:
// onGrant(dontAsk) / onDeny(dontAsk). Beim Ablehnen entscheidet der Aufrufer
// anhand von dontAsk, ob die Ablehnung dauerhaft persistiert wird.

import { Globe, Eye, Clock, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import "./OutboundConsentDialog.css";

export default function OutboundConsentDialog({ onGrant, onDeny }) {
  const { t } = useTranslation();

  // Lokaler Präsentations-State: das „Nicht mehr fragen"-Kästchen. Wird beim
  // Klick als Bool an onGrant/onDeny gereicht (der Aufrufer persistiert ggf.).
  const [dontAsk, setDontAsk] = useState(false);

  return (
    <div className="outbound-consent-overlay">
      <div
        className="outbound-consent-dialog"
        role="dialog"
        aria-modal="true"
        aria-label={t("beobachten.outbound.sni.consentTitle")}
      >
        {/* Titel-Zeile: Globe-Icon + Überschrift. */}
        <div className="outbound-consent-titel">
          <Globe size={20} aria-hidden="true" />
          <h2 className="outbound-consent-h">
            {t("beobachten.outbound.sni.consentTitle")}
          </h2>
        </div>

        {/* Intro-Absatz: warum echte Domainnamen sichtbar machen. */}
        <p className="outbound-consent-intro">
          {t("beobachten.outbound.sni.consentIntro")}
        </p>

        {/* Drei Eigenschaften-Zeilen: Icon + <strong>Titel</strong> + Text. */}
        <div className="outbound-consent-point">
          <Eye size={18} aria-hidden="true" />
          <span className="outbound-consent-point-text">
            <strong>{t("beobachten.outbound.sni.consentPassiveTitle")}</strong>{" "}
            {t("beobachten.outbound.sni.consentPassiveText")}
          </span>
        </div>
        <div className="outbound-consent-point">
          <Clock size={18} aria-hidden="true" />
          <span className="outbound-consent-point-text">
            <strong>{t("beobachten.outbound.sni.consentEphemeralTitle")}</strong>{" "}
            {t("beobachten.outbound.sni.consentEphemeralText")}
          </span>
        </div>
        <div className="outbound-consent-point">
          <ShieldCheck size={18} aria-hidden="true" />
          <span className="outbound-consent-point-text">
            <strong>{t("beobachten.outbound.sni.consentPrivilegeTitle")}</strong>{" "}
            {t("beobachten.outbound.sni.consentPrivilegeText")}
          </span>
        </div>

        {/* „Nicht mehr fragen"-Kästchen: rein lokaler State, an die Callbacks
            durchgereicht. */}
        <label className="outbound-consent-dontask">
          <input
            type="checkbox"
            checked={dontAsk}
            onChange={(e) => setDontAsk(e.target.checked)}
          />
          {t("beobachten.outbound.sni.consentDontAsk")}
        </label>

        {/* Knopfzeile, rechtsbündig: Ablehnen + Zustimmen. */}
        <div className="outbound-consent-actions">
          <button
            type="button"
            className="outbound-consent-button"
            onClick={() => onDeny(dontAsk)}
          >
            {t("beobachten.outbound.sni.consentDeny")}
          </button>
          <button
            type="button"
            className="outbound-consent-button outbound-consent-button--grant"
            onClick={() => onGrant(dontAsk)}
          >
            {t("beobachten.outbound.sni.consentGrant")}
          </button>
        </div>
      </div>
    </div>
  );
}
