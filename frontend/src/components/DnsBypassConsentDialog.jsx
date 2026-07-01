// Einwilligungs-Dialog vor dem ersten netzweiten Mitlesen (CERNIS PRO 2.0, E5)
//
// Reiner Praesentations-Dialog, Muster OutboundConsentDialog (Variante B,
// strukturiert): erklaert, was die netzweite, passive DNS-Umgehungs-Aufzeichnung
// tut, BEVOR sie zum ersten Mal startet. KEIN eigenes Settings-/Hook-Wissen --
// die Entscheidung (Zustimmen/Ablehnen) reicht er ueber onGrant/onDeny nach oben;
// der Aufrufer startet ggf. die Aufzeichnung. Nur CSS-Tokens; die Optik teilt er
// sich mit OutboundConsentDialog (dieselben outbound-consent-*-Klassen), darum
// KEINE eigene CSS-Datei.
//
// Drei Punkte machen die Eigenschaften der Aufzeichnung explizit -- ehrlich
// benannt fuer das NETZWEITE (nicht nur host-lokale) Mitlesen:
//   Passiv (Eye)          -- liest nur mit, greift nie in den Verkehr ein.
//   Nur im eigenen Netz (Network) -- liest nur den Verkehr des eigenen Netzes mit.
//   Voraussetzung (ShieldCheck)   -- braucht Netz-Sicht (Gateway/Mirror), sonst leer.
//
// Wie OutboundConsentDialog MIT "Nicht mehr fragen"-Kaestchen (dontAsk): die
// Einwilligung wird ueber das Setting dns_bypass_consent (granted/denied/null)
// persistiert; der Aufrufer entscheidet anhand von dontAsk, ob eine Ablehnung
// dauerhaft als "denied" abgelegt wird. onGrant(dontAsk)/onDeny(dontAsk).

import { Network, Eye, ShieldCheck, ShieldQuestion } from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import "./OutboundConsentDialog.css";

export default function DnsBypassConsentDialog({ onGrant, onDeny }) {
  const { t } = useTranslation();

  // Lokaler Praesentations-State: das "Nicht mehr fragen"-Kaestchen. Wird beim
  // Klick als Bool an onGrant/onDeny gereicht (der Aufrufer persistiert ggf.).
  const [dontAsk, setDontAsk] = useState(false);

  return (
    <div className="outbound-consent-overlay">
      <div
        className="outbound-consent-dialog"
        role="dialog"
        aria-modal="true"
        aria-label={t("beobachten.dnsbypass.consent.title")}
      >
        {/* Titel-Zeile: Netz-Icon + Ueberschrift. */}
        <div className="outbound-consent-titel">
          <Network size={20} aria-hidden="true" />
          <h2 className="outbound-consent-h">
            {t("beobachten.dnsbypass.consent.title")}
          </h2>
        </div>

        {/* Intro-Absatz: warum netzweit passiv mitlesen. */}
        <p className="outbound-consent-intro">
          {t("beobachten.dnsbypass.consent.intro")}
        </p>

        {/* Drei Eigenschaften-Zeilen: Icon + <strong>Titel</strong> + Text. */}
        <div className="outbound-consent-point">
          <Eye size={18} aria-hidden="true" />
          <span className="outbound-consent-point-text">
            <strong>{t("beobachten.dnsbypass.consent.passiveTitle")}</strong>{" "}
            {t("beobachten.dnsbypass.consent.passiveText")}
          </span>
        </div>
        <div className="outbound-consent-point">
          <ShieldCheck size={18} aria-hidden="true" />
          <span className="outbound-consent-point-text">
            <strong>{t("beobachten.dnsbypass.consent.ownNetTitle")}</strong>{" "}
            {t("beobachten.dnsbypass.consent.ownNetText")}
          </span>
        </div>
        <div className="outbound-consent-point">
          <ShieldQuestion size={18} aria-hidden="true" />
          <span className="outbound-consent-point-text">
            <strong>{t("beobachten.dnsbypass.consent.prereqTitle")}</strong>{" "}
            {t("beobachten.dnsbypass.consent.prereqText")}
          </span>
        </div>

        {/* "Nicht mehr fragen"-Kaestchen: rein lokaler State, an die Callbacks
            durchgereicht. */}
        <label className="outbound-consent-dontask">
          <input
            type="checkbox"
            checked={dontAsk}
            onChange={(e) => setDontAsk(e.target.checked)}
          />
          {t("beobachten.dnsbypass.consent.dontAsk")}
        </label>

        {/* Knopfzeile, rechtsbuendig: Ablehnen + Zustimmen. */}
        <div className="outbound-consent-actions">
          <button
            type="button"
            className="outbound-consent-button"
            onClick={() => onDeny(dontAsk)}
          >
            {t("beobachten.dnsbypass.consent.deny")}
          </button>
          <button
            type="button"
            className="outbound-consent-button outbound-consent-button--grant"
            onClick={() => onGrant(dontAsk)}
          >
            {t("beobachten.dnsbypass.consent.grant")}
          </button>
        </div>
      </div>
    </div>
  );
}
