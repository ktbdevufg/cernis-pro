// Npcap-Hinweis-Dialog (CERNIS PRO 2.0)
//
// Zentrierter Overlay-Dialog (Muster: PortLookupDialog.jsx — gleiche Overlay-/
// Head-/Body-Struktur, X-Schließen aus lucide-react, Escape + Backdrop-Klick
// schließen via onClose, nur CSS-Tokens, keine hartkodierten Farben). Erklärt
// ehrlich, warum die Sniff-Funktion ausgegraut ist, und bietet den Download-Link.
//
// Der Dialog kennt GENAU EINEN Fall (aus dem Backend-permission_error, siehe
// sniffd_unavailable_reason):
//   NPCAP_MISSING — Npcap fehlt: Text bodyMissing + Download-Button
//                   (öffnet https://npcap.com).
// Einen zweiten Marker gibt es nicht mehr: das Backend liefert bei erkanntem
// Npcap gar keinen Marker, die Funktion ist dann nutzbar. Es gibt darum auch
// KEINEN Sonst-Zweig mit abweichendem Text — ein solcher könnte nur eine
// unwahre Aussage zeigen.
//
// Link-Öffnen: wie PortLookupDialog über den Backend-Opener (POST /api/open-url,
// openUrl aus api/system.js) in den Systembrowser; Fallback window.open, wenn
// kein Backend läuft (Browser-Dev). Ein target="_blank" öffnet in der Tauri-
// WebView KEINEN Systembrowser, darum der Backend-Opener.
//
// Props:
//   onClose — schließt den Dialog (Aufrufer setzt seinen State zurück).

import { ExternalLink, X } from "lucide-react";
import { useEffect } from "react";
import { useTranslation } from "react-i18next";

import { openUrl } from "../api/system.js";
import "./NpcapDialog.css";

// Offizielle Npcap-Download-Seite (Nmap-Projekt). Wird ausschließlich bei
// bewusstem Klick auf den Download-Button geöffnet.
const NPCAP_URL = "https://npcap.com";

export default function NpcapDialog({ onClose }) {
  const { t } = useTranslation();

  // Escape schließt den Dialog (Standard-Overlay-Verhalten wie PortLookupDialog).
  useEffect(() => {
    const handler = (e) => {
      if (e.key === "Escape") {
        onClose();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onClose]);

  // Öffnet die Npcap-Download-URL beim Klick. Primärweg: Backend-Opener ->
  // Systembrowser (zuverlässig in der Tauri-App); Fallback window.open im
  // Browser-Dev ohne laufendes Backend.
  const handleDownloadClick = (e) => {
    e.preventDefault();
    openUrl(NPCAP_URL).catch(() => {
      window.open(NPCAP_URL, "_blank", "noopener,noreferrer");
    });
  };

  return (
    // Backdrop: Klick daneben schließt. Der Klick im Dialog selbst wird gestoppt,
    // damit er nicht durchschlägt.
    <div className="npcap-overlay" onMouseDown={onClose}>
      <div
        className="npcap-dialog"
        role="dialog"
        aria-modal="true"
        aria-label={t("npcap.title")}
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="npcap-dialog__head">
          <h2 className="npcap-dialog__title">{t("npcap.title")}</h2>
          <button
            type="button"
            className="npcap-dialog__close"
            aria-label={t("beobachten.scan.detail.ports.lookupDialog.close")}
            title={t("beobachten.scan.detail.ports.lookupDialog.close")}
            onClick={onClose}
          >
            <X size={18} aria-hidden="true" />
          </button>
        </div>

        <div className="npcap-dialog__body">
          <p className="npcap-dialog__desc">{t("npcap.bodyMissing")}</p>

          {/* Klar als extern erkennbarer Download-Link. Der Dialog wird nur
              geöffnet, wenn Npcap fehlt — der Link gehört darum unbedingt dazu
              und hängt an keiner Bedingung mehr.
              Öffnet erst bei bewusstem Klick über den Backend-Opener (WebView
              öffnet target="_blank" nicht selbst) und fällt im Browser-Dev auf
              window.open zurück. */}
          <a
            className="npcap-dialog__download"
            href={NPCAP_URL}
            target="_blank"
            rel="noopener noreferrer"
            onClick={handleDownloadClick}
          >
            <ExternalLink size={15} aria-hidden="true" />
            {t("npcap.downloadBtn")}
          </a>
        </div>
      </div>
    </div>
  );
}
