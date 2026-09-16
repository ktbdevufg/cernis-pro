// Port-Nachschlage-Dialog (CERNIS PRO 2.0)
//
// Zentrierter Overlay-Dialog (Muster: MaintenanceDialog.jsx — gleiche Overlay-
// Struktur, X-Schließen aus lucide-react, nur CSS-Tokens, keine hartkodierten
// Farben). Zeigt INTERNE Info zu einem offenen Port und darunter einen klar als
// extern erkennbaren Wikipedia-Link.
//
// Passiv: KEIN automatischer Web-Verkehr. Die interne Beschreibung kommt aus der
// lokalen Tabelle (lib/portInfo -> i18n); die Wikipedia-Suche wird ausschließlich
// bei bewusstem Klick auf den Link geöffnet.
//
// Link-Öffnen: Ein normales <a target="_blank"> öffnet in der Tauri-WebView
// KEINEN Systembrowser — und ein opener/shell-Plugin ist nicht gebaut. Darum
// geht der Klick über den bereits existierenden Backend-Opener
// (POST /api/open-url, öffnet via webbrowser.open im Systembrowser); das ist
// same-origin und in der installierten App zuverlässig. Im Browser-Dev (kein
// laufendes Backend) fällt es auf window.open zurück. href bleibt als
// semantischer Fallback gesetzt. Kein neues npm-Paket, keine neue Dependency.
//
// Props:
//   port    — { num, proto, service } des gewählten Ports.
//   onClose — schließt den Dialog (Aufrufer setzt seinen State zurück).

import { ExternalLink, X } from "lucide-react";
import { useEffect } from "react";
import { useTranslation } from "react-i18next";

import { openUrl } from "../api/system.js";
import { portBeschreibung } from "../lib/portInfo.js";
import "./PortLookupDialog.css";

// Basis der Wikipedia-Volltextsuche je Sprache. Die konkrete Suchanfrage wird
// angehängt (encodeURIComponent). Deutsch ist Default, Englisch bei i18n-Sprache
// "en".
const WIKI_BASIS = {
  de: "https://de.wikipedia.org/wiki/Spezial:Suche?search=",
  en: "https://en.wikipedia.org/wiki/Special:Search?search=",
};

export default function PortLookupDialog({ port, onClose }) {
  const { t, i18n } = useTranslation();

  // Escape schließt den Dialog (Standard-Overlay-Verhalten).
  useEffect(() => {
    const handler = (e) => {
      if (e.key === "Escape") {
        onClose();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onClose]);

  const proto = port.proto || "tcp";
  const { key, dienst } = portBeschreibung(port.num, proto);

  // Sprachwahl: alles außer "en" fällt auf Deutsch zurück (Default-Sprache).
  const sprache = i18n.language && i18n.language.startsWith("en") ? "en" : "de";

  // Dienst-Anzeige: bevorzugt der reale Scan-Service (port.service), sonst der
  // neutrale Kurzname aus der Tabelle. Kann null sein (unbekannter Port).
  const dienstAnzeige = port.service || dienst;

  // Interne Beschreibung: bei bekanntem Port aus i18n, sonst der generische Text.
  const beschreibung = key
    ? t(`beobachten.scan.detail.ports.lookupDialog.info.${key}`)
    : t("beobachten.scan.detail.ports.lookupDialog.generic");

  // Titel „Port <num>/<proto>".
  const titel = t("beobachten.scan.detail.ports.lookupDialog.title", {
    num: port.num,
    proto,
  });

  // Wikipedia-Suchanfrage: Portnummer + Dienstname (falls vorhanden), sonst
  // „Port <num>". Neutral gehalten, dient nur als Suchbegriff.
  const suchbegriff = dienstAnzeige
    ? `Port ${port.num} ${dienstAnzeige}`
    : `Port ${port.num}`;
  const wikiUrl = `${WIKI_BASIS[sprache]}${encodeURIComponent(suchbegriff)}`;

  // Öffnet die Wikipedia-URL beim Klick. Primärweg: der Backend-Opener
  // (POST /api/open-url) -> Systembrowser, zuverlässig in der Tauri-App. Schlägt
  // der Aufruf fehl (ApiError, z. B. Browser-Dev ohne laufendes Backend), fällt
  // es auf window.open zurück. e.preventDefault() unterdrückt das native
  // target="_blank" (das in der WebView ohnehin nicht in den Systembrowser
  // führt); der href bleibt am <a> als semantischer Fallback erhalten.
  const handleWikiClick = (e) => {
    e.preventDefault();
    openUrl(wikiUrl).catch(() => {
      window.open(wikiUrl, "_blank", "noopener,noreferrer");
    });
  };

  return (
    // Backdrop: Klick daneben schließt. Der Klick im Dialog selbst wird gestoppt,
    // damit er nicht durchschlägt.
    <div className="port-lookup-overlay" onMouseDown={onClose}>
      <div
        className="port-lookup-dialog"
        role="dialog"
        aria-modal="true"
        aria-label={titel}
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="port-lookup-dialog__head">
          <h2 className="port-lookup-dialog__title">{titel}</h2>
          <button
            type="button"
            className="port-lookup-dialog__close"
            aria-label={t("beobachten.scan.detail.ports.lookupDialog.close")}
            title={t("beobachten.scan.detail.ports.lookupDialog.close")}
            onClick={onClose}
          >
            <X size={18} aria-hidden="true" />
          </button>
        </div>

        <div className="port-lookup-dialog__body">
          {dienstAnzeige && (
            <div className="port-lookup-dialog__service-row">
              <span className="port-lookup-dialog__service-label">
                {t("beobachten.scan.detail.ports.lookupDialog.service")}
              </span>
              <span className="port-lookup-dialog__service">{dienstAnzeige}</span>
            </div>
          )}

          <p className="port-lookup-dialog__desc">{beschreibung}</p>

          {/* Klar als extern erkennbarer Link. Öffnet erst bei bewusstem Klick;
              der onClick-Handler leitet die URL über den Backend-Opener in den
              Systembrowser (WebView öffnet target="_blank" nicht selbst) und
              fällt im Browser-Dev auf window.open zurück. */}
          <a
            className="port-lookup-dialog__wiki"
            href={wikiUrl}
            target="_blank"
            rel="noopener noreferrer"
            onClick={handleWikiClick}
          >
            <ExternalLink size={15} aria-hidden="true" />
            {t("beobachten.scan.detail.ports.lookupDialog.wikipedia")}
          </a>
        </div>
      </div>
    </div>
  );
}
