// DNS-Waechter-Bildschirm (CERNIS PRO 2.0, E5) -- Zwei-Reiter-Container.
//
// Der DNS-Waechter-Bildschirm bekommt zwei Unterreiter mit einem kurzen Erklaer-
// Block, der den Unterschied ehrlich benennt:
//   Reiter 1 "Dieser Rechner"   -- die BESTEHENDE DnsWatchView, UNVERAENDERT
//                                  eingebettet (host-lokale Befunde).
//   Reiter 2 "Umgehung im Netz"  -- die neue netzweite DnsBypassView (gegen die
//                                  4b-Routen /api/dns-bypass + /status + /start
//                                  + /stop).
// Die ObserveView-Kachel bleibt "DNS-Waechter" (ein Einstieg, eine helpId); die
// Trennung passiert nur HIER im Bildschirm-Inhalt.
//
// Reine Praesentation: der aktive Reiter ist lokaler State. Nackte, tab-artige
// Knoepfe (Muster wie die Segmented Controls des Projekts), nur CSS-Tokens. t
// NIEMALS in useEffect/useMemo-Deps -- hier ohne Effekt, aber die Regel gilt.

import { useState } from "react";
import { useTranslation } from "react-i18next";

import DnsBypassView from "./DnsBypassView.jsx";
import DnsWatchView from "./DnsWatchView.jsx";
import "./DnsWatchScreen.css";

// Die beiden Unterreiter: id (State-Wert) + i18n-Schluessel des Labels. Reihenfolge
// verbindlich: host-lokal zuerst (der Bestand), dann netzweit (das Neue).
const REITER = [
  { id: "host", labelKey: "tabHost" },
  { id: "netz", labelKey: "tabNetz" },
];

export default function DnsWatchScreen() {
  const { t } = useTranslation();

  // Aktiver Unterreiter (host-lokal zuerst).
  const [aktiv, setAktiv] = useState("host");

  return (
    <div className="dnsscreen">
      {/* Reiterleiste + darunter der reiterabhaengige Erklaer-Block. */}
      <div className="dnsscreen__reiter" role="tablist">
        {REITER.map((r) => {
          const istAktiv = r.id === aktiv;
          return (
            <button
              key={r.id}
              type="button"
              role="tab"
              aria-selected={istAktiv}
              className={
                istAktiv
                  ? "dnsscreen__reiter-knopf dnsscreen__reiter-knopf--aktiv"
                  : "dnsscreen__reiter-knopf"
              }
              onClick={() => setAktiv(r.id)}
            >
              {t(`beobachten.dnsscreen.${r.labelKey}`)}
            </button>
          );
        })}
      </div>

      {/* Erklaer-Block: benennt den Unterschied host-lokal vs. netzweit ehrlich,
          passend zum aktiven Reiter. */}
      <p className="dnsscreen__erklaer">
        {aktiv === "host"
          ? t("beobachten.dnsscreen.erklaerHost")
          : t("beobachten.dnsscreen.erklaerNetz")}
      </p>

      {/* Inhalt des aktiven Reiters. Reiter 1 bettet die unveraenderte DnsWatchView
          ein; Reiter 2 die neue netzweite DnsBypassView. Beide bleiben gemountet
          zu lassen waere teurer (zwei Poll-Quellen) -- daher bewusst nur der aktive. */}
      <div className="dnsscreen__inhalt">
        {aktiv === "host" ? <DnsWatchView /> : <DnsBypassView />}
      </div>
    </div>
  );
}
