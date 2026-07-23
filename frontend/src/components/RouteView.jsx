// Route-zum-Ziel-Ansicht (CERNIS PRO 2.0)
// Der Nutzer gibt ein Internet-Ziel (Domain/IP) ein, CERNIS zeigt den Netzweg
// dorthin als Hop-Liste — pro Hop: Hop-Nr., IP (oder "keine Antwort" bei einer
// Lücke), Land mit Flagge, Betreiber (asn_org) + ASN, RTT. Macht den vorhandenen
// traceroute sichtbar und reichert jeden Hop lokal mit Geo/ASN an (ADR 0036).
//
// Zwei Datenpfade (ADR 0036):
//   * Hauptpfad (fetchRoute): lädt sofort, lokal + schnell. Land + ASN-Nummer
//     aus der lokalen Geo-DB; asn_org ist hier immer leer.
//   * Optionale Nachladung (fetchRouteOrgs): ein Schalter "Betreibernamen
//     nachladen" (Default AUS) löst die Org-Namen über RDAP (Internet) auf und
//     blendet sie in die schon sichtbare Liste ein — Muster der lazy PTR-Namen.
//
// Ehrliche Zustände: kein Ziel / traceroute fehlt (503) / keine Hops. Fehlende
// Geo-Daten = dezent leer, nicht erfunden. Eine null-IP ist eine Lücke, kein
// Fehler. i18n alle Texte über t(); t/i18n NIE in useEffect-Dependencies.

import { Globe, Play, Send } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { ApiError } from "../api/client.js";
import {
  fetchRoute,
  fetchRouteOrgs,
  fetchTraceroutePermission,
} from "../api/route.js";
import "./RouteView.css";

// Leitet die Unicode-Flagge aus einem ISO-3166-1-alpha-2-Ländercode ab (zwei
// Regional-Indicator-Symbole). KEINE Bild-/npm-Abhängigkeit, kein externes Asset.
// Ungültiger/leerer Code -> null (kein erfundenes Symbol).
function flaggeAusCode(code) {
  if (typeof code !== "string" || code.length !== 2 || !/^[A-Za-z]{2}$/.test(code)) {
    return null;
  }
  const basis = 0x1f1e6; // Regional Indicator Symbol Letter A
  const grossA = "A".charCodeAt(0);
  const chars = code
    .toUpperCase()
    .split("")
    .map((ch) => String.fromCodePoint(basis + (ch.charCodeAt(0) - grossA)));
  return chars.join("");
}

// Eine Hop-Zeile. Ein nicht-antwortender Hop (address === null) erscheint als
// dezente Lücke ("keine Antwort"); fehlende Geo-Felder bleiben leer (nicht
// erfunden). Der Betreibername (org) kommt erst nach der optionalen Nachladung.
function HopZeile({ eintrag, org }) {
  const { t } = useTranslation();
  const luecke = eintrag.address === null;
  const flagge = flaggeAusCode(eintrag.country);

  return (
    <tr className={luecke ? "route__row route__row--gap" : "route__row"}>
      <td className="route__hop-nr">{eintrag.hop}</td>
      <td className="route__ip">
        {luecke ? (
          <span className="route__muted">{t("untersuchen.route.noReply")}</span>
        ) : (
          <span className="route__mono">{eintrag.address}</span>
        )}
      </td>
      <td className="route__country">
        {eintrag.country ? (
          <span>
            {flagge && <span className="route__flag">{flagge} </span>}
            {eintrag.country}
          </span>
        ) : (
          <span className="route__muted">—</span>
        )}
      </td>
      <td className="route__operator">
        {org ? (
          <span className="route__org">{org}</span>
        ) : (
          <span className="route__muted">—</span>
        )}
        {eintrag.asn && <span className="route__asn">AS{eintrag.asn}</span>}
      </td>
      <td className="route__rtt">
        {eintrag.rttMs === null ? (
          <span className="route__muted">—</span>
        ) : (
          `${eintrag.rttMs.toFixed(1)} ms`
        )}
      </td>
    </tr>
  );
}

export default function RouteView() {
  const { t } = useTranslation();
  const [ziel, setZiel] = useState("");
  const [route, setRoute] = useState(null); // { target, privileged, hops }
  const [orgs, setOrgs] = useState({}); // { ip: org } aus der Nachladung
  const [laedt, setLaedt] = useState(false);
  const [fehler, setFehler] = useState(null); // { text } oder null
  const [permission, setPermission] = useState(null); // { ok, error } oder null
  // Schalter "Betreibernamen nachladen" (Default AUS — Internet-Abfrage).
  const [orgsNachladen, setOrgsNachladen] = useState(false);
  const [orgsLaden, setOrgsLaden] = useState(false);

  // Rechte-Status EINMAL beim Mount ziehen (für den dezenten Hinweis). t/i18n
  // bewusst NICHT in den Dependencies (Projektregel).
  useEffect(() => {
    let aktiv = true;
    fetchTraceroutePermission()
      .then((status) => {
        if (aktiv) {
          setPermission(status);
        }
      })
      .catch(() => {
        // Rechte-Status ist nur Beiwerk — ein Fehler hier blockiert die Messung
        // nicht (keine Sackgasse). Still ignorieren.
      });
    return () => {
      aktiv = false;
    };
  }, []);

  // Die Messung starten: lokaler Hauptpfad (schnell). Setzt orgs zurück (neue
  // Route) und nimmt die optionale Nachladung NICHT automatisch vor.
  const messen = useCallback(async () => {
    const target = ziel.trim();
    if (!target) {
      return;
    }
    setLaedt(true);
    setFehler(null);
    setOrgs({});
    try {
      const ergebnis = await fetchRoute(target, false);
      setRoute(ergebnis);
    } catch (ursache) {
      // traceroute-Binary fehlt -> 503; sonstige API-/Netzfehler ehrlich melden.
      const istToolFehlt = ursache instanceof ApiError && ursache.status === 503;
      setRoute(null);
      setFehler({
        text: istToolFehlt
          ? t("untersuchen.route.toolMissing")
          : t("untersuchen.route.error"),
      });
    } finally {
      setLaedt(false);
    }
  }, [ziel, t]);

  // Optionale Org-Namen-Nachladung über RDAP (Internet). Läuft NUR, wenn der
  // Schalter an ist und eine Route mit antwortenden IPs vorliegt. Fehlertolerant:
  // ein Fehler lässt die schon sichtbare Liste unberührt.
  useEffect(() => {
    if (!orgsNachladen || route === null) {
      return;
    }
    const ips = route.hops
      .map((h) => h.address)
      .filter((ip) => ip !== null);
    if (ips.length === 0) {
      return;
    }
    let aktiv = true;
    setOrgsLaden(true);
    fetchRouteOrgs(ips)
      .then((map) => {
        if (aktiv) {
          setOrgs(map);
        }
      })
      .catch(() => {
        // Nachladung ist optional — ein Fehler blockiert die Liste nicht.
      })
      .finally(() => {
        if (aktiv) {
          setOrgsLaden(false);
        }
      });
    return () => {
      aktiv = false;
    };
  }, [orgsNachladen, route]);

  const zeigeRechteHinweis =
    permission !== null && permission.ok === false && permission.error;

  return (
    <div className="route">
      <form
        className="route__form"
        onSubmit={(e) => {
          e.preventDefault();
          messen();
        }}
      >
        <input
          className="route__input"
          type="text"
          value={ziel}
          onChange={(e) => setZiel(e.target.value)}
          placeholder={t("untersuchen.route.targetPlaceholder")}
          aria-label={t("untersuchen.route.targetLabel")}
        />
        <button
          className="route__start"
          type="submit"
          disabled={laedt || ziel.trim() === ""}
        >
          <Play size={15} aria-hidden="true" />
          {laedt ? t("untersuchen.route.measuring") : t("untersuchen.route.start")}
        </button>
      </form>

      {/* Sichtbarer Laufhinweis waehrend der Messung: der deaktivierte Knopf allein
          liest sich wie "kaputt". role=status + aria-live, damit Screenreader die
          Zustandsaenderung mitbekommen. Kein Timer/Fortschritt — die echte
          Restdauer ist nicht bekannt, eine Prozentanzeige waere unehrlich. */}
      {laedt && (
        <div className="route__running" role="status" aria-live="polite">
          {t("untersuchen.route.runningHint")}
        </div>
      )}

      {zeigeRechteHinweis && (
        <div className="route__permission" role="note">
          {t("untersuchen.route.permissionHint")}
        </div>
      )}

      {fehler !== null && <div className="route__error">{fehler.text}</div>}

      {route !== null && fehler === null && (
        <>
          <div className="route__toolbar">
            <label className="route__toggle">
              <input
                type="checkbox"
                checked={orgsNachladen}
                onChange={(e) => setOrgsNachladen(e.target.checked)}
              />
              <Send size={14} aria-hidden="true" />
              {t("untersuchen.route.loadOrgs")}
              {orgsLaden && (
                <span className="route__muted"> {t("untersuchen.route.loadingOrgs")}</span>
              )}
            </label>
          </div>

          {route.hops.length === 0 ? (
            <div className="route__empty">{t("untersuchen.route.noHops")}</div>
          ) : (
            <table className="route__table">
              <thead>
                <tr>
                  <th>{t("untersuchen.route.colHop")}</th>
                  <th>{t("untersuchen.route.colIp")}</th>
                  <th>{t("untersuchen.route.colCountry")}</th>
                  <th>{t("untersuchen.route.colOperator")}</th>
                  <th>{t("untersuchen.route.colRtt")}</th>
                </tr>
              </thead>
              <tbody>
                {route.hops.map((eintrag) => (
                  <HopZeile
                    key={eintrag.hop}
                    eintrag={eintrag}
                    org={eintrag.address ? (orgs[eintrag.address] ?? null) : null}
                  />
                ))}
              </tbody>
            </table>
          )}
        </>
      )}

      {route === null && fehler === null && !laedt && (
        <div className="route__hint">
          <Globe size={28} aria-hidden="true" />
          <span>{t("untersuchen.route.idle")}</span>
        </div>
      )}
    </div>
  );
}
