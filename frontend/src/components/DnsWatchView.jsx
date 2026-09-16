// DNS-Wächter (CERNIS PRO 2.0)
// Lese-Ansicht der DNS-relevanten Außenkontakte DIESES Rechners: Geräte/Apps,
// die den erwarteten DNS umgehen — Port 53 zu einem fremden Resolver oder eine
// mögliche DoH-Verbindung. Reines Frontend gegen die fertigen Endpunkte
// GET /api/dns-watch + POST /api/dns-watch/acknowledge (api/dnsWatch.js).
//
// CERNIS ist PASSIV: hier wird NICHTS erlaubt/blockiert, nur sichtbar gemacht
// und höchstens „als bekannt markiert". Orange (Severity) NUR für offene,
// unquittierte Befunde — „hier lohnt ein Blick". Mögliche DoH ist NEUTRAL (rein
// heuristisch). Erwartungsgemäße Kontakte sind ruhig/neutral.

import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { acknowledgeDnsWatch, fetchDnsWatch } from "../api/dnsWatch.js";
import "./DnsWatchView.css";

// Anzeigereihenfolge der vier Kennzahlen: „offen" zuerst (dort lohnt der Blick),
// dann „mögliche DoH", „erwartungsgemäß" und zuletzt „quittiert". key zeigt auf das
// counts-Feld (Backend-Schlüssel), labelKey auf den i18n-Text, ton steuert die Optik.
//
// Die drei Kategorie-Zähler nennen seit S62 L7b nur noch die AKTIVEN (nicht
// quittierten) Befunde; die quittierten stehen daneben in „quittiert_<kategorie>".
// Weggerechnet ist damit nichts — der Bestand je Kategorie ist die Summe beider
// Zahlen. Die vierte Karte fasst die quittierten über alle Kategorien zusammen.
const KENNZAHLEN = [
  { key: "offen", labelKey: "countOpen", ton: "offen" },
  { key: "moegliche_doh", labelKey: "countDoh", ton: "neutral" },
  { key: "erwartungsgemaess", labelKey: "countExpected", ton: "neutral" },
  {
    keys: [
      "quittiert_offen",
      "quittiert_moegliche_doh",
      "quittiert_erwartungsgemaess",
    ],
    labelKey: "countAcknowledged",
    ton: "neutral",
  },
];

// Wert einer Kennzahl aus counts: entweder ein einzelner Schlüssel (key) oder die
// Summe mehrerer (keys). Fehlt ein Schlüssel, zählt er als 0 (ehrlich, kein Raten).
function kennzahlWert(counts, kennzahl) {
  if (kennzahl.keys) {
    return kennzahl.keys.reduce((summe, k) => summe + (counts[k] ?? 0), 0);
  }
  return counts[kennzahl.key] ?? 0;
}

// Eine ruhige Kennzahl-Karte: große Zahl + Label darunter. ton="offen" hebt die
// Zahl im Severity-Orange hervor, alles andere bleibt neutral.
function KennzahlKarte({ wert, label, ton }) {
  const klasse =
    ton === "offen"
      ? "dnswatch-kennzahl dnswatch-kennzahl--offen"
      : "dnswatch-kennzahl";
  return (
    <div className={klasse}>
      <span className="dnswatch-kennzahl__zahl">{wert}</span>
      <span className="dnswatch-kennzahl__label">{label}</span>
    </div>
  );
}

// Eine Umgeher-Zeile: Titel (hostname, sonst remoteIp), darunter klein die IP
// (nur wenn der Titel der hostname war, sonst stünde sie doppelt) + appName +
// „×connectionCount" + Kategorie-Label. Rechts die Quittier-Aktion, für JEDE
// Kategorie. Farb-Logik über die Zeilen-Klasse (siehe CSS) — sie bleibt davon
// unberührt, nur „offen" trägt weiterhin Farbe:
//   offen & nicht quittiert -> Orange-Akzent
//   offen & quittiert       -> gedämpftes Grün (bekannt, NICHT versteckt)
//   moegliche_doh           -> neutral
//   erwartungsgemaess       -> neutral/ruhig
function UmgeherZeile({ kontakt, onQuittieren }) {
  const { t } = useTranslation();

  const titel = kontakt.hostname ?? kontakt.remoteIp;
  const zeigeIpUnten = kontakt.hostname !== null;

  // Untertitel-Teile: nur vorhandene Felder, fehlende weglassen (S3-ehrlich).
  const subTeile = [];
  if (zeigeIpUnten) {
    subTeile.push(kontakt.remoteIp);
  }
  if (kontakt.appName !== null) {
    subTeile.push(kontakt.appName);
  }
  subTeile.push(
    t("beobachten.dnswatch.connectionsSuffix", {
      count: kontakt.connectionCount,
    }),
  );
  subTeile.push(t(`beobachten.dnswatch.categoryLabels.${kontakt.category}`));

  // Zeilen-Ton: nur „offen" trägt Farbe (orange bzw. gedämpftes Grün bei ack).
  let tonKlasse = "dnswatch-zeile";
  if (kontakt.category === "offen") {
    tonKlasse = kontakt.acknowledged
      ? "dnswatch-zeile dnswatch-zeile--bekannt"
      : "dnswatch-zeile dnswatch-zeile--offen";
  }

  // Quittier-Knopf für JEDE Kategorie. Das Backend nimmt jede Kategorie an und
  // zählt sie getrennt (quittiert_offen / quittiert_moegliche_doh /
  // quittiert_erwartungsgemaess), und die Kennzahl-Karte liest diese Zähler schon
  // — ein Zähler, der nicht befüllbar ist, wäre ein Widerspruch. Mündiger
  // Anwender: wer einen Befund eingeordnet hat, darf ihn abhaken. acknowledged
  // steuert Beschriftung und Aktion (ack <-> unack). NIE „Erlauben" (CERNIS ist
  // passiv) — Quittieren markiert als bekannt und erlaubt nichts.

  return (
    <li className={tonKlasse}>
      <div className="dnswatch-zeile__main">
        <span className="dnswatch-zeile__title dnswatch-mono">{titel}</span>
        <span className="dnswatch-zeile__sub dnswatch-mono">
          {subTeile.join(" · ")}
        </span>
      </div>
      <div className="dnswatch-zeile__aktion">
        <button
          type="button"
          className="dnswatch-zeile__ack"
          onClick={() =>
            onQuittieren(
              kontakt.remoteIp,
              kontakt.category,
              kontakt.acknowledged ? "unack" : "ack",
            )
          }
        >
          {kontakt.acknowledged
            ? t("beobachten.dnswatch.unmarkKnown")
            : t("beobachten.dnswatch.markKnown")}
        </button>
      </div>
    </li>
  );
}

export default function DnsWatchView() {
  const { t } = useTranslation();

  const [kontakte, setKontakte] = useState([]);
  const [hostScope, setHostScope] = useState(null);
  const [counts, setCounts] = useState({});
  const [expectedServers, setExpectedServers] = useState([]);
  // Naht für den ruhigen Hinweis-Streifen bei Ladefehler (kein Absturz).
  const [ladeFehler, setLadeFehler] = useState(false);

  // Lädt die Sicht und setzt den State. Wird beim Mount und nach jeder
  // erfolgreichen Quittierung aufgerufen (Neuladen statt lokalem Patchen, damit
  // der effektive ack-Status genau dem Backend folgt). Fehler tolerieren.
  async function ladeDaten() {
    try {
      const ergebnis = await fetchDnsWatch();
      setKontakte(ergebnis.contacts);
      setHostScope(ergebnis.hostScope);
      setCounts(ergebnis.counts);
      setExpectedServers(ergebnis.expectedServers);
      setLadeFehler(false);
    } catch {
      setLadeFehler(true);
    }
  }

  // Beim Mount laden. t NIEMALS in dep-Array (react-i18next-Regel) — leeres
  // dep-Array, einmal beim Mount. Fehler tolerieren: leere Liste + ruhiger
  // Hinweis-Streifen, kein Absturz.
  useEffect(() => {
    let abgebrochen = false;
    (async () => {
      try {
        const ergebnis = await fetchDnsWatch();
        if (abgebrochen) {
          return;
        }
        setKontakte(ergebnis.contacts);
        setHostScope(ergebnis.hostScope);
        setCounts(ergebnis.counts);
        setExpectedServers(ergebnis.expectedServers);
        setLadeFehler(false);
      } catch {
        if (!abgebrochen) {
          setLadeFehler(true);
        }
      }
    })();
    return () => {
      abgebrochen = true;
    };
  }, []);

  // Quittieren/Entquittieren: schreibt über die API und lädt danach die Liste
  // neu (laut Vorgabe). Bei Fehler den ruhigen Hinweis-Streifen zeigen.
  const handleQuittieren = async (remoteIp, category, action) => {
    try {
      await acknowledgeDnsWatch(remoteIp, category, action);
      await ladeDaten();
    } catch {
      setLadeFehler(true);
    }
  };

  return (
    <div className="dnswatch">
      {/* Ehrlicher host_scope-Banner: nur bei "local_host". Bei anderem/leerem
          Wert weglassen (S3-ehrlich). */}
      {hostScope === "local_host" && (
        <div className="dnswatch__scope" role="note">
          {t("beobachten.dnswatch.hostScopeLocal")}
        </div>
      )}

      {/* Ruhiger Hinweis-Streifen bei Lade-/Schreibfehler (Stil observe__hinweis). */}
      {ladeFehler && (
        <div className="dnswatch__hinweis" role="note">
          <span className="dnswatch__hinweis-title">
            {t("beobachten.traffic.permissionTitle")}
          </span>
          <span className="dnswatch__hinweis-text">
            {t("beobachten.dnswatch.loadError")}
          </span>
        </div>
      )}

      {/* Vier Kennzahlen ganz oben: offen / mögliche DoH / erwartungsgemäß /
          quittiert. Die ersten drei zählen nur AKTIVE (nicht quittierte) Befunde. */}
      <div className="dnswatch__kennzahlen">
        {KENNZAHLEN.map((k) => (
          <KennzahlKarte
            key={k.key ?? k.labelKey}
            wert={kennzahlWert(counts, k)}
            label={t(`beobachten.dnswatch.${k.labelKey}`)}
            ton={k.ton}
          />
        ))}
      </div>

      {/* Liste der Umgeher (Reihenfolge wie vom Backend geliefert: offen zuerst)
          oder ehrlicher Leerzustand, wenn keine Kontakte da sind. */}
      {kontakte.length === 0 ? (
        <p className="dnswatch__empty">{t("beobachten.dnswatch.empty")}</p>
      ) : (
        <ul className="dnswatch__liste">
          {kontakte.map((kontakt) => (
            <UmgeherZeile
              key={`${kontakt.remoteIp}:${kontakt.category}`}
              kontakt={kontakt}
              onQuittieren={handleQuittieren}
            />
          ))}
        </ul>
      )}

      {/* Fußzeile: erwartete DNS-Server + Verweis auf die Verwaltungs-Rubrik.
          Ist die erwartete Menge LEER, steht statt der schiefen "—"-Anzeige ein
          ruhiger Hinweis + Verweis. HINWEIS (D4 E4): DnsWatchView erhaelt keinen
          Sprung-/onNavigate-Prop (DnsWatchScreen rendert sie ohne Props, und
          handleNavigate in App.jsx kennt keinen Verwaltungs-Funktions-Deep-Link)
          -> der Verweis ist bewusst reiner Text, KEIN toter Button. */}
      <div className="dnswatch__footer">
        {expectedServers.length === 0 ? (
          <span className="dnswatch__footer-servers">
            {t("beobachten.dnswatch.noExpectedHint")}{" "}
            {t("beobachten.dnswatch.decideLink")}
          </span>
        ) : (
          <span className="dnswatch__footer-servers dnswatch-mono">
            {t("beobachten.dnswatch.footerExpected", {
              servers: expectedServers.join(", "),
            })}
          </span>
        )}
        <span className="dnswatch__footer-hint">
          {t("beobachten.dnswatch.settingsHint")}
        </span>
      </div>
    </div>
  );
}
