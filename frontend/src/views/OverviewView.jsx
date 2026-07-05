// Überblick-Ansicht (CERNIS PRO 2.0)
// Echte, datengetriebene Startseite ("Lage-Überblick"). Gestapeltes Layout,
// robust für schmale Fenster. Lädt beim Mount alle Quellen einzeln abgesichert
// (Promise.allSettled): fällt eine Quelle aus, entfällt nur ihr Bereich, KEIN
// Crash. Zeigt ausschließlich Fakten — kein Urteil ("ruhig/sicher" o. Ä.).
//
// Bereiche (jeder einzeln über das Backend-Setting `overview_sections`
// abschaltbar, Defaults alle true — in dieser Etappe NUR lesen + respektieren):
//   status         Status-Zeile: letzter Scan + Geräte, Beobachtungen,
//                  Monitoring-Baustein, "Neuer Scan"-Knopf.
//   schnellzugriff Kacheln (FunctionCard) für Scan/Monitoring/CVE.
//   beachtenswert  Achse-B-Hosts (analysisSeverity !== null) aus dem letzten Scan.
//   cve            Neue CVE-Befunde (isNew === true).
//   kennzahlen     Apps mit Verkehr + aktive Verbindungen.
//   status_monitoring  steuert NUR den Monitoring-Baustein der Status-Zeile.
//
// i18n: t/i18n NIE in useEffect-Dependencies (Render-Loop). Persistenz läuft
// ausschließlich über das Backend-Setting — KEINE localStorage-Eigenbauten hier.

import {
  Activity,
  FileClock,
  Globe,
  KeyRound,
  Network,
  Plus,
  Radar,
  Repeat,
  ShieldAlert,
  ShieldQuestion,
  Smartphone,
} from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { fetchCveFindings } from "../api/cve.js";
import { fetchMonitorStatus } from "../api/monitoring.js";
import { fetchScanDetail, fetchScanHistory } from "../api/scan.js";
import { fetchSettings } from "../api/settings.js";
import { fetchTraffic } from "../api/traffic.js";
import { fetchTopFeatures } from "../api/usage.js";
import { CardGrid } from "../components/AreaShell.jsx";
import FunctionCard from "../components/FunctionCard.jsx";
import "./OverviewView.css";

// Zentrale Zuordnung feature_id -> anzeigbare Kachel. Deckt ALLE regulär (nicht
// gesperrten) per onNavigate(tab, funktion) erreichbaren Funktionen ab; die feature_id
// ist der stabile Backend-Schlüssel `${tab}:${funktion}` (identisch zu App.jsx). Titel/
// Subtitle nutzen die BESTEHENDEN Kachel-i18n-Keys der jeweiligen Views (Wiederverwendung
// — keine neuen Keys). icon/tab/funktion steuern Darstellung und den Klick-Sprung
// (springe(tab, funktion)). Eine feature_id ohne Eintrag hier (z. B. der reine "observe"-
// Sprung des Neuer-Scan-Knopfs) ist bewusst nicht als Kachel darstellbar und wird beim
// Auflösen übersprungen.
const FEATURE_KATALOG = {
  "observe:scan": {
    icon: Radar,
    tab: "observe",
    funktion: "scan",
    titleKey: "beobachten.cards.scan.title",
    subtitleKey: "beobachten.cards.scan.subtitle",
    helpId: "help.scan.start",
  },
  "observe:watch": {
    icon: ShieldQuestion,
    tab: "observe",
    funktion: "watch",
    titleKey: "beobachten.cards.watch.title",
    subtitleKey: "beobachten.cards.watch.subtitle",
    helpId: "help.watch.uebersicht",
  },
  "observe:traffic": {
    icon: Repeat,
    tab: "observe",
    funktion: "traffic",
    titleKey: "beobachten.cards.traffic.title",
    subtitleKey: "beobachten.cards.traffic.subtitle",
    helpId: "help.traffic.uebersicht",
  },
  "observe:outbound": {
    icon: Globe,
    tab: "observe",
    funktion: "outbound",
    titleKey: "beobachten.cards.outbound.title",
    subtitleKey: "beobachten.cards.outbound.subtitle",
    helpId: "help.outbound.uebersicht",
  },
  "observe:dnswatch": {
    icon: ShieldAlert,
    tab: "observe",
    funktion: "dnswatch",
    titleKey: "beobachten.cards.dnswatch.title",
    subtitleKey: "beobachten.cards.dnswatch.subtitle",
    helpId: "help.dns_watch.uebersicht",
  },
  "observe:monitor": {
    icon: Activity,
    tab: "observe",
    funktion: "monitor",
    titleKey: "beobachten.cards.monitor.title",
    subtitleKey: "beobachten.cards.monitor.subtitle",
    helpId: "help.monitor.live",
  },
  "observe:logging": {
    icon: FileClock,
    tab: "observe",
    funktion: "logging",
    titleKey: "beobachten.cards.logging.title",
    subtitleKey: "beobachten.cards.logging.subtitle",
    helpId: "help.monitor.logging",
  },
  "observe:topology": {
    icon: Network,
    tab: "observe",
    funktion: "topology",
    titleKey: "beobachten.cards.topology.title",
    subtitleKey: "beobachten.cards.topology.subtitle",
    helpId: "help.topology.uebersicht",
  },
  "investigate:diagnose": {
    icon: Activity,
    tab: "investigate",
    funktion: "diagnose",
    titleKey: "untersuchen.cards.diagnose.title",
    subtitleKey: "untersuchen.cards.diagnose.subtitle",
    helpId: "help.diagnostics.route_geo",
  },
  "investigate:cve": {
    icon: ShieldAlert,
    tab: "investigate",
    funktion: "cve",
    titleKey: "untersuchen.cards.cve.title",
    subtitleKey: "untersuchen.cards.cve.subtitle",
    helpId: "help.cve.uebersicht",
  },
  "investigate:defaultcreds": {
    icon: KeyRound,
    tab: "investigate",
    funktion: "defaultcreds",
    titleKey: "untersuchen.cards.defaultcreds.title",
    subtitleKey: "untersuchen.cards.defaultcreds.subtitle",
    helpId: "help.security.default_creds",
  },
};

// Startbelegung/Fallback des Schnellzugriffs: solange weniger als 5 Funktionen echte
// Zähldaten haben, wird die Liste in DIESER Reihenfolge mit den bisherigen festen
// Defaults aufgefüllt (die drei ursprünglich fest verdrahteten Kacheln). Eine Funktion,
// die schon durch echte Zählung oben steht, wird NICHT noch einmal als Default ergänzt.
const DEFAULT_FEATURE_IDS = ["observe:scan", "observe:monitor", "investigate:cve"];

// Wie viele Kacheln der Schnellzugriff maximal zeigt.
const SCHNELLZUGRIFF_LIMIT = 5;

// Baut die anzuzeigende Kachel-Reihenfolge: zuerst die echten Top-Funktionen (nach count
// absteigend, so wie das Backend sie liefert), dann mit den Defaults aufgefüllt — jeweils
// nur bekannte (im Katalog auflösbare) feature_ids und ohne Duplikate, gedeckelt auf das
// Limit. Eine einmalige alte Nutzung blockiert keinen Platz dauerhaft: das ergibt sich aus
// der count-Sortierung des Backends.
function baueSchnellzugriff(topFeatureIds) {
  const reihenfolge = [];
  const gesehen = new Set();
  const hinzufuegen = (featureId) => {
    if (
      reihenfolge.length >= SCHNELLZUGRIFF_LIMIT ||
      gesehen.has(featureId) ||
      !FEATURE_KATALOG[featureId]
    ) {
      return;
    }
    gesehen.add(featureId);
    reihenfolge.push({ featureId, ...FEATURE_KATALOG[featureId] });
  };
  for (const featureId of topFeatureIds) {
    hinzufuegen(featureId);
  }
  for (const featureId of DEFAULT_FEATURE_IDS) {
    hinzufuegen(featureId);
  }
  return reihenfolge;
}

// Settings-Key für die Bereichs-Schalter. Wert ist ein JSON-Objekt mit Booleans;
// fehlt der Key -> alle Defaults true. In dieser Etappe NUR gelesen.
const SECTIONS_KEY = "overview_sections";

// Default-Sichtbarkeit aller Bereiche. Fehlt der Setting-Key oder ein einzelner
// Schalter, gilt der jeweilige Default (alle true).
const SECTION_DEFAULTS = {
  status: true,
  schnellzugriff: true,
  beachtenswert: true,
  cve: true,
  kennzahlen: true,
  status_monitoring: true,
};

// Liest `overview_sections` aus dem rohen Settings-Dict und mischt es über die
// Defaults. Der gespeicherte Wert kann ein Objekt ODER ein JSON-String sein
// (Backend-Settings tragen Werte teils als String); beides wird toleriert. Bei
// fehlendem/unparsbarem Wert bleiben die Defaults (alle true) — kein Crash.
function leseSektionen(settings) {
  const roh = settings?.[SECTIONS_KEY];
  let obj = null;
  if (roh && typeof roh === "object") {
    obj = roh;
  } else if (typeof roh === "string" && roh.length > 0) {
    try {
      const geparst = JSON.parse(roh);
      if (geparst && typeof geparst === "object") {
        obj = geparst;
      }
    } catch {
      // Unparsbarer Wert: bei den Defaults bleiben (kein stiller Müll-Wert).
      obj = null;
    }
  }
  if (!obj) {
    return { ...SECTION_DEFAULTS };
  }
  // Nur echte Booleans übernehmen; alles andere fällt auf den Default zurück.
  const ergebnis = { ...SECTION_DEFAULTS };
  for (const key of Object.keys(SECTION_DEFAULTS)) {
    if (typeof obj[key] === "boolean") {
      ergebnis[key] = obj[key];
    }
  }
  return ergebnis;
}

// Relativzeit ("vor X Min./Std./Tagen") aus einem ISO-Datum, clientseitig
// gerechnet. Liefert einen i18n-Schlüssel + count-Objekt zurück, damit die
// Pluralisierung über t() läuft. Unparsbar -> null (Aufrufer zeigt "Noch kein Scan").
function relativeZeit(isoString) {
  if (!isoString) {
    return null;
  }
  const ms = new Date(isoString).getTime();
  if (Number.isNaN(ms)) {
    return null;
  }
  const sekunden = Math.max(0, Math.floor((Date.now() - ms) / 1000));
  if (sekunden < 60) {
    return { key: "overview.status.relativeJustNow", count: null };
  }
  const minuten = Math.floor(sekunden / 60);
  if (minuten < 60) {
    return { key: "overview.status.relativeMinutes", count: minuten };
  }
  const stunden = Math.floor(minuten / 60);
  if (stunden < 24) {
    return { key: "overview.status.relativeHours", count: stunden };
  }
  const tage = Math.floor(stunden / 24);
  return { key: "overview.status.relativeDays", count: tage };
}

// Icon-Schlüssel des Scan-Mappers -> lucide-Komponente für die Beachtenswert-
// Zeile. Nur ein dezenter Anker; bei unbekanntem Schlüssel ein neutrales Default.
const HOST_ICON = {
  phone: Smartphone,
};

export default function OverviewView({ onNavigate, onOpenManual }) {
  const { t } = useTranslation();

  // Sichtbarkeit der Bereiche (Defaults true, bis das Setting geladen ist).
  const [sektionen, setSektionen] = useState(SECTION_DEFAULTS);

  // Status-Zeile: letzter Scan (Relativzeit-Basis) + bekannte Geräte.
  const [letzterScan, setLetzterScan] = useState(null); // { scannedAt, hostCount } | null
  // Achse-B-Hosts des letzten Scans (analysisSeverity !== null). Speist sowohl die
  // Beobachtungen-Zahl der Status-Zeile als auch den Beachtenswert-Bereich.
  const [auffaellige, setAuffaellige] = useState([]);
  // Aktive Monitoring-Ziele (nur Anzahl wird gebraucht).
  const [monitorZiele, setMonitorZiele] = useState([]);
  // Neue CVE-Befunde (isNew === true).
  const [neueCves, setNeueCves] = useState([]);
  // Kennzahlen-Fußzeile.
  const [kennzahlen, setKennzahlen] = useState(null); // { appsWithTraffic, activeConnections } | null

  // Dynamischer Schnellzugriff: die aufgelösten Kacheln (Top-Funktionen nach Nutzung,
  // mit Defaults aufgefüllt). Startwert ist die reine Default-Belegung, damit der
  // Schnellzugriff schon vor dem Laden nie leer ist.
  const [schnellzugriff, setSchnellzugriff] = useState(() => baueSchnellzugriff([]));

  // Dezenter Ladezustand (kein Vollbild-Spinner): nur, bis der erste Lauf durch ist.
  const [laedt, setLaedt] = useState(true);

  // Beim Mount alle Quellen laden. Jede Quelle einzeln gegen Fehler abgesichert
  // (Promise.allSettled): bei Fehler bleibt der jeweilige Bereich leer/weg, die
  // übrigen laufen weiter. t bewusst NICHT in den Dependencies (Render-Loop).
  useEffect(() => {
    let abgebrochen = false;

    async function laden() {
      // Settings zuerst lesen (steuert nur die Sichtbarkeit, nicht das Laden —
      // die Daten holen wir ohnehin, das Verstecken passiert im Render).
      const [
        settingsErg,
        historyErg,
        monitorErg,
        cveErg,
        trafficErg,
        topErg,
      ] = await Promise.allSettled([
        fetchSettings(),
        fetchScanHistory(1),
        fetchMonitorStatus(),
        fetchCveFindings(),
        fetchTraffic(),
        fetchTopFeatures(SCHNELLZUGRIFF_LIMIT),
      ]);

      if (abgebrochen) {
        return;
      }

      // Sektionen (Setting). Fehler -> Defaults (alle true).
      setSektionen(
        settingsErg.status === "fulfilled"
          ? leseSektionen(settingsErg.value)
          : { ...SECTION_DEFAULTS },
      );

      // Schnellzugriff: die Top-Funktionen (nach Nutzung) in Kacheln auflösen und mit
      // den Defaults auffüllen. Fehler -> reine Default-Belegung (nie leer). Das Backend
      // liefert [{feature_id, count, last_used}] absteigend nach count.
      const topFeatureIds =
        topErg.status === "fulfilled"
          ? (topErg.value ?? []).map((eintrag) => eintrag.feature_id)
          : [];
      setSchnellzugriff(baueSchnellzugriff(topFeatureIds));

      // Letzter Scan: neuester History-Eintrag liefert scannedAt + hostCount.
      // Sein id speist den Detail-Abruf für die Achse-B-Hosts.
      let scanId = null;
      if (historyErg.status === "fulfilled") {
        const neuester = (historyErg.value ?? [])[0] ?? null;
        if (neuester) {
          setLetzterScan({
            scannedAt: neuester.scannedAt,
            hostCount: neuester.hostCount,
          });
          scanId = neuester.id;
        } else {
          setLetzterScan(null);
        }
      } else {
        setLetzterScan(null);
      }

      // Monitoring-Ziele (nur Anzahl relevant).
      setMonitorZiele(
        monitorErg.status === "fulfilled" ? monitorErg.value ?? [] : [],
      );

      // Neue CVE-Befunde: nur isNew === true.
      setNeueCves(
        cveErg.status === "fulfilled"
          ? (cveErg.value ?? []).filter((b) => b.isNew === true)
          : [],
      );

      // Kennzahlen: Apps mit Verkehr (connectionCount > 0) + Summe der Verbindungen.
      if (trafficErg.status === "fulfilled") {
        const apps = trafficErg.value ?? [];
        const mitVerkehr = apps.filter((a) => (a.connectionCount ?? 0) > 0).length;
        const summe = apps.reduce((acc, a) => acc + (a.connectionCount ?? 0), 0);
        setKennzahlen({ appsWithTraffic: mitVerkehr, activeConnections: summe });
      } else {
        setKennzahlen(null);
      }

      // Achse-B-Hosts: Detail des neuesten Scans laden und Hosts mit
      // analysisSeverity !== null herausziehen. Eigene Absicherung, da dieser
      // Abruf von der scanId abhängt (kann fehlen oder fehlschlagen).
      if (scanId !== null && scanId !== undefined) {
        try {
          const detail = await fetchScanDetail(scanId);
          if (!abgebrochen) {
            setAuffaellige(
              (detail.geraete ?? []).filter((g) => g.analysisSeverity !== null),
            );
          }
        } catch {
          if (!abgebrochen) {
            setAuffaellige([]);
          }
        }
      } else {
        setAuffaellige([]);
      }

      if (!abgebrochen) {
        setLaedt(false);
      }
    }

    laden();
    return () => {
      abgebrochen = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ── Abgeleitete Anzeigewerte ───────────────────────────────────────────────

  const monitorAnzahl = monitorZiele.length;
  const beobachtungen = auffaellige.length;

  // Relativzeit-Text des letzten Scans (oder "Noch kein Scan").
  const relativ = relativeZeit(letzterScan?.scannedAt);
  const letzterScanText = relativ
    ? t("overview.status.lastScanRelative", {
        zeit:
          relativ.count === null
            ? t("overview.status.relativeJustNow")
            : t(relativ.key, { count: relativ.count }),
      })
    : t("overview.status.lastScanUnknown");

  // Sprung-Helfer: nur auslösen, wenn onNavigate verdrahtet ist (defensiv).
  // funktion ist optional: fehlt sie, wechselt nur der Reiter (wie bisher);
  // ist sie gesetzt, öffnet der Aufrufer zusätzlich die Ziel-Funktion.
  const springe = (tab, funktion) => {
    if (onNavigate) {
      onNavigate(tab, funktion);
    }
  };

  return (
    <div className="overview-view">
      {/* Status-Zeile (reine Fakten, KEIN Urteil) */}
      {sektionen.status && (
        <section className="overview-status" aria-label={t("overview.quickAccessHeading")}>
          <div className="overview-status__facts">
            <span className="overview-status__fact">{letzterScanText}</span>
            {letzterScan && (
              <span className="overview-status__fact">
                {t("overview.status.devicesKnown", { count: letzterScan.hostCount ?? 0 })}
              </span>
            )}
            <span className="overview-status__fact">
              {t("overview.status.observations", { count: beobachtungen })}
            </span>
            {/* Monitoring-Baustein NUR bei aktiven Zielen UND aktivem Unter-Schalter. */}
            {sektionen.status_monitoring && monitorAnzahl > 0 && (
              <span className="overview-status__fact overview-status__fact--monitor">
                <Activity size={14} aria-hidden="true" />
                {t("overview.status.monitoringActive", { count: monitorAnzahl })}
              </span>
            )}
          </div>
          <button
            type="button"
            className="overview-status__scan-btn"
            onClick={() => springe("observe")}
          >
            <Plus size={15} aria-hidden="true" />
            <span>{t("overview.status.newScan")}</span>
          </button>
        </section>
      )}

      {/* Schnellzugriff: DYNAMISCH — die meistgeöffneten Funktionen (nach Nutzung
          absteigend), mit den bisherigen Defaults aufgefüllt. Klick nutzt weiterhin
          springe(tab, funktion); der Sprung wird in App.jsx (handleNavigate) gezählt. */}
      {sektionen.schnellzugriff && schnellzugriff.length > 0 && (
        <section className="overview-section">
          <h2 className="overview-section__heading">{t("overview.quickAccessHeading")}</h2>
          <CardGrid>
            {schnellzugriff.map(
              ({ featureId, icon, tab, funktion, titleKey, subtitleKey, helpId }) => (
                <FunctionCard
                  key={featureId}
                  icon={icon}
                  title={t(titleKey)}
                  subtitle={t(subtitleKey)}
                  onOpen={() => springe(tab, funktion)}
                  helpId={helpId}
                  onOpenManual={onOpenManual}
                />
              ),
            )}
          </CardGrid>
        </section>
      )}

      {/* Beachtenswert: Achse-B-Hosts aus dem letzten Scan (nur wenn vorhanden) */}
      {sektionen.beachtenswert && auffaellige.length > 0 && (
        <section className="overview-section">
          <h2 className="overview-section__heading">
            {t("overview.beachtenswertHeading")}{" "}
            <span className="overview-section__sub">· {t("overview.fromLastScan")}</span>
          </h2>
          <ul className="overview-notable">
            {auffaellige.map((host) => {
              const Icon = HOST_ICON[host.icon] ?? Radar;
              const titel = host.label || host.hostname || host.ip || "—";
              const detail = [host.ip, host.label || host.hostname]
                .filter(Boolean)
                .join(" · ");
              return (
                <li
                  key={host.schluessel ?? host.ip}
                  className="overview-notable__item"
                  data-sev={host.analysisSeverity}
                >
                  <span className="overview-notable__icon" aria-hidden="true">
                    <Icon size={18} />
                  </span>
                  <span className="overview-notable__text">
                    <span className="overview-notable__title">{titel}</span>
                    <span className="overview-notable__meta">{detail}</span>
                  </span>
                </li>
              );
            })}
          </ul>
        </section>
      )}

      {/* Neue CVEs (nur wenn vorhanden): scrollbare Liste, eigener CSS-Scope */}
      {sektionen.cve && neueCves.length > 0 && (
        <section className="overview-section">
          <h2 className="overview-section__heading">{t("overview.cveHeading")}</h2>
          <ul className="overview-cve">
            {neueCves.map((befund) => {
              const hochCvss =
                typeof befund.cvssScore === "number" && befund.cvssScore >= 7;
              const ort = [befund.ip, befund.service].filter(Boolean).join(" · ");
              return (
                <li
                  key={`${befund.mac ?? befund.ip}-${befund.cveId}-${befund.port}`}
                  className="overview-cve__item"
                >
                  <span className="overview-cve__badge overview-cve__badge--new">
                    {t("overview.cveNewBadge")}
                  </span>
                  {befund.cvssScore !== null && (
                    <span
                      className="overview-cve__badge overview-cve__badge--cvss"
                      data-high={hochCvss ? "true" : "false"}
                    >
                      {befund.cvssScore}
                    </span>
                  )}
                  <span className="overview-cve__id">{befund.cveId}</span>
                  {ort && <span className="overview-cve__where">{ort}</span>}
                </li>
              );
            })}
          </ul>
        </section>
      )}

      {/* Kennzahlen-Fußzeile (schmal, sekundär, nur zwei Werte) */}
      {sektionen.kennzahlen && kennzahlen && (
        <section className="overview-metrics" aria-label={t("overview.metrics.appsWithTraffic")}>
          <div className="overview-metrics__item">
            <span className="overview-metrics__value">{kennzahlen.appsWithTraffic}</span>
            <span className="overview-metrics__label">{t("overview.metrics.appsWithTraffic")}</span>
          </div>
          <div className="overview-metrics__item">
            <span className="overview-metrics__value">{kennzahlen.activeConnections}</span>
            <span className="overview-metrics__label">{t("overview.metrics.activeConnections")}</span>
          </div>
        </section>
      )}

      {/* Dezenter Ladehinweis: nur während des ersten Laufs, kein Vollbild-Spinner. */}
      {laedt && <p className="overview-view__loading">…</p>}

    </div>
  );
}
