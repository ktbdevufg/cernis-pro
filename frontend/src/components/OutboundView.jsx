// Außenkontakte (CERNIS PRO 2.0)
// Lese-Ansicht der Außenkontakte DIESES Rechners: mit wem dieser Host nach außen
// spricht, gebündelt nach Betreiber / Land / Programm. Reines Frontend gegen den
// fertigen Endpunkt GET /api/outbound/contacts (api/outbound.js).
//
// Oben integriert: die Aufzeichnungs-Karte (OutboundRecordingPanel) — eine
// selbsterklärende Karte (Ruhe-/Aktiv-Kopf + „Neue Aufzeichnung" + Liste) mit
// Erstellen-/Detail-Modal. KEINE eigene Beobachten-Kachel mehr.
//
// Designsprache wie die übrigen Beobachten-Komponenten (ObserveView/TrafficView):
// dezent, flach, ruhig. Außenkontakte URTEILEN NICHT — KEINE Severity-Farben.

import { Globe, GlobeLock, Flag, Filter } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import {
  CAPTURE_ACCESS_OUTCOME,
  CAPTURE_ACCESS_STATE,
  fetchCaptureAccess,
  grantCaptureAccess,
} from "../api/captureAccess.js";
import { fetchOutboundContacts } from "../api/outbound.js";
import { matchContacts } from "../api/blocklist.js";
import { fetchSniMap, fetchSniStatus } from "../api/sni.js";
import { fetchSettings, updateSetting } from "../api/settings.js";
import { useSni } from "../hooks/useSni.js";
import CaptureAccessDialog from "./CaptureAccessDialog.jsx";
import NpcapDialog from "./NpcapDialog.jsx";
import OutboundRecordingPanel from "./OutboundRecordingPanel.jsx";
import OutboundConsentDialog from "./OutboundConsentDialog.jsx";
import "./OutboundView.css";

// Windows-Marker der Sniff-Verfügbarkeit (aus permission_error, siehe Backend
// sniffd_platform_supported). Trägt permissionError einen davon, ist die Sniff-
// Familie auf dieser Plattform grundsätzlich nicht nutzbar -> Ausgrau-Hinweis.
const NPCAP_MARKER = new Set(["NPCAP_MISSING", "WINDOWS_IPC_UNSUPPORTED"]);

function istNpcapMarker(marker) {
  return typeof marker === "string" && NPCAP_MARKER.has(marker);
}

// Reihenfolge/Erlaubte Gruppen der Blocklist-Badges. tracker_ads zuerst (häufiger,
// harmloser), threat zuletzt (zurückhaltend hervorgehoben). Unbekannte Gruppen-
// Strings werden NICHT als Badge gezeigt (kein roher Wire-String an den Nutzer).
const BADGE_GRUPPEN = ["tracker_ads", "threat"];

// Gruppierungs-Achsen des Segmented Control. Reihenfolge ist die Anzeige-
// reihenfolge; DEFAULT = der erste Eintrag (Betreiber). feld zeigt auf das
// Kontakt-Feld, das den Gruppen-Schlüssel liefert; leerLabel ist der i18n-Key
// für die ehrliche Sammelgruppe (Schlüssel === null).
const ACHSEN = [
  { id: "operator", feld: "operator", leerLabel: "emptyGroupOperator" },
  { id: "country", feld: "country", leerLabel: "emptyGroupCountry" },
  { id: "programm", feld: "appName", leerLabel: "emptyGroupProgramm" },
];

// Private/loopback/link-local/mapped-Präfixe: reine String/Präfix-Prüfung, KEINE
// Library. Deckt 10./172.16-31./192.168./127./169.254./::1/fe80/::ffff: ab.
// Defensiv gegen null/leer: ohne IP nicht als lokal werten (dann sichtbar).
function istLokaleIp(ip) {
  if (!ip || typeof ip !== "string") {
    return false;
  }
  const v = ip.toLowerCase();
  if (v === "::1" || v.startsWith("fe80") || v.startsWith("::ffff:")) {
    return true;
  }
  if (
    v.startsWith("10.") ||
    v.startsWith("192.168.") ||
    v.startsWith("127.") ||
    v.startsWith("169.254.")
  ) {
    return true;
  }
  // 172.16.0.0 – 172.31.255.255 (zweites Oktett 16–31).
  if (v.startsWith("172.")) {
    const zweites = Number.parseInt(v.split(".")[1], 10);
    if (zweites >= 16 && zweites <= 31) {
      return true;
    }
  }
  return false;
}

// Bündelt die Kontakte nach der gewählten Achse. Schlüssel === null/leer fällt in
// EINE ehrliche Sammelgruppe (label aus dem i18n-leerLabel). Pro Gruppe: Summe der
// connectionCount als Mengen-Zähler. Gruppen absteigend nach dieser Summe
// sortiert (deckt IoT-/Vielredner-Sicht ab).
function gruppiere(kontakte, achse, t) {
  const gruppen = new Map();
  for (const kontakt of kontakte) {
    const roh = kontakt[achse.feld];
    const istLeer = roh === null || roh === undefined || roh === "";
    const schluessel = istLeer ? "__leer__" : roh;
    const label = istLeer ? t(`beobachten.outbound.${achse.leerLabel}`) : roh;
    let gruppe = gruppen.get(schluessel);
    if (!gruppe) {
      gruppe = { schluessel, label, kontakte: [], menge: 0 };
      gruppen.set(schluessel, gruppe);
    }
    gruppe.kontakte.push(kontakt);
    gruppe.menge += kontakt.connectionCount;
  }
  return [...gruppen.values()].sort((a, b) => b.menge - a.menge);
}

// Bündelt die Blocklist-Treffer EINES Kontakts nach GRUPPE. Pro erlaubter Gruppe
// (BADGE_GRUPPEN) ein Eintrag mit den getroffenen Quellen (dedupliziert über
// sourceId); mehrere Threat-Listen ergeben EINE threat-Gruppe. Unbekannte Gruppen
// werden ausgelassen (kein roher Wire-String). Rückgabe in fester BADGE_GRUPPEN-
// Reihenfolge.
function gruppiereTreffer(treffer) {
  const proGruppe = new Map();
  for (const m of treffer) {
    if (!BADGE_GRUPPEN.includes(m.group)) {
      continue;
    }
    let eintrag = proGruppe.get(m.group);
    if (!eintrag) {
      eintrag = { group: m.group, quellen: [], gesehen: new Set() };
      proGruppe.set(m.group, eintrag);
    }
    // Quellen über sourceId deduplizieren (eine Quelle kann mehrfach treffen).
    if (!eintrag.gesehen.has(m.sourceId)) {
      eintrag.gesehen.add(m.sourceId);
      eintrag.quellen.push({ sourceName: m.sourceName, matchedOn: m.matchedOn });
    }
  }
  return BADGE_GRUPPEN.filter((g) => proGruppe.has(g)).map((g) =>
    proGruppe.get(g),
  );
}

// Eine Kontakt-Zeile: hostname (sonst remoteIp als ehrlicher Fallback), darunter
// klein remoteIp + operator + ASN (vorhandene Felder; fehlende weglassen), rechts
// appName-Pille (falls vorhanden) + "×connectionCount". treffer = die Blocklist-
// Treffer dieses Kontakts (matches[] || []); rein additiv, urteilt NICHT.
function KontaktZeile({ kontakt, treffer }) {
  const { t } = useTranslation();

  // hostname null -> IP zeigen. Der Untertitel führt die IP dann nur, wenn der
  // Titel der hostname ist (sonst stünde die IP doppelt).
  const titel = kontakt.hostname ?? kontakt.remoteIp;
  const zeigeIpUnten = kontakt.hostname !== null;

  // Untertitel-Teile: nur vorhandene Felder, fehlende weglassen (S3-ehrlich).
  const subTeile = [];
  if (zeigeIpUnten) {
    subTeile.push(kontakt.remoteIp);
  }
  if (kontakt.operator !== null) {
    subTeile.push(kontakt.operator);
  }
  if (kontakt.asn !== null) {
    subTeile.push(kontakt.asn);
  }

  // Blocklist-Treffer nach Gruppe (dedupliziert). Leer -> kein Badge-Bereich.
  const trefferGruppen = gruppiereTreffer(treffer ?? []);

  return (
    <li className="outbound-contact">
      <div className="outbound-contact__main">
        <span className="outbound-contact__title outbound-mono">{titel}</span>
        {subTeile.length > 0 && (
          <span className="outbound-contact__sub outbound-mono">
            {subTeile.join(" · ")}
          </span>
        )}
        {trefferGruppen.length > 0 && (
          <div className="outbound-contact__listen">
            {trefferGruppen.map((eintrag) => {
              // Quellen-Zeilen "<Quelle> (Treffer: <matchedOn>)" — die Quellangabe
              // ist die rote Linie: der Nutzer MUSS die Quelle erfahren können.
              const quellTexte = eintrag.quellen.map((q) =>
                t("beobachten.outbound.match.sourcePattern", {
                  source: q.sourceName,
                  matchedOn: q.matchedOn,
                }),
              );
              const klasse =
                eintrag.group === "threat"
                  ? "outbound-badge outbound-badge--threat"
                  : "outbound-badge outbound-badge--tracker";
              return (
                <div key={eintrag.group} className="outbound-listen-treffer">
                  <span
                    className={klasse}
                    title={`${t("beobachten.outbound.match.badgeTitle")}\n${quellTexte.join("\n")}`}
                  >
                    {t(`beobachten.outbound.match.group.${eintrag.group}`)}
                  </span>
                  <span className="outbound-listen-quellen">
                    {quellTexte.join(" · ")}
                  </span>
                </div>
              );
            })}
          </div>
        )}
      </div>
      <div className="outbound-contact__meta">
        {kontakt.appName !== null && (
          <span className="outbound-contact__app">{kontakt.appName}</span>
        )}
        <span className="outbound-contact__count outbound-mono">
          {t("beobachten.outbound.connectionsSuffix", {
            count: kontakt.connectionCount,
          })}
        </span>
      </div>
    </li>
  );
}

// Eine Gruppe: Kopfzeile (Gruppen-Label + Mengen-Zähler), darunter die Kontakte.
// trefferMap (remoteIp -> matches[]) reicht die Blocklist-Treffer pro Zeile durch.
function GruppenBlock({ gruppe, trefferMap }) {
  const { t } = useTranslation();
  return (
    <section className="outbound-group">
      <div className="outbound-group__header">
        <span className="outbound-group__label">{gruppe.label}</span>
        <span className="outbound-group__count outbound-mono">
          {t("beobachten.outbound.connectionsSuffix", { count: gruppe.menge })}
        </span>
      </div>
      <ul className="outbound-group__contacts">
        {gruppe.kontakte.map((kontakt) => (
          <KontaktZeile
            key={kontakt.remoteIp}
            kontakt={kontakt}
            treffer={trefferMap.get(kontakt.remoteIp) ?? []}
          />
        ))}
      </ul>
    </section>
  );
}

export default function OutboundView() {
  const { t } = useTranslation();

  const [kontakte, setKontakte] = useState([]);
  const [hostScope, setHostScope] = useState(null);
  // Naht für den ruhigen Hinweis-Streifen bei Ladefehler (kein Absturz).
  const [ladeFehler, setLadeFehler] = useState(false);
  // Gewählte Gruppierungs-Achse (DEFAULT = Betreiber).
  const [achseId, setAchseId] = useState(ACHSEN[0].id);
  // Filter "Lokale & Infrastruktur zeigen" (DEFAULT AUS).
  const [zeigeLokale, setZeigeLokale] = useState(false);
  // Anzahl host-weit gerade laufender Aufzeichnungen -- vom OutboundRecordingPanel
  // per onAktivCount nach oben gemeldet (kein zweiter Voll-Poll hier). Treibt den
  // Aufzeichnungs-Hinweis in der Banner-Zeile.
  const [aktivAnzahl, setAktivAnzahl] = useState(0);
  // Blocklist-Abgleich der geladenen Kontakte (matchContacts-results). Eigene,
  // fehlertolerante Naht: schlägt der Abgleich fehl, bleibt das leer -> keine
  // Badges, kein Hinweis, kein Absturz. Die Kontakte-Liste selbst bleibt intakt.
  const [matchResults, setMatchResults] = useState([]);

  // ── SNI-Block (Etappe 3b): Einwilligung + Lifecycle + Anreicherung ──────────
  // Einwilligung in die passive SNI-Beobachtung: "granted"|"denied"|null(=unset)|
  // "loading"(=Startwert, bis das Settings-Lesen durch ist). Steuert Lifecycle
  // und den Hinweisstreifen.
  const [consent, setConsent] = useState("loading");
  // Ob der Einwilligungs-Dialog gerade offen ist.
  const [zeigeConsentDialog, setZeigeConsentDialog] = useState(false);
  // SNI-Map remote_ip -> hostname (Plain-Object) für die Anreicherung. Leer,
  // solange SNI nicht läuft.
  const [sniMap, setSniMap] = useState({});
  // Ob der Threat-Filter aktiv ist (nur Gegenstellen auf Threat-Listen zeigen).
  const [threatGefiltert, setThreatGefiltert] = useState(false);

  // Windows-Marker aus dem SNI-Status (permissionError). Ist er einer der beiden
  // Npcap-Marker, ersetzt der Ausgrau-Block die Startphasen-/Startfehler-Hinweise.
  const [sniPermMarker, setSniPermMarker] = useState(null);
  // Offener NpcapDialog (Marker-String) oder null. Mount/Unmount wie bei Dialogen.
  const [npcapDialogMarker, setNpcapDialogMarker] = useState(null);

  // ── Rechteeinrichtung (Etappe 2) ────────────────────────────────────────────
  // Ob der Erklär-Dialog offen ist, der VOR der Systemabfrage sagt, was
  // eingerichtet wird. Erst nach dem Bestätigen dort wird die Abfrage ausgelöst.
  const [zeigeAccessDialog, setZeigeAccessDialog] = useState(false);
  // Ob die Systemabfrage gerade läuft (der native Dialog ist offen). Steuert den
  // Warte-Zustand — der Aufruf dauert, solange der Nutzer nicht geantwortet hat.
  const [accessLaeuft, setAccessLaeuft] = useState(false);
  // Ergebnis des letzten Einrichtungsversuchs: { outcome, reason } oder null.
  // "cancelled" ist KEIN Fehler und bekommt darum eine ruhige, eigene Anzeige.
  const [accessErgebnis, setAccessErgebnis] = useState(null);

  // Geteilter SNI-Lifecycle-Hook: real gestartet beim ERSTEN acquire, real
  // gestoppt erst beim LETZTEN release (Reference-Count). running/starting/error
  // spiegeln den globalen Sniffer-Zustand.
  const {
    running: sniAktiv,
    starting: sniStartet,
    error: sniError,
    acquire,
    release,
  } = useSni();

  // Beim Mount laden. t NIEMALS in dep-Array (react-i18next-Regel) — leeres
  // dep-Array, einmal beim Mount. Fehler tolerieren: leere Liste + ruhiger
  // Hinweis-Streifen, kein Absturz.
  useEffect(() => {
    let abgebrochen = false;
    (async () => {
      try {
        const ergebnis = await fetchOutboundContacts();
        if (abgebrochen) {
          return;
        }
        setKontakte(ergebnis.contacts);
        setHostScope(ergebnis.hostScope);
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

  // SNI-Block: Einwilligung beim Mount aus den Settings laden. t NICHT im
  // dep-Array (react-i18next-Regel) — leeres dep-Array, einmal beim Mount.
  // Fehlt der Wert (null), zeigen wir den Einwilligungs-Dialog. Fehler tolerieren:
  // consent bleibt null, Dialog zeigen ist ok (kein Absturz).
  useEffect(() => {
    let abgebrochen = false;
    (async () => {
      try {
        const settings = await fetchSettings();
        if (abgebrochen) {
          return;
        }
        const wert = settings["outbound_sni_consent"] ?? null;
        setConsent(wert);
        if (wert === null) {
          setZeigeConsentDialog(true);
        }
      } catch {
        if (!abgebrochen) {
          setConsent(null);
          setZeigeConsentDialog(true);
        }
      }
    })();
    return () => {
      abgebrochen = true;
    };
  }, []);

  // SNI-Lifecycle: bei erteilter Einwilligung den geteilten Sniffer anfordern
  // (acquire) und im Cleanup wieder freigeben (release). acquire/release sind
  // über useCallback stabil; sie gehören dennoch ins dep-Array. Bei nicht
  // erteilter Einwilligung passiert nichts.
  useEffect(() => {
    if (consent !== "granted") {
      return undefined;
    }
    acquire();
    return () => {
      release();
    };
  }, [consent, acquire, release]);

  // permissionError-Marker beim Mount holen: trägt er einen Windows-Marker, ist
  // der Sniff auf dieser Plattform grundsätzlich nicht nutzbar -> der Ausgrau-
  // Block ersetzt die Startphasen-/Startfehler-Hinweise. fetchSniStatus wirft
  // (kein still-Fallback); tolerant fangen, damit ein Patzer die View nicht kippt.
  useEffect(() => {
    fetchSniStatus()
      .then((s) => setSniPermMarker(s.permissionError ?? null))
      .catch(() => {});
  }, []);

  // SNI-Map-Anreicherung: läuft der Sniffer, einmal die Map remote_ip -> hostname
  // holen (fetchSniMap wirft nie). Läuft er nicht, die Map leeren. Bewusst KEIN
  // Dauer-Poll — einmal nach Aktivierung reicht für Stufe B.
  useEffect(() => {
    let abgebrochen = false;
    if (!sniAktiv) {
      setSniMap({});
      return undefined;
    }
    (async () => {
      const map = await fetchSniMap();
      if (!abgebrochen) {
        setSniMap(map);
      }
    })();
    return () => {
      abgebrochen = true;
    };
  }, [sniAktiv]);

  // Angereicherte Kontakte: hat ein Kontakt keinen hostname, aber die SNI-Map
  // kennt einen für seine remoteIp, setzen wir ihn ein. Sonst bleibt der Kontakt
  // unverändert. Diese Liste ersetzt im Match-/Render-Pfad die rohe kontakte-Liste,
  // damit Domain-Blocklisten auf den echten Hostnamen greifen. MUSS vor den
  // Effekten/Memos stehen, die sie nutzen.
  const kontakteMitSni = useMemo(
    () =>
      kontakte.map((kontakt) =>
        kontakt.hostname === null && sniMap[kontakt.remoteIp]
          ? { ...kontakt, hostname: sniMap[kontakt.remoteIp] }
          : kontakt,
      ),
    [kontakte, sniMap],
  );

  // Zweiter Effekt: nach geladenen Kontakten die Blocklist abgleichen. Abhängig von
  // [kontakteMitSni] (NICHT t — react-i18next-Regel) — gleicht die ANGEREICHERTEN
  // Kontakte ab, damit Domain-Blocklisten auf den SNI-Hostnamen greifen.
  // matchContacts OHNE strictness, damit das Backend die in der Verwaltung gesetzte
  // Strenge + Gruppen-Schalter nutzt (Anzeige bleibt konsistent zur Nutzer-
  // Einstellung). Fehler werden STILL behandelt: nur console.error, keine Badges,
  // kein Hinweis, kein Absturz.
  useEffect(() => {
    if (kontakteMitSni.length === 0) {
      setMatchResults([]);
      return undefined;
    }
    let abgebrochen = false;
    (async () => {
      try {
        const { results } = await matchContacts(kontakteMitSni);
        if (!abgebrochen) {
          setMatchResults(results);
        }
      } catch (fehler) {
        // Still: Liste bleibt voll funktionsfähig, nur ohne Badges.
        console.error("Blocklist-Abgleich fehlgeschlagen", fehler);
        if (!abgebrochen) {
          setMatchResults([]);
        }
      }
    })();
    return () => {
      abgebrochen = true;
    };
  }, [kontakteMitSni]);

  // Lookup-Map remoteIp -> matches[] über dem results-State. Aggregiert (eine IP
  // kommt höchstens einmal); defensiv überschreibend (letzte gewinnt, egal).
  const trefferMap = useMemo(() => {
    const map = new Map();
    for (const r of matchResults) {
      map.set(r.remoteIp, r.matches);
    }
    return map;
  }, [matchResults]);

  // Gibt es überhaupt einen Treffer? Steuert den einmaligen Quell-Hinweis (rote
  // Linie): nur zeigen, wenn tatsächlich Listen-Einordnungen sichtbar sind.
  const hatTreffer = useMemo(
    () => matchResults.some((r) => r.matches.length > 0),
    [matchResults],
  );

  // Threat-Aggregation: Anzahl der BETROFFENEN Gegenstellen (nicht einzelner
  // matches), die mindestens einen match mit group==="threat" haben. Treibt den
  // aggregierten Threat-Streifen.
  const threatAnzahl = useMemo(
    () =>
      matchResults.filter((r) => {
        // Lokale/Infrastruktur-Treffer (z.B. eigene FritzBox, localhost) nur
        // mitzaehlen, wenn der Lokale-Schalter aktiv ist -- konsistent zur Liste.
        if (!zeigeLokale && istLokaleIp(r.remoteIp)) {
          return false;
        }
        return r.matches.some((m) => m.group === "threat");
      }).length,
    [matchResults, zeigeLokale],
  );

  const achse = ACHSEN.find((a) => a.id === achseId) ?? ACHSEN[0];

  // Sichtbare Kontakte: per Default lokale/Infrastruktur-IPs ausblenden; mit
  // aktivem Schalter alle zeigen. Über den angereicherten Kontakten (SNI). Bei
  // aktivem Threat-Filter zusätzlich nur Gegenstellen mit threat-Treffer zeigen
  // (erst Lokale-Filter, dann ggf. Threat-Filter).
  const sichtbar = useMemo(() => {
    const nachLokal = zeigeLokale
      ? kontakteMitSni
      : kontakteMitSni.filter((k) => !istLokaleIp(k.remoteIp));
    if (!threatGefiltert) {
      return nachLokal;
    }
    return nachLokal.filter((k) =>
      (trefferMap.get(k.remoteIp) ?? []).some((m) => m.group === "threat"),
    );
  }, [kontakteMitSni, zeigeLokale, threatGefiltert, trefferMap]);

  const gruppen = useMemo(
    () => gruppiere(sichtbar, achse, t),
    // t bewusst NICHT in dep-Array (react-i18next-Regel); die Labels werden bei
    // Sprachwechsel ohnehin über den nächsten Render neu erzeugt.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [sichtbar, achse],
  );

  // Einwilligung erteilt: persistieren (fehlertolerant — UI läuft auch bei
  // Schreibfehler weiter), Zustand setzen, Dialog schließen. dontAsk wird beim
  // Zustimmen nicht gesondert gebraucht (Zustimmen persistiert ohnehin).
  //
  // Danach (Etappe 2): prüfen, ob der Zugriff auf die Mitschnitt-Geräte schon
  // eingerichtet ist. Fehlt er, wird NICHT sofort die Systemabfrage ausgelöst,
  // sondern erst der Erklär-Dialog gezeigt — der Nutzer soll wissen, was gleich
  // passiert, bevor ein Passwortfenster erscheint. Ist alles eingerichtet (oder
  // gilt die Einrichtung hier nicht, z. B. Linux), passiert nichts Zusätzliches:
  // SNI startet wie bisher über den consent-Zustand.
  const handleGrant = async () => {
    try {
      await updateSetting("outbound_sni_consent", "granted");
    } catch (fehler) {
      console.error("Einwilligung speichern fehlgeschlagen", fehler);
    }
    setConsent("granted");
    setZeigeConsentDialog(false);

    await pruefeUndBieteEinrichtungAn();
  };

  // EINZIGER Weg in die Rechteeinrichtung — bewusst als eine Funktion, die BEIDE
  // Einstiege nutzen: das erstmalige Zustimmen (handleGrant) und der Knopf im
  // Hinweisstreifen bei fehlenden Rechten (handleRechteEinrichten). Nur so gibt es
  // keine zwei auseinanderlaufenden Kopien derselben Logik.
  //
  // Prüft den Zustand und öffnet NUR bei tatsächlich fehlenden Rechten den Erklär-
  // Dialog. Stehen die Rechte schon (oder gilt die Einrichtung hier nicht, z. B.
  // Linux), passiert nichts — es wird kein Dialog gezeigt, den es nicht braucht.
  const pruefeUndBieteEinrichtungAn = async () => {
    try {
      const status = await fetchCaptureAccess();
      if (status.state === CAPTURE_ACCESS_STATE.MISSING) {
        setZeigeAccessDialog(true);
      }
      return status.state;
    } catch (fehler) {
      // Status nicht abfragbar (Backend weg): kein Dialog, kein Lärm. SNI meldet
      // fehlende Rechte ohnehin über seinen eigenen Hinweis.
      console.error("Status der Rechteeinrichtung nicht abfragbar", fehler);
      return null;
    }
  };

  // Einstieg aus dem Hinweisstreifen „Rechte fehlen". Anders als handleGrant hängt
  // er NICHT am Consent-Dialog: er ist immer erreichbar, solange die Rechte fehlen —
  // auch für Nutzer, die der SNI-Erfassung längst zugestimmt haben und den Dialog
  // deshalb nie wieder sehen.
  const handleRechteEinrichten = () => {
    void pruefeUndBieteEinrichtungAn();
  };

  // Erklär-Dialog bestätigt: JETZT die Systemabfrage auslösen. Der Aufruf dauert,
  // solange der native Dialog offen ist — darum accessLaeuft als Warte-Zustand.
  // Alle drei Ausgänge werden ehrlich übernommen: "granted" (SNI läuft weiter wie
  // bisher), "cancelled" (ruhiger Hinweis, jederzeit nachholbar) und "failed"
  // (verständliche Meldung mit Grund).
  const handleAccessGrant = async () => {
    setZeigeAccessDialog(false);
    setAccessLaeuft(true);
    try {
      const ergebnis = await grantCaptureAccess();
      setAccessErgebnis(ergebnis);
      if (ergebnis.outcome === CAPTURE_ACCESS_OUTCOME.GRANTED) {
        await uebernehmeNeueRechte();
      }
    } catch (fehler) {
      // Transportfehler (Backend nicht erreichbar) ist ein echter Fehlschlag —
      // aber ohne Grund vom Backend; der Text kommt dann aus der i18n.
      console.error("Rechteeinrichtung fehlgeschlagen", fehler);
      setAccessErgebnis({ outcome: CAPTURE_ACCESS_OUTCOME.FAILED, reason: "" });
    } finally {
      setAccessLaeuft(false);
    }
  };

  // Nach erfolgreicher Einrichtung den neuen Zustand übernehmen, OHNE dass der
  // Nutzer die App neu starten muss: den zuvor fehlgeschlagenen SNI-Start erneut
  // versuchen.
  //
  // Warum release() vor acquire(): nach einem Fehlstart steht der Reference-Count
  // des geteilten Hooks bereits auf 1, running aber auf false. Ein bloßes acquire()
  // würde deshalb nur hochzählen und NICHT neu starten (siehe useHelperResource).
  // Erst das release() setzt den Zähler zurück, dann startet acquire() wirklich neu.
  const uebernehmeNeueRechte = async () => {
    try {
      await release();
      await acquire();
    } catch (fehler) {
      // Der Neustart ist Komfort, kein Pflichtpfad: schlägt er fehl, bleibt der
      // bisherige Hinweis stehen und der Nutzer kann es erneut versuchen.
      console.error("SNI-Neustart nach Rechteeinrichtung fehlgeschlagen", fehler);
    }
  };

  // Erklär-Dialog abgelehnt: nichts einrichten, kein Fehler. Die Einwilligung in
  // die SNI-Beobachtung bleibt bestehen; der Nutzer kann es später nachholen.
  const handleAccessDismiss = () => setZeigeAccessDialog(false);

  // Ergebnis-Hinweis schließen bzw. erneut versuchen (öffnet wieder den Erklär-
  // Dialog, damit auch der zweite Anlauf mit der Erklärung beginnt).
  const handleAccessErgebnisSchliessen = () => setAccessErgebnis(null);
  const handleAccessErneut = () => {
    setAccessErgebnis(null);
    setZeigeAccessDialog(true);
  };

  // Einwilligung abgelehnt: nur bei "Nicht mehr fragen" dauerhaft als "denied"
  // persistieren (fehlertolerant); sonst unset lassen (consent=null) — dann fragt
  // die Ansicht beim nächsten Mal erneut. In beiden Fällen Dialog schließen.
  const handleDeny = async (dontAsk) => {
    if (dontAsk) {
      try {
        await updateSetting("outbound_sni_consent", "denied");
      } catch (fehler) {
        console.error("Ablehnung speichern fehlgeschlagen", fehler);
      }
      setConsent("denied");
    } else {
      setConsent(null);
    }
    setZeigeConsentDialog(false);
  };

  // „Anzeigen" im Off-Streifen: Einwilligungs-Dialog erneut öffnen.
  const handleHinweisShow = () => setZeigeConsentDialog(true);

  return (
    <div className="outbound">
      {/* Einwilligungs-Dialog (SNI): zentriertes Overlay über der Ansicht. */}
      {zeigeConsentDialog && (
        <OutboundConsentDialog onGrant={handleGrant} onDeny={handleDeny} />
      )}

      {/* Erklär-Dialog vor der Rechteeinrichtung (Etappe 2): erklärt in klarer
          Sprache, was eingerichtet wird, BEVOR das native Systemfenster nach dem
          Passwort fragt. Erst „Einrichten" löst die Systemabfrage aus. */}
      {zeigeAccessDialog && (
        <CaptureAccessDialog
          onConfirm={handleAccessGrant}
          onDismiss={handleAccessDismiss}
        />
      )}

      {/* Warte-Streifen, solange das Systemfenster offen ist. Ruhig gehalten —
          der Nutzer beantwortet gerade eine Passwort-/Touch-ID-Abfrage. */}
      {accessLaeuft && (
        <div className="outbound__hinweis" role="status">
          <span className="outbound__hinweis-text">
            {t("beobachten.outbound.access.laeuft")}
          </span>
        </div>
      )}

      {/* Ergebnis der Rechteeinrichtung — ehrlich nach Ausgang unterschieden:
          "granted"   -> kurze Bestätigung, SNI läuft wie bisher weiter.
          "cancelled" -> RUHIGER Hinweis, KEINE Fehleroptik; jederzeit nachholbar.
          "failed"    -> verständliche Meldung; der Grund aus dem Backend wird
                         angehängt, wenn es einen gibt (sonst nur der Klartext).
          "not_applicable" wird bewusst NICHT angezeigt: auf Linux ist nichts
          einzurichten, dafür braucht der Nutzer keine Meldung. */}
      {accessErgebnis &&
        accessErgebnis.outcome !== CAPTURE_ACCESS_OUTCOME.NOT_APPLICABLE && (
          <div className="outbound__hinweis" role="note">
            <span className="outbound__hinweis-text">
              {accessErgebnis.outcome === CAPTURE_ACCESS_OUTCOME.GRANTED &&
                t("beobachten.outbound.access.erfolg")}
              {accessErgebnis.outcome === CAPTURE_ACCESS_OUTCOME.CANCELLED &&
                t("beobachten.outbound.access.abgebrochen")}
              {accessErgebnis.outcome === CAPTURE_ACCESS_OUTCOME.FAILED &&
                (accessErgebnis.reason
                  ? `${t("beobachten.outbound.access.fehler")} ${accessErgebnis.reason}`
                  : t("beobachten.outbound.access.fehler"))}
            </span>
            {accessErgebnis.outcome !== CAPTURE_ACCESS_OUTCOME.GRANTED && (
              <button
                type="button"
                className="outbound__hinweis-button"
                onClick={handleAccessErneut}
              >
                {t("beobachten.outbound.access.erneut")}
              </button>
            )}
            <button
              type="button"
              className="outbound__hinweis-button"
              onClick={handleAccessErgebnisSchliessen}
            >
              {t("beobachten.outbound.access.schliessen")}
            </button>
          </div>
        )}

      {/* NpcapDialog: marker-abhängiger Erklär-/Download-Dialog. Mount/Unmount
          über den State (npcapDialogMarker); onClose setzt ihn zurück. */}
      {npcapDialogMarker && (
        <NpcapDialog
          marker={npcapDialogMarker}
          onClose={() => setNpcapDialogMarker(null)}
        />
      )}

      {/* Ehrlicher host_scope-Banner: nur bei "local_host". Bei anderem/leerem
          Wert weglassen (S3-ehrlich). Erweitert um zwei ehrliche dynamische Teile:
          (a) Anzahl der aktuell SICHTBAREN Aussenkontakte (nach Lokale-Filter),
          (b) ein ruhiger Aufzeichnungs-Hinweis, falls eine Aufzeichnung laeuft.
          Eine ruhige Banner-Zeile: statischer Kern + " — " + Anzahl (+ ggf.
          " — " + Aufzeichnungs-Hinweis). */}
      {hostScope === "local_host" && (
        <div className="outbound__scope" role="note">
          {t("beobachten.outbound.hostScopeLocal")}
          {" — "}
          {t("beobachten.outbound.sichtbareKontakte", { count: sichtbar.length })}
          {aktivAnzahl > 0 && (
            <>
              {" — "}
              {t("beobachten.outbound.aufzeichnungLaeuft", { count: aktivAnzahl })}
            </>
          )}
        </div>
      )}

      {/* Ruhiger Hinweis-Streifen bei Ladefehler (Stil observe__hinweis). */}
      {ladeFehler && (
        <div className="outbound__hinweis" role="note">
          <span className="outbound__hinweis-title">
            {t("beobachten.traffic.permissionTitle")}
          </span>
          <span className="outbound__hinweis-text">
            {t("beobachten.outbound.loadError")}
          </span>
        </div>
      )}

      {/* SNI-Hinweisstreifen bei ausgeschalteten echten Domainnamen: nur wenn
          die Einwilligung nicht erteilt ist, der Startwert nicht mehr lädt und
          der Dialog nicht offen ist. Rechts ein „Anzeigen"-Knopf, der den Dialog
          erneut öffnet. */}
      {consent !== "granted" && consent !== "loading" && !zeigeConsentDialog && (
        <div className="outbound__sni-hinweis" role="note">
          <GlobeLock size={16} aria-hidden="true" />
          <span className="outbound__sni-hinweis-text">
            {t("beobachten.outbound.sni.offHinweis")}
          </span>
          <button
            type="button"
            className="outbound__sni-hinweis-button"
            onClick={handleHinweisShow}
          >
            {t("beobachten.outbound.sni.offShow")}
          </button>
        </div>
      )}

      {/* Npcap-Ausgrau-Block: trägt der SNI-Status einen Windows-Marker (Npcap
          fehlt / IPC noch nicht portiert), ist der Sniff auf dieser Plattform
          grundsätzlich nicht nutzbar. Dann STATT der Startphasen-/Startfehler-
          Hinweise ein ehrlicher Ausgrau-Hinweis. Marker-abhängig wie der Dialog:
          NPCAP_MISSING -> Hinweistext + Button (öffnet NpcapDialog zum Download);
          WINDOWS_IPC_UNSUPPORTED -> IPC-Text OHNE Button (Npcap ist da, der Dialog-
          Aufruf ergäbe keinen Sinn). Nur bei erteilter Einwilligung (konsistent
          mit den SNI-Blöcken). */}
      {consent === "granted" && istNpcapMarker(sniPermMarker) && (
        <div className="outbound__hinweis" role="note">
          <span className="outbound__hinweis-text">
            {sniPermMarker === "WINDOWS_IPC_UNSUPPORTED"
              ? t("npcap.inlineHintIpc")
              : t("npcap.inlineHint")}
          </span>
          {sniPermMarker !== "WINDOWS_IPC_UNSUPPORTED" && (
            <button
              type="button"
              className="outbound__hinweis-button"
              onClick={() => setNpcapDialogMarker(sniPermMarker)}
            >
              {t("npcap.installBtn")}
            </button>
          )}
        </div>
      )}

      {/* SNI-Startphase: kurzer, ruhiger Lade-Hinweis, bis der Helfer läuft.
          Entfällt bei aktivem Npcap-Marker (dann greift der Ausgrau-Block). */}
      {consent === "granted" && !istNpcapMarker(sniPermMarker) && sniStartet && (
        <div className="outbound__hinweis" role="note">
          <span className="outbound__hinweis-text">
            {t("beobachten.outbound.sni.starting")}
          </span>
        </div>
      )}

      {/* Start-Fehler der SNI-Beobachtung: ruhiger Hinweis (Stil Ladefehler),
          nur bei erteilter Einwilligung und tatsächlichem Fehler. Entfällt bei
          aktivem Npcap-Marker (der Ausgrau-Block erklärt die Ursache ehrlicher). */}
      {consent === "granted" && !istNpcapMarker(sniPermMarker) && sniError && (
        <div className="outbound__hinweis" role="note">
          <span className="outbound__hinweis-title">
            {t("beobachten.traffic.permissionTitle")}
          </span>
          <span className="outbound__hinweis-text">
            {t("beobachten.outbound.sni.startError")}
          </span>
          {/* Weg aus dem Fehlzustand heraus (Etappe 2c): der Hinweis benennt nicht
              nur, dass Rechte fehlen, sondern bietet die Einrichtung direkt an.
              Ohne diesen Knopf war die Einrichtung nur beim ERSTMALIGEN Zustimmen
              erreichbar — wer früher zugestimmt hatte, kam nie mehr heran. Gleicher
              Weg wie bei handleGrant (eine gemeinsame Funktion, keine Kopie). */}
          <button
            type="button"
            className="outbound__hinweis-button"
            onClick={handleRechteEinrichten}
            disabled={accessLaeuft}
          >
            {t("beobachten.outbound.access.jetztEinrichten")}
          </button>
        </div>
      )}

      {/* Rote-Linie-Hinweis (einmalig, NICHT pro Zeile): nur wenn überhaupt
          Listen-Treffer sichtbar sind. Macht die Quelle der Einordnung explizit —
          sie stammt aus den Verwaltungs-Listen, nicht von einem CERNIS-Urteil. */}
      {hatTreffer && (
        <div className="outbound__listen-hinweis" role="note">
          {t("beobachten.outbound.match.disclaimer")}
        </div>
      )}

      {/* Aggregierter Threat-Streifen: zeigt zusammengefasst, wie viele
          Gegenstellen auf Threat-Listen stehen. Ohne aktiven Filter ein ruhiger
          Hinweis mit „Anzeigen"-Knopf (setzt den Threat-Filter); mit aktivem
          Filter der gefiltert-Zustand mit „Filter aufheben". */}
      {threatAnzahl > 0 &&
        (threatGefiltert ? (
          <div className="outbound__threat-gefiltert" role="note">
            <Filter size={16} aria-hidden="true" />
            <span className="outbound__threat-gefiltert-text">
              {threatAnzahl === 1
                ? t("beobachten.outbound.sni.threatFilteredOne")
                : t("beobachten.outbound.sni.threatFilteredMany", {
                    count: threatAnzahl,
                  })}
            </span>
            <button
              type="button"
              className="outbound__threat-button"
              onClick={() => setThreatGefiltert(false)}
            >
              {t("beobachten.outbound.sni.threatFilterClear")}
            </button>
          </div>
        ) : (
          <div className="outbound__threat-streifen" role="note">
            <Flag size={16} aria-hidden="true" />
            <div className="outbound__threat-streifen-body">
              <span className="outbound__threat-streifen-text">
                {threatAnzahl === 1
                  ? t("beobachten.outbound.sni.threatOne")
                  : t("beobachten.outbound.sni.threatMany", {
                      count: threatAnzahl,
                    })}
              </span>
              <span className="outbound__threat-streifen-disclaimer">
                {t("beobachten.outbound.sni.threatDisclaimer")}
              </span>
            </div>
            <button
              type="button"
              className="outbound__threat-button"
              onClick={() => setThreatGefiltert(true)}
            >
              {t("beobachten.outbound.sni.threatShow")}
            </button>
          </div>
        ))}

      {/* Aufzeichnungs-Karte (integriert), immer sichtbar: EINE selbsterklaerende
          Karte (Kopf mit Ruhe-/Aktiv-Status + "Neue Aufzeichnung" + Liste). Sie
          oeffnet Erstellen-/Detail-Masken als Modal-Overlays und meldet die Anzahl
          laufender Aufzeichnungen ueber onAktivCount nach oben (Banner-Hinweis). */}
      <OutboundRecordingPanel onAktivCount={setAktivAnzahl} />

      {/* Steuerleiste: Segmented Control (Gruppierung) + Filter-Schalter. */}
      <div className="outbound__controls">
        <div
          className="outbound__segmented"
          role="group"
          aria-label={t("beobachten.outbound.groupByLabel")}
        >
          {ACHSEN.map((a) => {
            const aktiv = a.id === achseId;
            const klasse = aktiv
              ? "outbound__seg outbound__seg--aktiv"
              : "outbound__seg";
            return (
              <button
                key={a.id}
                type="button"
                className={klasse}
                aria-pressed={aktiv}
                onClick={() => setAchseId(a.id)}
              >
                {t(`beobachten.outbound.groupBy.${a.id}`)}
              </button>
            );
          })}
        </div>

        <label className="outbound__toggle">
          <input
            type="checkbox"
            checked={zeigeLokale}
            onChange={(e) => setZeigeLokale(e.target.checked)}
          />
          {t("beobachten.outbound.showLocalToggle")}
        </label>
      </div>

      {/* Gruppen-Liste oder ehrlicher Leerzustand (keine Kontakte nach Filter). */}
      {gruppen.length === 0 ? (
        <p className="outbound__empty">{t("beobachten.outbound.empty")}</p>
      ) : (
        <div className="outbound__groups">
          {gruppen.map((gruppe) => (
            <GruppenBlock
              key={gruppe.schluessel}
              gruppe={gruppe}
              trefferMap={trefferMap}
            />
          ))}
        </div>
      )}
    </div>
  );
}
