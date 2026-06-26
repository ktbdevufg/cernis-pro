// Außenkontakte (CERNIS PRO 2.0)
// Lese-Ansicht der Außenkontakte DIESES Rechners: mit wem dieser Host nach außen
// spricht, gebündelt nach Betreiber / Land / Programm. Reines Frontend gegen den
// fertigen Endpunkt GET /api/outbound/contacts (api/outbound.js).
//
// Oben integriert: die Aufzeichnungs-Leiste (OutboundRecordingPanel) — eine
// schlanke, immer sichtbare Leiste mit aufklappbarer Verwaltung (Anlegen +
// Aufzeichnungs-Liste). KEINE eigene Beobachten-Kachel mehr.
//
// Designsprache wie die übrigen Beobachten-Komponenten (ObserveView/TrafficView):
// dezent, flach, ruhig. Außenkontakte URTEILEN NICHT — KEINE Severity-Farben.

import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { fetchOutboundContacts } from "../api/outbound.js";
import { matchContacts } from "../api/blocklist.js";
import OutboundRecordingPanel from "./OutboundRecordingPanel.jsx";
import "./OutboundView.css";

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

  // Zweiter Effekt: nach geladenen Kontakten die Blocklist abgleichen. Abhängig von
  // [kontakte] (NICHT t — react-i18next-Regel). matchContacts OHNE strictness, damit
  // das Backend die in der Verwaltung gesetzte Strenge + Gruppen-Schalter nutzt
  // (Anzeige bleibt konsistent zur Nutzer-Einstellung). Fehler werden STILL
  // behandelt: nur console.error, keine Badges, kein Hinweis, kein Absturz.
  useEffect(() => {
    if (kontakte.length === 0) {
      setMatchResults([]);
      return undefined;
    }
    let abgebrochen = false;
    (async () => {
      try {
        const { results } = await matchContacts(kontakte);
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
  }, [kontakte]);

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

  const achse = ACHSEN.find((a) => a.id === achseId) ?? ACHSEN[0];

  // Sichtbare Kontakte: per Default lokale/Infrastruktur-IPs ausblenden; mit
  // aktivem Schalter alle zeigen.
  const sichtbar = useMemo(
    () =>
      zeigeLokale
        ? kontakte
        : kontakte.filter((k) => !istLokaleIp(k.remoteIp)),
    [kontakte, zeigeLokale],
  );

  const gruppen = useMemo(
    () => gruppiere(sichtbar, achse, t),
    // t bewusst NICHT in dep-Array (react-i18next-Regel); die Labels werden bei
    // Sprachwechsel ohnehin über den nächsten Render neu erzeugt.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [sichtbar, achse],
  );

  return (
    <div className="outbound">
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

      {/* Rote-Linie-Hinweis (einmalig, NICHT pro Zeile): nur wenn überhaupt
          Listen-Treffer sichtbar sind. Macht die Quelle der Einordnung explizit —
          sie stammt aus den Verwaltungs-Listen, nicht von einem CERNIS-Urteil. */}
      {hatTreffer && (
        <div className="outbound__listen-hinweis" role="note">
          {t("beobachten.outbound.match.disclaimer")}
        </div>
      )}

      {/* Aufzeichnungs-Leiste (integriert): immer sichtbar, mit aufklappbarer
          Verwaltung. Sitzt über der Steuerleiste der Live-Liste. */}
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
