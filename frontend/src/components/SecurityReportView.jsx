// Sicherheitsbericht — In-App-Ansicht (CERNIS PRO 2.0, Etappe 3)
//
// Erste/einzige Kachel des Reporting-Bereichs. Verdichtet den aggregierten
// Sicherheitsbericht (GET /api/report/security) zu einer ruhigen Lesesicht: Score-
// Cockpit oben, vier Befund-Tabellen darunter, ein dezenter Rogue-DHCP-Statushinweis
// und ein Drucken-Knopf. Reine Lesesicht — greift NICHT ins Netz ein, mutiert nichts.
//
// Sie laedt selbst ueber fetchSecurityReport (useEffect mit abgebrochen-Flag, Lade-/
// Fehlerzustand wie LoggingProfileView). Achse B des Produkts: der Bericht BESCHREIBT
// und ORDNET EIN — er urteilt nicht. Quittierte Befunde stehen sichtbar ausserhalb der
// Wertung; der Score wird NICHT im Frontend neu gerechnet (das Backend liefert ihn
// fertig), das Frontend aggregiert nur die Findings je Geraet fuer die Balken-Anzeige.
//
// Stil wie der Bestand: Fehlertoleranz wie LoggingProfileView (ein Ladefehler kippt die
// Ansicht nicht, ruhige Meldung), SVG wie SlaChart/LoggingProfileView (viewBox-Raster,
// non-scaling-stroke, Text ausserhalb des gestreckten SVG), alle Texte ueber i18n, alle
// Farben ueber Tokens (tokens.css) — accent fuer "gut", sev-med fuer "auffaellig",
// cve-crit (das dunklere kritisch-Rot ueber sev-high) fuer "kritisch", sev-low fuer
// "ohne Befund". Nie feste Farben.

import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { fetchSecurityReport, fetchSecurityReportPdf } from "../api/report.js";
import "./SecurityReportView.css";

// Wie viele Geraete der "Auffaelligkeiten je Geraet"-Balken hoechstens zeigt; der Rest
// erscheint als "+ X weitere" Klartext (kein stilles Abschneiden).
const TOP_GERAETE = 6;

// Geometrie des Score-Halbkreises (gestreckter viewBox wie der SVG-Bestand). Der Bogen
// spannt 180° von links (0) nach rechts (100) ueber einen Halbkreis mit festem Radius.
const GAUGE_VB_BREITE = 200;
const GAUGE_VB_HOEHE = 110;
const GAUGE_CX = 100;
const GAUGE_CY = 100;
const GAUGE_R = 90;

// Token je Schweregrad-Achse. "kritisch" nutzt das dunklere CVE-CRIT-Rot ueber sev-high
// (tokens.css ~Z.47), "auffaellig" sev-med (orange), "ohne Befund/informativ" sev-low.
const FARBE_KRITISCH = "var(--cve-crit-bd)";
const FARBE_AUFFAELLIG = "var(--sev-med-bd)";
const FARBE_SAUBER = "var(--sev-low-bd)";

// Score-Stufe -> Bogen-/Zahl-Farbe (level kommt fertig aus dem Backend).
const FARBE_NACH_STUFE = {
  gut: "var(--color-accent)",
  maessig: "var(--sev-med-bd)",
  kritisch: "var(--cve-crit-bd)",
};

// Lastwert/Dezimalzahl -> deutsches Format mit zwei Nachkommastellen und Komma als
// Dezimaltrenner. null/NaN -> "—".
function formatLast(wert) {
  if (wert === null || wert === undefined || Number.isNaN(wert)) {
    return "—";
  }
  return wert.toFixed(2).replace(".", ",");
}

// Unix-Sekunden -> lokal formatiertes Datum/Uhrzeit. null -> null (der Aufrufer
// entscheidet ueber die Variante des Hinweises).
function formatZeitpunkt(tsSekunden, sprache) {
  if (tsSekunden === null || tsSekunden === undefined) {
    return null;
  }
  return new Date(tsSekunden * 1000).toLocaleString(sprache === "en" ? "en-US" : "de-DE");
}

// Punkt auf dem Score-Halbkreis fuer einen Anteil 0..1 (0 = links, 1 = rechts). Der
// Winkel laeuft von 180° (links) nach 0° (rechts).
function bogenPunkt(anteil) {
  const winkel = Math.PI * (1 - Math.max(0, Math.min(1, anteil)));
  return {
    x: GAUGE_CX + GAUGE_R * Math.cos(winkel),
    y: GAUGE_CY - GAUGE_R * Math.sin(winkel),
  };
}

// SVG-Pfad fuer den Halbkreis-Bogen von Anteil 0 bis `anteil` (immer der grosse-Bogen-
// freie Halbkreis-Sweep). Leerer Bogen (anteil 0) -> leerer Pfad.
function bogenPfad(anteil) {
  if (anteil <= 0) {
    return "";
  }
  const start = bogenPunkt(0);
  const ende = bogenPunkt(anteil);
  // sweep-flag 1: im Uhrzeigersinn von links nach rechts ueber den oberen Halbkreis.
  return `M ${start.x.toFixed(2)} ${start.y.toFixed(2)} A ${GAUGE_R} ${GAUGE_R} 0 0 1 ${ende.x.toFixed(2)} ${ende.y.toFixed(2)}`;
}

// Token-Badge fuer eine Severity ("critical"/"notable"). Klein, ausgeschrieben i18n.
function SeverityBadge({ severity, t }) {
  const istKritisch = severity === "critical";
  const klasse = istKritisch
    ? "security-report__badge security-report__badge--kritisch"
    : "security-report__badge security-report__badge--auffaellig";
  const text = istKritisch
    ? t("report.security.stufe.kritisch")
    : t("report.security.stufe.auffaellig");
  return <span className={klasse}>{text}</span>;
}

// Eine Schwere-Kennzahl-Kachel (grosse Zahl + dezentes Label), farblich getoent.
function Kennzahl({ wert, label, variante }) {
  return (
    <div className={`security-report__kennzahl security-report__kennzahl--${variante}`}>
      <span className="security-report__kennzahl-wert">{wert}</span>
      <span className="security-report__kennzahl-label">{label}</span>
    </div>
  );
}

export default function SecurityReportView() {
  const { t, i18n } = useTranslation();

  // Geladener Bericht (null = noch nicht geladen / nicht vorhanden) + Lade-/Fehlerzustand.
  const [bericht, setBericht] = useState(null);
  const [laedt, setLaedt] = useState(false);
  const [fehler, setFehler] = useState(false);
  // Aufklapp-Zustand der Score-Beitragsliste (nur Anzeige, kein Reload).
  const [beitraegeOffen, setBeitraegeOffen] = useState(false);
  // Lokaler Zustand des PDF-Downloads: laedt schaltet den Knopf disabled, pdfFehler
  // zeigt einen eigenen dezenten Hinweis (ueberschreibt NICHT den globalen Lade-Fehler
  // des Berichts).
  const [pdfLaedt, setPdfLaedt] = useState(false);
  const [pdfFehler, setPdfFehler] = useState(false);

  // PDF-Download anstossen. Setzt den lokalen Lade-/Fehler-State; bei erneutem Klick
  // wird ein vorheriger PDF-Fehler zurueckgesetzt. Der globale fehler-State bleibt
  // unberuehrt.
  async function handlePdf() {
    setPdfFehler(false);
    setPdfLaedt(true);
    try {
      await fetchSecurityReportPdf(i18n.language);
    } catch {
      setPdfFehler(true);
    } finally {
      setPdfLaedt(false);
    }
  }

  // Laedt den Bericht einmalig. Fehler -> dezenter Hinweis, kein Absturz (Muster
  // LoggingProfileView). t BEWUSST NICHT in den Deps (neue Referenz je Render -> Loop).
  useEffect(() => {
    let abgebrochen = false;

    (async () => {
      setLaedt(true);
      setFehler(false);
      try {
        const geladen = await fetchSecurityReport();
        if (!abgebrochen) {
          setBericht(geladen);
        }
      } catch {
        if (!abgebrochen) {
          setBericht(null);
          setFehler(true);
        }
      } finally {
        if (!abgebrochen) {
          setLaedt(false);
        }
      }
    })();

    return () => {
      abgebrochen = true;
    };
  }, []);

  const score = bericht?.score ?? null;
  const hatScan = bericht?.hasScan ?? false;

  // Aggregation fuer den Geraete-Balken: je deviceLabel die Anzahl kritischer und
  // auffaelliger Befunde ueber port/cve/net (cve-severity ist nicht "critical"/"notable",
  // darum hier ueber cvssScore eingeordnet: >= 9.0 kritisch, sonst auffaellig — das ist
  // reine ANZEIGE-Aggregation, nicht der Score). Sortiert nach Gesamtzahl absteigend.
  const geraeteBalken = useMemo(() => {
    if (!bericht) {
      return [];
    }
    const proGeraet = new Map(); // label -> { kritisch, auffaellig }
    const zaehle = (label, istKritisch) => {
      const eintrag = proGeraet.get(label) ?? { kritisch: 0, auffaellig: 0 };
      if (istKritisch) {
        eintrag.kritisch += 1;
      } else {
        eintrag.auffaellig += 1;
      }
      proGeraet.set(label, eintrag);
    };
    for (const p of bericht.portFindings) {
      zaehle(p.deviceLabel, p.severity === "critical");
    }
    for (const c of bericht.cveFindings) {
      zaehle(c.deviceLabel, (c.cvssScore ?? 0) >= 9.0);
    }
    for (const n of bericht.netFindings) {
      zaehle(n.deviceLabel, n.severity === "critical");
    }
    return Array.from(proGeraet.entries())
      .map(([label, zahl]) => ({ label, ...zahl, gesamt: zahl.kritisch + zahl.auffaellig }))
      .sort((a, b) => b.gesamt - a.gesamt);
  }, [bericht]);

  // Die drei acknowledged*-Listen zu EINER Tabelle zusammengefuehrt (Quelle | Geraet |
  // Kurzbeschreibung). Die Quelle bleibt ein STABILER Schluessel ("port"/"cve"/"net"),
  // der im Render uebersetzt wird — so folgt die Tabelle einem Sprachwechsel, ohne dass
  // t in den Memo-Deps stehen muss. Leer -> Abschnitt 4 entfaellt ganz.
  const quittierte = useMemo(() => {
    if (!bericht) {
      return [];
    }
    const zeilen = [];
    for (const p of bericht.acknowledgedPortFindings) {
      zeilen.push({
        quelle: "port",
        geraet: p.deviceLabel,
        beschreibung: `${p.ports} · ${p.reason}`,
      });
    }
    for (const c of bericht.acknowledgedCveFindings) {
      zeilen.push({
        quelle: "cve",
        geraet: c.deviceLabel,
        beschreibung: `${c.cveId} · ${c.service}`,
      });
    }
    for (const n of bericht.acknowledgedNetFindings) {
      zeilen.push({
        quelle: "net",
        geraet: n.deviceLabel,
        beschreibung: n.description,
      });
    }
    return zeilen;
  }, [bericht]);

  const sprache = i18n.language === "en" ? "en" : "de";
  const rogueZeitpunkt = bericht ? formatZeitpunkt(bericht.rogueDhcpCheckedTs, sprache) : null;
  // Erstelldatum des Berichts: heute, lokal formatiert. Reine Anzeige im Titelkopf und
  // in der Fusszeile (kein State, kein Effekt) — ein gedrucktes Dokument datiert sich.
  const erstelltDatum = new Date().toLocaleDateString(sprache === "en" ? "en-US" : "de-DE", {
    year: "numeric",
    month: "long",
    day: "numeric",
  });

  return (
    <div className="security-report">
      {/* ── 1. Bericht-Titelkopf: Logo + grosse Ueberschrift + Erstelldatum ──────
          Eigener Dokument-Kopf (NICHT die App-Navi). Der Hilfe-Anker bleibt am Titel. */}
      <header className="security-report__kopf">
        {/* Echtes Repo-Asset aus public/ (wie AppHeader). */}
        <img className="security-report__logo" src="/cernis-logo.png" alt="CERNIS PRO" />
        <div className="security-report__kopf-text">
          <h3 className="security-report__titel" id="help.report.security">
            {t("report.security.titel")}
          </h3>
          <p className="security-report__kopf-datum">
            {t("report.security.kopf.erstellt", { datum: erstelltDatum })}
          </p>
        </div>
        {/* PDF-Aktion rechtsbuendig im Kopf: spart den Weg ans Berichtsende. */}
        {bericht ? (
          <div className="security-report__kopf-aktionen">
            <button
              type="button"
              className="security-report__pdf"
              onClick={handlePdf}
              disabled={pdfLaedt}
            >
              {t("report.security.pdf")}
            </button>
            {pdfFehler ? (
              <p className="security-report__pdf-fehler" role="alert">
                {t("report.security.pdfFehler")}
              </p>
            ) : null}
          </div>
        ) : null}
      </header>

      {fehler && (
        <div className="security-report__fehler" role="note">
          {t("report.security.ladeFehler")}
        </div>
      )}

      {/* ── 2. Ehrlicher "kein Scan"-Zustand: keine Grafiken/Tabellen ───────────── */}
      {bericht && !hatScan ? (
        <div className="security-report__leerzustand" role="note">
          <p className="security-report__leerzustand-text">
            {t("report.security.keinScan")}
          </p>
        </div>
      ) : null}

      {/* ── 3. Zusammenfassung + Details nur bei vorhandenem Scan ──────────────── */}
      {bericht && hatScan && score ? (
        <>
          {/* 3.1 Einleitung: was dieser Bericht ist (Achse-B-Haltung in Klartext). */}
          <p className="security-report__einleitung">{t("report.security.einleitung")}</p>

          {/* 3.2 Score-Gauge MIT Erklaerzeile direkt darunter (Zahl sofort eingeordnet). */}
          <ScoreGauge score={score} t={t} />

          {/* 3.3 Drei Schwere-Kennzahlen als kompakte Zusammenfassung. */}
          <div className="security-report__kennzahlen">
            <Kennzahl
              wert={score.criticalDevices}
              label={t("report.security.kennzahl.kritisch")}
              variante="kritisch"
            />
            <Kennzahl
              wert={score.notableDevices}
              label={t("report.security.kennzahl.auffaellig")}
              variante="auffaellig"
            />
            <Kennzahl
              wert={score.cleanDevices}
              label={t("report.security.kennzahl.ohneBefund")}
              variante="sauber"
            />
          </div>

          {/* 3.4 ERST DANACH die Score-Beitragsliste mit eigener Ueberschrift. Am
              Bildschirm aufklappbar (Toggle); im Druck immer offen (CSS forciert). */}
          <ScoreBeitraege
            score={score}
            beitraegeOffen={beitraegeOffen}
            onToggle={() => setBeitraegeOffen((v) => !v)}
            t={t}
          />

          {/* 3.5 Schwere-Donut (ohne Legende — Zahlen stehen oben) + Geraete-Balken. */}
          <SchwereDonut
            kritisch={score.criticalDevices}
            auffaellig={score.notableDevices}
            sauber={score.cleanDevices}
            deviceCount={score.deviceCount}
            t={t}
          />
          <GeraeteBalken geraete={geraeteBalken} t={t} />

          {/* ── 4. Vier Tabellen ────────────────────────────────────────────── */}
          <PortTabelle findings={bericht.portFindings} t={t} />
          <CveTabelle findings={bericht.cveFindings} t={t} />
          <NetTabelle findings={bericht.netFindings} t={t} />
          {quittierte.length > 0 ? <QuittiertTabelle zeilen={quittierte} t={t} /> : null}

          {/* Rogue-DHCP-Statushinweis (dezent, kein Fehler). */}
          <p className="security-report__rogue" role="note">
            {rogueZeitpunkt === null
              ? t("report.security.rogue.ungeprueft")
              : t("report.security.rogue.geprueft", { datum: rogueZeitpunkt })}
          </p>

          {/* Achse-B-Fussnote: der Bericht beschreibt und ordnet ein — kein Urteil. */}
          <p className="security-report__fussnote">{t("report.security.fussnote")}</p>

          {/* Bericht-Fusszeile (UNSER Inhalt, nicht der Browser-Druckfuss): Wortmarke
              + Erstelldatum am Dokument-Ende. */}
          <footer className="security-report__fusszeile">
            {t("report.security.fusszeile", { datum: erstelltDatum })}
          </footer>
        </>
      ) : null}

      {/* Rogue-Hinweis auch ohne Scan zeigen (Status bleibt ehrlich sichtbar). */}
      {bericht && !hatScan ? (
        <p className="security-report__rogue" role="note">
          {rogueZeitpunkt === null
            ? t("report.security.rogue.ungeprueft")
            : t("report.security.rogue.geprueft", { datum: rogueZeitpunkt })}
        </p>
      ) : null}

      {laedt && <div className="security-report__laedt" aria-hidden="true" />}
    </div>
  );
}

// ── 3.2 Score-Gauge ───────────────────────────────────────────────────────────
// Halbkreis 0..100, Token-Farbe nach level. Grosse Zahl + "von 100" + Stufe, darunter
// eine ERKLAeRZEILE mit echten Zahlen, die den Score sofort einordnet (Score von 100,
// Stufe, Anzahl bewertet/kritisch/auffaellig/ohne Befund). Reine Anzeige (kein Reload).
function ScoreGauge({ score, t }) {
  const anteil = Math.max(0, Math.min(1, (score.score ?? 0) / 100));
  const farbe = FARBE_NACH_STUFE[score.level] ?? "var(--color-accent)";
  const ende = bogenPunkt(anteil);
  const start = bogenPunkt(0);
  const bahnEnde = bogenPunkt(1);

  return (
    <div className="security-report__gauge">
      <div className="security-report__gauge-visual">
        <svg
          className="security-report__gauge-svg"
          viewBox={`0 0 ${GAUGE_VB_BREITE} ${GAUGE_VB_HOEHE}`}
          role="img"
          aria-label={t("report.security.score.aria", { score: score.score })}
        >
          {/* Bahn (voller Halbkreis, dezent) + farbiger Fuell-Bogen bis zum Score. */}
          <path
            d={`M ${start.x.toFixed(2)} ${start.y.toFixed(2)} A ${GAUGE_R} ${GAUGE_R} 0 0 1 ${bahnEnde.x.toFixed(2)} ${bahnEnde.y.toFixed(2)}`}
            fill="none"
            stroke="var(--color-border)"
            strokeWidth="12"
            strokeLinecap="round"
            vectorEffect="non-scaling-stroke"
          />
          {anteil > 0 ? (
            <path
              d={bogenPfad(anteil)}
              fill="none"
              stroke={farbe}
              strokeWidth="12"
              strokeLinecap="round"
              vectorEffect="non-scaling-stroke"
            />
          ) : null}
          {/* Endmarke des Fuell-Bogens (kleiner Punkt). */}
          <circle cx={ende.x.toFixed(2)} cy={ende.y.toFixed(2)} r="4" fill={farbe} />
        </svg>
        <div className="security-report__gauge-zahl">
          <span className="security-report__gauge-wert" style={{ color: farbe }}>
            {score.score}
          </span>
          <span className="security-report__gauge-von">{t("report.security.score.von")}</span>
          <span className="security-report__gauge-stufe" style={{ color: farbe }}>
            {t(`report.security.stufe.${score.level}`)}
          </span>
        </div>
      </div>

      {/* Erklaerzeile: ordnet die Zahl SOFORT mit echten Werten ein. */}
      <p className="security-report__gauge-einordnung">
        {t("report.security.score.einordnung", {
          score: score.score,
          level: t(`report.security.stufe.${score.level}`),
          deviceCount: score.deviceCount,
          criticalDevices: score.criticalDevices,
          notableDevices: score.notableDevices,
          cleanDevices: score.cleanDevices,
        })}
      </p>
    </div>
  );
}

// ── 3.4 Score-Beitragsliste ("Wie der Score zustande kommt") ──────────────────
// Eigener Abschnitt MIT Ueberschrift, damit der Zusammenhang zur Score-Zahl klar ist.
// Am Bildschirm aufklappbar (aria-expanded, Toggle aendert nur die Anzeige); im Druck
// IMMER offen (CSS forciert .security-report__beitraege auf display:flex). Aufgeklappt:
// die Beitragsliste als kleine Tabelle plus Formel-Zeile und die saubere-Geraete-Zahl.
function ScoreBeitraege({ score, beitraegeOffen, onToggle, t }) {
  return (
    <section className="security-report__beitraege-abschnitt">
      <div className="security-report__beitraege-kopf">
        <h4 className="security-report__abschnitt-titel">
          {t("report.security.score.beitraegeTitel")}
        </h4>
        <button
          type="button"
          className="security-report__gauge-toggle"
          aria-expanded={beitraegeOffen}
          onClick={onToggle}
        >
          {beitraegeOffen
            ? t("report.security.score.beitraegeZu")
            : t("report.security.score.beitraegeAuf")}
        </button>
      </div>

      {/* Aufgeklappt: im Druck IMMER sichtbar (CSS forciert das). */}
      <div
        className={
          beitraegeOffen
            ? "security-report__beitraege security-report__beitraege--offen"
            : "security-report__beitraege"
        }
      >
        {score.contributions.length > 0 ? (
          <table className="security-report__tabelle security-report__tabelle--beitraege">
            <thead>
              <tr>
                <th>{t("report.security.beitraege.geraet")}</th>
                <th>{t("report.security.beitraege.befund")}</th>
                <th className="security-report__num">{t("report.security.beitraege.last")}</th>
              </tr>
            </thead>
            <tbody>
              {score.contributions.map((c, i) => (
                <tr key={`beitrag-${i}`}>
                  <td>{c.deviceLabel}</td>
                  <td>
                    <SeverityBadge severity={c.worstSeverity} t={t} />
                  </td>
                  <td className="security-report__num security-report__mono">
                    {formatLast(c.burdenValue)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="security-report__leer">{t("report.security.beitraege.leer")}</p>
        )}

        <p className="security-report__formel">
          {t("report.security.score.formel", {
            last: formatLast(score.totalBurden),
            geraete: score.deviceCount,
          })}
        </p>
        <p className="security-report__rest">
          {t("report.security.score.sauber", { anzahl: score.cleanDevices })}
        </p>
      </div>
    </section>
  );
}

// ── 3c. Schwere-Donut ─────────────────────────────────────────────────────────
// Anteile kritisch/auffaellig/sauber als Kreissegmente (Token-Farben). Mitte: Summe
// = deviceCount + Label "Geraete". OHNE Legende (die Zahlen stehen in den Kacheln).
function SchwereDonut({ kritisch, auffaellig, sauber, deviceCount, t }) {
  const summe = kritisch + auffaellig + sauber;
  const segmente = [
    { wert: kritisch, farbe: FARBE_KRITISCH },
    { wert: auffaellig, farbe: FARBE_AUFFAELLIG },
    { wert: sauber, farbe: FARBE_SAUBER },
  ];

  // Geometrie: Vollkreis-Donut, Umfang = 2πr. Jedes Segment ein dash-Abschnitt.
  const radius = 42;
  const umfang = 2 * Math.PI * radius;
  let offset = 0;

  return (
    <div className="security-report__donut">
      <svg
        className="security-report__donut-svg"
        viewBox="0 0 120 120"
        role="img"
        aria-label={t("report.security.donut.aria", { anzahl: deviceCount })}
      >
        {/* Grund-Ring (falls Summe 0: nur die Bahn). */}
        <circle
          cx="60"
          cy="60"
          r={radius}
          fill="none"
          stroke="var(--color-border)"
          strokeWidth="14"
        />
        {summe > 0
          ? segmente.map((seg, i) => {
              if (seg.wert <= 0) {
                return null;
              }
              const laenge = (seg.wert / summe) * umfang;
              const dash = `${laenge.toFixed(2)} ${(umfang - laenge).toFixed(2)}`;
              const aktuellerOffset = offset;
              offset += laenge;
              return (
                <circle
                  key={`seg-${i}`}
                  cx="60"
                  cy="60"
                  r={radius}
                  fill="none"
                  stroke={seg.farbe}
                  strokeWidth="14"
                  strokeDasharray={dash}
                  strokeDashoffset={(-aktuellerOffset).toFixed(2)}
                  // Start oben (12 Uhr) statt rechts (3 Uhr).
                  transform="rotate(-90 60 60)"
                />
              );
            })
          : null}
      </svg>
      <div className="security-report__donut-mitte">
        <span className="security-report__donut-summe">{deviceCount}</span>
        <span className="security-report__donut-label">{t("report.security.donut.geraete")}</span>
      </div>
    </div>
  );
}

// ── 3.5 Geraete-Balken "Auffaelligkeiten je Geraet" ───────────────────────────
// Je Geraet mit Befund ein gestapelter Mini-Balken (kritisch + auffaellig). Es werden
// IMMER ALLE Geraete gerendert; am Bildschirm blendet CSS die ueber Top-6 hinausgehenden
// Zeilen aus (Klasse --ueberzaehlig) und zeigt die "+ X weitere"-Zeile. Im Druck dreht
// das @media print das um: ALLE Zeilen sichtbar, "+ X weitere" weg -> vollstaendige
// Liste aufs Papier (kein Aufklappen im PDF moeglich). Keine slice-Doppellogik: die
// Balkenbreite bezieht sich auf das Maximum ueber ALLE Geraete (auch im Druck stimmig).
function GeraeteBalken({ geraete, t }) {
  if (geraete.length === 0) {
    return null;
  }
  const rest = geraete.length - TOP_GERAETE;
  const maxGesamt = geraete.reduce((acc, g) => Math.max(acc, g.gesamt), 0) || 1;

  return (
    <div className="security-report__balken">
      <div className="security-report__abschnitt-titel">
        {t("report.security.balken.titel")}
      </div>
      <div className="security-report__balken-liste">
        {geraete.map((g, i) => (
          <div
            key={`bal-${i}`}
            className={
              i >= TOP_GERAETE
                ? "security-report__balken-zeile security-report__balken-zeile--ueberzaehlig"
                : "security-report__balken-zeile"
            }
          >
            <span className="security-report__balken-label" title={g.label}>
              {g.label}
            </span>
            <div className="security-report__balken-bahn">
              {g.kritisch > 0 ? (
                <div
                  className="security-report__balken-fueller security-report__balken-fueller--kritisch"
                  style={{ width: `${((g.kritisch / maxGesamt) * 100).toFixed(1)}%` }}
                />
              ) : null}
              {g.auffaellig > 0 ? (
                <div
                  className="security-report__balken-fueller security-report__balken-fueller--auffaellig"
                  style={{ width: `${((g.auffaellig / maxGesamt) * 100).toFixed(1)}%` }}
                />
              ) : null}
            </div>
            <span className="security-report__balken-zahl security-report__mono">{g.gesamt}</span>
          </div>
        ))}
      </div>
      {rest > 0 ? (
        <p className="security-report__balken-rest">
          {t("report.security.balken.weitere", { anzahl: rest })}
        </p>
      ) : null}
    </div>
  );
}

// ── 4.1 Port-Tabelle ──────────────────────────────────────────────────────────
function PortTabelle({ findings, t }) {
  return (
    <Abschnitt nummer="1" titel={t("report.security.tabelle.ports")}>
      {findings.length > 0 ? (
        <table className="security-report__tabelle">
          <thead>
            <tr>
              <th>{t("report.security.spalte.geraet")}</th>
              <th>{t("report.security.spalte.ports")}</th>
              <th>{t("report.security.spalte.schwere")}</th>
              <th>{t("report.security.spalte.grund")}</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((p, i) => (
              <tr key={`port-${i}`}>
                <td>{p.deviceLabel}</td>
                <td className="security-report__mono">{p.ports}</td>
                <td>
                  <SeverityBadge severity={p.severity} t={t} />
                </td>
                {/* Fix 5: Der rohe Backend-reason ("...Achse-B-Regel") ist internes
                    Entwickler-Vokabular und gehoert nicht in einen Bericht fuer Menschen.
                    Da alle Port-Findings aktuell dieselbe uniforme, generische reason
                    tragen, zeigen wir statt des Roh-Strings einen verstaendlichen i18n-
                    Text (kein fragiles String-Matching). Truege reason je Fund einen
                    spezifischen Grund, muesste man hier differenzieren — derzeit nicht. */}
                <td>{t("report.security.portGrund")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p className="security-report__leer">{t("report.security.tabelle.leer")}</p>
      )}
    </Abschnitt>
  );
}

// CVE-Badge-Ton nach cvssScore: >= 9.0 dunkles kritisch-Rot, sonst auffaellig-Orange
// (reine ANZEIGE-Einordnung des cvssScore, kein Score-Eingriff).
function cveBadgeKlasse(cvssScore) {
  return (cvssScore ?? 0) >= 9.0
    ? "security-report__badge security-report__badge--kritisch"
    : "security-report__badge security-report__badge--auffaellig";
}

// Gruppiert CVE-Befunde nach Geraet. Pro Geraet die CVEs nach cvssScore absteigend;
// die Geraete-Reihenfolge nach hoechstem cvssScore des Geraets absteigend (schwerstes
// Geraet zuerst), bei Gleichstand nach deviceLabel. Reine ANZEIGE-Sortierung.
function gruppiereCvesNachGeraet(findings) {
  const proGeraet = new Map(); // deviceLabel -> CVE-Liste
  for (const c of findings) {
    const liste = proGeraet.get(c.deviceLabel) ?? [];
    liste.push(c);
    proGeraet.set(c.deviceLabel, liste);
  }
  return Array.from(proGeraet.entries())
    .map(([deviceLabel, cves]) => {
      const sortiert = [...cves].sort((a, b) => (b.cvssScore ?? 0) - (a.cvssScore ?? 0));
      const maxScore = sortiert.reduce((acc, c) => Math.max(acc, c.cvssScore ?? 0), 0);
      return { deviceLabel, cves: sortiert, maxScore };
    })
    .sort((a, b) => b.maxScore - a.maxScore || a.deviceLabel.localeCompare(b.deviceLabel));
}

// ── 4.2 CVE-Befunde (nach Geraet gruppiert) ───────────────────────────────────
// Pro Geraet ein Block: Geraete-Ueberschrift + kleine Tabelle (CVE-ID | CVSS-Badge |
// Dienst | Beschreibung). Beschreibung darf umbrechen. Token-Farben, alles i18n.
function CveTabelle({ findings, t }) {
  const gruppen = useMemo(() => gruppiereCvesNachGeraet(findings), [findings]);

  return (
    <Abschnitt nummer="2" titel={t("report.security.tabelle.cve")}>
      {gruppen.length > 0 ? (
        <div className="security-report__cve-gruppen">
          {gruppen.map((gruppe, gi) => (
            <div key={`cve-grp-${gi}`} className="security-report__cve-gruppe">
              <p className="security-report__cve-geraet">{gruppe.deviceLabel}</p>
              <table className="security-report__tabelle">
                <thead>
                  <tr>
                    <th>{t("report.security.spalte.cve")}</th>
                    <th className="security-report__num">{t("report.security.spalte.cvss")}</th>
                    <th>{t("report.security.spalte.dienst")}</th>
                    <th>{t("report.security.spalte.beschreibung")}</th>
                  </tr>
                </thead>
                <tbody>
                  {gruppe.cves.map((c, i) => (
                    <tr key={`cve-${gi}-${i}`}>
                      <td className="security-report__mono">{c.cveId}</td>
                      <td className="security-report__num">
                        <span className={cveBadgeKlasse(c.cvssScore)}>
                          {formatLast(c.cvssScore)}
                        </span>
                      </td>
                      <td>{c.service}</td>
                      <td className="security-report__cve-beschreibung">{c.description}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ))}
        </div>
      ) : (
        <p className="security-report__leer">{t("report.security.tabelle.leer")}</p>
      )}
    </Abschnitt>
  );
}

// ── 4.3 Netz-Tabelle ──────────────────────────────────────────────────────────
function NetTabelle({ findings, t }) {
  return (
    <Abschnitt nummer="3" titel={t("report.security.tabelle.net")}>
      {findings.length > 0 ? (
        <table className="security-report__tabelle">
          <thead>
            <tr>
              <th>{t("report.security.spalte.art")}</th>
              <th>{t("report.security.spalte.geraet")}</th>
              <th>{t("report.security.spalte.beschreibung")}</th>
              <th>{t("report.security.spalte.schwere")}</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((n, i) => (
              <tr key={`net-${i}`}>
                <td>{n.kind}</td>
                <td>{n.deviceLabel}</td>
                <td>{n.description}</td>
                <td>
                  <SeverityBadge severity={n.severity} t={t} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p className="security-report__leer">{t("report.security.tabelle.leer")}</p>
      )}
    </Abschnitt>
  );
}

// ── 4.4 Quittiert-Tabelle (zusammengefuehrt, ausserhalb der Wertung) ──────────
function QuittiertTabelle({ zeilen, t }) {
  return (
    <Abschnitt nummer="4" titel={t("report.security.tabelle.quittiert")}>
      <p className="security-report__quittiert-hinweis">
        {t("report.security.quittiertHinweis")}
      </p>
      <table className="security-report__tabelle">
        <thead>
          <tr>
            <th>{t("report.security.spalte.quelle")}</th>
            <th>{t("report.security.spalte.geraet")}</th>
            <th>{t("report.security.spalte.beschreibung")}</th>
          </tr>
        </thead>
        <tbody>
          {zeilen.map((z, i) => (
            <tr key={`ack-${i}`}>
              <td>{t(`report.security.quelle.${z.quelle}`)}</td>
              <td>{z.geraet}</td>
              <td>{z.beschreibung}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Abschnitt>
  );
}

// Ein nummerierter Tabellen-Abschnitt (Titel mit Akzent-Unterstrich). page-break-
// inside: avoid je Abschnitt liegt im CSS.
function Abschnitt({ nummer, titel, children }) {
  return (
    <section className="security-report__abschnitt">
      <h4 className="security-report__abschnitt-titel security-report__abschnitt-titel--num">
        <span className="security-report__abschnitt-nummer">{nummer}</span>
        {titel}
      </h4>
      {children}
    </section>
  );
}
