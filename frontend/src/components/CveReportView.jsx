// CVE-Bericht — In-App-Ansicht (CERNIS PRO 2.0, Etappe 3)
//
// Dritte Kachel des Reporting-Bereichs. Verdichtet den aggregierten CVE-Bericht
// (GET /api/report/cve) zu einer ruhigen Lesesicht: Kennzahlen oben, ein Severity-
// Donut, eine umschaltbare Muster-Sektion (Gerät <-> Dienst) als Tabelle, darunter
// die vollständige, filter-/sortierbare und nach Host gruppierte Befundliste und ein
// Drucken-Knopf. Reine Lesesicht — greift NICHT ins Netz ein, mutiert nichts.
//
// Sie lädt selbst über fetchCveReport (useEffect mit abgebrochen-Flag, Lade-/
// Fehlerzustand wie InventoryReportView). Achse B des Produkts: der Bericht
// BESCHREIBT und ORDNET EIN — er urteilt nicht. Filter/Sortierung/Umschalter sind
// reine Anzeige-Steuerung im Frontend (kein Reload). KEIN 404-Fall: leerer Stand ist
// ein DATUM (alle Zähler 0 + leere Listen), kein Fehler -> ruhiger Leerzustand.
//
// Severity-Optik exakt wie die Live-Ansicht CveView: eigene cve-report__sev-Klassen,
// aber dieselben Token-Variablen (--cve-crit-*, --sev-high/med/low-*, UNKNOWN über
// --color-bar/--color-text-tert/--color-border). Roh-Stufe (CRITICAL…) bleibt der
// data-sev-Schlüssel, der ANGEZEIGTE Text ist lokalisiert. Nie feste Farben. t
// NIEMALS in useEffect/useMemo-Deps (instabile Referenz -> Loop).

import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { fetchCveReport, fetchCveReportPdf } from "../api/report.js";
import "./CveReportView.css";

// Severity-Reihenfolge (Donut-Segmente + Anzeige) und Rang (Sortierung/Donut). Roh-
// Stufen bleiben der Schlüssel; der Text wird lokalisiert. UNKNOWN ist der niedrigste
// Rang und die letzte Stufe.
const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
const SEVERITY_RANG = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };

// Wie viele Geräte-/Dienst-Zeilen am Bildschirm höchstens sichtbar sind; der Rest
// erscheint als "+ X weitere"-Klartext (kein stilles Abschneiden). Im Druck (CSS
// @media print) werden IMMER alle gezeigt. Die Befundliste (Sektion 4) ist die
// Detailebene und hat KEIN Top-N.
const TOP_GERAETE = 12;
const TOP_DIENSTE = 12;

// Normalisiert eine rohe Severity-Stufe auf einen gültigen SEVERITY_RANG-Schlüssel.
// Unbekannte/leere Werte fallen sicher auf "UNKNOWN".
function severityKey(s) {
  const upper = (s ?? "").toUpperCase();
  return upper in SEVERITY_RANG ? upper : "UNKNOWN";
}

// Liefert die CSS-Variable für die Donut-Segmentfarbe je Severity-Stufe (dieselben
// Border-Töne wie die Live-Badges). KEINE festen Farben.
function sevColorVar(key) {
  if (key === "CRITICAL") {
    return "var(--cve-crit-bd)";
  }
  if (key === "HIGH") {
    return "var(--sev-high-bd)";
  }
  if (key === "MEDIUM") {
    return "var(--sev-med-bd)";
  }
  if (key === "LOW") {
    return "var(--sev-low-bd)";
  }
  return "var(--color-border)";
}

// Formatiert einen rohen NVD-Veröffentlichungs-String (ISO) zu einem kompakten
// lokalen Datum (TT.MM.JJJJ bzw. MM/TT/JJJJ). Leer -> "—"; Invalid Date -> roh.
function fmtPublished(iso, sprache) {
  if (!iso) {
    return "—";
  }
  const datum = new Date(iso.slice(0, 10));
  if (Number.isNaN(datum.getTime())) {
    return iso;
  }
  return datum.toLocaleDateString(sprache === "en" ? "en-US" : "de-DE", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
  });
}

// Severity-Badge (Optik wie CveView). Roh-Stufe als data-sev (Klassen-Schlüssel),
// angezeigter Text lokalisiert. Die Farbe macht CSS über [data-sev=...].
function SeverityBadge({ severity, t }) {
  const key = severityKey(severity);
  return (
    <span className="cve-report__sev" data-sev={key}>
      {t(`report.cve.severity.${key}`)}
    </span>
  );
}

// Status-Zelle je Befund-Zeile (Variante C). Quittiert -> dezenter Quittiert-Text.
// Sonst Aktiv; neu zusätzlich ein türkises NEU-Badge (--cve-new-*).
function StatusZelle({ acknowledged, isNew, t }) {
  if (acknowledged) {
    return (
      <span className="cve-report__status cve-report__status--quittiert">
        {t("report.cve.status.quittiert")}
      </span>
    );
  }
  return (
    <>
      <span className="cve-report__status cve-report__status--aktiv">
        {t("report.cve.status.aktiv")}
      </span>
      {isNew ? <span className="cve-report__neu">{t("report.cve.status.neu")}</span> : null}
    </>
  );
}

// Eine Kennzahl-Kachel (grosse Zahl + dezentes Label).
function Kennzahl({ wert, label }) {
  return (
    <div className="cve-report__kennzahl">
      <span className="cve-report__kennzahl-wert">{wert}</span>
      <span className="cve-report__kennzahl-label">{label}</span>
    </div>
  );
}

// Eine Text-Kennzahl (Inhalt = beliebiger Knoten, z. B. SeverityBadge oder Text).
function TextKennzahl({ inhalt, label }) {
  return (
    <div className="cve-report__kennzahl cve-report__kennzahl--text">
      <span className="cve-report__kennzahl-text">{inhalt}</span>
      <span className="cve-report__kennzahl-label">{label}</span>
    </div>
  );
}

// Severity-Donut mit Legende. segmente = [{ key, wert, farbe, label }]. Mitte = mitte
// (Zahl) + mitteLabel. Geometrie wie SchwereDonut/InventoryReportView (Vollkreis-
// Donut, Umfang = 2πr, jedes Segment ein dash-Abschnitt; Start oben). Leere Summe ->
// nur die Bahn. Legende nur Stufen mit wert > 0.
function Donut({ segmente, mitte, mitteLabel, ariaLabel }) {
  const summe = segmente.reduce((acc, s) => acc + Math.max(0, s.wert), 0);
  const radius = 42;
  const umfang = 2 * Math.PI * radius;
  let offset = 0;

  return (
    <div className="cve-report__donut-block">
      <div className="cve-report__donut">
        <svg
          className="cve-report__donut-svg"
          viewBox="0 0 120 120"
          role="img"
          aria-label={ariaLabel}
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
        <div className="cve-report__donut-mitte">
          <span className="cve-report__donut-summe">{mitte}</span>
          <span className="cve-report__donut-label">{mitteLabel}</span>
        </div>
      </div>
      <ul className="cve-report__legende">
        {segmente
          .filter((seg) => seg.wert > 0)
          .map((seg) => (
            <li key={`leg-${seg.key}`} className="cve-report__legende-zeile">
              <span
                className="cve-report__legende-punkt"
                style={{ background: seg.farbe }}
                aria-hidden="true"
              />
              <span className="cve-report__legende-label">{seg.label}</span>
              <span className="cve-report__legende-zahl cve-report__mono">{seg.wert}</span>
            </li>
          ))}
      </ul>
    </div>
  );
}

export default function CveReportView() {
  const { t, i18n } = useTranslation();

  // Geladener Bericht (null = noch nicht geladen / nicht vorhanden) + Lade-/Fehlerzustand.
  const [bericht, setBericht] = useState(null);
  const [laedt, setLaedt] = useState(false);
  const [fehler, setFehler] = useState(false);
  // Anzeige-Steuerung (reines Frontend, kein Reload).
  const [musterModus, setMusterModus] = useState("geraet"); // "geraet"|"dienst"
  const [filter, setFilter] = useState("alle"); // alle|aktiv|quittiert|neu
  const [sortierung, setSortierung] = useState("severity"); // severity|host|cvss
  // Lokaler Zustand des PDF-Downloads (überschreibt NICHT den globalen Lade-Fehler).
  const [pdfLaedt, setPdfLaedt] = useState(false);
  const [pdfFehler, setPdfFehler] = useState(false);

  // PDF-Download anstossen. Setzt den lokalen Lade-/Fehler-State; der globale
  // fehler-State bleibt unberührt (Muster InventoryReportView.handlePdf).
  async function handlePdf() {
    setPdfFehler(false);
    setPdfLaedt(true);
    try {
      await fetchCveReportPdf(i18n.language);
    } catch {
      setPdfFehler(true);
    } finally {
      setPdfLaedt(false);
    }
  }

  // Lädt den Bericht einmalig. Fehler -> dezenter Hinweis, kein Absturz (Muster
  // InventoryReportView). t BEWUSST NICHT in den Deps (neue Referenz je Render -> Loop).
  useEffect(() => {
    let abgebrochen = false;

    (async () => {
      setLaedt(true);
      setFehler(false);
      try {
        const geladen = await fetchCveReport();
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

  // Nach Host gruppierte, gefilterte + sortierte Befundliste (Sektion 4). Gruppen-
  // Schlüssel = mac. Pro Gruppe: deviceLabel (erste Zeile), ip (erste nicht-leere ip
  // falls Feld existiert, sonst ""), die Zeilen. Stabile Memo-Deps (kein t).
  const hostGruppen = useMemo(() => {
    if (!bericht) {
      return [];
    }

    // 1) Filter (Variante C): aktiv = !acknowledged, quittiert = acknowledged,
    //    neu = !acknowledged && isNew, alle = alles.
    let zeilen;
    if (filter === "aktiv") {
      zeilen = bericht.allRows.filter((r) => !r.acknowledged);
    } else if (filter === "quittiert") {
      zeilen = bericht.allRows.filter((r) => r.acknowledged);
    } else if (filter === "neu") {
      zeilen = bericht.allRows.filter((r) => !r.acknowledged && r.isNew);
    } else {
      zeilen = bericht.allRows;
    }

    // 2) Gruppieren nach mac (stabile Einfüge-Reihenfolge).
    const proMac = new Map();
    for (const r of zeilen) {
      let gruppe = proMac.get(r.mac);
      if (!gruppe) {
        gruppe = { mac: r.mac, deviceLabel: r.deviceLabel, ip: r.ip ?? "", zeilen: [] };
        proMac.set(r.mac, gruppe);
      }
      // Erste nicht-leere IP übernehmen (Feld fehlt aktuell in der Wire-Form -> "").
      if (!gruppe.ip && r.ip) {
        gruppe.ip = r.ip;
      }
      gruppe.zeilen.push(r);
    }

    const gruppen = [...proMac.values()];

    // 3) Innerhalb jeder Gruppe IMMER nach (Severity-Rang desc, cvss desc, port asc,
    //    cveId) sortieren. Kennzahlen je Gruppe für die Host-Sortierung ableiten.
    for (const g of gruppen) {
      g.zeilen.sort(
        (a, b) =>
          SEVERITY_RANG[severityKey(b.severity)] - SEVERITY_RANG[severityKey(a.severity)] ||
          (b.cvssScore ?? 0) - (a.cvssScore ?? 0) ||
          (a.port ?? 0) - (b.port ?? 0) ||
          (a.cveId ?? "").localeCompare(b.cveId ?? ""),
      );
      g.maxRang = g.zeilen.reduce(
        (acc, r) => Math.max(acc, SEVERITY_RANG[severityKey(r.severity)]),
        0,
      );
      g.maxCvss = g.zeilen.reduce((acc, r) => Math.max(acc, r.cvssScore ?? 0), 0);
      g.hoechsteSeverity = g.zeilen.length > 0 ? severityKey(g.zeilen[0].severity) : "UNKNOWN";
    }

    // 4) Host-Reihenfolge je Sortierung.
    if (sortierung === "host") {
      gruppen.sort((a, b) => (a.deviceLabel ?? "").localeCompare(b.deviceLabel ?? ""));
    } else if (sortierung === "cvss") {
      gruppen.sort((a, b) => b.maxCvss - a.maxCvss);
    } else {
      // "severity" (Default): höchster Rang desc, dann cvss desc, dann Anzahl desc,
      // dann deviceLabel.
      gruppen.sort(
        (a, b) =>
          b.maxRang - a.maxRang ||
          b.maxCvss - a.maxCvss ||
          b.zeilen.length - a.zeilen.length ||
          (a.deviceLabel ?? "").localeCompare(b.deviceLabel ?? ""),
      );
    }

    return gruppen;
  }, [bericht, filter, sortierung]);

  const sprache = i18n.language === "en" ? "en" : "de";
  // Erstelldatum des Berichts: heute, lokal formatiert. Reine Anzeige im Titelkopf und
  // in der Fusszeile (Muster InventoryReportView.erstelltDatum).
  const erstelltDatum = new Date().toLocaleDateString(sprache === "en" ? "en-US" : "de-DE", {
    year: "numeric",
    month: "long",
    day: "numeric",
  });

  // Ehrlicher Leerzustand: Bericht geladen, aber gar keine Befunde erfasst.
  const istLeer =
    bericht && bericht.generatedFindingsTotal === 0 && bericht.allRows.length === 0;

  // Donut-Segmente in fester SEVERITY_ORDER aus den (immer 5) severityCounts.
  const severityProStufe = new Map(
    (bericht?.severityCounts ?? []).map((c) => [severityKey(c.severity), c.count]),
  );
  const donutSegmente = SEVERITY_ORDER.map((key) => ({
    key,
    wert: severityProStufe.get(key) ?? 0,
    farbe: sevColorVar(key),
    label: `${t(`report.cve.severity.${key}`)} ${severityProStufe.get(key) ?? 0}`,
  }));
  const donutSumme = donutSegmente.reduce((acc, s) => acc + s.wert, 0);

  return (
    <div className="cve-report">
      {/* ── 1. Bericht-Titelkopf: Logo + grosse Ueberschrift + Erstelldatum ──────
          Eigener Dokument-Kopf (NICHT die App-Navi). Der Hilfe-Anker bleibt am Titel. */}
      <header className="cve-report__kopf">
        <img className="cve-report__logo" src="/cernis-logo.png" alt="CERNIS PRO" />
        <div className="cve-report__kopf-text">
          <h3 className="cve-report__titel" id="help.report.cve">
            {t("report.cve.titel")}
          </h3>
          <p className="cve-report__kopf-datum">
            {t("report.cve.kopf.erstellt", { datum: erstelltDatum })}
          </p>
        </div>
        {/* PDF-Aktion rechtsbuendig im Kopf: spart den Weg ans Berichtsende. */}
        {bericht ? (
          <div className="cve-report__kopf-aktionen">
            <button
              type="button"
              className="cve-report__pdf"
              onClick={handlePdf}
              disabled={pdfLaedt}
            >
              {t("report.cve.pdf")}
            </button>
            {pdfFehler ? (
              <p className="cve-report__pdf-fehler" role="alert">
                {t("report.cve.pdfFehler")}
              </p>
            ) : null}
          </div>
        ) : null}
      </header>

      {fehler && (
        <div className="cve-report__fehler" role="note">
          {t("report.cve.ladeFehler")}
        </div>
      )}

      {/* ── 2. Ehrlicher Leerzustand: keine Grafiken/Tabellen ──────────────────── */}
      {istLeer ? (
        <div className="cve-report__leerzustand" role="note">
          <p className="cve-report__leerzustand-text">{t("report.cve.leerzustand")}</p>
        </div>
      ) : null}

      {/* ── 3. Bericht-Inhalt nur bei vorhandenen Befunden ─────────────────────── */}
      {bericht && !istLeer ? (
        <>
          {/* 3.1 Einleitung (Achse-B-Haltung in Klartext). */}
          <p className="cve-report__einleitung">{t("report.cve.einleitung")}</p>

          {/* 3.2 Kennzahlen: Zahl-Reihe + Text-Reihe. */}
          <div className="cve-report__kennzahlen">
            <Kennzahl wert={bericht.activeTotal} label={t("report.cve.kennzahl.aktiv")} />
            <Kennzahl wert={bericht.newTotal} label={t("report.cve.kennzahl.neu")} />
            <Kennzahl
              wert={bericht.affectedDevices}
              label={t("report.cve.kennzahl.betroffen")}
            />
            <Kennzahl
              wert={bericht.acknowledgedTotal}
              label={t("report.cve.kennzahl.quittiert")}
            />
          </div>
          <div className="cve-report__kennzahlen">
            <TextKennzahl
              inhalt={<SeverityBadge severity={bericht.highestSeverity} t={t} />}
              label={t("report.cve.kennzahl.hoechste")}
            />
            <TextKennzahl
              inhalt={bericht.coverageText || "—"}
              label={t("report.cve.kennzahl.abdeckung")}
            />
            <TextKennzahl
              inhalt={fmtPublished(bericht.oldestPublished, sprache)}
              label={t("report.cve.kennzahl.aeltste")}
            />
          </div>

          {/* 3.3 Severity-Donut (ein Donut, Segmente in SEVERITY_ORDER). */}
          <div className="cve-report__donut-paar">
            <Donut
              segmente={donutSegmente}
              mitte={donutSumme}
              mitteLabel={t("report.cve.donut.befunde")}
              ariaLabel={t("report.cve.donut.aria", { anzahl: donutSumme })}
            />
          </div>

          {/* 3.4 Muster mit Umschalter (Gerät <-> Dienst). */}
          <Muster
            modus={musterModus}
            onModus={setMusterModus}
            deviceRows={bericht.deviceRows}
            serviceRows={bericht.serviceRows}
            fmtPublished={(iso) => fmtPublished(iso, sprache)}
            t={t}
          />

          {/* 3.5 Vollständige Befundliste, nach Host gruppiert. */}
          <Befundliste
            gruppen={hostGruppen}
            filter={filter}
            onFilter={setFilter}
            sortierung={sortierung}
            onSortierung={setSortierung}
            t={t}
          />

          {/* Neu-Erklärung + Achse-B-Fussnote: beschreibt und ordnet ein — kein Urteil. */}
          <p className="cve-report__neu-hinweis">{t("report.cve.neuHinweis")}</p>
          <p className="cve-report__fussnote">{t("report.cve.fussnote")}</p>

          {/* Bericht-Fusszeile (UNSER Inhalt, nicht der Browser-Druckfuss). */}
          <footer className="cve-report__fusszeile">
            {t("report.cve.fusszeile", { datum: erstelltDatum })}
          </footer>
        </>
      ) : null}


      {laedt && <div className="cve-report__laedt" aria-hidden="true" />}
    </div>
  );
}

// ── 3.4 Muster (Gerät <-> Dienst) ─────────────────────────────────────────────
// Umschalter (zwei Toggle-Knöpfe, aria-pressed) + je Modus eine Tabelle. Reihenfolge
// kommt schon vom Backend sortiert -> unverändert übernehmen (NICHT neu sortieren).
// Es werden IMMER ALLE Zeilen gerendert; am Bildschirm blendet CSS die über Top-N
// hinausgehenden aus (--ueberzaehlig) und zeigt die "+ X weitere"-Zeile; im Druck alle.
function Muster({ modus, onModus, deviceRows, serviceRows, fmtPublished, t }) {
  const istGeraet = modus === "geraet";
  const restGeraete = deviceRows.length - TOP_GERAETE;
  const restDienste = serviceRows.length - TOP_DIENSTE;

  return (
    <section className="cve-report__muster">
      <div className="cve-report__muster-kopf">
        <h4 className="cve-report__abschnitt-titel">{t("report.cve.muster.titel")}</h4>
        <div className="cve-report__toggle" role="group">
          <button
            type="button"
            className={
              istGeraet
                ? "cve-report__toggle-knopf cve-report__toggle-knopf--aktiv"
                : "cve-report__toggle-knopf"
            }
            aria-pressed={istGeraet}
            onClick={() => onModus("geraet")}
          >
            {t("report.cve.muster.geraet")}
          </button>
          <button
            type="button"
            className={
              !istGeraet
                ? "cve-report__toggle-knopf cve-report__toggle-knopf--aktiv"
                : "cve-report__toggle-knopf"
            }
            aria-pressed={!istGeraet}
            onClick={() => onModus("dienst")}
          >
            {t("report.cve.muster.dienst")}
          </button>
        </div>
      </div>

      {istGeraet ? (
        deviceRows.length > 0 ? (
          <>
            <table className="cve-report__tabelle">
              <thead>
                <tr>
                  <th>{t("report.cve.spalteGeraet.geraet")}</th>
                  <th className="cve-report__num">{t("report.cve.spalteGeraet.befunde")}</th>
                  <th>{t("report.cve.spalteGeraet.hoechste")}</th>
                  <th className="cve-report__num">{t("report.cve.spalteGeraet.cvss")}</th>
                  <th>{t("report.cve.spalteGeraet.dienste")}</th>
                </tr>
              </thead>
              <tbody>
                {deviceRows.map((r, i) => (
                  <tr
                    key={`geraet-${i}`}
                    className={
                      i >= TOP_GERAETE
                        ? "cve-report__zeile cve-report__zeile--ueberzaehlig"
                        : "cve-report__zeile"
                    }
                  >
                    <td>{r.deviceLabel}</td>
                    <td className="cve-report__num cve-report__mono">{r.findingCount}</td>
                    <td>
                      <SeverityBadge severity={r.highestSeverity} t={t} />
                    </td>
                    <td className="cve-report__num cve-report__mono">
                      {(r.highestCvss ?? 0).toFixed(1)}
                    </td>
                    <td>{r.services}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {restGeraete > 0 ? (
              <p className="cve-report__rest">
                {t("report.cve.muster.weitere", { anzahl: restGeraete })}
              </p>
            ) : null}
          </>
        ) : (
          <p className="cve-report__leer">{t("report.cve.muster.leer")}</p>
        )
      ) : serviceRows.length > 0 ? (
        <>
          <table className="cve-report__tabelle">
            <thead>
              <tr>
                <th>{t("report.cve.spalteDienst.dienst")}</th>
                <th className="cve-report__num">{t("report.cve.spalteDienst.befunde")}</th>
                <th className="cve-report__num">{t("report.cve.spalteDienst.geraete")}</th>
                <th>{t("report.cve.spalteDienst.hoechste")}</th>
                <th className="cve-report__num">{t("report.cve.spalteDienst.cvss")}</th>
                <th>{t("report.cve.spalteDienst.aeltste")}</th>
              </tr>
            </thead>
            <tbody>
              {serviceRows.map((r, i) => (
                <tr
                  key={`dienst-${i}`}
                  className={
                    i >= TOP_DIENSTE
                      ? "cve-report__zeile cve-report__zeile--ueberzaehlig"
                      : "cve-report__zeile"
                  }
                >
                  <td>
                    {r.service === "__service_unknown__"
                      ? t("report.cve.spalteDienst.ohneDienst")
                      : r.service}
                  </td>
                  <td className="cve-report__num cve-report__mono">{r.findingCount}</td>
                  <td className="cve-report__num cve-report__mono">{r.deviceCount}</td>
                  <td>
                    <SeverityBadge severity={r.highestSeverity} t={t} />
                  </td>
                  <td className="cve-report__num cve-report__mono">
                    {(r.highestCvss ?? 0).toFixed(1)}
                  </td>
                  <td>{fmtPublished(r.oldestPublished)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {restDienste > 0 ? (
            <p className="cve-report__rest">
              {t("report.cve.muster.weitere", { anzahl: restDienste })}
            </p>
          ) : null}
        </>
      ) : (
        <p className="cve-report__leer">{t("report.cve.muster.leer")}</p>
      )}
    </section>
  );
}

// ── 3.5 Befundliste (nach Host gruppiert) ─────────────────────────────────────
// Filter-Chips (alle/aktiv/quittiert/neu) + Sortier-Auswahl (severity/host/cvss),
// beides reine Anzeige-Steuerung. Je Host eine graue Kopfzeile (deviceLabel, dahinter
// IP+MAC dezent, rechts "N Befunde, höchste <SeverityBadge>") und darunter eine
// Tabelle der CVE-Zeilen. Kein Top-N: die Befundliste ist die Detailebene und darf
// vollständig sein (Druck zeigt sie ohnehin komplett). Leere Auswahl -> Leertext.
function Befundliste({ gruppen, filter, onFilter, sortierung, onSortierung, t }) {
  const chips = [
    { id: "alle", label: t("report.cve.filter.alle") },
    { id: "aktiv", label: t("report.cve.filter.aktiv") },
    { id: "quittiert", label: t("report.cve.filter.quittiert") },
    { id: "neu", label: t("report.cve.filter.neu") },
  ];

  return (
    <section className="cve-report__abschnitt">
      <h4 className="cve-report__abschnitt-titel cve-report__abschnitt-titel--num">
        <span className="cve-report__abschnitt-nummer">1</span>
        {t("report.cve.liste.titel")}
      </h4>

      {/* Steuerleiste: Filter-Chips links, Sortier-Auswahl rechts (im Druck weg). */}
      <div className="cve-report__steuerung">
        <div className="cve-report__chips" role="group">
          {chips.map((c) => (
            <button
              key={c.id}
              type="button"
              className={
                filter === c.id
                  ? "cve-report__chip cve-report__chip--aktiv"
                  : "cve-report__chip"
              }
              aria-pressed={filter === c.id}
              onClick={() => onFilter(c.id)}
            >
              {c.label}
            </button>
          ))}
        </div>
        <label className="cve-report__sortierung">
          <span className="cve-report__sortierung-label">
            {t("report.cve.sortierung.label")}
          </span>
          <select
            className="cve-report__sortierung-select"
            value={sortierung}
            onChange={(e) => onSortierung(e.target.value)}
          >
            <option value="severity">{t("report.cve.sortierung.severity")}</option>
            <option value="host">{t("report.cve.sortierung.host")}</option>
            <option value="cvss">{t("report.cve.sortierung.cvss")}</option>
          </select>
        </label>
      </div>

      {gruppen.length > 0 ? (
        <div className="cve-report__gruppen">
          {gruppen.map((g) => (
            <div className="cve-report__gruppe" key={`host-${g.mac}`}>
              {/* Host-Kopfzeile: deviceLabel, dahinter IP+MAC dezent, rechts Zähler +
                  höchste Severity. Die IP fehlt aktuell in der Wire-Form (g.ip == "")
                  -> nur MAC; sie wird je Zeile NICHT wiederholt. */}
              <div className="cve-report__host">
                <span className="cve-report__host-name">{g.deviceLabel}</span>
                <span className="cve-report__host-meta cve-report__mono">
                  {/* (Etappe 3b) IP nur zeigen, wenn vorhanden UND ungleich deviceLabel --
                      bei namenlosen Geraeten ist deviceLabel == ip (sonst doppelte IP). */}
                  {g.ip && g.ip !== g.deviceLabel ? `${g.ip} · ${g.mac}` : g.mac}
                </span>
                <span className="cve-report__host-zaehler">
                  {t("report.cve.liste.hostBefunde", { anzahl: g.zeilen.length })}{" "}
                  <SeverityBadge severity={g.hoechsteSeverity} t={t} />
                </span>
              </div>
              <table className="cve-report__tabelle">
                <thead>
                  <tr>
                    <th>{t("report.cve.spalte.cve")}</th>
                    <th>{t("report.cve.spalte.severity")}</th>
                    <th className="cve-report__num">{t("report.cve.spalte.cvss")}</th>
                    <th>{t("report.cve.spalte.dienst")}</th>
                    <th className="cve-report__num">{t("report.cve.spalte.port")}</th>
                    <th>{t("report.cve.spalte.erstmals")}</th>
                    <th>{t("report.cve.spalte.status")}</th>
                  </tr>
                </thead>
                <tbody>
                  {g.zeilen.map((r, i) => (
                    <tr key={`befund-${g.mac}-${i}`} className="cve-report__zeile">
                      <td className="cve-report__mono">{r.cveId}</td>
                      <td>
                        <SeverityBadge severity={r.severity} t={t} />
                      </td>
                      <td className="cve-report__num cve-report__mono">
                        {(r.cvssScore ?? 0).toFixed(1)}
                      </td>
                      <td>{r.service}</td>
                      <td className="cve-report__num cve-report__mono">{r.port}</td>
                      <td>{r.firstSeenText}</td>
                      <td>
                        <StatusZelle acknowledged={r.acknowledged} isNew={r.isNew} t={t} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ))}
        </div>
      ) : (
        <p className="cve-report__leer">{t("report.cve.tabelle.leer")}</p>
      )}
    </section>
  );
}
