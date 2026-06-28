// Bestandsbericht — In-App-Ansicht (CERNIS PRO 2.0, Etappe 3)
//
// Zweite Kachel des Reporting-Bereichs. Verdichtet den aggregierten Bestandsbericht
// (GET /api/report/inventory) zu einer ruhigen Lesesicht: Kennzahlen oben, zwei
// Donuts (bekannt/unbekannt + Vertrauensstatus), eine umschaltbare Verteilung
// (Hersteller <-> Kategorie) als Balken, darunter die filter-/sortierbare
// Geraeteliste und ein Drucken-Knopf. Reine Lesesicht — greift NICHT ins Netz ein,
// mutiert nichts.
//
// Sie laedt selbst ueber fetchInventoryReport (useEffect mit abgebrochen-Flag, Lade-/
// Fehlerzustand wie SecurityReportView). Achse B des Produkts: der Bericht BESCHREIBT
// und ORDNET EIN — er urteilt nicht. Filter/Sortierung/Umschalter sind reine Anzeige-
// Steuerung im Frontend (kein Reload). KEIN 404-Fall: leerer Bestand ist ein DATUM
// (alle Zaehler 0 + leere Listen), kein Fehler -> ruhiger Leerzustand.
//
// Stil wie der Bestand: SVG wie SchwereDonut/SecurityReportView (viewBox-Raster, Donut
// per stroke-dasharray), alle Texte ueber i18n, alle Farben ueber Tokens (tokens.css):
// accent fuer "bekannt/vertraut", sev-med fuer "unbekannt/beobachtet", sev-low fuer
// "neutral". Nie feste Farben. t NIEMALS in useEffect/useMemo-Deps (instabile Referenz
// -> Loop); Memo-Strukturen tragen stabile Schluessel.

import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { fetchInventoryReport, fetchInventoryReportPdf } from "../api/report.js";
import "./InventoryReportView.css";

// Wie viele Verteilungs-Balken bzw. Geraete-Zeilen am Bildschirm hoechstens sichtbar
// sind; der Rest erscheint als "+ X weitere" Klartext (kein stilles Abschneiden). Im
// Druck (CSS @media print) werden IMMER alle gezeigt.
const TOP_VERTEILUNG = 8;
const TOP_GERAETE = 12;

// Token je Achse. accent fuer bekannt/vertraut, sev-med fuer unbekannt/beobachtet,
// sev-low fuer neutral. KEINE festen Farben.
const FARBE_BEKANNT = "var(--color-accent)";
const FARBE_UNBEKANNT = "var(--sev-med-bd)";
const FARBE_VERTRAUT = "var(--color-accent)";
const FARBE_BEOBACHTET = "var(--sev-med-bd)";
const FARBE_NEUTRAL = "var(--sev-low-bd)";

// Eine Kennzahl-Kachel (grosse Zahl + dezentes Label).
function Kennzahl({ wert, label }) {
  return (
    <div className="inventory-report__kennzahl">
      <span className="inventory-report__kennzahl-wert">{wert}</span>
      <span className="inventory-report__kennzahl-label">{label}</span>
    </div>
  );
}

// Ein Donut mit Legende. segmente = [{ wert, farbe, label }]. Mitte = mitte (Zahl) +
// mitteLabel. Geometrie wie SchwereDonut (Vollkreis-Donut, Umfang = 2πr, jedes Segment
// ein dash-Abschnitt; Start oben). Leere Summe -> nur die Bahn.
function Donut({ titel, segmente, mitte, mitteLabel, ariaLabel }) {
  const summe = segmente.reduce((acc, s) => acc + Math.max(0, s.wert), 0);
  const radius = 42;
  const umfang = 2 * Math.PI * radius;
  let offset = 0;

  return (
    <div className="inventory-report__donut-block">
      <div className="inventory-report__donut-titel">{titel}</div>
      <div className="inventory-report__donut">
        <svg
          className="inventory-report__donut-svg"
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
        <div className="inventory-report__donut-mitte">
          <span className="inventory-report__donut-summe">{mitte}</span>
          <span className="inventory-report__donut-label">{mitteLabel}</span>
        </div>
      </div>
      <ul className="inventory-report__legende">
        {segmente.map((seg, i) => (
          <li key={`leg-${i}`} className="inventory-report__legende-zeile">
            <span
              className="inventory-report__legende-punkt"
              style={{ background: seg.farbe }}
              aria-hidden="true"
            />
            <span className="inventory-report__legende-label">{seg.label}</span>
            <span className="inventory-report__legende-zahl inventory-report__mono">
              {seg.wert}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

// Status-Badge je Geraete-Zeile. trustState "trusted" -> Vertraut (accent-Ton),
// "watch" -> Beobachtet (sev-med-Ton), "neutral" -> isKnown? Bekannt (neutraler Ton)
// : Unbekannt (warnender Ton). Texte i18n, Farben Token.
function StatusBadge({ trustState, isKnown, t }) {
  if (trustState === "trusted") {
    return (
      <span className="inventory-report__badge inventory-report__badge--vertraut">
        {t("report.inventory.status.vertraut")}
      </span>
    );
  }
  if (trustState === "watch") {
    return (
      <span className="inventory-report__badge inventory-report__badge--beobachtet">
        {t("report.inventory.status.beobachtet")}
      </span>
    );
  }
  if (isKnown) {
    return (
      <span className="inventory-report__badge inventory-report__badge--bekannt">
        {t("report.inventory.status.bekannt")}
      </span>
    );
  }
  return (
    <span className="inventory-report__badge inventory-report__badge--unbekannt">
      {t("report.inventory.status.unbekannt")}
    </span>
  );
}

export default function InventoryReportView() {
  const { t, i18n } = useTranslation();

  // Geladener Bericht (null = noch nicht geladen / nicht vorhanden) + Lade-/Fehlerzustand.
  const [bericht, setBericht] = useState(null);
  const [laedt, setLaedt] = useState(false);
  const [fehler, setFehler] = useState(false);
  // Anzeige-Steuerung (reines Frontend, kein Reload).
  const [verteilungModus, setVerteilungModus] = useState("vendor"); // "vendor"|"category"
  const [filter, setFilter] = useState("aktiv"); // aktiv|bekannt|unbekannt|archiviert
  const [sortierung, setSortierung] = useState("lastSeen"); // lastSeen|name|vendor
  // Lokaler Zustand des PDF-Downloads (ueberschreibt NICHT den globalen Lade-Fehler).
  const [pdfLaedt, setPdfLaedt] = useState(false);
  const [pdfFehler, setPdfFehler] = useState(false);

  // PDF-Download anstossen. Setzt den lokalen Lade-/Fehler-State; der globale
  // fehler-State bleibt unberuehrt (Muster SecurityReportView.handlePdf).
  async function handlePdf() {
    setPdfFehler(false);
    setPdfLaedt(true);
    try {
      await fetchInventoryReportPdf();
    } catch {
      setPdfFehler(true);
    } finally {
      setPdfLaedt(false);
    }
  }

  // Laedt den Bericht einmalig. Fehler -> dezenter Hinweis, kein Absturz (Muster
  // SecurityReportView). t BEWUSST NICHT in den Deps (neue Referenz je Render -> Loop).
  useEffect(() => {
    let abgebrochen = false;

    (async () => {
      setLaedt(true);
      setFehler(false);
      try {
        const geladen = await fetchInventoryReport();
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

  // Aktive Verteilungsquelle (Hersteller bzw. Kategorie), nach count absteigend.
  // Stabiler Memo-Schluessel: bericht + Modus (kein t).
  const verteilung = useMemo(() => {
    if (!bericht) {
      return [];
    }
    const quelle =
      verteilungModus === "category"
        ? bericht.categoryDistribution
        : bericht.vendorDistribution;
    return [...quelle].sort((a, b) => b.count - a.count);
  }, [bericht, verteilungModus]);

  // Gefilterte + sortierte Geraete-Zeilen fuer die Tabelle. Filter waehlt die Quelle
  // (deviceRows = aktive, archivedRows = archivierte — getrennte Backend-Listen) bzw.
  // ein Praedikat auf isKnown; Sortierung ordnet danach. Stabile Memo-Deps (kein t).
  const geraeteZeilen = useMemo(() => {
    if (!bericht) {
      return [];
    }
    let basis;
    if (filter === "archiviert") {
      basis = bericht.archivedRows;
    } else if (filter === "bekannt") {
      basis = bericht.deviceRows.filter((r) => r.isKnown);
    } else if (filter === "unbekannt") {
      basis = bericht.deviceRows.filter((r) => !r.isKnown);
    } else {
      // "aktiv" (Default): alle nicht-archivierten Geraete.
      basis = bericht.deviceRows;
    }

    const zeilen = [...basis];
    if (sortierung === "name") {
      zeilen.sort((a, b) =>
        (a.deviceLabel ?? "").localeCompare(b.deviceLabel ?? ""),
      );
    } else if (sortierung === "vendor") {
      zeilen.sort((a, b) => (a.vendor ?? "").localeCompare(b.vendor ?? ""));
    } else {
      // "lastSeen" (Default): letzte Sichtung absteigend (neueste zuerst).
      zeilen.sort((a, b) => (b.lastSeenTs ?? 0) - (a.lastSeenTs ?? 0));
    }
    return zeilen;
  }, [bericht, filter, sortierung]);

  const sprache = i18n.language === "en" ? "en" : "de";
  // Erstelldatum des Berichts: heute, lokal formatiert. Reine Anzeige im Titelkopf und
  // in der Fusszeile (Muster SecurityReportView.erstelltDatum).
  const erstelltDatum = new Date().toLocaleDateString(sprache === "en" ? "en-US" : "de-DE", {
    year: "numeric",
    month: "long",
    day: "numeric",
  });

  // Ehrlicher Leerzustand: Bericht geladen, aber gar keine Geraete erfasst.
  const istLeer =
    bericht &&
    bericht.total === 0 &&
    bericht.deviceRows.length === 0 &&
    bericht.archivedRows.length === 0;

  const vertrauenSumme = bericht
    ? bericht.trusted + bericht.watch + bericht.neutral
    : 0;

  return (
    <div className="inventory-report">
      {/* ── 1. Bericht-Titelkopf: Logo + grosse Ueberschrift + Erstelldatum ──────
          Eigener Dokument-Kopf (NICHT die App-Navi). Der Hilfe-Anker bleibt am Titel. */}
      <header className="inventory-report__kopf">
        <img className="inventory-report__logo" src="/cernis-logo.png" alt="CERNIS PRO" />
        <div className="inventory-report__kopf-text">
          <h3 className="inventory-report__titel" id="help.report.inventory">
            {t("report.inventory.titel")}
          </h3>
          <p className="inventory-report__kopf-datum">
            {t("report.inventory.kopf.erstellt", { datum: erstelltDatum })}
          </p>
        </div>
      </header>

      {fehler && (
        <div className="inventory-report__fehler" role="note">
          {t("report.inventory.ladeFehler")}
        </div>
      )}

      {/* ── 2. Ehrlicher Leerzustand: keine Grafiken/Tabellen ──────────────────── */}
      {istLeer ? (
        <div className="inventory-report__leerzustand" role="note">
          <p className="inventory-report__leerzustand-text">
            {t("report.inventory.leerzustand")}
          </p>
        </div>
      ) : null}

      {/* ── 3. Bericht-Inhalt nur bei vorhandenem Bestand ──────────────────────── */}
      {bericht && !istLeer ? (
        <>
          {/* 3.1 Einleitung (Achse-B-Haltung in Klartext). */}
          <p className="inventory-report__einleitung">{t("report.inventory.einleitung")}</p>

          {/* 3.2 Kennzahlen: zwei Reihen. */}
          <div className="inventory-report__kennzahlen">
            <Kennzahl wert={bericht.total} label={t("report.inventory.kennzahl.gesamt")} />
            <Kennzahl wert={bericht.known} label={t("report.inventory.kennzahl.bekannt")} />
            <Kennzahl wert={bericht.unknown} label={t("report.inventory.kennzahl.unbekannt")} />
            <Kennzahl wert={bericht.active24h} label={t("report.inventory.kennzahl.aktiv")} />
          </div>
          <div className="inventory-report__kennzahlen">
            <Kennzahl wert={bericht.trusted} label={t("report.inventory.kennzahl.vertraut")} />
            <Kennzahl wert={bericht.watch} label={t("report.inventory.kennzahl.beobachtet")} />
            <Kennzahl wert={bericht.neutral} label={t("report.inventory.kennzahl.neutral")} />
          </div>

          {/* 3.3 Zwei Donuts nebeneinander. */}
          <div className="inventory-report__donut-paar">
            <Donut
              titel={t("report.inventory.donut.bekanntTitel")}
              segmente={[
                { wert: bericht.known, farbe: FARBE_BEKANNT, label: t("report.inventory.legende.bekannt") },
                { wert: bericht.unknown, farbe: FARBE_UNBEKANNT, label: t("report.inventory.legende.unbekannt") },
              ]}
              mitte={bericht.total}
              mitteLabel={t("report.inventory.donut.geraete")}
              ariaLabel={t("report.inventory.donut.ariaBekannt", { anzahl: bericht.total })}
            />
            <Donut
              titel={t("report.inventory.donut.vertrauenTitel")}
              segmente={[
                { wert: bericht.trusted, farbe: FARBE_VERTRAUT, label: t("report.inventory.legende.vertraut") },
                { wert: bericht.watch, farbe: FARBE_BEOBACHTET, label: t("report.inventory.legende.beobachtet") },
                { wert: bericht.neutral, farbe: FARBE_NEUTRAL, label: t("report.inventory.legende.neutral") },
              ]}
              mitte={vertrauenSumme}
              mitteLabel={t("report.inventory.donut.geraete")}
              ariaLabel={t("report.inventory.donut.ariaVertrauen", { anzahl: vertrauenSumme })}
            />
          </div>

          {/* 3.4 Verteilung mit Umschalter (Hersteller <-> Kategorie). */}
          <Verteilung
            eintraege={verteilung}
            modus={verteilungModus}
            onModus={setVerteilungModus}
            t={t}
          />

          {/* 3.5 Geraeteliste (Filter-Chips + Sortier-Auswahl + Tabelle). */}
          <GeraeteListe
            zeilen={geraeteZeilen}
            filter={filter}
            onFilter={setFilter}
            sortierung={sortierung}
            onSortierung={setSortierung}
            t={t}
          />

          {/* Achse-B-Fussnote: der Bericht beschreibt und ordnet ein — kein Urteil. */}
          <p className="inventory-report__fussnote">{t("report.inventory.fussnote")}</p>

          {/* Bericht-Fusszeile (UNSER Inhalt, nicht der Browser-Druckfuss). */}
          <footer className="inventory-report__fusszeile">
            {t("report.inventory.fusszeile", { datum: erstelltDatum })}
          </footer>
        </>
      ) : null}

      {/* ── Aktionsleiste: Bericht als PDF herunterladen ───────────────────────── */}
      {bericht ? (
        <div className="inventory-report__aktionen">
          <button
            type="button"
            className="inventory-report__pdf"
            onClick={handlePdf}
            disabled={pdfLaedt}
          >
            {t("report.inventory.pdf")}
          </button>
          {pdfFehler ? (
            <p className="inventory-report__pdf-fehler" role="alert">
              {t("report.inventory.pdfFehler")}
            </p>
          ) : null}
        </div>
      ) : null}

      {laedt && <div className="inventory-report__laedt" aria-hidden="true" />}
    </div>
  );
}

// ── 3.4 Verteilung (Hersteller <-> Kategorie) ─────────────────────────────────
// Umschalter (zwei Toggle-Knoepfe, aria-pressed) + horizontale Balken. Es werden
// IMMER ALLE Eintraege gerendert; am Bildschirm blendet CSS die ueber TOP_VERTEILUNG
// hinausgehenden Zeilen aus (--ueberzaehlig) und zeigt die "+ X weitere"-Zeile. Im
// Druck dreht @media print das um: alle sichtbar, "weitere" weg. Balkenbreite relativ
// zum groessten count ueber ALLE Eintraege (auch im Druck stimmig). Leerer Label-Wert
// -> i18n-"(ohne)".
function Verteilung({ eintraege, modus, onModus, t }) {
  const rest = eintraege.length - TOP_VERTEILUNG;
  const maxCount = eintraege.reduce((acc, e) => Math.max(acc, e.count), 0) || 1;

  return (
    <section className="inventory-report__verteilung">
      <div className="inventory-report__verteilung-kopf">
        <h4 className="inventory-report__abschnitt-titel">
          {t("report.inventory.verteilung.titel")}
        </h4>
        <div className="inventory-report__toggle" role="group">
          <button
            type="button"
            className={
              modus === "vendor"
                ? "inventory-report__toggle-knopf inventory-report__toggle-knopf--aktiv"
                : "inventory-report__toggle-knopf"
            }
            aria-pressed={modus === "vendor"}
            onClick={() => onModus("vendor")}
          >
            {t("report.inventory.verteilung.vendor")}
          </button>
          <button
            type="button"
            className={
              modus === "category"
                ? "inventory-report__toggle-knopf inventory-report__toggle-knopf--aktiv"
                : "inventory-report__toggle-knopf"
            }
            aria-pressed={modus === "category"}
            onClick={() => onModus("category")}
          >
            {t("report.inventory.verteilung.kategorie")}
          </button>
        </div>
      </div>

      {eintraege.length > 0 ? (
        <>
          <div className="inventory-report__balken-liste">
            {eintraege.map((e, i) => (
              <div
                key={`vert-${i}`}
                className={
                  i >= TOP_VERTEILUNG
                    ? "inventory-report__balken-zeile inventory-report__balken-zeile--ueberzaehlig"
                    : "inventory-report__balken-zeile"
                }
              >
                <span
                  className="inventory-report__balken-label"
                  title={e.label || t("report.inventory.verteilung.ohne")}
                >
                  {e.label || t("report.inventory.verteilung.ohne")}
                </span>
                <div className="inventory-report__balken-bahn">
                  <div
                    className="inventory-report__balken-fueller"
                    style={{ width: `${((e.count / maxCount) * 100).toFixed(1)}%` }}
                  />
                </div>
                <span className="inventory-report__balken-zahl inventory-report__mono">
                  {e.count}
                </span>
              </div>
            ))}
          </div>
          {rest > 0 ? (
            <p className="inventory-report__balken-rest">
              {t("report.inventory.verteilung.weitere", { anzahl: rest })}
            </p>
          ) : null}
        </>
      ) : (
        <p className="inventory-report__leer">{t("report.inventory.verteilung.leer")}</p>
      )}
    </section>
  );
}

// ── 3.5 Geraeteliste ──────────────────────────────────────────────────────────
// Nummerierter Abschnitt mit Filter-Chips (aktiv/bekannt/unbekannt/archiviert) und
// Sortier-Auswahl (lastSeen/name/vendor). Beides reine Anzeige-Steuerung. Tabelle wie
// security-report__tabelle: Geraet | Hersteller | Letzte IP (mono) | Erste Sichtung |
// Letzte Sichtung | Gesehen (num, mono) | Kategorie | Status. Es werden IMMER ALLE
// Zeilen gerendert; am Bildschirm blendet CSS die ueber TOP_GERAETE hinausgehenden aus
// und zeigt die "+ X weitere · im PDF vollstaendig"-Zeile; im Druck alle sichtbar.
// Leere Auswahl -> dezenter Leertext.
function GeraeteListe({ zeilen, filter, onFilter, sortierung, onSortierung, t }) {
  const rest = zeilen.length - TOP_GERAETE;
  const chips = [
    { id: "aktiv", label: t("report.inventory.filter.aktiv") },
    { id: "bekannt", label: t("report.inventory.filter.bekannt") },
    { id: "unbekannt", label: t("report.inventory.filter.unbekannt") },
    { id: "archiviert", label: t("report.inventory.filter.archiviert") },
  ];

  return (
    <section className="inventory-report__abschnitt">
      <h4 className="inventory-report__abschnitt-titel inventory-report__abschnitt-titel--num">
        <span className="inventory-report__abschnitt-nummer">1</span>
        {t("report.inventory.liste.titel")}
      </h4>

      {/* Steuerleiste: Filter-Chips links, Sortier-Auswahl rechts (im Druck weg). */}
      <div className="inventory-report__steuerung">
        <div className="inventory-report__chips" role="group">
          {chips.map((c) => (
            <button
              key={c.id}
              type="button"
              className={
                filter === c.id
                  ? "inventory-report__chip inventory-report__chip--aktiv"
                  : "inventory-report__chip"
              }
              aria-pressed={filter === c.id}
              onClick={() => onFilter(c.id)}
            >
              {c.label}
            </button>
          ))}
        </div>
        <label className="inventory-report__sortierung">
          <span className="inventory-report__sortierung-label">
            {t("report.inventory.sortierung.label")}
          </span>
          <select
            className="inventory-report__sortierung-select"
            value={sortierung}
            onChange={(e) => onSortierung(e.target.value)}
          >
            <option value="lastSeen">{t("report.inventory.sortierung.lastSeen")}</option>
            <option value="name">{t("report.inventory.sortierung.name")}</option>
            <option value="vendor">{t("report.inventory.sortierung.vendor")}</option>
          </select>
        </label>
      </div>

      {zeilen.length > 0 ? (
        <>
          <table className="inventory-report__tabelle">
            <thead>
              <tr>
                <th>{t("report.inventory.spalte.geraet")}</th>
                <th>{t("report.inventory.spalte.hersteller")}</th>
                <th>{t("report.inventory.spalte.ip")}</th>
                <th>{t("report.inventory.spalte.erstSichtung")}</th>
                <th>{t("report.inventory.spalte.letztSichtung")}</th>
                <th className="inventory-report__num">{t("report.inventory.spalte.gesehen")}</th>
                <th>{t("report.inventory.spalte.kategorie")}</th>
                <th>{t("report.inventory.spalte.status")}</th>
              </tr>
            </thead>
            <tbody>
              {zeilen.map((r, i) => (
                <tr
                  key={`dev-${i}`}
                  className={
                    i >= TOP_GERAETE
                      ? "inventory-report__zeile inventory-report__zeile--ueberzaehlig"
                      : "inventory-report__zeile"
                  }
                >
                  <td>{r.deviceLabel}</td>
                  <td>{r.vendor}</td>
                  <td className="inventory-report__mono">{r.lastIp}</td>
                  <td>{r.firstSeenText}</td>
                  <td>{r.lastSeenText}</td>
                  <td className="inventory-report__num inventory-report__mono">{r.timesSeen}</td>
                  <td>{r.category}</td>
                  <td>
                    <StatusBadge trustState={r.trustState} isKnown={r.isKnown} t={t} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {rest > 0 ? (
            <p className="inventory-report__balken-rest">
              {t("report.inventory.liste.weitere", { anzahl: rest })}
            </p>
          ) : null}
        </>
      ) : (
        <p className="inventory-report__leer">{t("report.inventory.tabelle.leer")}</p>
      )}
    </section>
  );
}
