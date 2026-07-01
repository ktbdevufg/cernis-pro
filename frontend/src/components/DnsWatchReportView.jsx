// DNS-Waechter-Bericht — In-App-Ansicht (CERNIS PRO 2.0, Etappe 3)
//
// Fuenfte Kachel des Reporting-Bereichs. Verdichtet den aggregierten DNS-Waechter-
// Bericht (GET /api/report/dns-watch) zu einer ruhigen Lesesicht: Kennzahlen oben,
// ein Kategorie-Donut, eine umschaltbare Verteilung (Kategorie <-> Programm) als
// Tabelle, darunter die flache, filter-/sortierbare Kontaktliste, ein ehrlicher
// Grundlage-Block (verwendete Listen) und ein Drucken-Knopf. Reine Lesesicht —
// greift NICHT ins Netz ein, mutiert nichts.
//
// Sie laedt selbst ueber fetchDnsWatchReport (useEffect mit abgebrochen-Flag, Lade-/
// Fehlerzustand wie CveReportView). Achse B des Produkts: der Bericht BESCHREIBT und
// ORDNET EIN — er urteilt nicht. Filter/Sortierung/Umschalter sind reine Anzeige-
// Steuerung im Frontend (kein Reload). KEIN 404-Fall: leerer Stand ist ein DATUM
// (alle Zaehler 0 + leere Listen), kein Fehler -> ruhiger Leerzustand.
//
// Kategorie-Optik ueber eigene dns-report__cat-Klassen (data-cat-Schluessel), aber
// nur bestehende Token-Variablen (offen wie --sev-high, moegliche_doh wie --sev-med,
// erwartungsgemaess ruhig ueber --color-accent/--color-border). Roh-Kategorie bleibt
// der data-cat-Schluessel; der ANGEZEIGTE Text ist lokalisiert. Nie feste Farben. t
// NIEMALS in useEffect/useMemo-Deps (instabile Referenz -> Loop).

import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { fetchDnsWatchReport, fetchDnsWatchReportPdf } from "../api/report.js";
import "./DnsWatchReportView.css";

// Kategorie-Reihenfolge (Donut-Segmente + Anzeige) und Rang. Roh-Kategorien bleiben
// der Schluessel; der Text wird lokalisiert. Das Backend liefert nur diese drei.
const CATEGORY_ORDER = ["offen", "moegliche_doh", "erwartungsgemaess"];
const CATEGORY_RANK = { offen: 0, moegliche_doh: 1, erwartungsgemaess: 2 };

// Liefert die CSS-Variable fuer die Donut-Segmentfarbe je Kategorie (dieselben
// Border-Toene wie die Badges). KEINE festen Farben.
function catColorVar(key) {
  if (key === "offen") {
    return "var(--sev-high-bd)";
  }
  if (key === "moegliche_doh") {
    return "var(--sev-med-bd)";
  }
  if (key === "erwartungsgemaess") {
    return "var(--color-accent)";
  }
  return "var(--color-border)";
}

// Kategorie-Badge. Roh-Kategorie als data-cat (Klassen-Schluessel), angezeigter Text
// lokalisiert. Das Backend liefert nur die drei bekannten Kategorien; ein unbekannter
// key wird trotzdem ehrlich als roher key-Text gezeigt (kein stilles Umbiegen). Die
// Farbe macht CSS ueber [data-cat=...].
function CategoryBadge({ category, t }) {
  const key = category;
  const text = key in CATEGORY_RANK ? t(`report.dnsWatch.category.${key}`) : key;
  return (
    <span className="dns-report__cat" data-cat={key}>
      {text}
    </span>
  );
}

// Status-Zelle je Kontakt-Zeile. Quittiert -> dezenter Quittiert-Text. Sonst Aktiv.
// (KEIN NEU-Badge.)
function StatusZelle({ acknowledged, t }) {
  if (acknowledged) {
    return (
      <span className="dns-report__status dns-report__status--quittiert">
        {t("report.dnsWatch.status.quittiert")}
      </span>
    );
  }
  return (
    <span className="dns-report__status dns-report__status--aktiv">
      {t("report.dnsWatch.status.aktiv")}
    </span>
  );
}

// Eine Kennzahl-Kachel (grosse Zahl + dezentes Label).
function Kennzahl({ wert, label }) {
  return (
    <div className="dns-report__kennzahl">
      <span className="dns-report__kennzahl-wert">{wert}</span>
      <span className="dns-report__kennzahl-label">{label}</span>
    </div>
  );
}

// Eine Text-Kennzahl (Inhalt = beliebiger Knoten, z. B. CategoryBadge oder Text).
function TextKennzahl({ inhalt, label }) {
  return (
    <div className="dns-report__kennzahl dns-report__kennzahl--text">
      <span className="dns-report__kennzahl-text">{inhalt}</span>
      <span className="dns-report__kennzahl-label">{label}</span>
    </div>
  );
}

// Kategorie-Donut mit Legende. segmente = [{ key, wert, farbe, label }]. Mitte = mitte
// (Zahl) + mitteLabel. Geometrie wie CveReportView (Vollkreis-Donut, Umfang = 2πr,
// jedes Segment ein dash-Abschnitt; Start oben). Leere Summe -> nur die Bahn. Legende
// nur Stufen mit wert > 0.
function Donut({ segmente, mitte, mitteLabel, ariaLabel }) {
  const summe = segmente.reduce((acc, s) => acc + Math.max(0, s.wert), 0);
  const radius = 42;
  const umfang = 2 * Math.PI * radius;
  let offset = 0;

  return (
    <div className="dns-report__donut-block">
      <div className="dns-report__donut">
        <svg
          className="dns-report__donut-svg"
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
        <div className="dns-report__donut-mitte">
          <span className="dns-report__donut-summe">{mitte}</span>
          <span className="dns-report__donut-label">{mitteLabel}</span>
        </div>
      </div>
      <ul className="dns-report__legende">
        {segmente
          .filter((seg) => seg.wert > 0)
          .map((seg) => (
            <li key={`leg-${seg.key}`} className="dns-report__legende-zeile">
              <span
                className="dns-report__legende-punkt"
                style={{ background: seg.farbe }}
                aria-hidden="true"
              />
              <span className="dns-report__legende-label">{seg.label}</span>
              <span className="dns-report__legende-zahl dns-report__mono">{seg.wert}</span>
            </li>
          ))}
      </ul>
    </div>
  );
}

export default function DnsWatchReportView() {
  const { t, i18n } = useTranslation();

  // Geladener Bericht (null = noch nicht geladen / nicht vorhanden) + Lade-/Fehlerzustand.
  const [bericht, setBericht] = useState(null);
  const [laedt, setLaedt] = useState(false);
  const [fehler, setFehler] = useState(false);
  // Anzeige-Steuerung (reines Frontend, kein Reload).
  const [verteilModus, setVerteilModus] = useState("kategorie"); // "kategorie"|"programm"
  const [filter, setFilter] = useState("alle"); // alle|auffaellig|quittiert
  const [sortierung, setSortierung] = useState("kategorie"); // kategorie|kontakte|gegenstelle
  // Lokaler Zustand des PDF-Downloads (ueberschreibt NICHT den globalen Lade-Fehler).
  const [pdfLaedt, setPdfLaedt] = useState(false);
  const [pdfFehler, setPdfFehler] = useState(false);

  // PDF-Download anstossen. Setzt den lokalen Lade-/Fehler-State; der globale
  // fehler-State bleibt unberuehrt (Muster CveReportView.handlePdf).
  async function handlePdf() {
    setPdfFehler(false);
    setPdfLaedt(true);
    try {
      await fetchDnsWatchReportPdf();
    } catch {
      setPdfFehler(true);
    } finally {
      setPdfLaedt(false);
    }
  }

  // Laedt den Bericht einmalig. Fehler -> dezenter Hinweis, kein Absturz (Muster
  // CveReportView). t BEWUSST NICHT in den Deps (neue Referenz je Render -> Loop).
  useEffect(() => {
    let abgebrochen = false;

    (async () => {
      setLaedt(true);
      setFehler(false);
      try {
        const geladen = await fetchDnsWatchReport();
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

  // Gefilterte + sortierte Kontaktliste (flach, KEINE Host-Gruppierung). Stabile
  // Memo-Deps (kein t).
  const kontakte = useMemo(() => {
    if (!bericht) {
      return [];
    }

    // 1) Filter: auffaellig = !acknowledged && (offen|moegliche_doh),
    //    quittiert = acknowledged, alle = alles.
    let zeilen;
    if (filter === "auffaellig") {
      zeilen = bericht.contactRows.filter(
        (r) =>
          !r.acknowledged && (r.category === "offen" || r.category === "moegliche_doh"),
      );
    } else if (filter === "quittiert") {
      zeilen = bericht.contactRows.filter((r) => r.acknowledged);
    } else {
      zeilen = bericht.contactRows;
    }

    // 2) Sortierung. "kategorie" (Default): KEIN Umsortieren -- die Backend-Reihenfolge
    //    ist schon offen<doh<erwartungsgemaess, dann connectionCount desc, dann remoteIp.
    //    "kontakte" -> connectionCount desc ; "gegenstelle" -> remoteIp localeCompare.
    if (sortierung === "kontakte") {
      zeilen = [...zeilen].sort((a, b) => (b.connectionCount ?? 0) - (a.connectionCount ?? 0));
    } else if (sortierung === "gegenstelle") {
      zeilen = [...zeilen].sort((a, b) => (a.remoteIp ?? "").localeCompare(b.remoteIp ?? ""));
    }

    return zeilen;
  }, [bericht, filter, sortierung]);

  const sprache = i18n.language === "en" ? "en" : "de";
  // Erstelldatum des Berichts: heute, lokal formatiert. Reine Anzeige im Titelkopf und
  // in der Fusszeile (Muster CveReportView.erstelltDatum).
  const erstelltDatum = new Date().toLocaleDateString(sprache === "en" ? "en-US" : "de-DE", {
    year: "numeric",
    month: "long",
    day: "numeric",
  });

  // Ehrlicher Leerzustand: Bericht geladen, aber gar keine Kontakte erfasst.
  const istLeer =
    bericht && bericht.contactsTotal === 0 && bericht.contactRows.length === 0;

  // Donut-Segmente in fester CATEGORY_ORDER aus der categoryDistribution.
  const kategorieProKey = new Map(
    (bericht?.categoryDistribution ?? []).map((c) => [c.category, c.count]),
  );
  const donutSegmente = CATEGORY_ORDER.map((key) => ({
    key,
    wert: kategorieProKey.get(key) ?? 0,
    farbe: catColorVar(key),
    label: `${t(`report.dnsWatch.category.${key}`)} ${kategorieProKey.get(key) ?? 0}`,
  }));
  const donutSumme = donutSegmente.reduce((acc, s) => acc + s.wert, 0);

  return (
    <div className="dns-report">
      {/* ── 1. Bericht-Titelkopf: Logo + grosse Ueberschrift + Erstelldatum ──────
          Eigener Dokument-Kopf (NICHT die App-Navi). Der Hilfe-Anker bleibt am Titel. */}
      <header className="dns-report__kopf">
        <img className="dns-report__logo" src="/cernis-logo.png" alt="CERNIS PRO" />
        <div className="dns-report__kopf-text">
          <h3 className="dns-report__titel" id="help.report.dns_watch">
            {t("report.dnsWatch.titel")}
          </h3>
          <p className="dns-report__kopf-datum">
            {t("report.dnsWatch.kopf.erstellt", { datum: erstelltDatum })}
          </p>
        </div>
      </header>

      {fehler && (
        <div className="dns-report__fehler" role="note">
          {t("report.dnsWatch.ladeFehler")}
        </div>
      )}

      {/* ── 2. Ehrlicher Leerzustand: keine Grafiken/Tabellen ──────────────────── */}
      {istLeer ? (
        <div className="dns-report__leerzustand" role="note">
          <p className="dns-report__leerzustand-text">{t("report.dnsWatch.leerzustand")}</p>
        </div>
      ) : null}

      {/* ── 3. Bericht-Inhalt nur bei vorhandenen Kontakten ────────────────────── */}
      {bericht && !istLeer ? (
        <>
          {/* 3.1 Einleitung (Achse-B-Haltung in Klartext). */}
          <p className="dns-report__einleitung">{t("report.dnsWatch.einleitung")}</p>

          {/* 3.2 Kennzahlen (Zahl-Reihe). */}
          <div className="dns-report__kennzahlen">
            <Kennzahl
              wert={bericht.activeTotal}
              label={t("report.dnsWatch.kennzahl.aktiv")}
            />
            <Kennzahl
              wert={bericht.flaggedActive}
              label={t("report.dnsWatch.kennzahl.auffaellig")}
            />
            <Kennzahl
              wert={bericht.acknowledgedTotal}
              label={t("report.dnsWatch.kennzahl.quittiert")}
            />
            <Kennzahl
              wert={bericht.contactsTotal}
              label={t("report.dnsWatch.kennzahl.gesamt")}
            />
          </div>

          {/* 3.3 Kategorie-Donut (ein Donut, Segmente in CATEGORY_ORDER). */}
          <div className="dns-report__donut-paar">
            <Donut
              segmente={donutSegmente}
              mitte={donutSumme}
              mitteLabel={t("report.dnsWatch.donut.aktiv")}
              ariaLabel={t("report.dnsWatch.donut.aria", { anzahl: donutSumme })}
            />
          </div>

          {/* 3.4 Verteilung mit Umschalter (Kategorie <-> Programm). */}
          <Verteilung
            modus={verteilModus}
            onModus={setVerteilModus}
            categoryDistribution={bericht.categoryDistribution}
            appDistribution={bericht.appDistribution}
            t={t}
          />

          {/* 3.5 Flache Kontaktliste (KEINE Host-Gruppierung). */}
          <Kontaktliste
            zeilen={kontakte}
            filter={filter}
            onFilter={setFilter}
            sortierung={sortierung}
            onSortierung={setSortierung}
            t={t}
          />

          {/* 3.6 Grundlage der Einordnung (ehrlicher Beleg: verwendete Listen). */}
          <section className="dns-report__grundlage">
            <h4 className="dns-report__abschnitt-titel">
              {t("report.dnsWatch.grundlage.titel")}
            </h4>
            <p className="dns-report__grundlage-zeile">
              {`${t("report.dnsWatch.grundlage.erwartet")}: ${
                bericht.expectedServers.join(", ") || t("report.dnsWatch.grundlage.keine")
              }`}
            </p>
            <p className="dns-report__grundlage-zeile">
              {`${t("report.dnsWatch.grundlage.doh")}: ${
                bericht.dohProviders.join(", ") || t("report.dnsWatch.grundlage.keine")
              }`}
            </p>
          </section>

          {/* Achse-B-Fussnote: beschreibt und ordnet ein — kein Urteil. */}
          <p className="dns-report__fussnote">{t("report.dnsWatch.fussnote")}</p>

          {/* Bericht-Fusszeile (UNSER Inhalt, nicht der Browser-Druckfuss). */}
          <footer className="dns-report__fusszeile">
            {t("report.dnsWatch.fusszeile", { datum: erstelltDatum })}
          </footer>
        </>
      ) : null}

      {/* ── Aktionsleiste: Bericht als PDF herunterladen ───────────────────────── */}
      {bericht ? (
        <div className="dns-report__aktionen">
          <button
            type="button"
            className="dns-report__pdf"
            onClick={handlePdf}
            disabled={pdfLaedt}
          >
            {t("report.dnsWatch.pdf")}
          </button>
          {pdfFehler ? (
            <p className="dns-report__pdf-fehler" role="alert">
              {t("report.dnsWatch.pdfFehler")}
            </p>
          ) : null}
        </div>
      ) : null}

      {laedt && <div className="dns-report__laedt" aria-hidden="true" />}
    </div>
  );
}

// ── 3.4 Verteilung (Kategorie <-> Programm) ────────────────────────────────────
// Umschalter (zwei Toggle-Knoepfe, aria-pressed) + je Modus eine Tabelle. Die
// Reihenfolge kommt schon vom Backend sortiert -> unveraendert uebernehmen (NICHT neu
// sortieren). Kein Top-N: die Kategorien sind drei, die appDistribution ist kurz.
function Verteilung({ modus, onModus, categoryDistribution, appDistribution, t }) {
  const istKategorie = modus === "kategorie";
  // Kategorie-Zeilen in fester CATEGORY_ORDER (Badge-Optik), Wert aus der Verteilung.
  const katProKey = new Map(categoryDistribution.map((c) => [c.category, c.count]));
  const katZeilen = CATEGORY_ORDER.map((key) => ({ key, count: katProKey.get(key) ?? 0 }));

  return (
    <section className="dns-report__verteilung">
      <div className="dns-report__verteilung-kopf">
        <h4 className="dns-report__abschnitt-titel">{t("report.dnsWatch.muster.titel")}</h4>
        <div className="dns-report__toggle" role="group">
          <button
            type="button"
            className={
              istKategorie
                ? "dns-report__toggle-knopf dns-report__toggle-knopf--aktiv"
                : "dns-report__toggle-knopf"
            }
            aria-pressed={istKategorie}
            onClick={() => onModus("kategorie")}
          >
            {t("report.dnsWatch.muster.kategorie")}
          </button>
          <button
            type="button"
            className={
              !istKategorie
                ? "dns-report__toggle-knopf dns-report__toggle-knopf--aktiv"
                : "dns-report__toggle-knopf"
            }
            aria-pressed={!istKategorie}
            onClick={() => onModus("programm")}
          >
            {t("report.dnsWatch.muster.programm")}
          </button>
        </div>
      </div>

      {istKategorie ? (
        katZeilen.length > 0 ? (
          <table className="dns-report__tabelle">
            <thead>
              <tr>
                <th>{t("report.dnsWatch.spalteKat.kategorie")}</th>
                <th className="dns-report__num">{t("report.dnsWatch.spalteKat.kontakte")}</th>
              </tr>
            </thead>
            <tbody>
              {katZeilen.map((r) => (
                <tr key={`kat-${r.key}`} className="dns-report__zeile">
                  <td>
                    <CategoryBadge category={r.key} t={t} />
                  </td>
                  <td className="dns-report__num dns-report__mono">{r.count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="dns-report__leer">{t("report.dnsWatch.muster.leer")}</p>
        )
      ) : appDistribution.length > 0 ? (
        <table className="dns-report__tabelle">
          <thead>
            <tr>
              <th>{t("report.dnsWatch.spalteApp.programm")}</th>
              <th className="dns-report__num">{t("report.dnsWatch.spalteApp.kontakte")}</th>
            </tr>
          </thead>
          <tbody>
            {appDistribution.map((r, i) => (
              <tr key={`app-${i}`} className="dns-report__zeile">
                <td>{r.appName || "—"}</td>
                <td className="dns-report__num dns-report__mono">{r.count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p className="dns-report__leer">{t("report.dnsWatch.muster.leer")}</p>
      )}
    </section>
  );
}

// ── 3.5 Kontaktliste (flach, KEINE Host-Gruppierung) ───────────────────────────
// Filter-Chips (alle/auffaellig/quittiert) + Sortier-Auswahl (kategorie/kontakte/
// gegenstelle), beides reine Anzeige-Steuerung. Eine flache Tabelle der DNS-relevanten
// Aussenkontakte. Kein Top-N: die Liste ist die Detailebene und darf vollstaendig sein
// (Druck zeigt sie ohnehin komplett). Leere Auswahl -> Leertext.
function Kontaktliste({ zeilen, filter, onFilter, sortierung, onSortierung, t }) {
  const chips = [
    { id: "alle", label: t("report.dnsWatch.filter.alle") },
    { id: "auffaellig", label: t("report.dnsWatch.filter.auffaellig") },
    { id: "quittiert", label: t("report.dnsWatch.filter.quittiert") },
  ];

  return (
    <section className="dns-report__abschnitt">
      <h4 className="dns-report__abschnitt-titel dns-report__abschnitt-titel--num">
        <span className="dns-report__abschnitt-nummer">1</span>
        {t("report.dnsWatch.liste.titel")}
      </h4>

      {/* Steuerleiste: Filter-Chips links, Sortier-Auswahl rechts (im Druck weg). */}
      <div className="dns-report__steuerung">
        <div className="dns-report__chips" role="group">
          {chips.map((c) => (
            <button
              key={c.id}
              type="button"
              className={
                filter === c.id
                  ? "dns-report__chip dns-report__chip--aktiv"
                  : "dns-report__chip"
              }
              aria-pressed={filter === c.id}
              onClick={() => onFilter(c.id)}
            >
              {c.label}
            </button>
          ))}
        </div>
        <label className="dns-report__sortierung">
          <span className="dns-report__sortierung-label">
            {t("report.dnsWatch.sortierung.label")}
          </span>
          <select
            className="dns-report__sortierung-select"
            value={sortierung}
            onChange={(e) => onSortierung(e.target.value)}
          >
            <option value="kategorie">{t("report.dnsWatch.sortierung.kategorie")}</option>
            <option value="kontakte">{t("report.dnsWatch.sortierung.kontakte")}</option>
            <option value="gegenstelle">{t("report.dnsWatch.sortierung.gegenstelle")}</option>
          </select>
        </label>
      </div>

      {zeilen.length > 0 ? (
        <table className="dns-report__tabelle">
          <thead>
            <tr>
              <th>{t("report.dnsWatch.spalte.kategorie")}</th>
              <th>{t("report.dnsWatch.spalte.gegenstelle")}</th>
              <th>{t("report.dnsWatch.spalte.name")}</th>
              <th>{t("report.dnsWatch.spalte.programm")}</th>
              <th className="dns-report__num">{t("report.dnsWatch.spalte.kontakte")}</th>
              <th>{t("report.dnsWatch.spalte.status")}</th>
            </tr>
          </thead>
          <tbody>
            {zeilen.map((r, i) => (
              <tr key={`kontakt-${i}`} className="dns-report__zeile">
                <td>
                  <CategoryBadge category={r.category} t={t} />
                </td>
                <td className="dns-report__mono">{r.remoteIp}</td>
                <td>{r.hostname || "—"}</td>
                <td>{r.appName || "—"}</td>
                <td className="dns-report__num dns-report__mono">{r.connectionCount}</td>
                <td>
                  <StatusZelle acknowledged={r.acknowledged} t={t} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p className="dns-report__leer">{t("report.dnsWatch.tabelle.leer")}</p>
      )}
    </section>
  );
}
