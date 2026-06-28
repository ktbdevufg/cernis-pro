// Aussenkontakte-Bericht — In-App-Ansicht (CERNIS PRO 2.0, Etappe 3)
//
// Vierte Kachel des Reporting-Bereichs. Verdichtet den aggregierten Aussenkontakte-
// Bericht (GET /api/report/outbound) zu einer ruhigen Lesesicht: ein Bezugsrahmen-
// Dropdown (alle Aufzeichnungen oder eine), Kennzahlen oben (zwei Reihen), eine
// umschaltbare Verteilung (Land <-> Betreiber) als Balken, darunter die filter-/
// sortierbare Kontaktliste mit Bewertungs-Badge und ein Drucken-Knopf. Reine
// Lesesicht — greift NICHT ins Netz ein, mutiert nichts.
//
// Sie laedt selbst ueber fetchOutboundReport (useEffect mit abgebrochen-Flag, Lade-/
// Fehlerzustand wie InventoryReportView). Anders als die Vorlagen kennt sie einen
// Bezugsrahmen: ein eigener (einmaliger) useEffect laedt die waehlbaren Aufzeichnungen
// (Fehler still: leere Liste -> Dropdown zeigt nur "Alle"); der Haupt-useEffect haengt
// ausgewaehlteId in den Deps (Dropdown-Wechsel laedt neu). Achse B des Produkts: der
// Bericht BESCHREIBT und ORDNET EIN — er urteilt nicht. Filter/Sortierung/Umschalter/
// Lokale-Schalter sind reine Anzeige-Steuerung im Frontend (kein Reload). KEIN
// 404-Fall: leerer Stand ist ein DATUM (alle Zaehler 0 + leere Listen), kein Fehler
// -> ruhiger Leerzustand.
//
// Stil wie der Bestand: alle Texte ueber i18n, alle Farben ueber Tokens (tokens.css):
// sev-high fuer "Bedrohung", sev-med fuer "Tracker", dezent/neutral fuer "ohne". Nie
// feste Farben. t NIEMALS in useEffect/useMemo-Deps (instabile Referenz -> Loop);
// Memo-Strukturen tragen stabile Schluessel.

import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import {
  fetchOutboundReport,
  fetchOutboundReportPdf,
  fetchOutboundReportRecordings,
} from "../api/report.js";
import "./OutboundReportView.css";

// Wie viele Verteilungs-Balken bzw. Kontakt-Zeilen am Bildschirm hoechstens sichtbar
// sind; der Rest erscheint als "+ X weitere"-Klartext (kein stilles Abschneiden). Im
// Druck (CSS @media print) werden IMMER alle gezeigt.
const TOP_VERTEILUNG = 8;
const TOP_KONTAKTE = 15;

// Eine Kennzahl-Kachel (grosse Zahl + dezentes Label).
function Kennzahl({ wert, label }) {
  return (
    <div className="outbound-report__kennzahl">
      <span className="outbound-report__kennzahl-wert">{wert}</span>
      <span className="outbound-report__kennzahl-label">{label}</span>
    </div>
  );
}

// Bewertungs-Badge je Kontakt-Zeile. Bedrohung sticht (sev-high/crit-Ton) und gewinnt
// gegen Tracker; Tracker ist dezenter (sev-med-Ton); ohne Treffer ein neutraler "—".
// Roh-Listennamen wandern in den title (Einordnung stammt aus der jeweiligen Liste,
// nicht aus CERNIS). Texte i18n, Farben Token.
function BewertungBadge({ trackerLists, threatLists, t }) {
  if (threatLists.length > 0) {
    return (
      <span
        className="outbound-report__badge outbound-report__badge--bedrohung"
        title={t("report.outbound.badge.bedrohungTitel", {
          listen: threatLists.join(", "),
        })}
      >
        {t("report.outbound.bewertung.bedrohung")}
      </span>
    );
  }
  if (trackerLists.length > 0) {
    return (
      <span
        className="outbound-report__badge outbound-report__badge--tracker"
        title={t("report.outbound.badge.trackerTitel", {
          listen: trackerLists.join(", "),
        })}
      >
        {t("report.outbound.bewertung.tracker")}
      </span>
    );
  }
  return (
    <span className="outbound-report__badge outbound-report__badge--neutral">
      {t("report.outbound.bewertung.keine")}
    </span>
  );
}

export default function OutboundReportView() {
  const { t, i18n } = useTranslation();

  // Geladener Bericht (null = noch nicht geladen / nicht vorhanden) + Lade-/Fehlerzustand.
  const [bericht, setBericht] = useState(null);
  const [laedt, setLaedt] = useState(false);
  const [fehler, setFehler] = useState(false);
  // Bezugsrahmen: waehlbare Aufzeichnungen (Dropdown) + aktuelle Auswahl (null = alle).
  const [recordings, setRecordings] = useState([]);
  const [ausgewaehlteId, setAusgewaehlteId] = useState(null);
  // Anzeige-Steuerung (reines Frontend, kein Reload).
  const [verteilungModus, setVerteilungModus] = useState("country"); // "country"|"operator"
  const [filter, setFilter] = useState("alle"); // alle|auffaellig|lokal
  const [sortierung, setSortierung] = useState("kontakte"); // kontakte|name|land
  const [lokalAusblenden, setLokalAusblenden] = useState(true);
  // Lokaler Zustand des PDF-Downloads (ueberschreibt NICHT den globalen Lade-Fehler).
  const [pdfLaedt, setPdfLaedt] = useState(false);
  const [pdfFehler, setPdfFehler] = useState(false);

  // PDF-Download anstossen (Bezug = aktuelle Auswahl). Setzt den lokalen Lade-/Fehler-
  // State; der globale fehler-State bleibt unberuehrt (Muster InventoryReportView).
  async function handlePdf() {
    setPdfFehler(false);
    setPdfLaedt(true);
    try {
      await fetchOutboundReportPdf(ausgewaehlteId);
    } catch {
      setPdfFehler(true);
    } finally {
      setPdfLaedt(false);
    }
  }

  // Laedt die waehlbaren Aufzeichnungen EINMALIG fuers Dropdown. Fehler ist hier still:
  // leere Liste -> das Dropdown zeigt nur "Alle" (kein Fehlerbanner). t NICHT in Deps.
  useEffect(() => {
    let abgebrochen = false;

    (async () => {
      try {
        const geladen = await fetchOutboundReportRecordings();
        if (!abgebrochen) {
          setRecordings(geladen);
        }
      } catch {
        if (!abgebrochen) {
          setRecordings([]);
        }
      }
    })();

    return () => {
      abgebrochen = true;
    };
  }, []);

  // Laedt den Bericht fuer den gewaehlten Bezug. ausgewaehlteId IN den Deps -> ein
  // Dropdown-Wechsel laedt neu. Fehler -> dezenter Hinweis, kein Absturz (Muster
  // InventoryReportView). t BEWUSST NICHT in den Deps (neue Referenz je Render -> Loop).
  useEffect(() => {
    let abgebrochen = false;

    (async () => {
      setLaedt(true);
      setFehler(false);
      try {
        const geladen = await fetchOutboundReport(ausgewaehlteId);
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
  }, [ausgewaehlteId]);

  // Aktive Verteilungsquelle (Land bzw. Betreiber), nach count absteigend. Stabiler
  // Memo-Schluessel: bericht + Modus (kein t).
  const verteilung = useMemo(() => {
    if (!bericht) {
      return [];
    }
    const quelle =
      verteilungModus === "operator"
        ? bericht.operatorDistribution
        : bericht.countryDistribution;
    return [...quelle].sort((a, b) => b.count - a.count);
  }, [bericht, verteilungModus]);

  // Gefilterte + sortierte Kontakt-Zeilen fuer die Tabelle. lokalAusblenden wirft lokale
  // Zeilen raus (Default an); filter "auffaellig" zeigt nur Zeilen mit Tracker-/Bedroh-
  // Treffer, "lokal" zeigt NUR lokale (und ueberschreibt damit lokalAusblenden), "alle"
  // = Basis. Sortierung ordnet danach. Stabile Memo-Deps (kein t).
  const kontaktZeilen = useMemo(() => {
    if (!bericht) {
      return [];
    }

    let basis;
    if (filter === "lokal") {
      // Nur lokale Zeilen — lokalAusblenden ist hier bedeutungslos.
      basis = bericht.contactRows.filter((r) => r.isLocal);
    } else {
      basis = lokalAusblenden
        ? bericht.contactRows.filter((r) => !r.isLocal)
        : bericht.contactRows;
      if (filter === "auffaellig") {
        basis = basis.filter(
          (r) => r.trackerLists.length || r.threatLists.length,
        );
      }
    }

    const zeilen = [...basis];
    if (sortierung === "name") {
      zeilen.sort((a, b) =>
        (a.hostname || a.remoteIp).localeCompare(b.hostname || b.remoteIp),
      );
    } else if (sortierung === "land") {
      zeilen.sort((a, b) => (a.country ?? "").localeCompare(b.country ?? ""));
    } else {
      // "kontakte" (Default): meiste Kontakte zuerst.
      zeilen.sort((a, b) => (b.totalCount ?? 0) - (a.totalCount ?? 0));
    }
    return zeilen;
  }, [bericht, filter, sortierung, lokalAusblenden]);

  const sprache = i18n.language === "en" ? "en" : "de";
  // Erstelldatum des Berichts: heute, lokal formatiert. Reine Anzeige im Titelkopf und
  // in der Fusszeile (Muster InventoryReportView.erstelltDatum).
  const erstelltDatum = new Date().toLocaleDateString(sprache === "en" ? "en-US" : "de-DE", {
    year: "numeric",
    month: "long",
    day: "numeric",
  });

  // Ehrlicher Leerzustand: Bericht geladen, aber gar keine Aussenkontakte aufgezeichnet.
  const istLeer = bericht && bericht.contactsTotal === 0;

  return (
    <div className="outbound-report">
      {/* ── 1. Bericht-Titelkopf: Logo + grosse Ueberschrift + Erstelldatum ──────
          Eigener Dokument-Kopf (NICHT die App-Navi). Der Hilfe-Anker bleibt am Titel. */}
      <header className="outbound-report__kopf">
        <img className="outbound-report__logo" src="/cernis-logo.png" alt="CERNIS PRO" />
        <div className="outbound-report__kopf-text">
          <h3 className="outbound-report__titel" id="help.report.outbound">
            {t("report.outbound.titel")}
          </h3>
          <p className="outbound-report__kopf-datum">
            {t("report.outbound.kopf.erstellt", { datum: erstelltDatum })}
          </p>
        </div>
      </header>

      {/* Bezugsrahmen-Dropdown: nur wenn es waehlbare Aufzeichnungen gibt. value="" =
          alle, sonst die gewaehlte Aufzeichnung. Im Druck blendet CSS es aus. */}
      {recordings.length > 0 ? (
        <div className="outbound-report__bezug">
          <label className="outbound-report__bezug-label">
            <span>{t("report.outbound.bezug.label")}</span>
            <select
              className="outbound-report__bezug-select"
              value={ausgewaehlteId ?? ""}
              onChange={(e) => setAusgewaehlteId(e.target.value || null)}
            >
              <option value="">{t("report.outbound.bezug.alle")}</option>
              {recordings.map((rec) => (
                <option key={rec.id} value={rec.id}>
                  {rec.label}
                </option>
              ))}
            </select>
          </label>
        </div>
      ) : null}

      {fehler && (
        <div className="outbound-report__fehler" role="note">
          {t("report.outbound.ladeFehler")}
        </div>
      )}

      {/* ── 2. Ehrlicher Leerzustand: keine Grafiken/Tabellen ──────────────────── */}
      {istLeer ? (
        <div className="outbound-report__leerzustand" role="note">
          <p className="outbound-report__leerzustand-text">
            {t("report.outbound.leerzustand")}
          </p>
        </div>
      ) : null}

      {/* ── 3. Bericht-Inhalt nur bei vorhandenen Aussenkontakten ──────────────── */}
      {bericht && !istLeer ? (
        <>
          {/* 3.1 Einleitung (Achse-B-Haltung in Klartext). */}
          <p className="outbound-report__einleitung">{t("report.outbound.einleitung")}</p>

          {/* 3.2 Kennzahlen: zwei Reihen. */}
          <div className="outbound-report__kennzahlen">
            <Kennzahl
              wert={bericht.remoteTotal}
              label={t("report.outbound.kennzahl.gegenstellen")}
            />
            <Kennzahl
              wert={bericht.connectionTotal}
              label={t("report.outbound.kennzahl.verbindungen")}
            />
            <Kennzahl
              wert={bericht.countriesTotal}
              label={t("report.outbound.kennzahl.laender")}
            />
            <Kennzahl
              wert={bericht.operatorsTotal}
              label={t("report.outbound.kennzahl.betreiber")}
            />
          </div>
          <div className="outbound-report__kennzahlen">
            <Kennzahl
              wert={bericht.flaggedContacts}
              label={t("report.outbound.kennzahl.auffaellig")}
            />
            <Kennzahl
              wert={bericht.trackerContacts}
              label={t("report.outbound.kennzahl.tracker")}
            />
            <Kennzahl
              wert={bericht.threatContacts}
              label={t("report.outbound.kennzahl.bedrohung")}
            />
            <Kennzahl
              wert={bericht.localTotal}
              label={t("report.outbound.kennzahl.lokal")}
            />
          </div>

          {/* 3.3 Verteilung mit Umschalter (Land <-> Betreiber). */}
          <Verteilung
            eintraege={verteilung}
            modus={verteilungModus}
            onModus={setVerteilungModus}
            t={t}
          />

          {/* 3.4 Kontaktliste (Filter-Chips + Sortier-Auswahl + Lokal-Schalter + Tabelle). */}
          <KontaktListe
            zeilen={kontaktZeilen}
            filter={filter}
            onFilter={setFilter}
            sortierung={sortierung}
            onSortierung={setSortierung}
            lokalAusblenden={lokalAusblenden}
            onLokalAusblenden={setLokalAusblenden}
            t={t}
          />

          {/* Achse-B-Fussnote: der Bericht beschreibt und ordnet ein — kein Urteil. */}
          <p className="outbound-report__fussnote">{t("report.outbound.fussnote")}</p>

          {/* Bericht-Fusszeile (UNSER Inhalt, nicht der Browser-Druckfuss). */}
          <footer className="outbound-report__fusszeile">
            {t("report.outbound.fusszeile", { datum: erstelltDatum })}
          </footer>
        </>
      ) : null}

      {/* ── Aktionsleiste: Bericht als PDF herunterladen ───────────────────────── */}
      {bericht ? (
        <div className="outbound-report__aktionen">
          <button
            type="button"
            className="outbound-report__pdf"
            onClick={handlePdf}
            disabled={pdfLaedt}
          >
            {t("report.outbound.pdf")}
          </button>
          {pdfFehler ? (
            <p className="outbound-report__pdf-fehler" role="alert">
              {t("report.outbound.pdfFehler")}
            </p>
          ) : null}
        </div>
      ) : null}

      {laedt && <div className="outbound-report__laedt" aria-hidden="true" />}
    </div>
  );
}

// ── 3.3 Verteilung (Land <-> Betreiber) ───────────────────────────────────────
// Umschalter (zwei Toggle-Knoepfe, aria-pressed) + horizontale Balken. Es werden
// IMMER ALLE Eintraege gerendert; am Bildschirm blendet CSS die ueber TOP_VERTEILUNG
// hinausgehenden Zeilen aus (--ueberzaehlig) und zeigt die "+ X weitere"-Zeile. Im
// Druck dreht @media print das um: alle sichtbar, "weitere" weg. Balkenbreite relativ
// zum groessten count ueber ALLE Eintraege. Leerer Label-Wert -> i18n-"(unbekannt)".
function Verteilung({ eintraege, modus, onModus, t }) {
  const rest = eintraege.length - TOP_VERTEILUNG;
  const maxCount = eintraege.reduce((acc, e) => Math.max(acc, e.count), 0) || 1;

  return (
    <section className="outbound-report__verteilung">
      <div className="outbound-report__verteilung-kopf">
        <h4 className="outbound-report__abschnitt-titel">
          {t("report.outbound.verteilung.titel")}
        </h4>
        <div className="outbound-report__toggle" role="group">
          <button
            type="button"
            className={
              modus === "country"
                ? "outbound-report__toggle-knopf outbound-report__toggle-knopf--aktiv"
                : "outbound-report__toggle-knopf"
            }
            aria-pressed={modus === "country"}
            onClick={() => onModus("country")}
          >
            {t("report.outbound.verteilung.land")}
          </button>
          <button
            type="button"
            className={
              modus === "operator"
                ? "outbound-report__toggle-knopf outbound-report__toggle-knopf--aktiv"
                : "outbound-report__toggle-knopf"
            }
            aria-pressed={modus === "operator"}
            onClick={() => onModus("operator")}
          >
            {t("report.outbound.verteilung.betreiber")}
          </button>
        </div>
      </div>

      {eintraege.length > 0 ? (
        <>
          <div className="outbound-report__balken-liste">
            {eintraege.map((e, i) => {
              const label =
                (modus === "operator" ? e.operator : e.country) ||
                t("report.outbound.verteilung.unbekannt");
              return (
                <div
                  key={`vert-${i}`}
                  className={
                    i >= TOP_VERTEILUNG
                      ? "outbound-report__balken-zeile outbound-report__balken-zeile--ueberzaehlig"
                      : "outbound-report__balken-zeile"
                  }
                >
                  <span className="outbound-report__balken-label" title={label}>
                    {label}
                  </span>
                  <div className="outbound-report__balken-bahn">
                    <div
                      className="outbound-report__balken-fueller"
                      style={{ width: `${((e.count / maxCount) * 100).toFixed(1)}%` }}
                    />
                  </div>
                  <span className="outbound-report__balken-zahl outbound-report__mono">
                    {e.count}
                  </span>
                </div>
              );
            })}
          </div>
          {rest > 0 ? (
            <p className="outbound-report__balken-rest">
              {t("report.outbound.verteilung.weitere", { anzahl: rest })}
            </p>
          ) : null}
        </>
      ) : (
        <p className="outbound-report__leer">{t("report.outbound.verteilung.leer")}</p>
      )}
    </section>
  );
}

// ── 3.4 Kontaktliste ──────────────────────────────────────────────────────────
// Nummerierter Abschnitt mit Filter-Chips (alle/auffaellig/lokal), Sortier-Auswahl
// (kontakte/name/land) und einem "Lokale ausblenden"-Schalter. Alles reine Anzeige-
// Steuerung. Tabelle: Gegenstelle (mono) | Name | Land | Betreiber | App | Kontakte
// (num, mono) | Bewertung. Es werden IMMER ALLE Zeilen gerendert; am Bildschirm
// blendet CSS die ueber TOP_KONTAKTE hinausgehenden aus und zeigt die "+ X weitere ·
// im PDF vollstaendig"-Zeile; im Druck alle sichtbar. Leere Auswahl -> Leertext.
function KontaktListe({
  zeilen,
  filter,
  onFilter,
  sortierung,
  onSortierung,
  lokalAusblenden,
  onLokalAusblenden,
  t,
}) {
  const rest = zeilen.length - TOP_KONTAKTE;
  const chips = [
    { id: "alle", label: t("report.outbound.filter.alle") },
    { id: "auffaellig", label: t("report.outbound.filter.auffaellig") },
    { id: "lokal", label: t("report.outbound.filter.lokal") },
  ];

  return (
    <section className="outbound-report__abschnitt">
      <h4 className="outbound-report__abschnitt-titel outbound-report__abschnitt-titel--num">
        <span className="outbound-report__abschnitt-nummer">1</span>
        {t("report.outbound.liste.titel")}
      </h4>

      {/* Steuerleiste: Filter-Chips + Lokal-Schalter links, Sortier-Auswahl rechts
          (im Druck weg). */}
      <div className="outbound-report__steuerung">
        <div className="outbound-report__steuerung-links">
          <div className="outbound-report__chips" role="group">
            {chips.map((c) => (
              <button
                key={c.id}
                type="button"
                className={
                  filter === c.id
                    ? "outbound-report__chip outbound-report__chip--aktiv"
                    : "outbound-report__chip"
                }
                aria-pressed={filter === c.id}
                onClick={() => onFilter(c.id)}
              >
                {c.label}
              </button>
            ))}
          </div>
          <label className="outbound-report__schalter">
            <input
              type="checkbox"
              checked={lokalAusblenden}
              onChange={(e) => onLokalAusblenden(e.target.checked)}
            />
            <span>{t("report.outbound.schalter.lokaleAusblenden")}</span>
          </label>
        </div>
        <label className="outbound-report__sortierung">
          <span className="outbound-report__sortierung-label">
            {t("report.outbound.sortierung.label")}
          </span>
          <select
            className="outbound-report__sortierung-select"
            value={sortierung}
            onChange={(e) => onSortierung(e.target.value)}
          >
            <option value="kontakte">{t("report.outbound.sortierung.kontakte")}</option>
            <option value="name">{t("report.outbound.sortierung.name")}</option>
            <option value="land">{t("report.outbound.sortierung.land")}</option>
          </select>
        </label>
      </div>

      {zeilen.length > 0 ? (
        <>
          <table className="outbound-report__tabelle">
            <thead>
              <tr>
                <th>{t("report.outbound.spalte.gegenstelle")}</th>
                <th>{t("report.outbound.spalte.name")}</th>
                <th>{t("report.outbound.spalte.land")}</th>
                <th>{t("report.outbound.spalte.betreiber")}</th>
                <th>{t("report.outbound.spalte.app")}</th>
                <th className="outbound-report__num">
                  {t("report.outbound.spalte.kontakte")}
                </th>
                <th>{t("report.outbound.spalte.bewertung")}</th>
              </tr>
            </thead>
            <tbody>
              {zeilen.map((r, i) => (
                <tr
                  key={`kontakt-${i}`}
                  className={
                    i >= TOP_KONTAKTE
                      ? "outbound-report__zeile outbound-report__zeile--ueberzaehlig"
                      : "outbound-report__zeile"
                  }
                >
                  <td className="outbound-report__mono">{r.remoteIp}</td>
                  <td>{r.hostname || "—"}</td>
                  <td>{r.country || "—"}</td>
                  <td>{r.operator || "—"}</td>
                  <td>{r.appName || "—"}</td>
                  <td className="outbound-report__num outbound-report__mono">
                    {r.totalCount}
                  </td>
                  <td>
                    <BewertungBadge
                      trackerLists={r.trackerLists}
                      threatLists={r.threatLists}
                      t={t}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {rest > 0 ? (
            <p className="outbound-report__balken-rest">
              {t("report.outbound.liste.weitere", { anzahl: rest })}
            </p>
          ) : null}
        </>
      ) : (
        <p className="outbound-report__leer">{t("report.outbound.tabelle.leer")}</p>
      )}
    </section>
  );
}
