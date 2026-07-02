// DNS-Waechter-Bericht — In-App-Ansicht (CERNIS PRO 2.0, Etappe 3 + 6)
//
// Fuenfte Kachel des Reporting-Bereichs. Verdichtet den aggregierten DNS-Waechter-
// Bericht zu einer ruhigen Lesesicht. Seit Etappe 6 traegt die View OBEN einen
// Bezugsrahmen-Umschalter (Optik wie die DnsWatchScreen-Reiter):
//   "Dieser Rechner"  -> die BESTEHENDE host-lokale Sicht (GET /api/report/dns-watch),
//                        UNVERAENDERT als HostBericht ausgelagert.
//   "Umgehung im Netz" -> die NEUE netzweite Sicht (GET /api/report/dns-bypass mit
//                        Aufzeichnungs-Auswahl), als NetzBericht.
// Der Umschalter-Zustand ist reiner Frontend-State im Shell-Container; beide
// Teilsichten laden je fuer sich (eigener useEffect mit abgebrochen-Flag). Konsistent
// zur Live-View DnsWatchScreen (zwei Reiter) und zum Aussenkontakte-Bericht
// (Aufzeichnungs-Dropdown).
//
// Achse B des Produkts: der Bericht BESCHREIBT und ORDNET EIN — er urteilt nicht.
// Filter/Sortierung/Umschalter sind reine Anzeige-Steuerung im Frontend (kein Reload).
// KEIN 404-Fall: leerer Stand ist ein DATUM (alle Zaehler 0 + leere Listen), kein
// Fehler -> ruhiger Leerzustand.
//
// Kategorie-Optik ueber eigene dns-report__cat-Klassen (data-cat-Schluessel), aber
// nur bestehende Token-Variablen. Nie feste Farben. t NIEMALS in useEffect/useMemo-
// Deps (instabile Referenz -> Loop).

import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import {
  fetchDnsBypassReport,
  fetchDnsBypassReportPdf,
  fetchDnsBypassReportRecordings,
  fetchDnsWatchReport,
  fetchDnsWatchReportPdf,
} from "../api/report.js";
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

// ── Shell-Container: Bezugsrahmen-Umschalter + je Bezug eine Teilsicht ──────────
// Der einzige neue Zustand hier ist der Bezug ("host"|"netz") — reiner Frontend-State,
// Reihenfolge verbindlich host-lokal zuerst (der Bestand), dann netzweit (das Neue),
// wie im DnsWatchScreen. Beide Teilsichten laden je fuer sich; nur die aktive ist
// gemountet (die andere haelt keine Poll-/Ladelast). t NIEMALS in Deps — hier ohne
// Effekt, aber die Regel gilt.
export default function DnsWatchReportView() {
  const { t } = useTranslation();

  // Aktiver Bezugsrahmen (host-lokal zuerst).
  const [bezug, setBezug] = useState("host");

  return (
    <div className="dns-report">
      {/* Bezugsrahmen-Umschalter (Optik der DnsWatchScreen-Reiter). Im Druck weg. */}
      <div className="dns-report__bezug-reiter" role="tablist">
        <button
          type="button"
          role="tab"
          aria-selected={bezug === "host"}
          className={
            bezug === "host"
              ? "dns-report__bezug-knopf dns-report__bezug-knopf--aktiv"
              : "dns-report__bezug-knopf"
          }
          onClick={() => setBezug("host")}
        >
          {t("report.dnsBypass.umschalter.host")}
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={bezug === "netz"}
          className={
            bezug === "netz"
              ? "dns-report__bezug-knopf dns-report__bezug-knopf--aktiv"
              : "dns-report__bezug-knopf"
          }
          onClick={() => setBezug("netz")}
        >
          {t("report.dnsBypass.umschalter.netz")}
        </button>
      </div>

      {bezug === "host" ? <HostBericht t={t} /> : <NetzBericht t={t} />}
    </div>
  );
}

// ── "Dieser Rechner": host-lokale Sicht (UNVERAENDERT aus Etappe 3) ─────────────
// Bis auf die Auslagerung in eine eigene Komponente + den durchgereichten t identisch
// zum bisherigen Bericht: eigener useEffect (fetchDnsWatchReport), Kategorie-Donut,
// Verteilungs-Umschalter (Kategorie/Programm), flache Kontaktliste, Grundlage-Block,
// PDF ueber fetchDnsWatchReportPdf. Der aeussere .dns-report-Wrapper liegt jetzt im
// Shell-Container; hier bleibt der Inhalt.
function HostBericht({ t }) {
  const { i18n } = useTranslation();

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
    <>
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
    </>
  );
}

// ── "Umgehung im Netz": netzweite Sicht (NEU, Etappe 6) ─────────────────────────
// Naht wie der Aussenkontakte-Bericht: ein eigener (einmaliger) useEffect laedt die
// waehlbaren Aufzeichnungen (Fehler still: leere Liste -> Dropdown zeigt nur "Alle");
// der Haupt-useEffect haengt ausgewaehlteId in den Deps (Dropdown-Wechsel laedt neu).
// Inhalt: Kennzahlen (queriesTotal/bypassTotal/expectedTotal/bypassDevices), die
// Resolver-Verteilung als schlichte Balken-Tabelle, die bypass_rows als flache Liste
// (Geraet + DoH-Badge + Ziel + Anfragen + Beispiel-Qnames). Ehrlicher Leerzustand.
// PDF ueber fetchDnsBypassReportPdf(ausgewaehlteId). t NIEMALS in Deps.
function NetzBericht({ t }) {
  const { i18n } = useTranslation();

  // Geladener Bericht (null = noch nicht geladen / nicht vorhanden) + Lade-/Fehlerzustand.
  const [bericht, setBericht] = useState(null);
  const [laedt, setLaedt] = useState(false);
  const [fehler, setFehler] = useState(false);
  // Bezugsrahmen: waehlbare Aufzeichnungen (Dropdown) + aktuelle Auswahl (null = alle).
  const [recordings, setRecordings] = useState([]);
  const [ausgewaehlteId, setAusgewaehlteId] = useState(null);
  // Lokaler Zustand des PDF-Downloads (ueberschreibt NICHT den globalen Lade-Fehler).
  const [pdfLaedt, setPdfLaedt] = useState(false);
  const [pdfFehler, setPdfFehler] = useState(false);

  // PDF-Download anstossen (Bezug = aktuelle Auswahl). Setzt den lokalen Lade-/Fehler-
  // State; der globale fehler-State bleibt unberuehrt (Muster OutboundReportView).
  async function handlePdf() {
    setPdfFehler(false);
    setPdfLaedt(true);
    try {
      await fetchDnsBypassReportPdf(ausgewaehlteId);
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
        const geladen = await fetchDnsBypassReportRecordings();
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
  // OutboundReportView). t BEWUSST NICHT in den Deps (neue Referenz je Render -> Loop).
  useEffect(() => {
    let abgebrochen = false;

    (async () => {
      setLaedt(true);
      setFehler(false);
      try {
        const geladen = await fetchDnsBypassReport(ausgewaehlteId);
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

  // Resolver-Verteilung nach count absteigend fuer die Balken-Tabelle. Stabile
  // Memo-Deps (kein t).
  const resolver = useMemo(() => {
    if (!bericht) {
      return [];
    }
    return [...bericht.resolverDistribution].sort((a, b) => b.count - a.count);
  }, [bericht]);

  const sprache = i18n.language === "en" ? "en" : "de";
  // Erstelldatum des Berichts: heute, lokal formatiert (Muster OutboundReportView).
  const erstelltDatum = new Date().toLocaleDateString(sprache === "en" ? "en-US" : "de-DE", {
    year: "numeric",
    month: "long",
    day: "numeric",
  });

  // Zwei ehrliche Leerzustaende (Muster der Live-View-Texte): gibt es gar keine
  // Aufzeichnung zur Auswahl, fehlt die Netz-Voraussetzung; gibt es eine, aber keine
  // Umgehung, ist das ein Datum (moeglicherweise ohne Netz-Sicht).
  const keineAufzeichnung = recordings.length === 0;
  const istLeer = bericht && bericht.bypassTotal === 0 && bericht.bypassRows.length === 0;

  return (
    <>
      {/* ── 1. Bericht-Titelkopf: Logo + grosse Ueberschrift + Erstelldatum ────── */}
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

      {/* Bezugsrahmen-Dropdown: nur wenn es waehlbare Aufzeichnungen gibt. value="" =
          alle, sonst die gewaehlte Aufzeichnung. Im Druck blendet CSS es aus. */}
      {recordings.length > 0 ? (
        <div className="dns-report__bezug">
          <label className="dns-report__bezug-label">
            <span>{t("report.dnsBypass.bezug.label")}</span>
            <select
              className="dns-report__bezug-select"
              value={ausgewaehlteId ?? ""}
              onChange={(e) => setAusgewaehlteId(e.target.value || null)}
            >
              <option value="">{t("report.dnsBypass.bezug.alle")}</option>
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
        <div className="dns-report__fehler" role="note">
          {t("report.dnsBypass.ladeFehler")}
        </div>
      )}

      {/* ── 2. Ehrlicher Leerzustand: keine Aufzeichnung ODER keine Umgehung ───── */}
      {keineAufzeichnung ? (
        <div className="dns-report__leerzustand" role="note">
          <p className="dns-report__leerzustand-text">
            {t("report.dnsBypass.leerzustandKeineAufzeichnung")}
          </p>
        </div>
      ) : istLeer ? (
        <div className="dns-report__leerzustand" role="note">
          <p className="dns-report__leerzustand-text">
            {t("report.dnsBypass.leerzustandKeineUmgehung")}
          </p>
        </div>
      ) : null}

      {/* ── 3. Bericht-Inhalt nur bei vorhandener Umgehung ─────────────────────── */}
      {bericht && !keineAufzeichnung && !istLeer ? (
        <>
          {/* 3.1 Einleitung (Achse-B-Haltung in Klartext). */}
          <p className="dns-report__einleitung">{t("report.dnsBypass.einleitung")}</p>

          {/* 3.2 Kennzahlen (Zahl-Reihe): Umgeher / Geraete / Anfragen / erwartet. */}
          <div className="dns-report__kennzahlen">
            <Kennzahl
              wert={bericht.bypassTotal}
              label={t("report.dnsBypass.kennzahl.umgeher")}
            />
            <Kennzahl
              wert={bericht.bypassDevices}
              label={t("report.dnsBypass.kennzahl.geraete")}
            />
            <Kennzahl
              wert={bericht.queriesTotal}
              label={t("report.dnsBypass.kennzahl.anfragen")}
            />
            <Kennzahl
              wert={bericht.expectedTotal}
              label={t("report.dnsBypass.kennzahl.erwartet")}
            />
          </div>

          {/* 3.3 Resolver-Verteilung (fremde Ziel-IPs) als schlichte Balken-Tabelle. */}
          <ResolverVerteilung eintraege={resolver} t={t} />

          {/* 3.4 Umgeher-Liste (flach). */}
          <UmgeherListe zeilen={bericht.bypassRows} t={t} />

          {/* 3.5 Grundlage der Einordnung (ehrlicher Beleg: erwartete DNS-Server). */}
          <section className="dns-report__grundlage">
            <h4 className="dns-report__abschnitt-titel">
              {t("report.dnsBypass.grundlage.titel")}
            </h4>
            <p className="dns-report__grundlage-zeile">
              {`${t("report.dnsBypass.grundlage.erwartet")}: ${
                bericht.expectedServers.join(", ") || t("report.dnsBypass.grundlage.keine")
              }`}
            </p>
          </section>

          {/* Achse-B-Fussnote: beschreibt und ordnet ein — kein Urteil. */}
          <p className="dns-report__fussnote">{t("report.dnsBypass.fussnote")}</p>

          {/* Bericht-Fusszeile (UNSER Inhalt, nicht der Browser-Druckfuss). */}
          <footer className="dns-report__fusszeile">
            {t("report.dnsBypass.fusszeile", { datum: erstelltDatum })}
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
            {t("report.dnsBypass.pdf")}
          </button>
          {pdfFehler ? (
            <p className="dns-report__pdf-fehler" role="alert">
              {t("report.dnsBypass.pdfFehler")}
            </p>
          ) : null}
        </div>
      ) : null}

      {laedt && <div className="dns-report__laedt" aria-hidden="true" />}
    </>
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

// ── 3.3 (netzweit) Resolver-Verteilung (fremde Ziel-IPs) ───────────────────────
// Schlichte Balken-Tabelle: je fremdem Resolver (dst_ip) ein Balken relativ zum
// groessten count, plus die Zahl. Reihenfolge kommt sortiert (count desc) rein. Leere
// Verteilung -> ruhiger Leertext (Muster OutboundReportView.Verteilung, aber ohne
// Umschalter/Top-N: die Liste fremder Resolver ist kurz).
function ResolverVerteilung({ eintraege, t }) {
  const maxCount = eintraege.reduce((acc, e) => Math.max(acc, e.count), 0) || 1;

  return (
    <section className="dns-report__verteilung">
      <div className="dns-report__verteilung-kopf">
        <h4 className="dns-report__abschnitt-titel">
          {t("report.dnsBypass.resolver.titel")}
        </h4>
      </div>

      {eintraege.length > 0 ? (
        <div className="dns-report__balken-liste">
          {eintraege.map((e, i) => (
            <div key={`res-${i}`} className="dns-report__balken-zeile">
              <span
                className="dns-report__balken-label dns-report__mono"
                title={e.resolverName ? `${e.dstIp} (${e.resolverName})` : e.dstIp}
              >
                {e.dstIp}
                {e.resolverName && (
                  <span className="dns-report__resolver-name"> ({e.resolverName})</span>
                )}
              </span>
              <div className="dns-report__balken-bahn">
                <div
                  className="dns-report__balken-fueller"
                  style={{ width: `${((e.count / maxCount) * 100).toFixed(1)}%` }}
                />
              </div>
              <span className="dns-report__balken-zahl dns-report__mono">{e.count}</span>
            </div>
          ))}
        </div>
      ) : (
        <p className="dns-report__leer">{t("report.dnsBypass.resolver.leer")}</p>
      )}
    </section>
  );
}

// ── 3.4 (netzweit) Umgeher-Liste (flach) ───────────────────────────────────────
// Eine flache Tabelle der Umgeher: Geraet (device_name, sonst src_ip; DoH-Badge, wenn
// is_doh) | Ziel-IP | Anfragen | Beispiel-Namen (sample_qnames, kompakt). Kein Filter/
// keine Sortierung/keine Quittierung (die netzweiten Routen kennen keine Ack). Kein
// Top-N: die Liste ist die Detailebene und darf vollstaendig sein. Leer -> Leertext.
function UmgeherListe({ zeilen, t }) {
  return (
    <section className="dns-report__abschnitt">
      <h4 className="dns-report__abschnitt-titel dns-report__abschnitt-titel--num">
        <span className="dns-report__abschnitt-nummer">1</span>
        {t("report.dnsBypass.liste.titel")}
      </h4>

      {zeilen.length > 0 ? (
        <table className="dns-report__tabelle">
          <thead>
            <tr>
              <th>{t("report.dnsBypass.spalte.geraet")}</th>
              <th>{t("report.dnsBypass.spalte.ziel")}</th>
              <th className="dns-report__num">{t("report.dnsBypass.spalte.anfragen")}</th>
              <th>{t("report.dnsBypass.spalte.beispiele")}</th>
            </tr>
          </thead>
          <tbody>
            {zeilen.map((r, i) => {
              // Titel: Geraetename, sonst die Quell-IP. Ist der Name da, wandert die
              // Quell-IP dezent darunter (S3-ehrlich: nur vorhandene Felder).
              const titel = r.deviceName ?? r.srcIp;
              const zeigeIpUnten = r.deviceName !== null;
              const beispiele = r.sampleQnames.slice(0, 3);
              return (
                <tr key={`umgeher-${i}`} className="dns-report__zeile">
                  <td>
                    <span className="dns-report__geraet">
                      <span className="dns-report__geraet-titel dns-report__mono">{titel}</span>
                      {r.isDoh ? (
                        <span className="dns-report__cat" data-cat="moegliche_doh">
                          {r.dohSourceName
                            ? t("report.dnsBypass.dohBadgeNamed", { quelle: r.dohSourceName })
                            : t("report.dnsBypass.dohBadge")}
                        </span>
                      ) : null}
                      {zeigeIpUnten ? (
                        <span className="dns-report__geraet-ip dns-report__mono">
                          {r.srcIp}
                        </span>
                      ) : null}
                    </span>
                  </td>
                  <td className="dns-report__mono">
                    {r.dstIp}
                    {r.resolverName && (
                      <span className="dns-report__resolver-name"> ({r.resolverName})</span>
                    )}
                  </td>
                  <td className="dns-report__num dns-report__mono">{r.queryCount}</td>
                  <td className="dns-report__qnames dns-report__mono">
                    {beispiele.length > 0 ? beispiele.join(", ") : "—"}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      ) : (
        <p className="dns-report__leer">{t("report.dnsBypass.tabelle.leer")}</p>
      )}
    </section>
  );
}
