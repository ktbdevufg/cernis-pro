// Benutzerhandbuch-Ansicht (CERNIS PRO 2.0)
// Eigener Modus (kein Reiter), erreichbar über den „Handbuch"-Knopf in der
// Kopfzeile. Nutzt das function-shell-Muster der übrigen Bereiche (Zurück-Weg +
// Titel) wie SettingsView und bekommt onClose als Prop.
//
// Inhaltsquelle ist AUSSCHLIESSLICH help_content.json (Ausspielweg B: die
// lang-Texte). baueKategorien/kategorieAnker/springeZu und die Abschnitt-
// Inhalte (Titel, Vorläufig, Absatz-Split, Links) bleiben unverändert. Neu in
// V3: gerahmtes zweispaltiges Layout, mitlaufender Kapitelname (Observer),
// persistente Schriftgröße (manual_font_scale) und eine Inline-Suche.

import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { FunctionShell } from "../components/AreaShell.jsx";
import { fetchSettings, updateSetting } from "../api/settings.js";
import { fetchManualPdf } from "../api/report.js";
import { CODES, mitCode } from "../lib/fehlercodes.js";
import helpContent from "../lib/help_content.json";
import "./ManualView.css";

// Einträge in JSON-Reihenfolge, nach `kategorie` gruppiert. Die Reihenfolge der
// Kategorien folgt dem ERSTEN Auftreten in der JSON (redaktionell gewollt, nicht
// alphabetisch). Der _meta-Schlüssel ist kein Eintrag und wird übersprungen.
//
// Reines Lesen aus dem Import -> einmal pro Modul berechnet, nicht pro Render.
function baueKategorien() {
  const kategorien = []; // [{ kategorie, eintraege: [{ helpId, eintrag }] }]
  const indexNachName = new Map();

  for (const [helpId, eintrag] of Object.entries(helpContent)) {
    if (helpId === "_meta") {
      continue;
    }
    const name = eintrag.kategorie;
    if (!indexNachName.has(name)) {
      indexNachName.set(name, kategorien.length);
      kategorien.push({ kategorie: name, eintraege: [] });
    }
    kategorien[indexNachName.get(name)].eintraege.push({ helpId, eintrag });
  }

  return kategorien;
}

const KATEGORIEN = baueKategorien();

// Schriftgrößen-Stufen (Ziel 3). Persistiert als manual_font_scale in der DB.
// Wert ist der CSS-Skalierungsfaktor; unbekannte/fehlende Werte -> "normal".
const SCHRIFT_STUFEN = {
  klein: 0.9,
  normal: 1.0,
  gross: 1.2,
};
const SCHRIFT_DEFAULT = "normal";
const SCHRIFT_KEY = "manual_font_scale";

// Liest manual_font_scale aus dem rohen Settings-Dict; fehlt der Key oder ist er
// unbekannt -> normal (kein lauter Fehler).
function leseSchriftStufe(settings) {
  const wert = settings?.[SCHRIFT_KEY];
  return Object.prototype.hasOwnProperty.call(SCHRIFT_STUFEN, wert)
    ? wert
    : SCHRIFT_DEFAULT;
}

// Stabiler Anker-Id für eine Kategorie (für die Sprungliste). Die help_id-Anker
// der Einträge tragen ihre help_id direkt; die Kategorie-Überschriften brauchen
// einen eigenen, kollisionsfreien Id-Raum.
function kategorieAnker(name) {
  return `manual-kat-${name}`;
}

// Sucht den ECHTEN Scroll-Container: vom Ziel aufwärts das erste Vorfahren-
// Element, dessen overflowY "auto"/"scroll" ist UND das tatsächlich überläuft
// (scrollHeight > clientHeight). Der früher angenommene .function-shell__body
// hat overflow-y: visible und scrollt NICHT — der reale Scroller ist das <main>
// .app__content. Darum den Container dynamisch statt per fester Klasse suchen.
function findeScroller(el) {
  let e = el.parentElement;
  while (e) {
    const s = getComputedStyle(e).overflowY;
    if ((s === "auto" || s === "scroll") && e.scrollHeight > e.clientHeight) {
      return e;
    }
    e = e.parentElement;
  }
  return null;
}

// Realer Sprung-Offset: die Unterkante des sticky-Balkens .manual__bar relativ
// zur Oberkante des Scroll-Containers (+ kleiner Puffer). Der Balken sitzt NICHT
// am Container-Rand, sondern tiefer — die reine Balkenhöhe als Offset war darum
// systematisch zu klein und die Überschrift landete unter dem Balken.
function berechneOffset(container) {
  const balken = document.querySelector(".manual__bar");
  if (!balken || !container) {
    return 0;
  }
  const bb = balken.getBoundingClientRect();
  const cb = container.getBoundingClientRect();
  // Unterkante des sticky-Balkens relativ zur Container-Oberkante + kleiner Puffer.
  return bb.bottom - cb.top + 8;
}

// Sanfter Sprung zu einem Anker per Id (getElementById statt Hash-Navigation,
// weil die help_id-Anker Punkte enthalten und ein "#a.b.c" als CSS-Selektor
// ungültig wäre — als reines Ziel-Element funktioniert die Id aber).
//
// Der sticky .manual__bar sitzt in einem anderen Kontext, weshalb scroll-margin-
// top an den Ankern nicht greift. Darum manuell im echten Scroll-Container
// scrollen und den Offset (reale Balken-Unterkante, berechneOffset) selbst
// abziehen. Fällt der Container-Fund aus, greift das alte scrollIntoView.
function springeZu(id) {
  const ziel = document.getElementById(id);
  if (!ziel) {
    return;
  }
  const container = findeScroller(ziel);
  if (!container) {
    ziel.scrollIntoView({ behavior: "smooth", block: "start" });
    return;
  }
  const offset = berechneOffset(container);
  const zielTop = ziel.getBoundingClientRect().top;
  const contTop = container.getBoundingClientRect().top;
  const neu = container.scrollTop + (zielTop - contTop) - offset;
  container.scrollTo({ top: neu, behavior: "smooth" });
}

// Zerlegt einen Text-Knoten anhand des Suchbegriffs in Fragmente und rendert
// Treffer als <mark> — OHNE dangerouslySetInnerHTML. Jeder Treffer bekommt
// fortlaufend einen globalen Index aus dem mitlaufenden Zähler (`zaehler.wert`),
// damit die Treffer-Navigation über alle Abschnitte hinweg eindeutig nummeriert
// ist. Der aktive Treffer wird zusätzlich markiert und referenziert.
function Hervorhebung({ text, suche, zaehler, aktiverIndex, aktivRef }) {
  if (!suche) {
    return text;
  }

  const needle = suche.toLowerCase();
  const haystack = text.toLowerCase();
  const teile = [];
  let pos = 0;
  let schluessel = 0;

  while (true) {
    const treffer = haystack.indexOf(needle, pos);
    if (treffer === -1) {
      teile.push(text.slice(pos));
      break;
    }
    if (treffer > pos) {
      teile.push(text.slice(pos, treffer));
    }
    const globalerIndex = zaehler.wert;
    zaehler.wert += 1;
    const istAktiv = globalerIndex === aktiverIndex;
    teile.push(
      <mark
        key={`m-${schluessel}`}
        ref={istAktiv ? aktivRef : null}
        className={
          istAktiv ? "manual__mark manual__mark--aktiv" : "manual__mark"
        }
      >
        {text.slice(treffer, treffer + suche.length)}
      </mark>,
    );
    schluessel += 1;
    pos = treffer + suche.length;
  }

  return teile;
}

// Ein einzelner Handbuch-Abschnitt: Titel, Vorläufig-Hinweis (falls), lang-Text
// in Absätze gesplittet, optionale Weiterführend-Links. Reiner Text in <p> —
// keine Markdown-Lib, kein dangerouslySetInnerHTML. Titel und lang-Text laufen
// bei aktiver Suche durch <Hervorhebung>.
function Abschnitt({ helpId, sprache, t, suche, zaehler, aktiverIndex, aktivRef }) {
  const eintrag = helpContent[helpId];
  // Defensiver Sprach-Fallback auf "de" (Parität ist zugesichert, aber ein
  // fehlender Zweig darf nicht crashen).
  const inhalt = eintrag[sprache] ?? eintrag.de;
  const absaetze = inhalt.lang.split("\n\n");

  return (
    <section id={helpId} className="manual__section">
      <h3 className="manual__section-title">
        <Hervorhebung
          text={inhalt.titel}
          suche={suche}
          zaehler={zaehler}
          aktiverIndex={aktiverIndex}
          aktivRef={aktivRef}
        />
      </h3>

      {eintrag.status === "vorlaeufig" ? (
        <p className="manual__vorlaeufig">{t("manual.vorlaeufigHint")}</p>
      ) : null}

      {absaetze.map((absatz, i) => (
        <p key={i} className="manual__paragraph">
          <Hervorhebung
            text={absatz}
            suche={suche}
            zaehler={zaehler}
            aktiverIndex={aktiverIndex}
            aktivRef={aktivRef}
          />
        </p>
      ))}

      {Array.isArray(inhalt.links) && inhalt.links.length > 0 ? (
        <div className="manual__links">
          <span className="manual__links-label">{t("manual.linksLabel")}</span>
          <ul className="manual__links-list">
            {inhalt.links.map((link) => (
              <li key={link.url}>
                <a
                  href={link.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="manual__link"
                >
                  {link.label}
                </a>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </section>
  );
}

// Zählt die Suchtreffer im gerenderten Text (Titel + lang-Text jedes Eintrags)
// der aktuellen Sprache. Gleiche Logik wie <Hervorhebung>, nur ohne Markup —
// damit Treffer-Zähler und Navigation dieselbe Gesamtzahl sehen wie die Anzeige.
function zaehleTreffer(suche, sprache) {
  if (!suche) {
    return 0;
  }
  const needle = suche.toLowerCase();
  let summe = 0;
  for (const { eintraege } of KATEGORIEN) {
    for (const { helpId } of eintraege) {
      const eintrag = helpContent[helpId];
      const inhalt = eintrag[sprache] ?? eintrag.de;
      const texte = [inhalt.titel, ...inhalt.lang.split("\n\n")];
      for (const text of texte) {
        const haystack = text.toLowerCase();
        let pos = 0;
        while (true) {
          const treffer = haystack.indexOf(needle, pos);
          if (treffer === -1) {
            break;
          }
          summe += 1;
          pos = treffer + needle.length;
        }
      }
    }
  }
  return summe;
}

export default function ManualView({ onClose, sprungZiel }) {
  const { t, i18n } = useTranslation();
  const sprache = i18n.language === "en" ? "en" : "de";

  // Ziel 2 — mitlaufender Kapitelname (oberste sichtbare Kategorie).
  const [aktiveKategorie, setAktiveKategorie] = useState(
    KATEGORIEN.length > 0 ? KATEGORIEN[0].kategorie : "",
  );

  // Ziel 3 — Schriftgröße, persistent. State-Muster wie overview_sections:
  // useState(Default) -> useEffect lädt -> Klick schreibt via updateSetting.
  const [schriftStufe, setSchriftStufe] = useState(SCHRIFT_DEFAULT);
  const [ladeStatus, setLadeStatus] = useState("laedt"); // laedt | bereit | fehler
  const [speicherFehler, setSpeicherFehler] = useState(false);

  // PDF-Download (Muster wie SecurityReportView): Lade- und Fehlerzustand.
  const [pdfLaedt, setPdfLaedt] = useState(false);
  const [pdfFehler, setPdfFehler] = useState(false);

  // Ziel 4 — Suche.
  const [sucheOffen, setSucheOffen] = useState(false);
  const [suchbegriff, setSuchbegriff] = useState("");
  const [aktiverTreffer, setAktiverTreffer] = useState(0); // 0-basiert
  const suchfeldRef = useRef(null);
  const aktivMarkRef = useRef(null);

  // Reale Höhe der sticky-Kopfzeile .manual__bar. Wird per ResizeObserver
  // gemessen und als CSS-Variable --manual-bar-h an den Wrapper geschrieben,
  // damit scroll-margin-top an den Ankern der echten Balkenhöhe folgt (statt
  // eines festen Werts, der bei anderer Auflösung/Schriftstufe/Umbruch bricht).
  const barRef = useRef(null);
  const [barHoehe, setBarHoehe] = useState(0);

  // Schriftgröße einmal beim Mount laden, über den Default mischen. Fehler nicht
  // verschlucken (console.error), in den Lade-Fehlerzustand gehen. t NICHT als
  // Dependency.
  useEffect(() => {
    let aktiv = true;
    (async () => {
      try {
        const settings = await fetchSettings();
        if (!aktiv) {
          return;
        }
        setSchriftStufe(leseSchriftStufe(settings));
        setLadeStatus("bereit");
      } catch (fehler) {
        if (!aktiv) {
          return;
        }
        console.error("Handbuch-Schriftgröße laden fehlgeschlagen:", fehler);
        setLadeStatus("fehler");
      }
    })();
    return () => {
      aktiv = false;
    };
  }, []);

  // Ziel 2 — IntersectionObserver über die Kategorie-Sections. Die oberste
  // aktuell sichtbare Kategorie wird zum Kapitelnamen. Sauber beim Unmount
  // trennen (disconnect in der Cleanup).
  useEffect(() => {
    const sichtbar = new Map(); // name -> intersectionRatio

    const observer = new IntersectionObserver(
      (eintraege) => {
        for (const eintrag of eintraege) {
          const name = eintrag.target.dataset.kategorie;
          if (eintrag.isIntersecting) {
            sichtbar.set(name, eintrag.intersectionRatio);
          } else {
            sichtbar.delete(name);
          }
        }
        // Oberste sichtbare Kategorie = erste in KATEGORIEN-Reihenfolge, die
        // gerade sichtbar ist.
        const oberste = KATEGORIEN.find(({ kategorie }) =>
          sichtbar.has(kategorie),
        );
        if (oberste) {
          setAktiveKategorie(oberste.kategorie);
        }
      },
      { rootMargin: "-10% 0px -70% 0px", threshold: [0, 1] },
    );

    for (const { kategorie } of KATEGORIEN) {
      const el = document.getElementById(kategorieAnker(kategorie));
      if (el) {
        observer.observe(el);
      }
    }

    return () => observer.disconnect();
  }, []);

  // Schriftgröße umschalten: lokal spiegeln, dann persistieren. Bei Fehler den
  // dezenten Speicher-Fehlerzustand setzen, lokalen Zustand belassen.
  const handleSchrift = async (stufe) => {
    setSpeicherFehler(false);
    setSchriftStufe(stufe);
    try {
      await updateSetting(SCHRIFT_KEY, stufe);
    } catch (fehler) {
      console.error("manual_font_scale speichern fehlgeschlagen:", fehler);
      setSpeicherFehler(true);
    }
  };

  // Handbuch als PDF in der aktuellen Sprache herunterladen. Dezenter Lade-/
  // Fehlerzustand wie beim Sicherheitsbericht; der eigentliche Download läuft
  // über fetchManualPdf -> apiDownload (Blob).
  async function handlePdfDownload() {
    setPdfFehler(false);
    setPdfLaedt(true);
    try {
      await fetchManualPdf(sprache);
    } catch {
      setPdfFehler(true);
    } finally {
      setPdfLaedt(false);
    }
  }

  // Treffer-Gesamtzahl der aktuellen Suche/Sprache. Bei jeder Eingabe neu
  // berechnet; der mitlaufende Render-Zähler vergibt dieselben Indizes.
  const trefferGesamt = zaehleTreffer(suchbegriff, sprache);

  // Aktiven Treffer ins Bild holen, sobald er sich ändert.
  useEffect(() => {
    if (aktivMarkRef.current) {
      aktivMarkRef.current.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  }, [aktiverTreffer, suchbegriff]);

  const handleSucheToggle = () => {
    setSucheOffen((offen) => {
      const naechste = !offen;
      if (!naechste) {
        setSuchbegriff("");
        setAktiverTreffer(0);
      }
      return naechste;
    });
  };

  const handleSuchEingabe = (wert) => {
    setSuchbegriff(wert);
    setAktiverTreffer(0);
  };

  const naechsterTreffer = () => {
    if (trefferGesamt > 0) {
      setAktiverTreffer((i) => (i + 1) % trefferGesamt);
    }
  };

  const vorigerTreffer = () => {
    if (trefferGesamt > 0) {
      setAktiverTreffer((i) => (i - 1 + trefferGesamt) % trefferGesamt);
    }
  };

  const handleSuchTaste = (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      naechsterTreffer();
    } else if (e.key === "Escape") {
      e.preventDefault();
      setSucheOffen(false);
      setSuchbegriff("");
      setAktiverTreffer(0);
    }
  };

  // Beim Öffnen der Suche das Feld fokussieren.
  useEffect(() => {
    if (sucheOffen && suchfeldRef.current) {
      suchfeldRef.current.focus();
    }
  }, [sucheOffen]);

  // Reale Höhe der sticky-Kopfzeile per ResizeObserver messen und in barHoehe
  // spiegeln (initial einmal direkt messen). ResizeObserver ist in Chromium/
  // Tauri Standard — kein Polyfill nötig. Kein t/i18n im Dep-Array (leer);
  // Cleanup trennt den Observer sauber.
  useEffect(() => {
    if (!barRef.current) {
      return undefined;
    }
    const messen = () => {
      setBarHoehe(Math.round(barRef.current.getBoundingClientRect().height));
    };
    messen();
    const observer = new ResizeObserver(() => messen());
    observer.observe(barRef.current);
    return () => observer.disconnect();
  }, []);

  // Sprung aus einem "?"-Hilfe-Popup: ist ein sprungZiel (help_id) gesetzt, zum
  // passenden <section id={helpId}>-Anker springen. Abhängig von [sprungZiel,
  // barHoehe], weil scroll-margin-top an der real gemessenen Balkenhöhe hängt:
  // erst springen, wenn barHoehe steht (sonst greift der 60px-Fallback und die
  // Überschrift rutscht unter den Balken). barHoehe===0 -> noch nicht gemessen,
  // return; der Effekt läuft erneut, sobald der ResizeObserver sie setzt. Ein
  // requestAnimationFrame reicht dann. t bewusst NICHT als Dependency.
  useEffect(() => {
    if (!sprungZiel || !barHoehe) {
      return undefined;
    }
    let aktiv = true;
    let rafId = 0;
    // Beim Kaltstart (Öffnen übers "?"-Popup) ist der Scroll-Container
    // .function-shell__body erst nach mehreren Frames voll gelayoutet; ein
    // einzelnes rAF springt zu früh und scrollTop bleibt 0. Darum den Sprung
    // pro Frame wiederholen, bis das Ziel die Sollposition erreicht hat oder das
    // Versuchslimit (20 Frames ~ 0,3s) greift — dann aufhören, kein Endlosloop.
    const versuch = (n) => {
      if (!aktiv) {
        return;
      }
      springeZu(sprungZiel);
      const ziel = document.getElementById(sprungZiel);
      const container = ziel ? findeScroller(ziel) : null;
      if (ziel && container) {
        const soll = berechneOffset(container);
        const ist =
          ziel.getBoundingClientRect().top -
          container.getBoundingClientRect().top;
        if (Math.abs(ist - soll) <= 2) {
          return;
        }
      }
      if (n < 20) {
        rafId = requestAnimationFrame(() => versuch(n + 1));
      }
    };
    rafId = requestAnimationFrame(() => versuch(0));
    return () => {
      aktiv = false;
      if (rafId) {
        cancelAnimationFrame(rafId);
      }
    };
  }, [sprungZiel, barHoehe]);

  // Mitlaufender Render-Zähler: vor jedem Render zurücksetzen, <Hervorhebung>
  // vergibt daraus die globalen Treffer-Indizes in Renderreihenfolge.
  const zaehler = { wert: 0 };

  const suche = sucheOffen ? suchbegriff : "";
  const kapitelName = aktiveKategorie
    ? t(`manual.kategorien.${aktiveKategorie}`, aktiveKategorie)
    : "";

  return (
    <FunctionShell title={t("manual.title")} onBack={onClose}>
      <div
        className="manual"
        style={{ "--manual-fontscale": SCHRIFT_STUFEN[schriftStufe] }}
      >
        {/* Linke Spalte: vertikale Kategorie-Navigation, sticky. Der aktive
            Eintrag (Observer) wird im Akzent hervorgehoben. */}
        <nav className="manual__toc" aria-label={t("manual.tocLabel")}>
          <span className="manual__toc-label">{t("manual.tocLabel")}</span>
          <ul className="manual__toc-list">
            {KATEGORIEN.map(({ kategorie }) => (
              <li key={kategorie}>
                <button
                  type="button"
                  className={
                    kategorie === aktiveKategorie
                      ? "manual__toc-link manual__toc-link--aktiv"
                      : "manual__toc-link"
                  }
                  aria-current={kategorie === aktiveKategorie ? "true" : undefined}
                  onClick={() => springeZu(kategorieAnker(kategorie))}
                >
                  {t(`manual.kategorien.${kategorie}`, kategorie)}
                </button>
              </li>
            ))}
          </ul>
        </nav>

        {/* Rechte Spalte: umrahmter Container mit sticky-Kopfzeile (Kapitelname
            + Werkzeugleiste) und darunter dem Textbereich. */}
        <div className="manual__panel">
          <div className="manual__bar" ref={barRef}>
            <span className="manual__chapter">{kapitelName}</span>

            <div className="manual__tools">
              {sucheOffen ? (
                <div className="manual__search">
                  <input
                    ref={suchfeldRef}
                    type="text"
                    className="manual__search-input"
                    placeholder={t("manual.suche.platzhalter")}
                    value={suchbegriff}
                    onChange={(e) => handleSuchEingabe(e.target.value)}
                    onKeyDown={handleSuchTaste}
                  />
                  <span className="manual__search-count">
                    {t("manual.suche.zaehler", {
                      n: trefferGesamt > 0 ? aktiverTreffer + 1 : 0,
                      m: trefferGesamt,
                    })}
                  </span>
                  <button
                    type="button"
                    className="manual__icon-btn"
                    aria-label={t("manual.suche.vorige")}
                    onClick={vorigerTreffer}
                    disabled={trefferGesamt === 0}
                  >
                    ↑
                  </button>
                  <button
                    type="button"
                    className="manual__icon-btn"
                    aria-label={t("manual.suche.naechste")}
                    onClick={naechsterTreffer}
                    disabled={trefferGesamt === 0}
                  >
                    ↓
                  </button>
                  <button
                    type="button"
                    className="manual__icon-btn"
                    aria-label={t("manual.suche.schliessen")}
                    onClick={handleSucheToggle}
                  >
                    ✕
                  </button>
                </div>
              ) : null}

              {/* Schriftgröße — A- / A / A+. Aktive Stufe im Akzent. Während des
                  Ladens deaktiviert; Lade-Fehler kippt nicht das Layout. */}
              <div
                className="manual__fontsize"
                role="group"
                aria-label={t("manual.schrift.label")}
              >
                {[
                  { stufe: "klein", zeichen: "A-", aria: "manual.schrift.klein" },
                  { stufe: "normal", zeichen: "A", aria: "manual.schrift.normal" },
                  { stufe: "gross", zeichen: "A+", aria: "manual.schrift.gross" },
                ].map(({ stufe, zeichen, aria }) => (
                  <button
                    key={stufe}
                    type="button"
                    className={
                      stufe === schriftStufe
                        ? "manual__font-btn manual__font-btn--aktiv"
                        : "manual__font-btn"
                    }
                    aria-label={t(aria)}
                    aria-pressed={stufe === schriftStufe}
                    disabled={ladeStatus === "laedt"}
                    onClick={() => handleSchrift(stufe)}
                  >
                    {zeichen}
                  </button>
                ))}
              </div>

              {/* Handbuch als PDF (aktuelle Sprache). Gleiche Optik wie der
                  Such-Button (manual__icon-btn). */}
              <button
                type="button"
                className="manual__icon-btn"
                aria-label={t("manual.pdf.download")}
                disabled={pdfLaedt}
                onClick={handlePdfDownload}
              >
                {pdfLaedt ? "…" : "⤓"}
              </button>

              {!sucheOffen ? (
                <button
                  type="button"
                  className="manual__icon-btn"
                  aria-label={t("manual.suche.oeffnen")}
                  onClick={handleSucheToggle}
                >
                  🔍
                </button>
              ) : null}
            </div>
          </div>

          {speicherFehler ? (
            <p className="manual__save-error">
              {mitCode(t("manual.schrift.saveError"), CODES.E_501)}
            </p>
          ) : null}

          {pdfFehler ? (
            <p className="manual__save-error" role="alert">{t("manual.pdf.fehler")}</p>
          ) : null}

          <div className="manual__content">
            {KATEGORIEN.map(({ kategorie, eintraege }) => (
              <section
                key={kategorie}
                id={kategorieAnker(kategorie)}
                data-kategorie={kategorie}
                className="manual__category"
              >
                <h2 className="manual__category-title">
                  {t(`manual.kategorien.${kategorie}`, kategorie)}
                </h2>
                {eintraege.map(({ helpId }) => (
                  <Abschnitt
                    key={helpId}
                    helpId={helpId}
                    sprache={sprache}
                    t={t}
                    suche={suche}
                    zaehler={zaehler}
                    aktiverIndex={aktiverTreffer}
                    aktivRef={aktivMarkRef}
                  />
                ))}
              </section>
            ))}
          </div>
        </div>
      </div>
    </FunctionShell>
  );
}
