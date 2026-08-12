// Ansicht "Ueber CERNIS PRO" (CERNIS PRO 2.0)
// EIGENER MODUS neben Einstellungen und Handbuch (kein Reiter), erreichbar ueber
// die Kopfzeile. Nutzt dieselbe FunctionShell wie ManualView/SettingsView -- also
// denselben Weg zurueck -- und bekommt onClose sowie onOpenManual als Props.
//
// Inhalt ist eine Uebersicht mit Einstieg in den Lizenz-Browser, in VIER
// Abschnitten und in dieser Reihenfolge:
//   1. eigenes Werk (Urheber, Lizenz, Bezugsort des Quelltextes)
//   2. mitgelieferte Bestandteile   (Ebenen python, npm, rust + nativ)
//   3. mitgelieferte Daten          (Ebene daten)
//   4. vorausgesetzte Programme     (Ebene programme)
//
// EINORDNUNG STATT LUECKENEINDRUCK: die vorausgesetzten Programme werden NICHT
// mitgeliefert; ihre Lizenz gehoert zum System des Anwenders, deshalb tragen sie
// keine Lizenzangabe. Das steht sichtbar im Abschnitt. Das Feld ``vorhanden`` ist
// eine eigene Angabe und wird mit dem Zustand ``nicht_zutreffend`` richtig benannt,
// nicht als Fehler. Ebenso wird der Zustand ``kein_paketverzeichnis`` der Ebene
// nativ mit dem vorhandenen Feld ``hinweis`` erklaert, statt eine leere Liste zu
// zeigen -- ausschliesslich aus den Feldern ``zustand`` und ``hinweis``, nichts
// geraten.
//
// KEINE NETZABFRAGE ZUR LAUFZEIT: nur die beiden eigenen Endpunkte. Kein externer
// Abruf, keine Schriftart und kein Bild von aussen. ``projektadresse`` wird als
// Text gezeigt, bewusst NICHT als Verweis.

import { useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { fetchLicenseManifest } from "../api/licenses.js";
import { FunctionShell } from "../components/AreaShell.jsx";
import LicenseBrowser, {
  HERKUNFT_GRUPPE_MITGELIEFERT,
  HERKUNFT_MITGELIEFERT,
} from "../components/LicenseBrowser.jsx";
import "./AboutView.css";

// Die Ebenen der mitgelieferten Programmbestandteile (Abschnitt 2). ``daten`` und
// ``programme`` haben eigene Abschnitte, die native Ebene kommt separat als
// ``ebene_nativ`` und wird in Abschnitt 2 eingeordnet.
//
// Die Liste kommt aus dem Lizenz-Browser und wird hier NICHT zweitgeschrieben:
// der Schalter dieses Abschnitts oeffnet den Browser mit genau dieser Gruppe als
// Filter (Fund 2, Weg B). Zwei getrennte Listen liefen auseinander, und dann
// zeigte der Browser eine andere Menge als die Zahl, auf die geklickt wurde.
const EBENEN_BESTANDTEILE = HERKUNFT_MITGELIEFERT;

// Zeigt einen Wert -- oder die ausdrueckliche Aussage, dass er nicht belegt ist.
// Leerer String, null und undefined gelten als nicht belegt. Kein Ersatztext.
function Angabe({ wert, t, mono }) {
  const belegt =
    typeof wert === "string" ? wert.trim() !== "" : wert !== null && wert !== undefined;
  if (!belegt) {
    return <span className="about__wert about__wert--leer">{t("lizenzen.nichtBelegt")}</span>;
  }
  return (
    <span className={mono ? "about__wert about__mono" : "about__wert"}>{String(wert)}</span>
  );
}

// Eine Angabe-Zeile: Label links, Wert rechts.
function AngabeZeile({ label, wert, t, mono }) {
  return (
    <div className="about__zeile">
      <span className="about__label">{label}</span>
      <Angabe wert={wert} t={t} mono={mono} />
    </div>
  );
}

// Die Praefixe, mit denen die Aufstellung ihre Lizenztext-SCHLUESSEL bildet
// (gemessen: "werk:GPL-2.0-only", "spdx:MIT", "paket:python/anyio"). Sie stehen
// hier NUR, um eine unaufgeloest durchgereichte Referenz zu ERKENNEN -- nicht, um
// sie aufzuloesen. Das Aufloesen ist Sache der Anwendungsschicht.
const TEXT_REFERENZ_PRAEFIXE = ["werk:", "spdx:", "paket:"];

// Ist das, was in werk.lizenz_text steht, wirklich ein Lizenztext -- oder noch die
// unaufgeloeste Referenz? Zweiteres ist kein Text, sondern ein Schluessel; ihn im
// Aufklappblock zu zeigen war Befund 54b, Teil 2. Erkennt die Ansicht ihn, greift
// stattdessen der vorhandene Ersatzhinweis.
function istWerkLizenztext(wert) {
  if (typeof wert !== "string" || wert === "") {
    return false;
  }
  return !TEXT_REFERENZ_PRAEFIXE.some((praefix) => wert.startsWith(praefix));
}

// Abschnitt 1 -- das eigene Werk: Urheber, Lizenz und Bezugsort des Quelltextes.
function AbschnittWerk({ werk, t }) {
  return (
    <section className="about__section">
      <h3 className="about__section-title">{t("lizenzen.abschnitt.werk.titel")}</h3>
      <p className="about__section-text">{t("lizenzen.abschnitt.werk.text")}</p>

      <div className="about__felder">
        <AngabeZeile label={t("lizenzen.feld.name")} wert={werk?.name} t={t} />
        <AngabeZeile label={t("lizenzen.feld.urheber")} wert={werk?.urheber} t={t} />
        <AngabeZeile label={t("lizenzen.feld.lizenzId")} wert={werk?.lizenz_id} t={t} mono />
        <AngabeZeile
          label={t("lizenzen.feld.lizenzTextQuelle")}
          wert={werk?.lizenz_text_quelle}
          t={t}
        />
        {/* Bezugsort des Quelltextes -- als Text, bewusst NICHT als Verweis. */}
        <AngabeZeile
          label={t("lizenzen.feld.quelltextBezug")}
          wert={werk?.quelltext_bezug}
          t={t}
          mono
        />
        <AngabeZeile
          label={t("lizenzen.feld.quelltextBezugQuelle")}
          wert={werk?.quelltext_bezug_quelle}
          t={t}
        />
      </div>

      {/* Der Lizenztext des eigenen Werks: die Aufstellung traegt in lizenz_text
          nur die REFERENZ (gemessen "werk:GPL-2.0-only"); den Volltext legt der
          Sammler in der Ebene lizenztexte ab. Aufgeloest wird an der
          Anwendungsschicht (GetLicenseManifest), damit hier zeichengleich der
          Text ankommt -- ohne zweiten Abruf und ohne dass die grosse Ebene
          lizenztexte durchgereicht werden muesste. Bleibt die Referenz
          unaufloesbar, kommt das Feld unveraendert an; dann greift der
          Ersatzhinweis unten. */}
      {istWerkLizenztext(werk?.lizenz_text) ? (
        <details className="about__details">
          <summary className="about__summary">{t("lizenzen.abschnitt.werk.volltext")}</summary>
          <pre className="about__text">{werk.lizenz_text}</pre>
        </details>
      ) : (
        <p className="about__hinweis">{t("lizenzen.detail.keinText")}</p>
      )}
    </section>
  );
}

// EIN Eintrag der nativen Ebene, beschriftet -- nach demselben Muster, das der
// Programm-Abschnitt weiter unten schon nutzt: Name als Kopfzeile, darunter
// AngabeZeile je Feld (Fund 3). Vorher stand hier das rohe JSON.stringify des
// ganzen Objekts, also eine Zeile aus 17 Feldern mit Klammern und Anfuehrungs-
// zeichen -- lesbar allenfalls fuer den, der das Datenformat kennt.
//
// WELCHE FELDER: gezeigt wird, was der Anwender fuer die Lizenzfrage braucht --
// welche Bibliothek (``dateiname``), aus welchem Paket sie stammt
// (``lieferndes_paket``), unter welcher Lizenz (``lizenz_id``), von wem
// (``urhebervermerk``), und in welchen der beiden Binaries sie steckt
// (``binaries``). Das sind genau die Felder, die auch bei den uebrigen Ebenen
// gezeigt werden.
//
// WAS BEWUSST WEGBLEIBT: ``archivname`` (gemessen fast immer gleich
// ``dateiname``), ``groesse_bytes`` (sagt zur Lizenzlage nichts),
// ``python_paket`` (in ``lieferndes_paket`` bereits enthalten), die drei
// ``*_quelle``-Felder und ``copyright_datei`` (Herkunftsnachweis der Angabe, kein
// Inhalt -- der gehoert in den Lizenz-Browser, nicht in diese Uebersicht), sowie
// ``lizenz_text_ref``, die nur ein Schluessel ist.
//
// Ein Eintrag ist gemessen NIE ein String, sondern immer ein Objekt. Der
// String-Zweig bleibt als Rueckfall stehen, weil diese Ebene aus dem Bau kommt
// und ein anders geformter Eintrag hier lieber sichtbar als verschluckt sein
// soll -- er darf nur nicht mehr der Normalfall sein.
function NativerEintrag({ eintrag, t }) {
  if (typeof eintrag === "string") {
    return <span className="about__mono">{eintrag}</span>;
  }
  if (!eintrag || typeof eintrag !== "object") {
    return <span className="about__wert about__wert--leer">{t("lizenzen.nichtBelegt")}</span>;
  }

  const binaries = Array.isArray(eintrag.binaries) ? eintrag.binaries.join(", ") : null;

  return (
    <>
      <div className="about__programm-kopf">
        <span className="about__programm-name about__mono">
          {eintrag.dateiname ?? t("lizenzen.nichtBelegt")}
        </span>
      </div>
      <AngabeZeile
        label={t("lizenzen.feld.lieferndesPaket")}
        wert={eintrag.lieferndes_paket}
        t={t}
      />
      <AngabeZeile label={t("lizenzen.feld.lizenzId")} wert={eintrag.lizenz_id} t={t} />
      <AngabeZeile
        label={t("lizenzen.feld.urhebervermerk")}
        wert={eintrag.urhebervermerk}
        t={t}
      />
      <AngabeZeile label={t("lizenzen.feld.binaries")} wert={binaries} t={t} mono />
    </>
  );
}

// Der Zustand der nativen Ebene -- EINORDNUNG statt leerer Liste. Es werden
// ausschliesslich die vorhandenen Felder ``zustand`` und ``hinweis`` genutzt.
function NativeEbene({ nativ, t }) {
  const zustand = nativ?.zustand;

  return (
    <div className="about__nativ">
      <h4 className="about__untertitel">{t("lizenzen.nativ.titel")}</h4>

      <AngabeZeile
        label={t("lizenzen.feld.zustand")}
        wert={zustand ? t(`lizenzen.nativ.zustand.${zustand}`, zustand) : null}
        t={t}
      />
      <AngabeZeile label={t("lizenzen.feld.zielplattform")} wert={nativ?.zielplattform} t={t} />
      <AngabeZeile
        label={t("lizenzen.feld.quelleDerBinaries")}
        wert={nativ?.quelle_der_binaries}
        t={t}
      />
      <AngabeZeile
        label={t("lizenzen.feld.geleseneBinaries")}
        wert={
          Array.isArray(nativ?.gelesene_binaries) ? nativ.gelesene_binaries.length : null
        }
        t={t}
      />

      {/* Statt einer leeren Liste: der Hinweis des Erzeugers im Wortlaut. Er ist
          die Erklaerung -- fehlt er, wird das als nicht belegt gesagt. */}
      {Array.isArray(nativ?.eintraege) && nativ.eintraege.length > 0 ? (
        <ul className="about__nativ-liste">
          {nativ.eintraege.map((eintrag, i) => (
            <li key={i} className="about__nativ-eintrag">
              <NativerEintrag eintrag={eintrag} t={t} />
            </li>
          ))}
        </ul>
      ) : (
        <p className="about__hinweis">
          <Angabe wert={nativ?.hinweis} t={t} />
        </p>
      )}
    </div>
  );
}

// Abschnitt 4 -- vorausgesetzte Programme. Erklaert SICHTBAR, dass sie nicht
// mitgeliefert werden und ihre Lizenz zum System des Anwenders gehoert; darum
// tragen sie keine Lizenzangabe. Der Zustand ``vorhanden`` ist eine eigene Angabe.
function AbschnittProgramme({ programme, t }) {
  return (
    <section className="about__section">
      <h3 className="about__section-title">{t("lizenzen.abschnitt.programme.titel")}</h3>
      <p className="about__section-text">{t("lizenzen.abschnitt.programme.einordnung")}</p>

      {programme.length === 0 ? (
        <p className="about__hinweis">{t("lizenzen.abschnitt.programme.keine")}</p>
      ) : (
        <ul className="about__programme">
          {programme.map((teil, i) => (
            <li key={`${teil?.name ?? "?"}-${i}`} className="about__programm">
              <div className="about__programm-kopf">
                <span className="about__programm-name">
                  {teil?.name ?? t("lizenzen.nichtBelegt")}
                </span>
                {/* vorhanden als EIGENE Angabe, mit benanntem Zustand --
                    nicht_zutreffend ist kein Fehler. */}
                <span
                  className={
                    "about__vorhanden about__vorhanden--" +
                    (teil?.vorhanden ?? "unbekannt")
                  }
                >
                  {teil?.vorhanden
                    ? t(`lizenzen.vorhanden.${teil.vorhanden}`, teil.vorhanden)
                    : t("lizenzen.nichtBelegt")}
                </span>
              </div>
              <AngabeZeile label={t("lizenzen.feld.zweck")} wert={teil?.zweck} t={t} />
              {/* Die Abstufung aus Befund 54b: ohne sie stuende ein Kerneltreiber,
                  den die Anwendung nie startet, ununterscheidbar neben einem
                  Werkzeug, das sie wirklich aufruft. */}
              <AngabeZeile
                label={t("lizenzen.feld.bezugsart")}
                wert={
                  teil?.bezugsart
                    ? t(`lizenzen.bezugsart.${teil.bezugsart}`, teil.bezugsart)
                    : null
                }
                t={t}
              />
              <AngabeZeile
                label={t("lizenzen.feld.lieferndesPaket")}
                wert={teil?.lieferndes_paket}
                t={t}
              />
              <AngabeZeile label={t("lizenzen.feld.plattform")} wert={teil?.plattform} t={t} />
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

export default function AboutView({ onClose, onOpenManual }) {
  const { t } = useTranslation();

  const [aufstellung, setAufstellung] = useState(null);
  const [status, setStatus] = useState("laedt"); // laedt | bereit | fehler
  const [fehler, setFehler] = useState(null);
  // Die Filtervorwahl fuer den Lizenz-Browser (Fund 2, Weg B). ``stand`` zaehlt
  // die Klicks: nur so wirkt ein zweiter Klick auf denselben Schalter wieder,
  // nachdem der Anwender den Filter zwischendurch von Hand geaendert hat.
  const [browserVorwahl, setBrowserVorwahl] = useState(null);
  // Der Anker des Browser-Abschnitts -- der Schalter setzt nicht nur den Filter,
  // er bringt den Browser auch ins Bild. Ein Filter, den man erst suchen muss,
  // waere nur die halbe Antwort auf die Frage "wo stehen diese Bestandteile?".
  const browserRef = useRef(null);

  // Die Aufstellung EINMAL beim Mount holen. t bewusst NICHT als Dependency
  // (Render-Schleife); der Effekt haengt an nichts und laeuft genau einmal.
  useEffect(() => {
    let aktiv = true;
    (async () => {
      try {
        const daten = await fetchLicenseManifest();
        if (!aktiv) {
          return;
        }
        setAufstellung(daten);
        setStatus("bereit");
      } catch (ursache) {
        if (!aktiv) {
          return;
        }
        // Kein stiller Leerzustand: der Fehler wird als solcher gezeigt (S3).
        console.error("Lizenzaufstellung laden fehlgeschlagen:", ursache);
        setFehler(ursache);
        setStatus("fehler");
      }
    })();
    return () => {
      aktiv = false;
    };
  }, []);

  const bestandteile = useMemo(
    () => (Array.isArray(aufstellung?.bestandteile) ? aufstellung.bestandteile : []),
    [aufstellung],
  );

  // Die drei datengetriebenen Abschnitte trennen sich allein ueber ``ebene``.
  const mitgelieferte = useMemo(
    () => bestandteile.filter((teil) => EBENEN_BESTANDTEILE.includes(teil?.ebene)),
    [bestandteile],
  );
  const daten = useMemo(
    () => bestandteile.filter((teil) => teil?.ebene === "daten"),
    [bestandteile],
  );
  const programme = useMemo(
    () => bestandteile.filter((teil) => teil?.ebene === "programme"),
    [bestandteile],
  );

  // Fund 2, Weg B: die Zahl in Abschnitt 2 bleibt, was sie ist -- eine Zahl. Der
  // Schalter daneben oeffnet den Lizenz-Browser mit genau der Menge, aus der sie
  // entsteht (die Ebenen aus EBENEN_BESTANDTEILE), und bringt ihn ins Bild.
  const zeigeMitgelieferteImBrowser = () => {
    setBrowserVorwahl((alt) => ({
      herkunft: HERKUNFT_GRUPPE_MITGELIEFERT,
      stand: (alt?.stand ?? 0) + 1,
    }));
    browserRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  return (
    <FunctionShell
      title={t("lizenzen.titel")}
      onBack={onClose}
      helpId="help.lizenzen.uebersicht"
      onOpenManual={onOpenManual}
    >
      <div className="about">
        {status === "laedt" ? (
          <p className="about__laden">{t("lizenzen.laden")}</p>
        ) : status === "fehler" ? (
          // Ehrlicher Fehlerzustand: beim 503 die Aussage, dass die Aufstellung im
          // laufenden Betrieb nicht gefunden wurde, MIT dem detail des Servers
          // (den geprueften Pfaden). Keine leere Seite, kein stiller Zustand.
          <div className="about__fehler" role="alert">
            <p className="about__fehler-titel">
              {fehler?.status === 503
                ? t("lizenzen.fehler.keineAufstellung")
                : t("lizenzen.fehler.allgemein")}
            </p>
            {fehler?.detail ? (
              <pre className="about__fehler-detail">{fehler.detail}</pre>
            ) : (
              <p className="about__fehler-detail-leer">
                {fehler?.message ?? t("lizenzen.nichtBelegt")}
              </p>
            )}
          </div>
        ) : !aufstellung ? (
          <div className="about__fehler" role="alert">
            <p className="about__fehler-titel">{t("lizenzen.fehler.allgemein")}</p>
          </div>
        ) : (
          <>
            {/* Kopf der Aufstellung: woher sie stammt und fuer welchen Stand. */}
            <div className="about__kopf">
              <AngabeZeile
                label={t("lizenzen.feld.produktversion")}
                wert={aufstellung?.produktversion}
                t={t}
                mono
              />
              <AngabeZeile
                label={t("lizenzen.feld.plattform")}
                wert={aufstellung?.plattform}
                t={t}
              />
              <AngabeZeile
                label={t("lizenzen.feld.erzeugtAm")}
                wert={aufstellung?.erzeugt_am}
                t={t}
                mono
              />
            </div>

            {/* --- Abschnitt 1: eigenes Werk --- */}
            <AbschnittWerk werk={aufstellung?.werk} t={t} />

            {/* --- Abschnitt 2: mitgelieferte Bestandteile --- */}
            <section className="about__section">
              <h3 className="about__section-title">
                {t("lizenzen.abschnitt.bestandteile.titel")}
              </h3>
              <p className="about__section-text">
                {t("lizenzen.abschnitt.bestandteile.text", { n: mitgelieferte.length })}
              </p>
              {/* Fund 2, Weg B: der Weg von der Zahl zu den gezaehlten Eintraegen.
                  Nur zeigen, wenn es ueberhaupt welche gibt -- ein Schalter, der
                  garantiert eine leere Liste oeffnet, ist eine Sackgasse. */}
              {mitgelieferte.length > 0 ? (
                <button
                  type="button"
                  className="about__schalter"
                  onClick={zeigeMitgelieferteImBrowser}
                >
                  {t("lizenzen.abschnitt.bestandteile.imBrowserZeigen")}
                </button>
              ) : null}
              <NativeEbene nativ={aufstellung?.ebene_nativ} t={t} />
            </section>

            {/* --- Abschnitt 3: mitgelieferte Daten --- */}
            <section className="about__section">
              <h3 className="about__section-title">{t("lizenzen.abschnitt.daten.titel")}</h3>
              <p className="about__section-text">
                {t("lizenzen.abschnitt.daten.text", { n: daten.length })}
              </p>
              {daten.length === 0 ? (
                <p className="about__hinweis">{t("lizenzen.abschnitt.daten.keine")}</p>
              ) : (
                <ul className="about__liste">
                  {daten.map((teil, i) => (
                    <li key={`${teil?.name ?? "?"}-${i}`} className="about__listen-eintrag">
                      <span className="about__daten-name">
                        {teil?.name ?? t("lizenzen.nichtBelegt")}
                      </span>
                      <span className="about__mono about__daten-lizenz">
                        {typeof teil?.lizenz_id === "string" && teil.lizenz_id !== ""
                          ? teil.lizenz_id
                          : t("lizenzen.nichtBelegt")}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </section>

            {/* --- Abschnitt 4: vorausgesetzte Programme --- */}
            <AbschnittProgramme programme={programme} t={t} />

            {/* --- Einstieg in den Lizenz-Browser --- */}
            <section className="about__section" ref={browserRef}>
              <h3 className="about__section-title">{t("lizenzen.browser.titel")}</h3>
              <p className="about__section-text">{t("lizenzen.browser.text")}</p>
              <LicenseBrowser bestandteile={bestandteile} vorwahl={browserVorwahl} />
            </section>

            {/* Offene Angaben der Aufstellung -- benannt, nicht verschwiegen. */}
            {Array.isArray(aufstellung?.luecken) && aufstellung.luecken.length > 0 ? (
              <section className="about__section">
                <h3 className="about__section-title">{t("lizenzen.luecken.titel")}</h3>
                <p className="about__section-text">
                  {t("lizenzen.luecken.text", { n: aufstellung.luecken.length })}
                </p>
                <ul className="about__liste">
                  {aufstellung.luecken.map((luecke, i) => (
                    <li key={`${luecke?.name ?? "?"}-${i}`} className="about__listen-eintrag">
                      <span className="about__daten-name">
                        {luecke?.name ?? t("lizenzen.nichtBelegt")}
                      </span>
                      <span className="about__mono about__daten-lizenz">
                        {Array.isArray(luecke?.fehlt)
                          ? luecke.fehlt
                              .map((feld) => t(`lizenzen.feld.${feld}`, feld))
                              .join(", ")
                          : t("lizenzen.nichtBelegt")}
                      </span>
                    </li>
                  ))}
                </ul>
              </section>
            ) : null}
          </>
        )}
      </div>
    </FunctionShell>
  );
}
