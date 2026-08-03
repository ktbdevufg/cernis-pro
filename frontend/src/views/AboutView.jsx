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

import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { fetchLicenseManifest } from "../api/licenses.js";
import { FunctionShell } from "../components/AreaShell.jsx";
import LicenseBrowser from "../components/LicenseBrowser.jsx";
import "./AboutView.css";

// Die Ebenen der mitgelieferten Programmbestandteile (Abschnitt 2). ``daten`` und
// ``programme`` haben eigene Abschnitte, die native Ebene kommt separat als
// ``ebene_nativ`` und wird in Abschnitt 2 eingeordnet.
const EBENEN_BESTANDTEILE = ["python", "npm", "rust"];

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

      {/* Der Lizenztext des eigenen Werks liegt der Aufstellung direkt bei
          (Feld lizenz_text) -- zeichengleich, ohne zweiten Abruf. */}
      {typeof werk?.lizenz_text === "string" && werk.lizenz_text !== "" ? (
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
        <ul className="about__liste">
          {nativ.eintraege.map((eintrag, i) => (
            <li key={i} className="about__listen-eintrag">
              <span className="about__mono">
                {typeof eintrag === "string" ? eintrag : JSON.stringify(eintrag)}
              </span>
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
            <section className="about__section">
              <h3 className="about__section-title">{t("lizenzen.browser.titel")}</h3>
              <p className="about__section-text">{t("lizenzen.browser.text")}</p>
              <LicenseBrowser bestandteile={bestandteile} />
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
