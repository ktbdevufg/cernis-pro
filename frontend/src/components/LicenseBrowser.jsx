// Lizenz-Browser (CERNIS PRO 2.0)
// Zweispaltiges Master-Detail nach dem Vorbild von observe__split: LINKS die
// Liste der Bestandteile, RECHTS die Detailspalte mit dem Volltext der Lizenz.
// Die Detailspalte erscheint ERST bei Auswahl und verschwindet ueber onClose --
// genau wie ScanDetailPanel neben ScanTable.
//
// Filter nach Lizenz und nach Herkunft (Ebene), dazu eine Suche ueber Namen und
// Fassung. WICHTIG UND NICHT ZU VERTAUSCHEN: der Lizenzfilter ARBEITET auf
// lizenz_id_normalisiert (dem Filterindex), ZEIGT aber lizenz_id im
// Originalwortlaut.
//
// Die Lizenztexte werden EINZELN nachgeladen, erst wenn die Detailspalte sie
// braucht; ein bereits geholter Text wird nicht erneut geholt (Zwischenspeicher
// nach Schluessel). Der Text wird NICHT veraendert -- nicht gekuerzt, nicht
// umbrochen, nicht uebersetzt, keine Zeilenumbrueche entfernt oder hinzugefuegt;
// die Anzeige stellt ihn in fester Schriftbreite mit erhaltenen Umbruechen dar.
//
// Wo eine Angabe nicht belegt ist, steht das als solches (t("lizenzen.nichtBelegt"))
// -- nie ein leeres Feld ohne Erklaerung und nie ein Ersatztext.

import { X } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { fetchLicenseText } from "../api/licenses.js";
import "./LicenseBrowser.css";

// Stabiler Listen-Schluessel eines Bestandteils. name+fassung+ebene ist innerhalb
// der Aufstellung eindeutig; der Index sichert den Rest ab.
function eintragSchluessel(teil, index) {
  return `${teil?.ebene ?? "?"}|${teil?.name ?? "?"}|${teil?.fassung ?? "?"}|${index}`;
}

// Zeigt einen Wert an -- oder die ausdrueckliche Aussage, dass er nicht belegt
// ist. Leerer String, null und undefined gelten als nicht belegt. KEIN Ersatztext,
// kein stilles Leerfeld.
function Wert({ wert, t, mono }) {
  const belegt = typeof wert === "string" ? wert.trim() !== "" : wert !== null && wert !== undefined;
  if (!belegt) {
    return (
      <span className="license-detail__value license-detail__value--leer">
        {t("lizenzen.nichtBelegt")}
      </span>
    );
  }
  return (
    <span
      className={
        mono
          ? "license-detail__value license-browser__mono"
          : "license-detail__value"
      }
    >
      {String(wert)}
    </span>
  );
}

// Eine Feld-Zeile in der Detailspalte: Label links, Wert rechts.
function FeldZeile({ label, wert, t, mono }) {
  return (
    <div className="license-detail__field">
      <span className="license-detail__field-label">{label}</span>
      <Wert wert={wert} t={t} mono={mono} />
    </div>
  );
}

// Detailspalte rechts: Stammangaben des gewaehlten Bestandteils und darunter der
// Lizenz-Volltext. Der Text wird ueber fetchLicenseText geholt, sobald ein
// lizenz_text_ref vorliegt und der Schluessel noch nicht im Zwischenspeicher
// steht. t bewusst NICHT in den useEffect-Abhaengigkeiten (Render-Schleife).
function LicenseDetailPanel({ teil, textCache, onTextGeladen, onClose }) {
  const { t } = useTranslation();

  const ref = teil?.lizenz_text_ref ?? null;
  const [status, setStatus] = useState("leer"); // leer | laedt | bereit | fehler
  const [fehler, setFehler] = useState(null);

  // Bereits geholte Texte NICHT erneut holen: liegt der Schluessel im Cache,
  // laeuft kein zweiter Abruf. onTextGeladen/textCache bewusst nicht in den
  // Abhaengigkeiten -- der Effekt haengt allein am Schluessel; die Referenz auf
  // den Cache wird ueber ein Ref gelesen, damit ein Cache-Wechsel keinen
  // Neu-Abruf ausloest.
  const cacheRef = useRef(textCache);
  cacheRef.current = textCache;
  const meldeRef = useRef(onTextGeladen);
  meldeRef.current = onTextGeladen;

  useEffect(() => {
    if (!ref) {
      setStatus("leer");
      setFehler(null);
      return undefined;
    }
    if (Object.prototype.hasOwnProperty.call(cacheRef.current, ref)) {
      setStatus("bereit");
      setFehler(null);
      return undefined;
    }

    let aktiv = true;
    setStatus("laedt");
    setFehler(null);
    (async () => {
      try {
        const text = await fetchLicenseText(ref);
        if (!aktiv) {
          return;
        }
        meldeRef.current(ref, text);
        setStatus("bereit");
      } catch (ursache) {
        if (!aktiv) {
          return;
        }
        setFehler(ursache);
        setStatus("fehler");
      }
    })();
    return () => {
      aktiv = false;
    };
  }, [ref]);

  const text = ref ? textCache[ref] : undefined;

  return (
    <aside className="license-detail">
      <div className="license-detail__header">
        <div className="license-detail__heading">
          <h3 className="license-detail__title">
            {teil?.name ?? t("lizenzen.nichtBelegt")}
          </h3>
          <span className="license-detail__subtitle">
            {teil?.fassung
              ? t("lizenzen.detail.fassungKurz", { fassung: teil.fassung })
              : t("lizenzen.nichtBelegt")}
          </span>
        </div>
        <button
          type="button"
          className="license-detail__close"
          aria-label={t("lizenzen.detail.schliessen")}
          onClick={onClose}
        >
          <X size={16} />
        </button>
      </div>

      <div className="license-detail__body">
        <section className="license-detail__section">
          {/* lizenz_id im ORIGINALWORTLAUT (nicht der Filterindex). */}
          <FeldZeile label={t("lizenzen.feld.lizenzId")} wert={teil?.lizenz_id} t={t} mono />
          <FeldZeile
            label={t("lizenzen.feld.lizenzIdQuelle")}
            wert={teil?.lizenz_id_quelle}
            t={t}
          />
          <FeldZeile
            label={t("lizenzen.feld.herkunft")}
            wert={teil?.ebene ? t(`lizenzen.ebene.${teil.ebene}`, teil.ebene) : null}
            t={t}
          />
          <FeldZeile
            label={t("lizenzen.feld.urhebervermerk")}
            wert={teil?.urhebervermerk}
            t={t}
          />
          <FeldZeile
            label={t("lizenzen.feld.urhebervermerkQuelle")}
            wert={teil?.urhebervermerk_quelle}
            t={t}
          />
          {/* projektadresse wird als TEXT gezeigt, bewusst NICHT als Verweis. */}
          <FeldZeile
            label={t("lizenzen.feld.projektadresse")}
            wert={teil?.projektadresse}
            t={t}
            mono
          />
          <FeldZeile
            label={t("lizenzen.feld.mitgeliefert")}
            wert={
              typeof teil?.mitgeliefert === "boolean"
                ? teil.mitgeliefert
                  ? t("lizenzen.ja")
                  : t("lizenzen.nein")
                : teil?.mitgeliefert
            }
            t={t}
          />

          {/* Ebenen-spezifische Zusatzfelder -- nur zeigen, wenn die Ebene sie
              ueberhaupt fuehrt (kein erfundenes Feld). */}
          {teil?.ebene === "python" ? (
            <FeldZeile
              label={t("lizenzen.feld.nurClassifier")}
              wert={
                typeof teil?.lizenz_id_nur_classifier === "boolean"
                  ? teil.lizenz_id_nur_classifier
                    ? t("lizenzen.ja")
                    : t("lizenzen.nein")
                  : teil?.lizenz_id_nur_classifier
              }
              t={t}
            />
          ) : null}
          {teil?.ebene === "npm" ? (
            <FeldZeile label={t("lizenzen.feld.npmOrt")} wert={teil?.npm_ort} t={t} mono />
          ) : null}
          {teil?.ebene === "daten" ? (
            <>
              <FeldZeile label={t("lizenzen.feld.pfad")} wert={teil?.pfad} t={t} mono />
              <FeldZeile
                label={t("lizenzen.feld.lizenzIdFundstelle")}
                wert={teil?.lizenz_id_fundstelle}
                t={t}
              />
            </>
          ) : null}
          {teil?.ebene === "programme" ? (
            <>
              <FeldZeile label={t("lizenzen.feld.zweck")} wert={teil?.zweck} t={t} />
              <FeldZeile
                label={t("lizenzen.feld.quelleDerAngabe")}
                wert={teil?.quelle_der_angabe}
                t={t}
              />
              <FeldZeile
                label={t("lizenzen.feld.lieferndesPaket")}
                wert={teil?.lieferndes_paket}
                t={t}
              />
              <FeldZeile label={t("lizenzen.feld.fundstelle")} wert={teil?.fundstelle} t={t} mono />
              <FeldZeile label={t("lizenzen.feld.plattform")} wert={teil?.plattform} t={t} />
              {/* vorhanden ist eine EIGENE Angabe -- nicht_zutreffend ist kein
                  Fehler, sondern ein benannter Zustand. */}
              <FeldZeile
                label={t("lizenzen.feld.vorhanden")}
                wert={
                  teil?.vorhanden
                    ? t(`lizenzen.vorhanden.${teil.vorhanden}`, teil.vorhanden)
                    : null
                }
                t={t}
              />
            </>
          ) : null}
        </section>

        <section className="license-detail__section">
          <h4 className="license-detail__section-title">
            {t("lizenzen.detail.volltext")}
          </h4>
          <FeldZeile
            label={t("lizenzen.feld.lizenzTextQuelle")}
            wert={teil?.lizenz_text_quelle}
            t={t}
          />

          {!ref ? (
            <p className="license-detail__hinweis">{t("lizenzen.detail.keinText")}</p>
          ) : status === "laedt" ? (
            <p className="license-detail__hinweis">{t("lizenzen.detail.textLaedt")}</p>
          ) : status === "fehler" ? (
            <p className="license-detail__fehler" role="alert">
              {fehler?.status === 404
                ? t("lizenzen.detail.textUnbekannt", { schluessel: ref })
                : fehler?.status === 503
                  ? t("lizenzen.fehler.keineAufstellung")
                  : t("lizenzen.detail.textFehler")}
              {fehler?.detail ? (
                <span className="license-detail__fehler-detail">{fehler.detail}</span>
              ) : null}
            </p>
          ) : typeof text === "string" && text !== "" ? (
            // Zeichengleiche Darstellung: feste Schriftbreite, Umbrueche erhalten.
            <pre className="license-detail__text">{text}</pre>
          ) : (
            <p className="license-detail__hinweis">{t("lizenzen.detail.keinText")}</p>
          )}
        </section>
      </div>
    </aside>
  );
}

// Der Browser selbst: Werkzeugleiste (zwei Filter + Suche), links die Liste,
// rechts die Detailspalte bei Auswahl.
export default function LicenseBrowser({ bestandteile }) {
  const { t } = useTranslation();

  const [lizenzFilter, setLizenzFilter] = useState("");   // lizenz_id_normalisiert
  const [herkunftFilter, setHerkunftFilter] = useState(""); // ebene
  const [suchbegriff, setSuchbegriff] = useState("");
  const [gewaehlt, setGewaehlt] = useState(null); // Listen-Schluessel oder null
  // Zwischenspeicher der bereits geholten Lizenztexte, nach Schluessel. Ein
  // bereits geholter Text wird nicht erneut geholt.
  const [textCache, setTextCache] = useState({});

  const liste = useMemo(
    () => (Array.isArray(bestandteile) ? bestandteile : []),
    [bestandteile],
  );

  // Ein stabiler Schluessel JE Bestandteil, einmal an der ungefilterten Liste
  // vergeben. So bleibt die Auswahl beim Filtern erhalten und die Zuordnung ist
  // ein einfacher Nachschlag statt einer Suche ueber die Liste.
  const schluesselVon = useMemo(() => {
    const map = new Map();
    liste.forEach((teil, index) => map.set(teil, eintragSchluessel(teil, index)));
    return map;
  }, [liste]);

  // Auswahlliste der Lizenzen: Wert ist lizenz_id_normalisiert (der Filterindex),
  // Beschriftung ist lizenz_id im ORIGINALWORTLAUT. Beides nicht vertauschen.
  // Traegt ein Bestandteil mehrere Schreibweisen zur selben Normalform, werden sie
  // in der Beschriftung gesammelt gezeigt -- es wird keine davon unterschlagen.
  const lizenzOptionen = useMemo(() => {
    const nachNorm = new Map(); // norm -> Set(originale lizenz_id)
    for (const teil of liste) {
      const norm = teil?.lizenz_id_normalisiert;
      if (typeof norm !== "string" || norm === "") {
        continue;
      }
      if (!nachNorm.has(norm)) {
        nachNorm.set(norm, new Set());
      }
      const roh = teil?.lizenz_id;
      if (typeof roh === "string" && roh !== "") {
        nachNorm.get(norm).add(roh);
      }
    }
    return [...nachNorm.entries()]
      .map(([norm, originale]) => ({
        wert: norm,
        // Beschriftung = Originalwortlaut; fehlt er ganz, ist das nicht belegt.
        beschriftung:
          originale.size > 0 ? [...originale].sort().join(" · ") : t("lizenzen.nichtBelegt"),
      }))
      .sort((a, b) => a.beschriftung.localeCompare(b.beschriftung));
  }, [liste, t]);

  // Auswahlliste der Herkunft: die vorkommenden Ebenen, in Vorkommensreihenfolge.
  const herkunftOptionen = useMemo(() => {
    const ebenen = [];
    for (const teil of liste) {
      const ebene = teil?.ebene;
      if (typeof ebene === "string" && ebene !== "" && !ebenen.includes(ebene)) {
        ebenen.push(ebene);
      }
    }
    return ebenen;
  }, [liste]);

  // Gefilterte Liste: Lizenzfilter auf lizenz_id_normalisiert, Herkunftsfilter auf
  // ebene, Suche ueber Namen UND Fassung.
  const gefiltert = useMemo(() => {
    const needle = suchbegriff.trim().toLowerCase();
    return liste.filter((teil) => {
      if (lizenzFilter && teil?.lizenz_id_normalisiert !== lizenzFilter) {
        return false;
      }
      if (herkunftFilter && teil?.ebene !== herkunftFilter) {
        return false;
      }
      if (needle) {
        const heu = `${teil?.name ?? ""} ${teil?.fassung ?? ""}`.toLowerCase();
        if (!heu.includes(needle)) {
          return false;
        }
      }
      return true;
    });
  }, [liste, lizenzFilter, herkunftFilter, suchbegriff]);

  // Der gewaehlte Bestandteil -- nur, wenn er in der gefilterten Liste noch
  // vorkommt. Faellt er durch einen Filter heraus, verschwindet die Detailspalte.
  const gewaehltesTeil = useMemo(() => {
    if (!gewaehlt) {
      return null;
    }
    return gefiltert.find((teil) => schluesselVon.get(teil) === gewaehlt) ?? null;
  }, [gewaehlt, gefiltert, schluesselVon]);

  const merkeText = (schluessel, text) => {
    setTextCache((alt) =>
      Object.prototype.hasOwnProperty.call(alt, schluessel)
        ? alt
        : { ...alt, [schluessel]: text },
    );
  };

  return (
    <div className="license-browser">
      <div className="license-browser__toolbar">
        <label className="license-browser__feld">
          <span className="license-browser__feld-label">
            {t("lizenzen.filter.lizenz")}
          </span>
          <select
            className="license-browser__select"
            value={lizenzFilter}
            onChange={(e) => setLizenzFilter(e.target.value)}
          >
            <option value="">{t("lizenzen.filter.alle")}</option>
            {lizenzOptionen.map((option) => (
              <option key={option.wert} value={option.wert}>
                {option.beschriftung}
              </option>
            ))}
          </select>
        </label>

        <label className="license-browser__feld">
          <span className="license-browser__feld-label">
            {t("lizenzen.filter.herkunft")}
          </span>
          <select
            className="license-browser__select"
            value={herkunftFilter}
            onChange={(e) => setHerkunftFilter(e.target.value)}
          >
            <option value="">{t("lizenzen.filter.alle")}</option>
            {herkunftOptionen.map((ebene) => (
              <option key={ebene} value={ebene}>
                {t(`lizenzen.ebene.${ebene}`, ebene)}
              </option>
            ))}
          </select>
        </label>

        <label className="license-browser__feld license-browser__feld--suche">
          <span className="license-browser__feld-label">
            {t("lizenzen.filter.suche")}
          </span>
          <input
            type="text"
            className="license-browser__input"
            placeholder={t("lizenzen.filter.suchePlatzhalter")}
            value={suchbegriff}
            onChange={(e) => setSuchbegriff(e.target.value)}
          />
        </label>

        <span className="license-browser__count">
          {t("lizenzen.filter.zaehler", {
            n: gefiltert.length,
            m: liste.length,
          })}
        </span>
      </div>

      {/* Master-Detail nach dem Vorbild observe__split: Liste links, Detailspalte
          rechts -- letztere erscheint erst bei Auswahl. */}
      <div className="license-browser__split">
        <div className="license-browser__list">
          {gefiltert.length === 0 ? (
            <p className="license-browser__leer">
              {liste.length === 0
                ? t("lizenzen.liste.keineBestandteile")
                : t("lizenzen.liste.keinTreffer")}
            </p>
          ) : (
            <table className="license-browser__table">
              <thead className="license-browser__head">
                <tr>
                  <th className="license-browser__th">{t("lizenzen.spalte.name")}</th>
                  <th className="license-browser__th">{t("lizenzen.spalte.fassung")}</th>
                  <th className="license-browser__th">{t("lizenzen.spalte.lizenz")}</th>
                  <th className="license-browser__th">{t("lizenzen.spalte.herkunft")}</th>
                </tr>
              </thead>
              <tbody>
                {gefiltert.map((teil) => {
                  const schluessel = schluesselVon.get(teil);
                  const aktiv = schluessel === gewaehlt;
                  return (
                    <tr
                      key={schluessel}
                      className={
                        aktiv
                          ? "license-browser__row license-browser__row--aktiv"
                          : "license-browser__row"
                      }
                      onClick={() => setGewaehlt(aktiv ? null : schluessel)}
                      aria-selected={aktiv}
                    >
                      <td className="license-browser__td">
                        {teil?.name ?? t("lizenzen.nichtBelegt")}
                      </td>
                      <td className="license-browser__td license-browser__mono">
                        {teil?.fassung ?? t("lizenzen.nichtBelegt")}
                      </td>
                      {/* Angezeigt wird lizenz_id im Originalwortlaut. */}
                      <td className="license-browser__td license-browser__mono">
                        {typeof teil?.lizenz_id === "string" && teil.lizenz_id !== ""
                          ? teil.lizenz_id
                          : t("lizenzen.nichtBelegt")}
                      </td>
                      <td className="license-browser__td">
                        {teil?.ebene
                          ? t(`lizenzen.ebene.${teil.ebene}`, teil.ebene)
                          : t("lizenzen.nichtBelegt")}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>

        {gewaehltesTeil ? (
          <LicenseDetailPanel
            key={gewaehlt}
            teil={gewaehltesTeil}
            textCache={textCache}
            onTextGeladen={merkeText}
            onClose={() => setGewaehlt(null)}
          />
        ) : null}
      </div>
    </div>
  );
}
