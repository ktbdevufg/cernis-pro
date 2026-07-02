// Geräteverwaltungs-Panel (CERNIS PRO 2.0)
// Die zentrale Geräte-Funktion hinter der Verwaltungs-Kachel. Drei Bereiche in
// einem Panel: aktive Geräte (sehen, archivieren), Gerät anlegen, Archiv
// (wiederherstellen). Markup-/CSS-Konventionen wie FritzBoxPanel.jsx
// (CSS-Tokens, keine festen Farben, fritz-table-artige Tabellen → hier dm-*).
//
// Daten laden in einem useEffect; Reload nach jeder Aktion über einen
// gemeinsamen useCallback-Pfad (laden). t/i18n NIE in useEffect-Dependencies
// (Render-Loop), Muster wie CveView.jsx.
//
// Lebenszyklus-Sprache (Vision: zeigen + einordnen, kein Imperativ-Druck):
// archivierte Geräte sind aus Wertungen/Listen ausgenommen, aber NICHT gelöscht
// — der Weg zurück ist immer da (Wiederherstellen).

import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import {
  archiveDevice,
  createDevice,
  fetchArchivedDevices,
  fetchDevices,
  restoreDevice,
  tagsAusText,
} from "../api/devices.js";
import { ApiError } from "../api/client.js";
import "./DeviceManagementPanel.css";

// Anzeige-Name eines Geräts: label -> hostname -> mac (kein erfundener Wert,
// die MAC ist immer vorhanden). Reine Hilfsfunktion.
function anzeigeName(geraet) {
  return geraet.label || geraet.hostname || geraet.mac;
}

// Ein roher ISO/epoch-Wert -> kurzes lokales Datum+Uhrzeit. Bei fehlendem/
// unparsbarem Wert -> null (Aufrufer zeigt dann „—“). Analog kurzDatum in
// CveView.jsx, hier mit Uhrzeit (toLocaleString). Kein erfundenes Datum.
function lokalesDatum(roh) {
  if (!roh) {
    return null;
  }
  const d = new Date(roh);
  return Number.isNaN(d.getTime()) ? null : d.toLocaleString();
}

// Herkunfts-Badge: "self" -> „eigener Host", "manual" -> „manuell", sonst
// „Scan". Dezent über die CSS-Tokens, keine erfundene Farbe.
function HerkunftBadge({ source }) {
  const { t } = useTranslation();
  const istSelbst = source === "self";
  const istManuell = source === "manual";
  const herkunft = istSelbst ? "self" : istManuell ? "manual" : "scan";
  const text = istSelbst
    ? t("geraete.verwaltung.herkunftSelbst")
    : istManuell
      ? t("geraete.verwaltung.herkunftManuell")
      : t("geraete.verwaltung.herkunftScan");
  return (
    <span className="dm-badge" data-herkunft={herkunft}>
      {text}
    </span>
  );
}

// Tabelle der aktiven Geräte. Leerer Bestand -> ruhige Leerzeile. Die Aktion
// „Archivieren" ist während einer laufenden Aktion gesperrt (busyMacs).
function AktiveTabelle({ devices, onArchivieren, busyMacs }) {
  const { t } = useTranslation();

  if (devices.length === 0) {
    return <p className="dm-empty">{t("geraete.verwaltung.leerAktiv")}</p>;
  }

  return (
    <div className="dm-table-wrap">
      <table className="dm-table">
        <thead>
          <tr>
            <th className="dm-table__th">
              {t("geraete.verwaltung.spaltenLabel")}
            </th>
            <th className="dm-table__th">
              {t("geraete.verwaltung.spaltenMac")}
            </th>
            <th className="dm-table__th">
              {t("geraete.verwaltung.spaltenIp")}
            </th>
            <th className="dm-table__th">
              {t("geraete.verwaltung.spaltenHerkunft")}
            </th>
            <th className="dm-table__th">
              {t("geraete.verwaltung.spaltenGesehen")}
            </th>
            <th className="dm-table__th dm-table__th--action" />
          </tr>
        </thead>
        <tbody>
          {devices.map((geraet) => {
            const gesehen = lokalesDatum(geraet.lastSeen);
            const beschaeftigt = busyMacs.has(geraet.mac);
            return (
              <tr key={geraet.mac} className="dm-table__row">
                <td className="dm-table__cell">{anzeigeName(geraet)}</td>
                <td className="dm-table__cell dm-panel__mono">{geraet.mac}</td>
                <td className="dm-table__cell dm-panel__mono">
                  {geraet.lastIp || "—"}
                </td>
                <td className="dm-table__cell">
                  <HerkunftBadge source={geraet.source} />
                </td>
                <td className="dm-table__cell dm-table__cell--nowrap">
                  {gesehen || "—"}
                </td>
                <td className="dm-table__cell dm-table__cell--action">
                  <button
                    type="button"
                    className="dm-row-action"
                    onClick={() => onArchivieren(geraet.mac)}
                    disabled={beschaeftigt}
                  >
                    {t("geraete.verwaltung.aktionArchivieren")}
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// Tabelle der archivierten Geräte. Gleiche Spalten wie aktiv, aber ohne
// Herkunft; Aktion „Wiederherstellen". Leeres Archiv -> ruhige Leerzeile.
function ArchivTabelle({ archived, onWiederherstellen, busyMacs }) {
  const { t } = useTranslation();

  if (archived.length === 0) {
    return <p className="dm-empty">{t("geraete.verwaltung.leerArchiv")}</p>;
  }

  return (
    <div className="dm-table-wrap">
      <table className="dm-table">
        <thead>
          <tr>
            <th className="dm-table__th">
              {t("geraete.verwaltung.spaltenLabel")}
            </th>
            <th className="dm-table__th">
              {t("geraete.verwaltung.spaltenMac")}
            </th>
            <th className="dm-table__th">
              {t("geraete.verwaltung.spaltenIp")}
            </th>
            <th className="dm-table__th">
              {t("geraete.verwaltung.spaltenGesehen")}
            </th>
            <th className="dm-table__th dm-table__th--action" />
          </tr>
        </thead>
        <tbody>
          {archived.map((geraet) => {
            const gesehen = lokalesDatum(geraet.lastSeen);
            const beschaeftigt = busyMacs.has(geraet.mac);
            return (
              <tr key={geraet.mac} className="dm-table__row">
                <td className="dm-table__cell">{anzeigeName(geraet)}</td>
                <td className="dm-table__cell dm-panel__mono">{geraet.mac}</td>
                <td className="dm-table__cell dm-panel__mono">
                  {geraet.lastIp || "—"}
                </td>
                <td className="dm-table__cell dm-table__cell--nowrap">
                  {gesehen || "—"}
                </td>
                <td className="dm-table__cell dm-table__cell--action">
                  <button
                    type="button"
                    className="dm-row-action"
                    onClick={() => onWiederherstellen(geraet.mac)}
                    disabled={beschaeftigt}
                  >
                    {t("geraete.verwaltung.aktionWiederherstellen")}
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// Anlege-Formular: kleine Eingabemaske, KEIN <form>-Submit-Reload (Button mit
// onClick). MAC ist Pflicht; der Anlegen-Knopf ist ohne MAC bzw. während des
// Anlegens gesperrt. Fehler werden als ruhiges Hinweisfeld gezeigt (kein
// alert()).
function AnlegeFormular({ onAnlegen, arbeitet, fehlerMeldung }) {
  const { t } = useTranslation();
  const [mac, setMac] = useState("");
  const [label, setLabel] = useState("");
  const [category, setCategory] = useState("");
  const [notes, setNotes] = useState("");
  const [tagsText, setTagsText] = useState("");

  const macGesetzt = mac.trim().length > 0;

  const handleAnlegen = async () => {
    const erfolg = await onAnlegen({
      mac: mac.trim(),
      label,
      notes,
      category,
      tags: tagsAusText(tagsText),
    });
    // Nur bei Erfolg das Formular leeren — bei Fehler bleibt die Eingabe stehen.
    if (erfolg) {
      setMac("");
      setLabel("");
      setCategory("");
      setNotes("");
      setTagsText("");
    }
  };

  return (
    <div className="dm-form">
      <div className="dm-form__row">
        <label className="dm-form__field">
          <span className="dm-form__label">
            {t("geraete.verwaltung.feldMac")}
          </span>
          <input
            className="dm-form__input dm-panel__mono"
            type="text"
            value={mac}
            onChange={(e) => setMac(e.target.value)}
          />
        </label>
        <label className="dm-form__field">
          <span className="dm-form__label">
            {t("geraete.verwaltung.feldLabel")}
          </span>
          <input
            className="dm-form__input"
            type="text"
            value={label}
            onChange={(e) => setLabel(e.target.value)}
          />
        </label>
        <label className="dm-form__field">
          <span className="dm-form__label">
            {t("geraete.verwaltung.feldKategorie")}
          </span>
          <input
            className="dm-form__input"
            type="text"
            value={category}
            onChange={(e) => setCategory(e.target.value)}
          />
        </label>
      </div>

      <div className="dm-form__row">
        <label className="dm-form__field dm-form__field--wide">
          <span className="dm-form__label">
            {t("geraete.verwaltung.feldNotizen")}
          </span>
          <input
            className="dm-form__input"
            type="text"
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
          />
        </label>
        <label className="dm-form__field dm-form__field--wide">
          <span className="dm-form__label">
            {t("geraete.verwaltung.feldTags")}
          </span>
          <input
            className="dm-form__input"
            type="text"
            value={tagsText}
            onChange={(e) => setTagsText(e.target.value)}
          />
        </label>
      </div>

      {fehlerMeldung ? (
        <p className="dm-form__error" role="alert">
          {fehlerMeldung}
        </p>
      ) : null}

      <button
        type="button"
        className="dm-form__button"
        onClick={handleAnlegen}
        disabled={arbeitet || !macGesetzt}
      >
        {t("geraete.verwaltung.knopfAnlegen")}
      </button>
    </div>
  );
}

export default function DeviceManagementPanel() {
  const { t } = useTranslation();

  const [devices, setDevices] = useState([]);
  const [archived, setArchived] = useState([]);
  const [laden, setLaden] = useState(true);
  const [fehler, setFehler] = useState(null);
  // MACs mit gerade laufender Archivieren/Wiederherstellen-Aktion (Knopf gesperrt).
  const [beschaeftigt, setBeschaeftigt] = useState(new Set());
  // Anlege-Zustand: läuft die Aktion + die ruhige Fehlermeldung (null = keine).
  const [legtAn, setLegtAn] = useState(false);
  const [anlegeFehler, setAnlegeFehler] = useState(null);

  // Aktive + archivierte Geräte laden. Gemeinsamer Pfad für Mount und Reload
  // nach jeder Aktion. t/i18n NICHT in den Dependencies.
  const ladeListen = useCallback(async () => {
    setLaden(true);
    setFehler(null);
    try {
      const [aktiv, archiv] = await Promise.all([
        fetchDevices(false),
        fetchArchivedDevices(),
      ]);
      setDevices(aktiv);
      setArchived(archiv);
    } catch (ursache) {
      console.error("Geräteverwaltung laden fehlgeschlagen:", ursache);
      setFehler("ladeFehler");
    } finally {
      setLaden(false);
    }
  }, []);

  useEffect(() => {
    ladeListen();
  }, [ladeListen]);

  // Eine MAC für die Dauer einer Aktion sperren / wieder freigeben.
  const markiereBeschaeftigt = (mac, an) => {
    setBeschaeftigt((prev) => {
      const next = new Set(prev);
      if (an) {
        next.add(mac);
      } else {
        next.delete(mac);
      }
      return next;
    });
  };

  const handleArchivieren = useCallback(
    async (mac) => {
      markiereBeschaeftigt(mac, true);
      try {
        await archiveDevice(mac);
        await ladeListen();
      } catch (ursache) {
        console.error("Gerät archivieren fehlgeschlagen:", ursache);
        setFehler("ladeFehler");
      } finally {
        markiereBeschaeftigt(mac, false);
      }
    },
    [ladeListen],
  );

  const handleWiederherstellen = useCallback(
    async (mac) => {
      markiereBeschaeftigt(mac, true);
      try {
        await restoreDevice(mac);
        await ladeListen();
      } catch (ursache) {
        console.error("Gerät wiederherstellen fehlgeschlagen:", ursache);
        setFehler("ladeFehler");
      } finally {
        markiereBeschaeftigt(mac, false);
      }
    },
    [ladeListen],
  );

  // Gerät anlegen. Fehlerunterscheidung über ApiError.status: 409 -> MAC
  // existiert, 422 -> MAC ungültig, sonst generisch. Gibt true bei Erfolg
  // zurück, damit das Formular sich nur dann leert.
  const handleAnlegen = useCallback(
    async (eingabe) => {
      setLegtAn(true);
      setAnlegeFehler(null);
      try {
        await createDevice(eingabe);
        await ladeListen();
        return true;
      } catch (ursache) {
        if (ursache instanceof ApiError && ursache.status === 409) {
          setAnlegeFehler(t("geraete.verwaltung.fehlerExistiert"));
        } else if (ursache instanceof ApiError && ursache.status === 422) {
          setAnlegeFehler(t("geraete.verwaltung.fehlerMacUngueltig"));
        } else {
          setAnlegeFehler(t("geraete.verwaltung.fehlerAnlegen"));
        }
        return false;
      } finally {
        setLegtAn(false);
      }
    },
    [ladeListen, t],
  );

  if (laden && devices.length === 0 && archived.length === 0) {
    return (
      <div className="dm-panel">
        <p className="dm-panel__loading">{t("geraete.verwaltung.laedt")}</p>
      </div>
    );
  }

  if (fehler) {
    return (
      <div className="dm-panel">
        <p className="dm-empty">{t("geraete.verwaltung.ladeFehler")}</p>
      </div>
    );
  }

  return (
    <div className="dm-panel">
      <section className="dm-section">
        <h3 className="dm-section__title">
          {t("geraete.verwaltung.titelAktiv")}
        </h3>
        <AktiveTabelle
          devices={devices}
          onArchivieren={handleArchivieren}
          busyMacs={beschaeftigt}
        />
      </section>

      <section className="dm-section">
        <h3 className="dm-section__title">
          {t("geraete.verwaltung.titelAnlegen")}
        </h3>
        <AnlegeFormular
          onAnlegen={handleAnlegen}
          arbeitet={legtAn}
          fehlerMeldung={anlegeFehler}
        />
      </section>

      <section className="dm-section">
        <h3 className="dm-section__title">
          {t("geraete.verwaltung.titelArchiv")}
        </h3>
        <p className="dm-section__hint">
          {t("geraete.verwaltung.archivHinweis")}
        </p>
        <ArchivTabelle
          archived={archived}
          onWiederherstellen={handleWiederherstellen}
          busyMacs={beschaeftigt}
        />
      </section>
    </div>
  );
}
