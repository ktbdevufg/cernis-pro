// Archiv-Nachfrage-Dialog (CERNIS PRO 2.0)
// Erscheint nach einem Scan, wenn das Backend lange nicht gesehene Geräte als
// Archiv-Kandidaten meldet. Der Dialog fragt je Gerät ruhig nach, ob es aus der
// Liste genommen (archiviert) werden soll — NICHTS passiert automatisch, der
// Nutzer entscheidet (S3, mündiger Anwender, kein Imperativ-Druck, kein Zwang).
//
// Markup-/CSS-Konventionen wie DeviceManagementPanel.jsx (CSS-Tokens, keine
// festen Farben). Anzeige-Name- und Datums-Logik bewusst identisch zum Panel:
// keine neu erfundene Tage-Berechnung — gezeigt wird das Datum "zuletzt gesehen"
// plus den einordnenden i18n-Text.
//
// Props:
//   candidates  Array gemappter Geräte (camelCase, wie aus mappeDevice).
//   onAntwort   (mac, archive) -> Promise. Resolve -> Zeile verschwindet;
//               Reject -> Zeile bleibt stehen (Nutzer kann es erneut versuchen).
//   onClose     () -> void. Schließt den Dialog (jederzeit verfügbar, kein Zwang).

import { useState } from "react";
import { useTranslation } from "react-i18next";

import "./ArchivePromptDialog.css";

// Anzeige-Name eines Geräts: label -> hostname -> mac (kein erfundener Wert,
// die MAC ist immer vorhanden). Gleiche Logik wie im Verwaltungs-Panel.
function anzeigeName(geraet) {
  return geraet.label || geraet.hostname || geraet.mac;
}

// Ein roher ISO/epoch-Wert -> kurzes lokales Datum+Uhrzeit. Bei fehlendem/
// unparsbarem Wert -> null (Aufrufer zeigt dann „—“). Gleiche Logik wie
// lokalesDatum im Verwaltungs-Panel. Kein erfundenes Datum.
function lokalesDatum(roh) {
  if (!roh) {
    return null;
  }
  const d = new Date(roh);
  return Number.isNaN(d.getTime()) ? null : d.toLocaleString();
}

export default function ArchivePromptDialog({ candidates, onAntwort, onClose }) {
  const { t } = useTranslation();

  // Bereits beantwortete MACs (lokal herausgefiltert — die Zeile verschwindet
  // nach erfolgreicher Antwort). Reine Sicht-Filterung, der Server-Stand kommt
  // beim nächsten Verwaltungs-Aufruf.
  const [beantwortet, setBeantwortet] = useState(new Set());
  // MACs mit gerade laufender Antwort: sperrt beide Knöpfe der Zeile (Muster
  // wie busyMacs im Verwaltungs-Panel).
  const [beschaeftigt, setBeschaeftigt] = useState(new Set());

  // Noch offene Kandidaten: alles, was nicht bereits beantwortet wurde.
  const offen = candidates.filter((g) => !beantwortet.has(g.mac));

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

  // Antwort auf eine Zeile: ruft onAntwort und entscheidet anhand resolve/reject,
  // ob die Zeile verschwindet. Bei Erfolg wird die MAC als beantwortet markiert;
  // ist danach keine Zeile mehr offen, schließt der Dialog automatisch. Bei
  // Fehler bleibt die Zeile stehen (kein Hängenbleiben, erneut versuchbar) —
  // Komfortpfad, daher keine dezente Fehleranzeige nötig.
  const handleAntwort = async (mac, archive) => {
    markiereBeschaeftigt(mac, true);
    try {
      await onAntwort(mac, archive);
      const verbleibend = offen.filter((g) => g.mac !== mac);
      setBeantwortet((prev) => {
        const next = new Set(prev);
        next.add(mac);
        return next;
      });
      if (verbleibend.length === 0) {
        onClose();
      }
    } catch (ursache) {
      console.error("Archiv-Nachfrage beantworten fehlgeschlagen:", ursache);
    } finally {
      markiereBeschaeftigt(mac, false);
    }
  };

  // Sollte über die Aufruf-Bedingung (candidates.length > 0) nicht vorkommen;
  // defensiv dennoch eine ruhige Leerzeile statt eines leeren Dialogs.
  return (
    <div className="ap-overlay" role="presentation" onClick={onClose}>
      <div
        className="ap-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="ap-titel"
        onClick={(e) => e.stopPropagation()}
      >
        <h2 id="ap-titel" className="ap-dialog__titel">
          {t("geraete.nachfrage.titel")}
        </h2>
        <p className="ap-dialog__einleitung">
          {t("geraete.nachfrage.einleitung")}
        </p>

        {offen.length === 0 ? (
          <p className="ap-empty">{t("geraete.nachfrage.leer")}</p>
        ) : (
          <ul className="ap-liste">
            {offen.map((geraet) => {
              const gesehen = lokalesDatum(geraet.lastSeen);
              const beschaeftigtZeile = beschaeftigt.has(geraet.mac);
              return (
                <li key={geraet.mac} className="ap-zeile">
                  <div className="ap-zeile__info">
                    <span className="ap-zeile__name">
                      {anzeigeName(geraet)}
                    </span>
                    <span className="ap-zeile__mac ap-mono">{geraet.mac}</span>
                    <span className="ap-zeile__gesehen">
                      {t("geraete.nachfrage.zuletztGesehen")} {gesehen || "—"}
                    </span>
                  </div>
                  <div className="ap-zeile__aktionen">
                    <button
                      type="button"
                      className="ap-aktion ap-aktion--archivieren"
                      onClick={() => handleAntwort(geraet.mac, true)}
                      disabled={beschaeftigtZeile}
                    >
                      {t("geraete.nachfrage.knopfArchivieren")}
                    </button>
                    <button
                      type="button"
                      className="ap-aktion ap-aktion--behalten"
                      onClick={() => handleAntwort(geraet.mac, false)}
                      disabled={beschaeftigtZeile}
                    >
                      {t("geraete.nachfrage.knopfBehalten")}
                    </button>
                  </div>
                </li>
              );
            })}
          </ul>
        )}

        <div className="ap-dialog__fuss">
          <button type="button" className="ap-spaeter" onClick={onClose}>
            {t("geraete.nachfrage.knopfSpaeter")}
          </button>
        </div>
      </div>
    </div>
  );
}
