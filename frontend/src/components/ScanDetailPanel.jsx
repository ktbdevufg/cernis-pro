// Scan-Detail-Panel (CERNIS PRO 2.0)
// Seitliches Panel rechts neben der Scan-Tabelle. Zeigt die Details des
// gewählten Geräts in drei Abschnitten — das Wichtigste zuerst: Identität,
// offene Ports, Gerätenotizen.
//
// Die Komponente kennt nur ihre Props (geraet, onClose). Sie hält keinen
// echten Zustand: die Notizfelder sind optisch vollständig, ihre Werte sind
// vorerst Platzhalter aus dem Mock. Speichern und Port-Nachschlagen rufen
// reine Platzhalter-Handler.

import { Fingerprint, Network, StickyNote, X } from "lucide-react";
import { useTranslation } from "react-i18next";

import "./ScanDetailPanel.css";

// Eine Feld-Zeile: Label links, Wert rechts. mono tönt den Wert monospace.
function FeldZeile({ label, wert, mono }) {
  return (
    <div className="scan-detail__field">
      <span className="scan-detail__field-label">{label}</span>
      <span
        className={
          mono
            ? "scan-detail__field-value scan-detail__mono"
            : "scan-detail__field-value"
        }
      >
        {wert}
      </span>
    </div>
  );
}

export default function ScanDetailPanel({ geraet, onClose }) {
  const { t } = useTranslation();

  // Kopf: Gerätename/Hostname, fällt auf IP zurück, wenn kein Hostname.
  const titel = geraet.hostname || geraet.ip;

  // Statuszeile in Sprache (nicht Ampel): neu vs. bekannt, notable dezent.
  const statusKlasse = geraet.isNew
    ? "scan-detail__status scan-detail__status--neu"
    : "scan-detail__status scan-detail__status--bekannt";
  const statusText = geraet.isNew
    ? t("beobachten.scan.detail.identity.statusNew")
    : t("beobachten.scan.detail.identity.statusKnown");

  // Platzhalter — späteres echtes Nachschlagen hängt sich hier an.
  const handleNachschlagen = (port) => {
    // Bewusst ohne Funktion (Nachschlagen kommt mit der Datenanbindung).
    void port;
  };

  // TEMP: Speichern ist Platzhalter — wird mit echter API verdrahtet.
  const handleSpeichern = () => {
    // Bewusst ohne Funktion.
  };

  return (
    <aside className="scan-detail">
      <div className="scan-detail__header">
        <div className="scan-detail__heading">
          <h3 className="scan-detail__title">{titel}</h3>
          <span className="scan-detail__subtitle scan-detail__mono">
            {geraet.ip}
          </span>
        </div>
        <button
          type="button"
          className="scan-detail__close"
          onClick={onClose}
          aria-label={t("beobachten.scan.detail.close")}
          title={t("beobachten.scan.detail.close")}
        >
          <X size={18} />
        </button>
      </div>

      <div className="scan-detail__body">
        {/* 1. Identität */}
        <section className="scan-detail__section">
          <h4 className="scan-detail__section-heading">
            <Fingerprint size={15} aria-hidden="true" />
            <span>{t("beobachten.scan.detail.identity.heading")}</span>
          </h4>
          <div className="scan-detail__fields">
            <FeldZeile
              label={t("beobachten.scan.detail.identity.hostname")}
              wert={geraet.hostname || "—"}
            />
            <FeldZeile
              label={t("beobachten.scan.detail.identity.ip")}
              wert={geraet.ip}
              mono
            />
            <FeldZeile
              label={t("beobachten.scan.detail.identity.mac")}
              wert={geraet.mac}
              mono
            />
            <FeldZeile
              label={t("beobachten.scan.detail.identity.vendor")}
              wert={geraet.vendor || "—"}
            />
            <FeldZeile
              label={t("beobachten.scan.detail.identity.os")}
              wert={geraet.osGuess || "—"}
            />
            <FeldZeile
              label={t("beobachten.scan.detail.identity.ping")}
              wert={
                geraet.pingMs === null || geraet.pingMs === undefined
                  ? "—"
                  : geraet.pingMs === 0
                    ? t("beobachten.scan.pingSubMs")
                    : t("beobachten.scan.detail.identity.pingUnit", {
                        value: geraet.pingMs,
                      })
              }
              mono
            />
            {geraet.additionalIps && geraet.additionalIps.length > 0 && (
              <FeldZeile
                label={t("beobachten.scan.detail.identity.additionalIps")}
                wert={geraet.additionalIps.join(", ")}
                mono
              />
            )}
          </div>

          <p className={statusKlasse}>{statusText}</p>
          {geraet.notable && (
            <p className="scan-detail__status scan-detail__status--notable">
              {t("beobachten.scan.detail.identity.notable")}
            </p>
          )}
        </section>

        {/* 2. Offene Ports */}
        <section className="scan-detail__section">
          <h4 className="scan-detail__section-heading">
            <Network size={15} aria-hidden="true" />
            <span>{t("beobachten.scan.detail.ports.heading")}</span>
          </h4>

          {geraet.ports.length === 0 ? (
            <p className="scan-detail__empty">
              {t("beobachten.scan.detail.ports.empty")}
            </p>
          ) : (
            <ul className="scan-detail__ports">
              {geraet.ports.map((port) => (
                <li
                  key={`${port.num}/${port.proto}`}
                  className="scan-detail__port"
                >
                  <span className="scan-detail__port-num scan-detail__mono">
                    {port.num}
                  </span>
                  <span className="scan-detail__port-proto">{port.proto}</span>
                  {port.service && (
                    <span className="scan-detail__port-service">
                      {port.service}
                    </span>
                  )}
                  <button
                    type="button"
                    className="scan-detail__lookup"
                    onClick={() => handleNachschlagen(port)}
                  >
                    {t("beobachten.scan.detail.ports.lookup")}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>

        {/* 3. Gerätenotizen */}
        <section className="scan-detail__section">
          <h4 className="scan-detail__section-heading">
            <StickyNote size={15} aria-hidden="true" />
            <span>{t("beobachten.scan.detail.notes.heading")}</span>
          </h4>

          <div className="scan-detail__form">
            <label className="scan-detail__form-row">
              <span className="scan-detail__form-label">
                {t("beobachten.scan.detail.notes.label")}
              </span>
              <input
                type="text"
                className="scan-detail__input"
                defaultValue={geraet.label || ""}
                placeholder={t(
                  "beobachten.scan.detail.notes.labelPlaceholder",
                )}
              />
            </label>

            <label className="scan-detail__form-row">
              <span className="scan-detail__form-label">
                {t("beobachten.scan.detail.notes.tags")}
              </span>
              <input
                type="text"
                className="scan-detail__input"
                defaultValue={(geraet.tags || []).join(", ")}
                placeholder={t("beobachten.scan.detail.notes.tagsPlaceholder")}
              />
            </label>

            <label className="scan-detail__form-row">
              <span className="scan-detail__form-label">
                {t("beobachten.scan.detail.notes.notes")}
              </span>
              <textarea
                className="scan-detail__textarea"
                rows={4}
                defaultValue={geraet.notes || ""}
                placeholder={t("beobachten.scan.detail.notes.notesPlaceholder")}
              />
            </label>

            {/* TEMP: Speichern ist Platzhalter — wird mit echter API verdrahtet. */}
            <button
              type="button"
              className="scan-detail__save"
              onClick={handleSpeichern}
            >
              {t("beobachten.scan.detail.notes.save")}
            </button>
            <p className="scan-detail__save-hint">
              {t("beobachten.scan.detail.notes.saveHint")}
            </p>
          </div>
        </section>
      </div>
    </aside>
  );
}
