// Scan-Detail-Panel (CERNIS PRO 2.0)
// Seitliches Panel rechts neben der Scan-Tabelle. Zeigt die Details des
// gewählten Geräts in drei Abschnitten — das Wichtigste zuerst: Identität,
// offene Ports, Gerätenotizen.
//
// Die Komponente kennt ihre Props (geraet, onClose, onGespeichert). Die drei
// Notizfelder (label/tags/notes) sind controlled und werden per
// PUT /api/devices/{mac} gespeichert; bei Erfolg meldet onGespeichert das
// aktualisierte View-Gerät nach oben. Das Port-Nachschlagen öffnet ein kleines
// Info-Fenster (PortLookupDialog) mit interner Beschreibung + Wikipedia-Link.

import { Fingerprint, Network, StickyNote, X } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { acknowledge } from "../api/analysis.js";
import {
  setTrustState as setDeviceTrustState,
  tagsAusText,
  updateDeviceMeta,
} from "../api/devices.js";
import { CODES, mitCode } from "../lib/fehlercodes.js";
import PortLookupDialog from "./PortLookupDialog.jsx";
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

export default function ScanDetailPanel({ geraet, onClose, onGespeichert }) {
  const { t } = useTranslation();

  // Kopf: Gerätename/Hostname, fällt auf IP zurück, wenn kein Hostname.
  const titel = geraet.hostname || geraet.ip;

  // Controlled Notizfelder. tagsWert ist der ROHE kommagetrennte Text (erst beim
  // Speichern in ein Array zerlegt). Initial aus dem gewählten Gerät.
  const [labelWert, setLabelWert] = useState(geraet.label || "");
  const [tagsWert, setTagsWert] = useState((geraet.tags || []).join(", "));
  const [notesWert, setNotesWert] = useState(geraet.notes || "");
  // Speicher-Status: "idle" | "speichert" | "ok" | "fehler".
  const [status, setStatus] = useState("idle");

  // Wertende Einordnung (trusted/neutral/watch) als Segmented Control. Eigener
  // State, da sofort-speichernd beim Klick (entkoppelt vom Notizen-Speichern).
  const [trustState, setTrustState] = useState(geraet.trustState || "neutral");
  // Dezenter Fehlerhinweis, wenn das Sofort-Speichern fehlschlägt.
  const [trustFehler, setTrustFehler] = useState(false);

  // Lokaler Quittier-Status PRO Port (Schnitt 8b): portNum -> "idle" | "sending"
  // | "acked" | "unacked" | "error". Bewusst KEINE optimistische Änderung von
  // Pille/Färbung/acknowledgedPorts — der echte Zustand kommt erst beim nächsten
  // Scan über das Frame. Dieser State trägt nur den dezenten Hinweis am Port.
  const [ackStatus, setAckStatus] = useState({});

  // Der Port, dessen Nachschlage-Dialog offen ist (null = geschlossen).
  const [lookupPort, setLookupPort] = useState(null);

  // Gerätewechsel: alle drei Felder neu aus dem Gerät setzen (sonst bleiben
  // alte Eingaben stehen). Status zurück auf idle.
  useEffect(() => {
    setLabelWert(geraet.label || "");
    setTagsWert((geraet.tags || []).join(", "));
    setNotesWert(geraet.notes || "");
    setStatus("idle");
    // Einordnung neu aus dem Gerät; Fehlerhinweis zurücknehmen.
    setTrustState(geraet.trustState || "neutral");
    setTrustFehler(false);
    // Quittier-Hinweise pro Port mit zurücksetzen — wie die Notizfelder gehören
    // sie zum gewählten Gerät und dürfen nicht auf das nächste übergreifen.
    setAckStatus({});
    // Offenen Nachschlage-Dialog schließen — er gehört zum vorigen Gerät.
    setLookupPort(null);
    // Abhängig allein von der MAC: ein anderes Gerät heißt neue Initialwerte.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [geraet.mac]);

  // Statuszeile in Sprache (nicht Ampel): neu vs. bekannt, notable dezent.
  const statusKlasse = geraet.isNew
    ? "scan-detail__status scan-detail__status--neu"
    : "scan-detail__status scan-detail__status--bekannt";
  const statusText = geraet.isNew
    ? t("beobachten.scan.detail.identity.statusNew")
    : t("beobachten.scan.detail.identity.statusKnown");

  // Port-Nachschlagen: öffnet den Info-Dialog für den gewählten Port.
  const handleNachschlagen = (port) => {
    setLookupPort(port);
  };

  // Quittiert einen bewerteten Port bzw. nimmt die Quittierung zurück (Schnitt 8b).
  // action ist "ack" | "unack". Sendet die NACKTE Portnummer (port.num) und die
  // Severity (nur Audit-Metadatum). KEINE optimistische Änderung des geraet-
  // Objekts: bei Erfolg setzen wir nur den lokalen Hinweis-State; der echte
  // Zustand folgt beim nächsten Scan über das Frame. Bei Fehler bleibt der Knopf
  // klickbar (Status "error"), nur ein dezenter Hinweis erscheint.
  const handleQuittieren = async (portNum, severity, action) => {
    setAckStatus((vorher) => ({ ...vorher, [portNum]: "sending" }));
    try {
      await acknowledge(geraet.mac, portNum, severity, action);
      setAckStatus((vorher) => ({
        ...vorher,
        [portNum]: action === "ack" ? "acked" : "unacked",
      }));
    } catch (fehler) {
      setAckStatus((vorher) => ({ ...vorher, [portNum]: "error" }));
      console.error("Quittieren des Ports fehlgeschlagen:", fehler);
    }
  };

  // Setzt die Einordnung (trusted/neutral/watch) sofort beim Klick. Lokaler
  // State wird optimistisch gesetzt, dann per PUT geschrieben. Bei Erfolg meldet
  // onGespeichert das aktualisierte Gerät nach oben (der echte is_known-Wert
  // kommt so zurück — KEINE optimistische is_known-Anzeige hier). Bei Fehler
  // wird der lokale State zurückgedreht und ein dezenter Hinweis gezeigt.
  const handleTrustChange = async (neu) => {
    if (neu === trustState) {
      return;
    }
    const vorher = trustState;
    setTrustState(neu);
    setTrustFehler(false);
    try {
      const aktualisiert = await setDeviceTrustState(geraet.mac, neu);
      if (onGespeichert) {
        onGespeichert(aktualisiert);
      }
    } catch (fehler) {
      setTrustState(vorher);
      setTrustFehler(true);
      console.error("Setzen der Einordnung fehlgeschlagen:", fehler);
    }
  };

  // Speichert die drei Notizfelder per PUT /api/devices/{mac}. tagsWert wird
  // erst hier in ein Array zerlegt. Bei Erfolg meldet onGespeichert das
  // aktualisierte View-Gerät nach oben; Fehler werden nicht verschluckt.
  const handleSpeichern = async () => {
    setStatus("speichert");
    try {
      const aktualisiert = await updateDeviceMeta(geraet.mac, {
        label: labelWert,
        tags: tagsAusText(tagsWert),
        notes: notesWert,
      });
      setStatus("ok");
      if (onGespeichert) {
        onGespeichert(aktualisiert);
      }
    } catch (fehler) {
      setStatus("fehler");
      console.error("Speichern der Gerätenotizen fehlgeschlagen:", fehler);
    }
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

          {/* Einordnung: wertende Einschätzung als Segmented Control. Sofort-
              speichernd beim Klick. Eigenständig zu is_known (neu/bekannt). */}
          <div className="scan-detail__trust">
            <span
              id="scan-detail-trust-label"
              className="scan-detail__trust-heading"
            >
              {t("beobachten.scan.detail.identity.trust.heading")}
            </span>
            <div
              className="scan-detail__trust-group"
              role="group"
              aria-labelledby="scan-detail-trust-label"
            >
              {[
                { wert: "trusted", key: "trusted" },
                { wert: "neutral", key: "neutral" },
                { wert: "watch", key: "watch" },
              ].map(({ wert, key }) => (
                <button
                  key={wert}
                  type="button"
                  className={
                    trustState === wert
                      ? "scan-detail__trust-btn scan-detail__trust-btn--aktiv"
                      : "scan-detail__trust-btn"
                  }
                  aria-pressed={trustState === wert}
                  onClick={() => handleTrustChange(wert)}
                >
                  {t(`beobachten.scan.detail.identity.trust.${key}`)}
                </button>
              ))}
            </div>
            {trustFehler && (
              <p className="scan-detail__trust-error">
                {mitCode(
                  t("beobachten.scan.detail.identity.trust.saveError"),
                  CODES.E_501,
                )}
              </p>
            )}
          </div>

          {/* Abweichungs-Feststellung: dezenter, neutraler Hinweis aus der
              vorhandenen Baseline. Erscheint NUR, wenn das Gerät neu ist oder
              sich seine IP geändert hat. isNew/isChanged sind laut Mapper
              disjunkt; isNew hat Vorrang, defensiv per if/else-if. Bewusst
              KEINE "neuer Port"-Aussage (newPorts kommt im Frame nicht an). */}
          {(geraet.isNew || geraet.isChanged) && (
            <p className="scan-detail__deviation">
              <span className="scan-detail__deviation-label">
                {t("beobachten.scan.detail.identity.deviation.label")}
              </span>{" "}
              {geraet.isNew
                ? t("beobachten.scan.detail.identity.deviation.new")
                : t("beobachten.scan.detail.identity.deviation.changed")}
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
              {geraet.ports.map((port) => {
                // Achse-B-Severity dieses Ports aus flaggedPorts ableiten
                // (critical schlägt notable). null = kein Achse-B-Port -> kein
                // Quittier-Bereich. flaggedPorts ist defensiv (Mapper-Default).
                const flagged = geraet.flaggedPorts ?? {
                  critical: [],
                  notable: [],
                };
                const severity = flagged.critical?.includes(port.num)
                  ? "critical"
                  : flagged.notable?.includes(port.num)
                    ? "notable"
                    : null;
                // Quittiert laut Frame (echter Zustand) vs. lokaler Klick-Status.
                const istQuittiert = (geraet.acknowledgedPorts ?? []).includes(
                  port.num,
                );
                const lokal = ackStatus[port.num] ?? "idle";
                // Severity-Tönung der Zeile: kritisch -> rot, auffällig -> orange,
                // quittiert -> gedämpft (überschreibt die Tönung optisch).
                const portKlasse = [
                  "scan-detail__port",
                  severity === "critical"
                    ? "scan-detail__port--kritisch"
                    : severity === "notable"
                      ? "scan-detail__port--auffaellig"
                      : "",
                  istQuittiert ? "scan-detail__port--quittiert" : "",
                ]
                  .filter(Boolean)
                  .join(" ");
                return (
                  <li key={`${port.num}/${port.proto}`} className={portKlasse}>
                    <div className="scan-detail__port-haupt">
                      <span className="scan-detail__port-num scan-detail__mono">
                        {port.num}
                      </span>
                      <span className="scan-detail__port-proto">
                        {port.proto}
                      </span>
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
                    </div>

                    {/* Quittier-Bereich nur für bewertete Ports (severity!=null):
                        ohne Achse-B-Bewertung gibt es nichts zu quittieren. */}
                    {(severity !== null || istQuittiert) &&
                      (lokal === "acked" || lokal === "unacked" ? (
                        // Nach erfolgreichem Klick: nur der dezente Hinweis, kein
                        // Knopf. Der echte Zustand folgt beim nächsten Scan.
                        <p className="scan-detail__ack-hint">
                          {lokal === "acked"
                            ? t("beobachten.scan.detail.ports.ackDone")
                            : t("beobachten.scan.detail.ports.unackDone")}
                        </p>
                      ) : istQuittiert ? (
                        // Bereits quittiert (laut Frame): Zurücknehmen anbieten.
                        // severity fürs unack-Audit: "notable" als Default — die
                        // Stufe steht beim quittierten Port nicht mehr in
                        // flaggedPorts, und das Backend nutzt severity nur fürs
                        // Audit; der effektive Status ist portbasiert.
                        <div className="scan-detail__ack">
                          <button
                            type="button"
                            className="scan-detail__ack-btn"
                            disabled={lokal === "sending"}
                            onClick={() =>
                              handleQuittieren(port.num, "notable", "unack")
                            }
                          >
                            {t("beobachten.scan.detail.ports.unacknowledge")}
                          </button>
                          {lokal === "error" && (
                            <p className="scan-detail__ack-error">
                              {mitCode(
                                t("beobachten.scan.detail.ports.ackError"),
                                CODES.E_503,
                              )}
                            </p>
                          )}
                        </div>
                      ) : (
                        // Bewertet und nicht quittiert: Quittieren anbieten,
                        // severity dieses Ports mitsenden.
                        <div className="scan-detail__ack">
                          <button
                            type="button"
                            className={`scan-detail__ack-btn scan-detail__ack-btn--${
                              severity === "critical" ? "kritisch" : "auffaellig"
                            }`}
                            disabled={lokal === "sending"}
                            onClick={() =>
                              handleQuittieren(port.num, severity, "ack")
                            }
                          >
                            {t("beobachten.scan.detail.ports.acknowledge")}
                          </button>
                          {lokal === "error" && (
                            <p className="scan-detail__ack-error">
                              {mitCode(
                                t("beobachten.scan.detail.ports.ackError"),
                                CODES.E_503,
                              )}
                            </p>
                          )}
                        </div>
                      ))}
                  </li>
                );
              })}
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
                value={labelWert}
                onChange={(e) => setLabelWert(e.target.value)}
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
                value={tagsWert}
                onChange={(e) => setTagsWert(e.target.value)}
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
                value={notesWert}
                onChange={(e) => setNotesWert(e.target.value)}
                placeholder={t("beobachten.scan.detail.notes.notesPlaceholder")}
              />
            </label>

            <button
              type="button"
              className="scan-detail__save"
              onClick={handleSpeichern}
              disabled={status === "speichert"}
            >
              {t("beobachten.scan.detail.notes.save")}
            </button>
            <p className="scan-detail__save-hint">
              {status === "ok"
                ? t("beobachten.scan.detail.notes.saveOk")
                : status === "fehler"
                  ? mitCode(
                      t("beobachten.scan.detail.notes.saveError"),
                      CODES.E_501,
                    )
                  : t("beobachten.scan.detail.notes.saveHint")}
            </p>
          </div>
        </section>
      </div>

      {/* Port-Nachschlage-Dialog: nur offen, wenn ein Port gewählt wurde.
          position:fixed -> die DOM-Position im Panel ist fürs Layout egal. */}
      {lookupPort && (
        <PortLookupDialog
          port={lookupPort}
          onClose={() => setLookupPort(null)}
        />
      )}
    </aside>
  );
}
