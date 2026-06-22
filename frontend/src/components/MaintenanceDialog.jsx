// Wartungs-Dialog „Daten löschen" (CERNIS PRO 2.0)
//
// Zentrierter Overlay-Dialog für die zweistufige Daten-Löschung. Es gibt im
// Projekt KEIN bestehendes Modal-Muster (ColumnManager ist nur ein Popover) —
// daher ein eigenständiger, zentrierter Overlay-Dialog im App-Stil (nur
// CSS-Tokens, keine hartkodierten Farben; orange/rot über die Severity-Tokens).
//
// Zwei Fenster im selben Overlay (lokaler State, kein Routing):
//   FENSTER 1 — Stufe wählen: zwei Blöcke (Scan-Daten zurücksetzen / Werkszustand).
//   FENSTER 2 — bestätigen: Auflistung, optionales Secrets-Kästchen (nur Stufe 2),
//               roter Schluss-Hinweis, „Zurück" + „Endgültig löschen".
//
// Der eigentliche Backend-Aufruf läuft über onBestaetigt (von der Sektion gereicht,
// die das ruhige „erledigt"-Feedback hält). Fehler kommen als ApiError zurück:
// Dialog bleibt offen, dezenter Inline-Fehler, Knopf wieder klickbar.

import { X } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import "./MaintenanceDialog.css";

// Die zwei Stufen als Konstanten — vermeidet Tippfehler-Strings im JSX.
const STUFE_SCAN = "scan";
const STUFE_FACTORY = "factory";

export default function MaintenanceDialog({ onSchliessen, onBestaetigt }) {
  const { t } = useTranslation();

  // null = Fenster 1 (Stufe wählen); sonst die gewählte Stufe = Fenster 2.
  const [stufe, setStufe] = useState(null);
  // Nur Stufe 2: auch gespeicherte Zugangsdaten entfernen. Default AUS.
  const [secretsEntfernen, setSecretsEntfernen] = useState(false);
  const [laeuft, setLaeuft] = useState(false); // Request aktiv -> Doppelklick-Schutz
  const [fehler, setFehler] = useState(false); // dezenter Inline-Fehler im Dialog

  // Escape schließt den Dialog (Standard-Overlay-Verhalten), solange kein Request
  // läuft — ein laufendes Löschen nicht versehentlich „verlieren".
  useEffect(() => {
    const handler = (e) => {
      if (e.key === "Escape" && !laeuft) {
        onSchliessen();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [laeuft, onSchliessen]);

  // Stufe wählen -> Fenster 2. Beim Wechsel Fehler/Secrets-Kästchen zurücksetzen.
  const waehleStufe = (gewaehlt) => {
    setFehler(false);
    setSecretsEntfernen(false);
    setStufe(gewaehlt);
  };

  // Zurück zu Fenster 1.
  const zurueck = () => {
    setFehler(false);
    setStufe(null);
  };

  // „Endgültig löschen": Backend-Aufruf über onBestaetigt. Bei Erfolg schließt die
  // aufrufende Sektion den Dialog (und zeigt das ruhige „erledigt"); bei Fehler
  // bleibt der Dialog offen mit dezentem Hinweis, Knopf wieder klickbar.
  const bestaetigen = async () => {
    setFehler(false);
    setLaeuft(true);
    try {
      await onBestaetigt(stufe, secretsEntfernen);
      // Erfolg: das Schließen übernimmt die Sektion (sie hält das Feedback).
    } catch {
      setFehler(true);
      setLaeuft(false);
    }
  };

  // Punkte der gewählten Stufe für die „wird unwiderruflich gelöscht"-Liste.
  const loeschPunkte =
    stufe === STUFE_FACTORY
      ? [
          t("settings.wartung.confirm.factory.item1"),
          t("settings.wartung.confirm.factory.item2"),
          t("settings.wartung.confirm.factory.item3"),
          t("settings.wartung.confirm.factory.item4"),
        ]
      : [
          t("settings.wartung.confirm.scan.item1"),
          t("settings.wartung.confirm.scan.item2"),
          t("settings.wartung.confirm.scan.item3"),
          t("settings.wartung.confirm.scan.item4"),
        ];

  const titel =
    stufe === null
      ? t("settings.wartung.dialog.title")
      : stufe === STUFE_FACTORY
        ? t("settings.wartung.confirm.factory.title")
        : t("settings.wartung.confirm.scan.title");

  return (
    // Backdrop: Klick daneben schließt (wenn kein Request läuft). Der Klick im
    // Dialog selbst wird gestoppt, damit er nicht durchschlägt.
    <div
      className="maint-overlay"
      onMouseDown={() => {
        if (!laeuft) {
          onSchliessen();
        }
      }}
    >
      <div
        className="maint-dialog"
        role="dialog"
        aria-modal="true"
        aria-label={titel}
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="maint-dialog__head">
          <h2 className="maint-dialog__title">{titel}</h2>
          <button
            type="button"
            className="maint-dialog__close"
            aria-label={t("settings.wartung.dialog.close")}
            title={t("settings.wartung.dialog.close")}
            onClick={onSchliessen}
            disabled={laeuft}
          >
            <X size={18} aria-hidden="true" />
          </button>
        </div>

        {stufe === null ? (
          // ── FENSTER 1 — Stufe wählen ───────────────────────────────────────
          <div className="maint-dialog__body">
            <button
              type="button"
              className="maint-choice maint-choice--scan"
              onClick={() => waehleStufe(STUFE_SCAN)}
            >
              <span className="maint-choice__title">
                {t("settings.wartung.choice.scan.title")}
              </span>
              <span className="maint-choice__line">
                {t("settings.wartung.choice.scan.deletes")}
              </span>
              <span className="maint-choice__line maint-choice__line--keep">
                {t("settings.wartung.choice.scan.keeps")}
              </span>
            </button>

            <button
              type="button"
              className="maint-choice maint-choice--factory"
              onClick={() => waehleStufe(STUFE_FACTORY)}
            >
              <span className="maint-choice__title">
                {t("settings.wartung.choice.factory.title")}
              </span>
              <span className="maint-choice__line">
                {t("settings.wartung.choice.factory.deletes")}
              </span>
            </button>

            <div className="maint-dialog__actions">
              <button
                type="button"
                className="maint-button"
                onClick={onSchliessen}
              >
                {t("settings.wartung.dialog.cancel")}
              </button>
            </div>
          </div>
        ) : (
          // ── FENSTER 2 — bestätigen ─────────────────────────────────────────
          <div className="maint-dialog__body">
            <p className="maint-confirm__lead">
              {t("settings.wartung.confirm.lead")}
            </p>
            <ul className="maint-confirm__list">
              {loeschPunkte.map((punkt) => (
                <li key={punkt} className="maint-confirm__item">
                  {punkt}
                </li>
              ))}
            </ul>

            {/* Secrets-Kästchen NUR bei Werkszustand (Stufe 2). */}
            {stufe === STUFE_FACTORY ? (
              <label className="maint-confirm__secrets">
                <input
                  type="checkbox"
                  className="maint-confirm__checkbox"
                  checked={secretsEntfernen}
                  onChange={(e) => setSecretsEntfernen(e.target.checked)}
                  disabled={laeuft}
                />
                <span>{t("settings.wartung.confirm.includeSecrets")}</span>
              </label>
            ) : null}

            <div className="maint-confirm__warn" role="alert">
              {t("settings.wartung.confirm.warning")}
            </div>

            {fehler ? (
              <span className="maint-dialog__error">
                {t("settings.wartung.confirm.error")}
              </span>
            ) : null}

            <div className="maint-dialog__actions">
              <button
                type="button"
                className="maint-button"
                onClick={zurueck}
                disabled={laeuft}
              >
                {t("settings.wartung.confirm.back")}
              </button>
              <button
                type="button"
                className="maint-button maint-button--danger"
                onClick={bestaetigen}
                disabled={laeuft}
              >
                {t("settings.wartung.confirm.delete")}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
