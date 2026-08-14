// Dialog „Nach Netz aufräumen" (CERNIS PRO 2.0, S88-P3)
//
// DER ANLASS: Der Gerätebestand kennt kein Netz. Scannt der Anwender ein anderes
// Netz, bleiben die alten Geräte unmarkiert in der Liste stehen — bisher wurde er
// sie nur einzeln los. Dieser Dialog räumt sie gruppenweise ab.
//
// Zwei Fenster im selben Overlay, Bauform des Wartungsdialogs:
//   FENSTER 1 — Auswahl: je Netzgruppe eine Häkchen-Zeile mit Netzangabe und
//               Anzahl, darunter der Hinweis zur Herkunft der Zuordnung.
//   FENSTER 2 — Bestätigung: die GETEILTE ConfirmDeleteDialog-Komponente, die auch
//               der Wartungsdialog benutzt. Bewusst NICHT nachgebaut — zwei
//               Auslegungen desselben Bestätigungswegs liefen mit der Zeit
//               auseinander, und niemand wüsste später, ob eine Abweichung
//               Absicht war.
//
// CSS: Overlay, Rahmen, Häkchenliste und Knöpfe benutzen die maint-*-Klassen aus
// MaintenanceDialog.css. Das ist ABSICHT und kein Versehen: beide Listen sollen
// gleich aussehen, weil sie dasselbe tun. Die Klassen wurden bewusst NICHT
// umbenannt oder kopiert — ein zweiter Satz gleich aussehender Klassen wäre eine
// zweite Wahrheit über dasselbe Erscheinungsbild.
//
// Eigenes, schlankes Markup statt der Baukasten-Liste des Wartungsdialogs: dieser
// Fall braucht dessen Wurzel- und Sperrlogik (scan_history zieht abgeleitete
// Posten zwingend mit) nicht — hier ist jede Gruppe frei wählbar. Sie
// herauszuziehen wäre ein Umbau ohne Gegenwert.

import { X } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import ConfirmDeleteDialog from "./ConfirmDeleteDialog.jsx";
import "./MaintenanceDialog.css";

// Die Kennung, die das Backend für Geräte ohne brauchbare letzte IP schickt
// (application/maintenance/netz_aufraeumen.py: OHNE_IP). Sie ist bewusst keine
// gültige Netzangabe, damit sie sich nie mit einer echten Gruppe verwechseln
// lässt; hier wird sie in den übersetzten Namen aufgelöst.
const OHNE_IP = "ohne-ip";

export default function NetzAufraeumenDialog({
  gruppen,
  onSchliessen,
  onBestaetigt,
}) {
  const { t } = useTranslation();

  // Angehakte Netzangaben (die netz-Strings, nicht die MACs).
  const [auswahl, setAuswahl] = useState(() => new Set());
  // false = Fenster 1 (Auswahl), true = Fenster 2 (Bestätigung).
  const [bestaetigtAnsicht, setBestaetigtAnsicht] = useState(false);
  const [laeuft, setLaeuft] = useState(false); // Doppelklick-Schutz
  const [fehler, setFehler] = useState(false); // dezenter Inline-Fehler (E-502)

  // Escape schließt, solange kein Request läuft — Verhalten wie im
  // Wartungsdialog, damit sich beide Dialoge gleich anfühlen.
  useEffect(() => {
    const handler = (e) => {
      if (e.key === "Escape" && !laeuft) {
        onSchliessen();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [laeuft, onSchliessen]);

  // Der Anzeigename einer Gruppe: die Netzangabe selbst, für die Restgruppe der
  // übersetzte Name. Kein erfundener Wert.
  const gruppenName = (netz) =>
    netz === OHNE_IP ? t("geraete.verwaltung.aufraeumen.ohneIp") : netz;

  const toggle = (netz) => {
    setAuswahl((prev) => {
      const next = new Set(prev);
      if (next.has(netz)) {
        next.delete(netz);
      } else {
        next.add(netz);
      }
      return next;
    });
  };

  // Die gewählten Gruppen in der Reihenfolge, die das Backend geliefert hat
  // (echte Netze aufsteigend, Ohne-IP zuletzt) — damit die Vorschau ruhig wirkt.
  const gewaehlteGruppen = gruppen.filter((g) => auswahl.has(g.netz));

  // Die Posten der Bestätigungs-Liste, zeichengenau nach Vorgabe:
  //   „Geräte im Netz {{netz}} ({{anzahl}})"
  const loeschPunkte = gewaehlteGruppen.map((g) =>
    t("geraete.verwaltung.aufraeumen.vorschauPosten", {
      netz: gruppenName(g.netz),
      anzahl: g.anzahl,
    }),
  );

  // Alle MACs der gewählten Gruppen — das, was das Backend zu löschen bekommt.
  const gewaehlteMacs = gewaehlteGruppen.flatMap((g) => g.macs);

  const bestaetigen = async () => {
    setFehler(false);
    setLaeuft(true);
    try {
      await onBestaetigt(gewaehlteMacs);
      // Erfolg: das Schließen und Neuladen übernimmt der Aufrufer.
    } catch {
      setFehler(true);
      setLaeuft(false);
    }
  };

  const titel = bestaetigtAnsicht
    ? t("geraete.verwaltung.aufraeumen.knopf")
    : t("geraete.verwaltung.aufraeumen.titelAuswahl");

  return (
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

        {bestaetigtAnsicht ? (
          // ── FENSTER 2 — die GETEILTE Bestätigung (nicht nachgebaut) ────────
          <ConfirmDeleteDialog
            posten={loeschPunkte}
            fehler={fehler}
            laeuft={laeuft}
            onZurueck={() => {
              setFehler(false);
              setBestaetigtAnsicht(false);
            }}
            onBestaetigen={bestaetigen}
          />
        ) : (
          // ── FENSTER 1 — Auswahl der Netzgruppen ───────────────────────────
          <div className="maint-dialog__body">
            {gruppen.length === 0 ? (
              <p className="maint-builder__hint">
                {t("geraete.verwaltung.aufraeumen.leer")}
              </p>
            ) : (
              <div className="maint-builder__group">
                {gruppen.map((gruppe) => (
                  <label key={gruppe.netz} className="maint-builder__item">
                    <input
                      type="checkbox"
                      className="maint-builder__checkbox"
                      checked={auswahl.has(gruppe.netz)}
                      onChange={() => toggle(gruppe.netz)}
                    />
                    <span className="maint-builder__label">
                      {gruppenName(gruppe.netz)} ({gruppe.anzahl})
                    </span>
                  </label>
                ))}
              </div>
            )}

            <p className="maint-builder__hint">
              {t("geraete.verwaltung.aufraeumen.hinweis")}
            </p>

            <div className="maint-dialog__actions">
              <button
                type="button"
                className="maint-button"
                onClick={onSchliessen}
              >
                {t("settings.wartung.dialog.cancel")}
              </button>
              <button
                type="button"
                className="maint-button maint-button--danger"
                onClick={() => {
                  setFehler(false);
                  setBestaetigtAnsicht(true);
                }}
                disabled={gewaehlteMacs.length === 0}
                title={
                  gewaehlteMacs.length === 0
                    ? t("geraete.verwaltung.aufraeumen.nichtsGewaehlt")
                    : undefined
                }
              >
                {t("geraete.verwaltung.aufraeumen.weiter")}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
