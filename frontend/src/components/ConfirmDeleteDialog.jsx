// Bestätigungs-Fenster für Löschvorgänge (CERNIS PRO 2.0)
//
// HERKUNFT: Dieses Fenster stand bis S88-P3 wörtlich in MaintenanceDialog.jsx als
// „FENSTER 2 — bestätigen". Es wurde HERAUSGEZOGEN, nicht neu erfunden: gleiches
// Markup, gleiche CSS-Klassen (maint-confirm__* / maint-button*, weiterhin in
// MaintenanceDialog.css), gleiche i18n-Schlüssel, gleiche Reihenfolge. Der Umbau
// ist rein strukturell — es gibt den Bestätigungsweg danach genau EINMAL, statt
// zweimal in zwei Auslegungen, die mit der Zeit auseinanderlaufen.
//
// Diese Komponente kennt ihre Aufrufer NICHT. Sie bekommt Titel, Posten,
// optionales Kästchen, Fehlerzustand und zwei Callbacks — und sonst nichts. Es
// gibt bewusst KEINEN Schalter der Bauart „wenn Geräteaufräumung, dann anders";
// jede Besonderheit eines Aufrufers reist als Prop herein, nicht als Fallunter-
// scheidung hier drin.
//
// Sie rendert NUR den Fenster-Inhalt (maint-dialog__body), nicht das Overlay und
// nicht den Kopf mit Titel/Schließen-Knopf — das ist Sache des umgebenden
// Dialogs, weil beide Aufrufer ihren eigenen Rahmen mitbringen.

import { CODES, mitCode } from "../lib/fehlercodes.js";
import { useTranslation } from "react-i18next";

export default function ConfirmDeleteDialog({
  // Die aufzuzählenden Posten als fertige Texte (der Aufrufer übersetzt sie
  // selbst — diese Komponente kennt seine i18n-Schlüssel nicht).
  posten,
  // Optionales Kästchen unter der Liste. null/undefined = kein Kästchen.
  // Form: { text, checked, onChange }.
  kaestchen = null,
  // true -> die dezente Fehlerzeile mit E-502 erscheint.
  fehler = false,
  // true -> beide Knöpfe gesperrt (laufender Request, Doppelklick-Schutz).
  laeuft = false,
  onZurueck,
  onBestaetigen,
}) {
  const { t } = useTranslation();

  return (
    <div className="maint-dialog__body">
      <p className="maint-confirm__lead">{t("settings.wartung.confirm.lead")}</p>
      <ul className="maint-confirm__list">
        {posten.map((punkt) => (
          <li key={punkt} className="maint-confirm__item">
            {punkt}
          </li>
        ))}
      </ul>

      {/* Optionales Kästchen (im Wartungsdialog: „auch Zugangsdaten entfernen"). */}
      {kaestchen ? (
        <label className="maint-confirm__secrets">
          <input
            type="checkbox"
            className="maint-confirm__checkbox"
            checked={kaestchen.checked}
            onChange={(e) => kaestchen.onChange(e.target.checked)}
            disabled={laeuft}
          />
          <span>{kaestchen.text}</span>
        </label>
      ) : null}

      <div className="maint-confirm__warn" role="alert">
        {t("settings.wartung.confirm.warning")}
      </div>

      {fehler ? (
        <span className="maint-dialog__error">
          {mitCode(t("settings.wartung.confirm.error"), CODES.E_502)}
        </span>
      ) : null}

      <div className="maint-dialog__actions">
        <button
          type="button"
          className="maint-button"
          onClick={onZurueck}
          disabled={laeuft}
        >
          {t("settings.wartung.confirm.back")}
        </button>
        <button
          type="button"
          className="maint-button maint-button--danger"
          onClick={onBestaetigen}
          disabled={laeuft}
        >
          {t("settings.wartung.confirm.delete")}
        </button>
      </div>
    </div>
  );
}
