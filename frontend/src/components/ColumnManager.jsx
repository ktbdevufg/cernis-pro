// Column-Manager (CERNIS PRO 2.0)
// Dezenter "Spalten"-Knopf mit Popover, das je umschaltbarer Scan-Tabellen-
// Spalte eine Checkbox zeigt. Fixe Spalten (Status, IP) werden NICHT gelistet —
// sie sind immer sichtbar. Eine Änderung meldet die neue Sicht-Liste sofort über
// onChange; Persistenz hält der Aufrufer (ObserveView).
//
// Die Komponente ist stateless bzgl. Persistenz: sichtbar (Array der sichtbaren
// umschaltbaren IDs) kommt als Prop, jede Änderung geht als vollständiges neues
// Array zurück. Reihenfolge im zurückgegebenen Array folgt UMSCHALTBARE_SPALTEN.

import { Columns3 } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import "./ColumnManager.css";
import { UMSCHALTBARE_SPALTEN } from "./ScanTable.jsx";

export default function ColumnManager({ sichtbar, onChange }) {
  const { t } = useTranslation();
  const [offen, setOffen] = useState(false);
  const wurzelRef = useRef(null);

  // Klick außerhalb schließt das Popover. Nur registrieren, wenn offen.
  useEffect(() => {
    if (!offen) {
      return undefined;
    }
    const beiKlickAussen = (event) => {
      if (wurzelRef.current && !wurzelRef.current.contains(event.target)) {
        setOffen(false);
      }
    };
    document.addEventListener("mousedown", beiKlickAussen);
    return () => document.removeEventListener("mousedown", beiKlickAussen);
  }, [offen]);

  const sichtbarSet = new Set(sichtbar);

  // Eine Checkbox umschalten: neues Array in fester Reihenfolge bilden und an
  // onChange melden. Der lokale Zustand der Sicht-Liste liegt beim Aufrufer.
  const umschalten = (id) => {
    const neu = sichtbarSet.has(id)
      ? sichtbar.filter((s) => s !== id)
      : [...sichtbar, id];
    const geordnet = UMSCHALTBARE_SPALTEN.filter((s) => neu.includes(s));
    onChange(geordnet);
  };

  return (
    <div className="column-manager" ref={wurzelRef}>
      <button
        type="button"
        className="control-button column-manager__button"
        aria-haspopup="dialog"
        aria-expanded={offen}
        onClick={() => setOffen((auf) => !auf)}
      >
        <Columns3 size={16} aria-hidden="true" />
        {t("beobachten.scan.columnManager.button")}
      </button>

      {offen && (
        <div className="column-manager__panel" role="dialog" aria-label={t("beobachten.scan.columnManager.title")}>
          <span className="column-manager__title">
            {t("beobachten.scan.columnManager.title")}
          </span>
          <ul className="column-manager__list">
            {UMSCHALTBARE_SPALTEN.map((id) => (
              <li key={id} className="column-manager__item">
                <label className="column-manager__label">
                  <input
                    type="checkbox"
                    checked={sichtbarSet.has(id)}
                    onChange={() => umschalten(id)}
                  />
                  {t(`beobachten.scan.columns.${id}`)}
                </label>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
