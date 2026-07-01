// Kontextsensitiver "?"-Hilfe-Punkt (CERNIS PRO 2.0)
// Ausspielweg A: ein dezenter Umriss-Kreis neben einem Funktionstitel. Klick
// öffnet ein kleines Popup mit dem Kurztext (help_content.json -> kurz) des
// zugehörigen Eintrags, einem Knopf "Mehr im Handbuch" (springt in den
// Handbuch-Modus zum passenden Anker) und — falls vorhanden — den Vertiefungs-
// Links des Eintrags.
//
// Quelle ist AUSSCHLIESSLICH help_content.json (derselbe Import wie ManualView,
// dort für die lang-Texte). Fehlt der Eintrag, rendert die Komponente nichts
// (null) — kein Absturz, kein leerer Knopf.

import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import helpContent from "../lib/help_content.json";
import "./HelpDot.css";

// helpId: Schlüssel in help_content.json (z. B. "help.scan.start").
// onOpenManual(helpId): öffnet das Handbuch und springt zum Anker der help_id.
export default function HelpDot({ helpId, onOpenManual }) {
  const { t, i18n } = useTranslation();

  const [offen, setOffen] = useState(false);
  const wrapRef = useRef(null);

  // Schließen bei Klick außerhalb des Wrappers und bei Escape. Nur aktiv,
  // solange das Popup offen ist — sonst hängen keine Listener am document.
  // t/i18n bewusst NICHT als Dependency (kein Neu-Binden bei Sprachwechsel,
  // keine Render-Schleife); der Effekt hängt allein an `offen`.
  useEffect(() => {
    if (!offen) {
      return undefined;
    }
    const beiMausunten = (e) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target)) {
        setOffen(false);
      }
    };
    const beiTaste = (e) => {
      if (e.key === "Escape") {
        setOffen(false);
      }
    };
    document.addEventListener("mousedown", beiMausunten);
    document.addEventListener("keydown", beiTaste);
    return () => {
      document.removeEventListener("mousedown", beiMausunten);
      document.removeEventListener("keydown", beiTaste);
    };
  }, [offen]);

  // Eintrag erst NACH den Hooks auflösen (Hooks-Regeln: kein früher Return vor
  // useState/useEffect). Fehlt der Eintrag, nichts rendern.
  const eintrag = helpContent[helpId];
  if (!eintrag) {
    return null;
  }

  const sprache = i18n.language === "en" ? "en" : "de";
  const inhalt = eintrag[sprache] ?? eintrag.de;

  // "Mehr im Handbuch": Handbuch öffnen (und zum Anker springen), Popup zu.
  const handleMehr = () => {
    onOpenManual?.(helpId);
    setOffen(false);
  };

  return (
    <span className="help-dot-wrap" ref={wrapRef}>
      <button
        type="button"
        className="help-dot"
        aria-label={t("help.ariaOeffnen")}
        onClick={() => setOffen((z) => !z)}
      >
        ?
      </button>

      {offen ? (
        <div className="help-pop" role="dialog">
          <div className="help-pop__head">
            <span className="help-pop__title">
              <span className="help-pop__dot" aria-hidden="true" />
              {inhalt.titel}
            </span>
            <button
              type="button"
              className="help-pop__close"
              aria-label={t("help.ariaSchliessen")}
              onClick={() => setOffen(false)}
            >
              ✕
            </button>
          </div>

          <div className="help-pop__body">{inhalt.kurz}</div>

          <div className="help-pop__foot">
            <button
              type="button"
              className="help-pop__more"
              onClick={handleMehr}
            >
              {t("help.mehrImHandbuch")}
            </button>

            {Array.isArray(inhalt.links) && inhalt.links.length > 0 ? (
              <div className="help-pop__links">
                {inhalt.links.map((link) => (
                  <a
                    key={link.url}
                    href={link.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="help-pop__link"
                  >
                    {link.label}
                  </a>
                ))}
              </div>
            ) : null}
          </div>
        </div>
      ) : null}
    </span>
  );
}
