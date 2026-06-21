// Benutzerhandbuch-Ansicht (CERNIS PRO 2.0)
// Eigener Modus (kein Reiter), erreichbar über den „Handbuch"-Knopf in der
// Kopfzeile. Nutzt das function-shell-Muster der übrigen Bereiche (Zurück-Weg +
// Titel) wie SettingsView und bekommt onClose als Prop.
//
// Inhaltsquelle ist AUSSCHLIESSLICH help_content.json (Ausspielweg B: die
// lang-Texte). Diese View rendert nur — sie hält keinen Daten-State, kein
// useEffect, keine API. Sprache folgt der App-Sprache (i18n.language) mit
// defensivem Fallback auf "de", obwohl Parität zugesichert ist.

import { useTranslation } from "react-i18next";

import { FunctionShell } from "../components/AreaShell.jsx";
import helpContent from "../lib/help_content.json";
import "./ManualView.css";

// Einträge in JSON-Reihenfolge, nach `kategorie` gruppiert. Die Reihenfolge der
// Kategorien folgt dem ERSTEN Auftreten in der JSON (redaktionell gewollt, nicht
// alphabetisch). Der _meta-Schlüssel ist kein Eintrag und wird übersprungen.
//
// Reines Lesen aus dem Import -> einmal pro Modul berechnet, nicht pro Render.
function baueKategorien() {
  const kategorien = []; // [{ kategorie, eintraege: [{ helpId, eintrag }] }]
  const indexNachName = new Map();

  for (const [helpId, eintrag] of Object.entries(helpContent)) {
    if (helpId === "_meta") {
      continue;
    }
    const name = eintrag.kategorie;
    if (!indexNachName.has(name)) {
      indexNachName.set(name, kategorien.length);
      kategorien.push({ kategorie: name, eintraege: [] });
    }
    kategorien[indexNachName.get(name)].eintraege.push({ helpId, eintrag });
  }

  return kategorien;
}

const KATEGORIEN = baueKategorien();

// Stabiler Anker-Id für eine Kategorie (für die Sprungliste). Die help_id-Anker
// der Einträge tragen ihre help_id direkt; die Kategorie-Überschriften brauchen
// einen eigenen, kollisionsfreien Id-Raum.
function kategorieAnker(name) {
  return `manual-kat-${name}`;
}

// Sanfter Sprung zu einem Anker per Id (getElementById statt Hash-Navigation,
// weil die help_id-Anker Punkte enthalten und ein "#a.b.c" als CSS-Selektor
// ungültig wäre — als reines scrollIntoView-Ziel funktioniert die Id aber).
function springeZu(id) {
  const ziel = document.getElementById(id);
  if (ziel) {
    ziel.scrollIntoView({ behavior: "smooth", block: "start" });
  }
}

// Ein einzelner Handbuch-Abschnitt: Titel, Vorläufig-Hinweis (falls), lang-Text
// in Absätze gesplittet, optionale Weiterführend-Links. Reiner Text in <p> —
// keine Markdown-Lib, kein dangerouslySetInnerHTML.
function Abschnitt({ helpId, sprache, t }) {
  const eintrag = helpContent[helpId];
  // Defensiver Sprach-Fallback auf "de" (Parität ist zugesichert, aber ein
  // fehlender Zweig darf nicht crashen).
  const inhalt = eintrag[sprache] ?? eintrag.de;
  const absaetze = inhalt.lang.split("\n\n");

  return (
    <section id={helpId} className="manual__section">
      <h3 className="manual__section-title">{inhalt.titel}</h3>

      {eintrag.status === "vorlaeufig" ? (
        <p className="manual__vorlaeufig">{t("manual.vorlaeufigHint")}</p>
      ) : null}

      {absaetze.map((absatz, i) => (
        <p key={i} className="manual__paragraph">
          {absatz}
        </p>
      ))}

      {Array.isArray(inhalt.links) && inhalt.links.length > 0 ? (
        <div className="manual__links">
          <span className="manual__links-label">{t("manual.linksLabel")}</span>
          <ul className="manual__links-list">
            {inhalt.links.map((link) => (
              <li key={link.url}>
                <a
                  href={link.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="manual__link"
                >
                  {link.label}
                </a>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </section>
  );
}

export default function ManualView({ onClose }) {
  const { t, i18n } = useTranslation();
  const sprache = i18n.language === "en" ? "en" : "de";

  return (
    <FunctionShell title={t("manual.title")} onBack={onClose}>
      <div className="manual">
        {/* Sprungliste: rein anker-basiert (kein neues npm-Paket), springt per
            scrollIntoView zu den Kategorien. */}
        <nav className="manual__toc" aria-label={t("manual.tocLabel")}>
          <span className="manual__toc-label">{t("manual.tocLabel")}</span>
          <ul className="manual__toc-list">
            {KATEGORIEN.map(({ kategorie }) => (
              <li key={kategorie}>
                <button
                  type="button"
                  className="manual__toc-link"
                  onClick={() => springeZu(kategorieAnker(kategorie))}
                >
                  {t(`manual.kategorien.${kategorie}`, kategorie)}
                </button>
              </li>
            ))}
          </ul>
        </nav>

        {KATEGORIEN.map(({ kategorie, eintraege }) => (
          <section
            key={kategorie}
            id={kategorieAnker(kategorie)}
            className="manual__category"
          >
            <h2 className="manual__category-title">
              {t(`manual.kategorien.${kategorie}`, kategorie)}
            </h2>
            {eintraege.map(({ helpId }) => (
              <Abschnitt
                key={helpId}
                helpId={helpId}
                sprache={sprache}
                t={t}
              />
            ))}
          </section>
        ))}
      </div>
    </FunctionShell>
  );
}
