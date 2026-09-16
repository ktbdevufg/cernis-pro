// Standardzugänge-LISTE (CERNIS PRO 2.0, Etappe C-Frontend)
//
// Eigener Einstellungs-Menüpunkt zur Verwaltung der Credential-Datenbank, die
// die aktive Prüfung „Standardzugänge prüfen" speist. STRIKT getrennt vom
// scharfen Session-Schalter (DefaultCredsSektion in SettingsView.jsx) — hier
// geht es nur um die Liste der Kandidaten: einsehen, hinzufügen, ändern,
// löschen, aktiv-schalten und auf Standard zurücksetzen.
//
// Muster wie AuffaelligkeitSektion: Laden beim Mount, Lade-/Fehlerzustand, CRUD
// gegen die security-API, auffaelligkeit__*-Styling wo es passt. Als eigene
// Komponente ausgelagert, weil SettingsView.jsx schon sehr groß ist; die
// Sektion baut ihr Section-Gerüst selbst im gleichen Markup wie SettingsSektion
// (h3.settings__section-title + div.settings__section-body), damit sie ohne
// Export interner Helfer aus SettingsView auskommt.
//
// Bearbeiten: ein Bearbeiten-MODUS pro Eintrag (Karte klappt zwischen Lese- und
// Formular-Ansicht um). „Hinzufügen" nutzt dasselbe Formular mit leerem Eintrag.
// Das ist der einfachere, robuste Weg (eine Formular-Implementierung für beides)
// und passt zum bestehenden Settings-Stil.
//
// t NIE in ein useEffect-dependency-array (Projekt-Render-Loop-Falle).

import { Trash2 } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";

import { ApiError } from "../api/client.js";
import {
  fetchDefaultCredsList,
  addDefaultCredsEintrag,
  updateDefaultCredsEintrag,
  deleteDefaultCredsEintrag,
  setDefaultCredsEintragAktiv,
  resetDefaultCredsList,
} from "../api/security.js";

// Erlaubte Werte laut Backend-Vertrag (Etappe C). Doppelquelle bewusst und
// dokumentiert — die Auswahllisten der Formulare spiegeln die Backend-Enums.
const ZUSTAENDE = ["hat_defaults", "keine_bekannten_defaults"];
const KONFIDENZEN = ["gesichert", "auch_moeglich", "vermutet", "benutzer"];

// i18n-Key-Suffix je Zustand/Konfidenz/Herkunft (das Backend liefert Snake-Case-
// Werte; die Labels liegen als camelCase-Keys). Fehlt ein Wert (unerwartet), wird
// der rohe Wert gezeigt statt zu crashen.
const ZUSTAND_KEY = {
  hat_defaults: "hatDefaults",
  keine_bekannten_defaults: "keineBekanntenDefaults",
};
const KONFIDENZ_KEY = {
  gesichert: "konfidenzGesichert",
  auch_moeglich: "konfidenzAuchMoeglich",
  vermutet: "konfidenzVermutet",
  benutzer: "konfidenzBenutzer",
};
const HERKUNFT_KEY = {
  mitgeliefert: "herkunftMitgeliefert",
  benutzer: "herkunftBenutzer",
};

// Client-seitige ID für selbst angelegte Einträge: „user-" + Zeitstempel +
// kleiner Zufallsanteil (Kollisionsschutz bei schnellen Anlagen). herkunft und
// aktiv setzt der Aufrufer.
function neueBenutzerId() {
  const rand = Math.random().toString(36).slice(2, 8);
  return `user-${Date.now()}-${rand}`;
}

// Leeres Formular-Modell für einen neuen Eintrag. Kandidaten starten mit einer
// leeren Zeile, damit sofort etwas zum Ausfüllen da ist.
function leeresFormular() {
  return {
    hersteller: "",
    modell: "",
    zustand: "hat_defaults",
    kandidaten: [{ username: "", password: "", konfidenz: "benutzer" }],
    quelle_url: "",
  };
}

// Einen vom Backend gelieferten Eintrag in ein editierbares Formular-Modell
// überführen (nur die editierbaren Felder; eintrag_id/herkunft/aktiv bleiben am
// Original hängen). Robust gegen fehlende Felder.
function eintragZuFormular(eintrag) {
  return {
    hersteller: String(eintrag.hersteller ?? ""),
    modell: String(eintrag.modell ?? ""),
    zustand: ZUSTAENDE.includes(eintrag.zustand)
      ? eintrag.zustand
      : "hat_defaults",
    kandidaten: Array.isArray(eintrag.kandidaten)
      ? eintrag.kandidaten.map((k) => ({
          username: String(k.username ?? ""),
          password: String(k.password ?? ""),
          konfidenz: KONFIDENZEN.includes(k.konfidenz)
            ? k.konfidenz
            : "benutzer",
        }))
      : [],
    quelle_url: String(eintrag.quelle_url ?? ""),
  };
}

// Ein neutrales kleines Badge (auffaelligkeit__badge--neutral) mit Label.
function NeutralBadge({ children }) {
  return (
    <span className="auffaelligkeit__badge auffaelligkeit__badge--neutral">
      {children}
    </span>
  );
}

// Das Editier-/Anlege-Formular für einen Eintrag. Kontrolliert über `wert`
// (Formular-Modell) und `onChange`. Kandidaten lassen sich hinzufügen, ändern
// und entfernen. Speichern/Abbrechen liegen beim Aufrufer.
function EintragFormular({ wert, onChange, onSpeichern, onAbbrechen, speichert }) {
  const { t } = useTranslation();
  const p = "settings.defaultCredsList";

  const setFeld = (feld, v) => onChange({ ...wert, [feld]: v });

  const setKandidat = (index, feld, v) => {
    const kandidaten = wert.kandidaten.map((k, i) =>
      i === index ? { ...k, [feld]: v } : k,
    );
    onChange({ ...wert, kandidaten });
  };

  const kandidatHinzufuegen = () => {
    onChange({
      ...wert,
      kandidaten: [
        ...wert.kandidaten,
        { username: "", password: "", konfidenz: "benutzer" },
      ],
    });
  };

  const kandidatEntfernen = (index) => {
    onChange({
      ...wert,
      kandidaten: wert.kandidaten.filter((_, i) => i !== index),
    });
  };

  return (
    <div className="auffaelligkeit__block">
      <div className="settings__row">
        <span className="settings__row-label">{t(`${p}.hersteller`)}</span>
        <div className="settings__row-control">
          <input
            className="settings__input"
            type="text"
            value={wert.hersteller}
            onChange={(e) => setFeld("hersteller", e.target.value)}
          />
        </div>
      </div>

      <div className="settings__row">
        <span className="settings__row-label">{t(`${p}.modell`)}</span>
        <div className="settings__row-control">
          <input
            className="settings__input"
            type="text"
            value={wert.modell}
            onChange={(e) => setFeld("modell", e.target.value)}
            placeholder={t(`${p}.modellLeer`)}
          />
        </div>
      </div>

      <div className="settings__row">
        <span className="settings__row-label">{t(`${p}.zustand`)}</span>
        <div className="settings__row-control">
          <select
            className="settings__select"
            value={wert.zustand}
            onChange={(e) => setFeld("zustand", e.target.value)}
          >
            {ZUSTAENDE.map((z) => (
              <option key={z} value={z}>
                {t(`${p}.${ZUSTAND_KEY[z]}`)}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="settings__row">
        <span className="settings__row-label">{t(`${p}.quelleUrl`)}</span>
        <div className="settings__row-control">
          <input
            className="settings__input"
            type="text"
            value={wert.quelle_url}
            onChange={(e) => setFeld("quelle_url", e.target.value)}
          />
        </div>
      </div>

      {/* Kandidaten-Editor. */}
      <NeutralBadge>{t(`${p}.kandidaten`)}</NeutralBadge>
      {wert.kandidaten.length === 0 ? (
        <span className="auffaelligkeit__empty">
          {t(`${p}.keineKandidaten`)}
        </span>
      ) : (
        <ul className="dcreds__kandidaten-edit">
          {wert.kandidaten.map((k, index) => (
            // Index als Key ist hier bewusst ok: die Liste ist eine reine
            // Formular-Zeilenliste ohne stabile IDs, Reihenfolge egal.
            // eslint-disable-next-line react/no-array-index-key
            <li key={index} className="dcreds__kandidat-edit">
              <input
                className="settings__input"
                type="text"
                value={k.username}
                onChange={(e) => setKandidat(index, "username", e.target.value)}
                placeholder={t(`${p}.username`)}
                aria-label={t(`${p}.username`)}
              />
              <input
                className="settings__input"
                type="text"
                value={k.password}
                onChange={(e) => setKandidat(index, "password", e.target.value)}
                placeholder={t(`${p}.password`)}
                aria-label={t(`${p}.password`)}
              />
              <select
                className="settings__select"
                value={k.konfidenz}
                onChange={(e) => setKandidat(index, "konfidenz", e.target.value)}
                aria-label={t(`${p}.konfidenz`)}
              >
                {KONFIDENZEN.map((c) => (
                  <option key={c} value={c}>
                    {t(`${p}.${KONFIDENZ_KEY[c]}`)}
                  </option>
                ))}
              </select>
              <button
                type="button"
                className="auffaelligkeit__remove"
                aria-label={t(`${p}.kandidatEntfernen`)}
                title={t(`${p}.kandidatEntfernen`)}
                onClick={() => kandidatEntfernen(index)}
              >
                <Trash2 size={14} aria-hidden="true" />
              </button>
            </li>
          ))}
        </ul>
      )}
      <button
        type="button"
        className="settings__link-button"
        onClick={kandidatHinzufuegen}
      >
        {t(`${p}.kandidatHinzufuegen`)}
      </button>

      <div className="settings__row settings__row--actions">
        <button
          type="button"
          className="settings__link-button"
          onClick={onAbbrechen}
          disabled={speichert}
        >
          {t(`${p}.abbrechen`)}
        </button>
        <button
          type="button"
          className="settings__button"
          onClick={onSpeichern}
          disabled={speichert}
        >
          {t(`${p}.speichern`)}
        </button>
      </div>
    </div>
  );
}

// Eine Lese-Karte für einen Eintrag: Kopf (Hersteller/Modell + Zustand/Herkunft-
// Badges + Aktiv-Toggle), Kandidaten-Liste, Quelle, plus Aktionen (Bearbeiten /
// Löschen mit Inline-Bestätigung). Alle Zustandsänderungen laufen über die
// Callbacks — die Sektion hält die Persistenz.
function EintragKarte({
  eintrag,
  onBearbeiten,
  onToggleAktiv,
  onLoeschen,
}) {
  const { t } = useTranslation();
  const p = "settings.defaultCredsList";

  // Inline-Löschbestätigung (kein window.confirm): erst „Löschen", dann ein
  // Zwischenschritt „Wirklich löschen?" / „Abbrechen".
  const [loeschBestaetigung, setLoeschBestaetigung] = useState(false);

  const zustandLabel = ZUSTAND_KEY[eintrag.zustand]
    ? t(`${p}.${ZUSTAND_KEY[eintrag.zustand]}`)
    : eintrag.zustand;
  const herkunftLabel = HERKUNFT_KEY[eintrag.herkunft]
    ? t(`${p}.${HERKUNFT_KEY[eintrag.herkunft]}`)
    : eintrag.herkunft;

  const kandidaten = Array.isArray(eintrag.kandidaten)
    ? eintrag.kandidaten
    : [];

  return (
    <li className="dcreds__karte">
      <div className="dcreds__karte-kopf">
        <span className="dcreds__titel">
          <span className="dcreds__hersteller">
            {eintrag.hersteller || "—"}
          </span>
          <span className="dcreds__modell">
            {eintrag.modell ? eintrag.modell : t(`${p}.modellLeer`)}
          </span>
        </span>
        <span className="dcreds__badges">
          <NeutralBadge>{zustandLabel}</NeutralBadge>
          <NeutralBadge>{herkunftLabel}</NeutralBadge>
        </span>
        {/* Aktiv-Toggle im auffaelligkeit__switch-Stil. */}
        <span className="auffaelligkeit__rule-switchbox">
          <input
            type="checkbox"
            className="auffaelligkeit__switch"
            checked={Boolean(eintrag.aktiv)}
            aria-label={t(`${p}.aktiv`)}
            onChange={(e) => onToggleAktiv(eintrag, e.target.checked)}
          />
        </span>
      </div>

      {/* Kandidaten. */}
      {kandidaten.length === 0 ? (
        <span className="auffaelligkeit__empty">
          {t(`${p}.keineKandidaten`)}
        </span>
      ) : (
        <ul className="dcreds__kandidaten">
          {kandidaten.map((k, index) => {
            const konfidenzLabel = KONFIDENZ_KEY[k.konfidenz]
              ? t(`${p}.${KONFIDENZ_KEY[k.konfidenz]}`)
              : k.konfidenz;
            return (
              // eslint-disable-next-line react/no-array-index-key
              <li key={index} className="dcreds__kandidat">
                <span className="dcreds__kandidat-user">
                  {k.username || "—"}
                </span>
                <span className="dcreds__kandidat-pass">
                  {k.password === "" || k.password == null
                    ? t(`${p}.passwortLeer`)
                    : k.password}
                </span>
                <NeutralBadge>{konfidenzLabel}</NeutralBadge>
              </li>
            );
          })}
        </ul>
      )}

      {/* Quelle nur zeigen, wenn vorhanden. */}
      {eintrag.quelle_url ? (
        <span className="settings__hint dcreds__quelle">
          {t(`${p}.quelleUrl`)}: {eintrag.quelle_url}
        </span>
      ) : null}

      {/* Aktionen. */}
      <div className="dcreds__karte-aktionen">
        <button
          type="button"
          className="settings__link-button"
          onClick={() => onBearbeiten(eintrag)}
        >
          {t(`${p}.bearbeiten`)}
        </button>
        {loeschBestaetigung ? (
          <>
            <span className="settings__hint">
              {t(`${p}.loeschenBestaetigen`)}
            </span>
            <button
              type="button"
              className="settings__link-button"
              onClick={() => {
                setLoeschBestaetigung(false);
                onLoeschen(eintrag);
              }}
            >
              {t(`${p}.loeschen`)}
            </button>
            <button
              type="button"
              className="settings__link-button"
              onClick={() => setLoeschBestaetigung(false)}
            >
              {t(`${p}.abbrechen`)}
            </button>
          </>
        ) : (
          <button
            type="button"
            className="settings__link-button"
            onClick={() => setLoeschBestaetigung(true)}
          >
            {t(`${p}.loeschen`)}
          </button>
        )}
      </div>
    </li>
  );
}

// Die Sektion selbst. onGespeichert ist das gemeinsame zeigeGespeichert-Feedback
// aus SettingsView (gleiches Muster wie die übrigen Sektionen).
export default function DefaultCredsListeSektion({ onGespeichert }) {
  const { t } = useTranslation();
  const p = "settings.defaultCredsList";

  const [liste, setListe] = useState([]);
  const [ladeStatus, setLadeStatus] = useState("laedt"); // laedt | bereit | fehler

  // Bearbeiten-Modus: eintrag_id des gerade editierten Eintrags (oder null).
  const [editId, setEditId] = useState(null);
  // Anlege-Modus: true, wenn das Neu-Formular offen ist.
  const [neuOffen, setNeuOffen] = useState(false);
  // Gemeinsames Formular-Modell für Bearbeiten UND Anlegen.
  const [formular, setFormular] = useState(leeresFormular());
  const [speichert, setSpeichert] = useState(false);
  // Fachliche Fehlermeldung (z. B. 422-Validierung) — ruhig anzeigen.
  const [fehlerText, setFehlerText] = useState("");
  const [resetLaeuft, setResetLaeuft] = useState(false);

  // aktiv-Flag beim Laden nicht verlieren: aus dem letzten Backend-Stand
  // ableiten. Wir merken uns den zuletzt bekannten Eintrag über die Liste.
  const listeRef = useRef(liste);
  listeRef.current = liste;

  // Liste laden. In eine benannte Funktion gezogen, damit reset/Speichern sie
  // neu anstoßen können. aktiv-Guard verhindert setState nach Unmount.
  const ladeListe = async (aktivGuard = { aktiv: true }) => {
    try {
      const daten = await fetchDefaultCredsList();
      if (!aktivGuard.aktiv) {
        return;
      }
      setListe(Array.isArray(daten) ? daten : []);
      setLadeStatus("bereit");
    } catch (ursache) {
      if (!aktivGuard.aktiv) {
        return;
      }
      console.error("Standardzugänge-Liste laden fehlgeschlagen:", ursache);
      setLadeStatus("fehler");
    }
  };

  // Einmal beim Mount laden. t NICHT ins dependency-array (Render-Loop-Falle).
  useEffect(() => {
    const guard = { aktiv: true };
    ladeListe(guard);
    return () => {
      guard.aktiv = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Aktiv-Toggle eines Eintrags: optimistisch lokal spiegeln, dann persistieren.
  // Bei Fehler zurückrollen und Meldung zeigen.
  const handleToggleAktiv = async (eintrag, aktiv) => {
    setFehlerText("");
    setListe((vorher) =>
      vorher.map((e) =>
        e.eintrag_id === eintrag.eintrag_id ? { ...e, aktiv } : e,
      ),
    );
    try {
      await setDefaultCredsEintragAktiv(eintrag.eintrag_id, aktiv);
      onGespeichert();
    } catch (ursache) {
      console.error("Aktiv-Schalten fehlgeschlagen:", ursache);
      // Zurückrollen.
      setListe((vorher) =>
        vorher.map((e) =>
          e.eintrag_id === eintrag.eintrag_id ? { ...e, aktiv: !aktiv } : e,
        ),
      );
      setFehlerText(
        ursache instanceof ApiError ? ursache.message : String(ursache),
      );
    }
  };

  // Bearbeiten öffnen: Formular aus dem Eintrag befüllen, Anlege-Modus schließen.
  const handleBearbeiten = (eintrag) => {
    setFehlerText("");
    setNeuOffen(false);
    setEditId(eintrag.eintrag_id);
    setFormular(eintragZuFormular(eintrag));
  };

  // Anlegen öffnen: leeres Formular, Bearbeiten-Modus schließen.
  const handleNeu = () => {
    setFehlerText("");
    setEditId(null);
    setNeuOffen(true);
    setFormular(leeresFormular());
  };

  // Formular abbrechen (Bearbeiten oder Anlegen).
  const handleAbbrechen = () => {
    setEditId(null);
    setNeuOffen(false);
    setFehlerText("");
    setFormular(leeresFormular());
  };

  // Bearbeiten speichern: den vollständigen Eintrag (mit eintrag_id/herkunft/
  // aktiv aus dem Original) an updateDefaultCredsEintrag. 422 ruhig anzeigen.
  const handleSpeichernBearbeiten = async () => {
    const original = listeRef.current.find((e) => e.eintrag_id === editId);
    if (!original) {
      return;
    }
    setSpeichert(true);
    setFehlerText("");
    const eintrag = {
      eintrag_id: original.eintrag_id,
      hersteller: formular.hersteller,
      modell: formular.modell,
      zustand: formular.zustand,
      kandidaten: formular.kandidaten,
      quelle_url: formular.quelle_url,
      aktiv: original.aktiv,
      herkunft: original.herkunft,
    };
    try {
      await updateDefaultCredsEintrag(original.eintrag_id, eintrag);
      onGespeichert();
      setEditId(null);
      setFormular(leeresFormular());
      await ladeListe();
    } catch (ursache) {
      console.error("Eintrag speichern fehlgeschlagen:", ursache);
      setFehlerText(
        ursache instanceof ApiError ? ursache.message : String(ursache),
      );
    } finally {
      setSpeichert(false);
    }
  };

  // Anlegen speichern: client-seitige eintrag_id, herkunft="benutzer", aktiv=true.
  // 422 (z. B. hat_defaults ohne Kandidaten) ruhig anzeigen.
  const handleSpeichernNeu = async () => {
    setSpeichert(true);
    setFehlerText("");
    const eintrag = {
      eintrag_id: neueBenutzerId(),
      hersteller: formular.hersteller,
      modell: formular.modell,
      zustand: formular.zustand,
      kandidaten: formular.kandidaten,
      quelle_url: formular.quelle_url,
      aktiv: true,
      herkunft: "benutzer",
    };
    try {
      await addDefaultCredsEintrag(eintrag);
      onGespeichert();
      setNeuOffen(false);
      setFormular(leeresFormular());
      await ladeListe();
    } catch (ursache) {
      console.error("Eintrag anlegen fehlgeschlagen:", ursache);
      setFehlerText(
        ursache instanceof ApiError ? ursache.message : String(ursache),
      );
    } finally {
      setSpeichert(false);
    }
  };

  // Löschen: nach Erfolg Liste neu laden. Fehler ruhig anzeigen.
  const handleLoeschen = async (eintrag) => {
    setFehlerText("");
    try {
      await deleteDefaultCredsEintrag(eintrag.eintrag_id);
      onGespeichert();
      // Falls der gelöschte Eintrag gerade editiert wurde, Formular schließen.
      if (editId === eintrag.eintrag_id) {
        setEditId(null);
        setFormular(leeresFormular());
      }
      await ladeListe();
    } catch (ursache) {
      console.error("Eintrag löschen fehlgeschlagen:", ursache);
      setFehlerText(
        ursache instanceof ApiError ? ursache.message : String(ursache),
      );
    }
  };

  // Auf Standard zurücksetzen: reset, danach Liste neu laden.
  const handleReset = async () => {
    setResetLaeuft(true);
    setFehlerText("");
    try {
      await resetDefaultCredsList();
      onGespeichert();
      handleAbbrechen();
      await ladeListe();
    } catch (ursache) {
      console.error("Liste zurücksetzen fehlgeschlagen:", ursache);
      setFehlerText(
        ursache instanceof ApiError ? ursache.message : String(ursache),
      );
    } finally {
      setResetLaeuft(false);
    }
  };

  if (ladeStatus === "laedt") {
    return (
      <section className="settings__section">
        <h3 className="settings__section-title">{t(`${p}.title`)}</h3>
        <div className="settings__section-body">
          <div className="settings__row">
            <span className="settings__hint">{t(`${p}.loading`)}</span>
          </div>
        </div>
      </section>
    );
  }

  if (ladeStatus === "fehler") {
    return (
      <section className="settings__section">
        <h3 className="settings__section-title">{t(`${p}.title`)}</h3>
        <div className="settings__section-body">
          <div className="settings__row">
            <span className="settings__hint settings__hint--error">
              {t(`${p}.ladeFehler`)}
            </span>
          </div>
        </div>
      </section>
    );
  }

  return (
    <section className="settings__section">
      <h3 className="settings__section-title">{t(`${p}.title`)}</h3>
      <div className="settings__section-body">
        <p className="settings__hint">{t(`${p}.intro`)}</p>

        {/* Kopfzeile: Hinzufügen + Reset. */}
        <div className="dcreds__toolbar">
          <button
            type="button"
            className="settings__button"
            onClick={handleNeu}
            disabled={neuOffen}
          >
            {t(`${p}.hinzufuegen`)}
          </button>
          <button
            type="button"
            className="settings__link-button"
            onClick={handleReset}
            disabled={resetLaeuft}
          >
            {t(`${p}.reset`)}
          </button>
        </div>
        <span className="settings__hint">{t(`${p}.resetHinweis`)}</span>

        {fehlerText !== "" ? (
          <span className="settings__hint settings__hint--error">
            {fehlerText}
          </span>
        ) : null}

        {/* Anlege-Formular (falls offen). */}
        {neuOffen ? (
          <div className="dcreds__karte dcreds__karte--neu">
            <NeutralBadge>{t(`${p}.neuerEintrag`)}</NeutralBadge>
            <EintragFormular
              wert={formular}
              onChange={setFormular}
              onSpeichern={handleSpeichernNeu}
              onAbbrechen={handleAbbrechen}
              speichert={speichert}
            />
          </div>
        ) : null}

        {/* Liste der Einträge. */}
        {liste.length === 0 && !neuOffen ? (
          <span className="auffaelligkeit__empty">
            {t(`${p}.leerzustand`)}
          </span>
        ) : (
          <ul className="dcreds__liste">
            {liste.map((eintrag) =>
              editId === eintrag.eintrag_id ? (
                <li key={eintrag.eintrag_id} className="dcreds__karte">
                  <EintragFormular
                    wert={formular}
                    onChange={setFormular}
                    onSpeichern={handleSpeichernBearbeiten}
                    onAbbrechen={handleAbbrechen}
                    speichert={speichert}
                  />
                </li>
              ) : (
                <EintragKarte
                  key={eintrag.eintrag_id}
                  eintrag={eintrag}
                  onBearbeiten={handleBearbeiten}
                  onToggleAktiv={handleToggleAktiv}
                  onLoeschen={handleLoeschen}
                />
              ),
            )}
          </ul>
        )}

        {/* Ehrlichkeits-Hinweis. */}
        <div className="auffaelligkeit__block auffaelligkeit__honesty">
          <p className="settings__hint">{t(`${p}.hint`)}</p>
        </div>
      </div>
    </section>
  );
}
