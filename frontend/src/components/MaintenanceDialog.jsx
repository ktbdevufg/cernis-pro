// Wartungs-Dialog „Daten löschen" (CERNIS PRO 2.0)
//
// Zentrierter Overlay-Dialog für die Daten-Löschung. Es gibt im Projekt KEIN
// bestehendes Modal-Muster (ColumnManager ist nur ein Popover) — daher ein
// eigenständiger, zentrierter Overlay-Dialog im App-Stil (nur CSS-Tokens, keine
// hartkodierten Farben; orange/rot über die Severity-Tokens).
//
// Drei Fenster im selben Overlay (lokaler State, kein Routing):
//   FENSTER 1  — Stufe wählen: zwei Blöcke (Scan-Daten zurücksetzen / Werkszustand).
//   FENSTER 1b — Baukasten: gruppierte Ankreuz-Liste (nur für „Scan-Daten").
//   FENSTER 2  — bestätigen: Auflistung der effektiv gewählten Posten, optionales
//                Secrets-Kästchen (nur Werkszustand), roter Schluss-Hinweis,
//                „Zurück" + „Endgültig löschen".
//
// Wurzel-Sperrlogik (§13): In der Gruppe „Scan & Analyse" ist scan_history die
// WURZEL. Ist sie angehakt, werden die vier abgeleiteten Posten (cve, arp_guard,
// analysis_acknowledgements, known_hosts) zwangsweise mit-angehakt UND gesperrt
// (disabled), optisch mit „+" und gedämpft. Sinn: Scan-Historie löschen zieht die
// abgeleiteten Befunde zwingend mit.
//
// Der eigentliche Backend-Aufruf läuft über onBestaetigt (von der Sektion gereicht,
// die das ruhige „erledigt"-Feedback hält). Fehler kommen als ApiError zurück:
// Dialog bleibt offen, dezenter Inline-Fehler, Knopf wieder klickbar.

import { X } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import "./MaintenanceDialog.css";

// Die Fenster/Stufen als Konstanten — vermeidet Tippfehler-Strings im JSX.
const STUFE_SELECTED = "selected"; // Baukasten-Auswahl -> reset-selected
const STUFE_FACTORY = "factory"; // Werkszustand -> factory-reset

// Wurzel-Posten der Gruppe „Scan & Analyse" und seine erzwungenen Ableitungen.
const WURZEL = "scan_history";
const ABGELEITET = ["cve", "arp_guard", "analysis_acknowledgements", "known_hosts"];

// Gruppen + Posten. wire = exakter Backend-String, labelKey = i18n unter
// settings.wartung.builder.item.*, derived = unter der Wurzel erzwungen.
const GRUPPEN = [
  {
    titleKey: "settings.wartung.builder.groupScan",
    posten: [
      { wire: "scan_history", labelKey: "settings.wartung.builder.item.scanHistory" },
      { wire: "cve", labelKey: "settings.wartung.builder.item.cve", derived: true },
      { wire: "arp_guard", labelKey: "settings.wartung.builder.item.arpGuard", derived: true },
      {
        wire: "analysis_acknowledgements",
        labelKey: "settings.wartung.builder.item.analysisAcks",
        derived: true,
      },
      { wire: "known_hosts", labelKey: "settings.wartung.builder.item.knownHosts", derived: true },
    ],
  },
  {
    titleKey: "settings.wartung.builder.groupMonitoring",
    posten: [
      { wire: "rtt", labelKey: "settings.wartung.builder.item.rtt" },
      { wire: "sla", labelKey: "settings.wartung.builder.item.sla" },
      { wire: "logging", labelKey: "settings.wartung.builder.item.logging" },
    ],
  },
  {
    titleKey: "settings.wartung.builder.groupOutbound",
    posten: [
      {
        wire: "outbound_recordings",
        labelKey: "settings.wartung.builder.item.outboundRecordings",
      },
    ],
  },
  {
    titleKey: "settings.wartung.builder.groupDns",
    posten: [
      {
        wire: "dns_bypass_recordings",
        labelKey: "settings.wartung.builder.item.dnsBypassRecordings",
      },
      {
        wire: "dns_trust_servers",
        labelKey: "settings.wartung.builder.item.dnsTrustServers",
      },
    ],
  },
];

// Flache Karte wire -> labelKey, für die Bestätigungs-Liste (Fenster 2).
const LABEL_KEY = GRUPPEN.reduce((acc, g) => {
  for (const p of g.posten) {
    acc[p.wire] = p.labelKey;
  }
  return acc;
}, {});

// Effektive Item-Menge (Wire-Strings) aus der Roh-Auswahl: ist die Wurzel gewählt,
// gehören die vier abgeleiteten Posten zwangsweise dazu. Reihenfolge stabil
// (Gruppen-/Posten-Reihenfolge), damit die Bestätigungs-Liste ruhig wirkt.
function effektiveItems(gewaehlt) {
  const aktiv = new Set(gewaehlt);
  if (aktiv.has(WURZEL)) {
    for (const d of ABGELEITET) {
      aktiv.add(d);
    }
  }
  const out = [];
  for (const g of GRUPPEN) {
    for (const p of g.posten) {
      if (aktiv.has(p.wire)) {
        out.push(p.wire);
      }
    }
  }
  return out;
}

export default function MaintenanceDialog({ onSchliessen, onBestaetigt }) {
  const { t } = useTranslation();

  // null = Fenster 1 (Stufe wählen); STUFE_SELECTED = Baukasten (1b) bzw. dessen
  // Bestätigung; STUFE_FACTORY = Werkszustand-Bestätigung.
  const [stufe, setStufe] = useState(null);
  // true erst, wenn aus dem Baukasten heraus „Ausgewähltes löschen" gedrückt wurde
  // (Fenster 2). Solange false und stufe===SELECTED zeigen wir den Baukasten (1b).
  const [bestaetigtAnsicht, setBestaetigtAnsicht] = useState(false);
  // Roh angehakte Posten (Wire-Strings) im Baukasten — OHNE die erzwungenen.
  const [auswahl, setAuswahl] = useState(() => new Set());
  // Nur Werkszustand: auch gespeicherte Zugangsdaten entfernen. Default AUS.
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

  // Scan-Kachel -> Baukasten (1b). Auswahl/Fehler frisch.
  const oeffneBaukasten = () => {
    setFehler(false);
    setAuswahl(new Set());
    setBestaetigtAnsicht(false);
    setStufe(STUFE_SELECTED);
  };

  // Werkszustand-Kachel -> direkt zur Bestätigung (Fenster 2).
  const waehleFactory = () => {
    setFehler(false);
    setSecretsEntfernen(false);
    setBestaetigtAnsicht(true);
    setStufe(STUFE_FACTORY);
  };

  // Einen Posten an-/abwählen (nur frei wählbare; erzwungene sind disabled).
  const toggle = (wire) => {
    setAuswahl((prev) => {
      const next = new Set(prev);
      if (next.has(wire)) {
        next.delete(wire);
      } else {
        next.add(wire);
      }
      return next;
    });
  };

  // Baukasten -> Bestätigung (Fenster 2) mit der konkreten Auswahl.
  const zurBestaetigung = () => {
    setFehler(false);
    setBestaetigtAnsicht(true);
  };

  // Zurück: aus der Baukasten-Bestätigung zurück zum Baukasten, sonst zu Fenster 1.
  const zurueck = () => {
    setFehler(false);
    if (stufe === STUFE_SELECTED && bestaetigtAnsicht) {
      setBestaetigtAnsicht(false);
      return;
    }
    setBestaetigtAnsicht(false);
    setStufe(null);
  };

  // Effektive Item-Liste (Wire-Strings) für Backend + Bestätigungs-Liste.
  const items = effektiveItems(auswahl);

  // „Endgültig löschen": Backend-Aufruf über onBestaetigt. Bei Erfolg schließt die
  // aufrufende Sektion den Dialog (und zeigt das ruhige „erledigt"); bei Fehler
  // bleibt der Dialog offen mit dezentem Hinweis, Knopf wieder klickbar.
  const bestaetigen = async () => {
    setFehler(false);
    setLaeuft(true);
    try {
      await onBestaetigt(stufe, { items, secretsEntfernen });
      // Erfolg: das Schließen übernimmt die Sektion (sie hält das Feedback).
    } catch {
      setFehler(true);
      setLaeuft(false);
    }
  };

  // Ob die Wurzel aktiv ist — steuert Sperrung/Optik der abgeleiteten Posten.
  const wurzelAktiv = auswahl.has(WURZEL);

  // Punkte der Bestätigungs-Liste (Fenster 2): factory = feste Aufzählung,
  // selected = die effektiv gewählten Posten-Labels.
  const loeschPunkte =
    stufe === STUFE_FACTORY
      ? [
          t("settings.wartung.confirm.factory.item1"),
          t("settings.wartung.confirm.factory.item2"),
          t("settings.wartung.confirm.factory.item3"),
          t("settings.wartung.confirm.factory.item4"),
        ]
      : items.map((wire) => t(LABEL_KEY[wire]));

  const titel =
    stufe === null
      ? t("settings.wartung.dialog.title")
      : stufe === STUFE_FACTORY
        ? t("settings.wartung.confirm.factory.title")
        : bestaetigtAnsicht
          ? t("settings.wartung.confirm.scan.title")
          : t("settings.wartung.builder.title");

  // Welche Ansicht: Fenster 1 / Baukasten (1b) / Bestätigung (2).
  const zeigeBaukasten = stufe === STUFE_SELECTED && !bestaetigtAnsicht;
  const zeigeBestaetigung = stufe !== null && bestaetigtAnsicht;

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
              onClick={oeffneBaukasten}
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
              onClick={waehleFactory}
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
        ) : zeigeBaukasten ? (
          // ── FENSTER 1b — Baukasten (gruppierte Ankreuz-Liste) ──────────────
          <div className="maint-dialog__body">
            {GRUPPEN.map((gruppe) => {
              // Eine einzelne Posten-Zeile rendern. Die Sperr-/„+"-Logik bleibt
              // unverändert; nur die Einrückung der abgeleiteten Posten ist neu.
              const renderPosten = (posten) => {
                // Abgeleiteter Posten bei aktiver Wurzel: erzwungen + gesperrt.
                const erzwungen = posten.derived && wurzelAktiv;
                const angehakt = erzwungen || auswahl.has(posten.wire);
                const klasse = [
                  "maint-builder__item",
                  posten.derived ? "maint-builder__item--child" : null,
                  erzwungen ? "maint-builder__item--locked" : null,
                ]
                  .filter(Boolean)
                  .join(" ");
                return (
                  <label key={posten.wire} className={klasse}>
                    <input
                      type="checkbox"
                      className="maint-builder__checkbox"
                      checked={angehakt}
                      disabled={erzwungen}
                      onChange={() => toggle(posten.wire)}
                    />
                    {erzwungen ? (
                      <span className="maint-builder__plus" aria-hidden="true">
                        +
                      </span>
                    ) : null}
                    <span className="maint-builder__label">{t(posten.labelKey)}</span>
                  </label>
                );
              };

              // Wurzel-Posten (flach) und abgeleitete Posten (eingerückt) trennen.
              // Reihenfolge bleibt: erst die nicht-abgeleiteten, dann die Kinder
              // im eingerückten Container darunter.
              const wurzelPosten = gruppe.posten.filter((p) => !p.derived);
              const kindPosten = gruppe.posten.filter((p) => p.derived);

              return (
                <div key={gruppe.titleKey} className="maint-builder__group">
                  <h3 className="maint-builder__group-title">{t(gruppe.titleKey)}</h3>
                  {wurzelPosten.map(renderPosten)}
                  {kindPosten.length > 0 ? (
                    <div className="maint-builder__children">
                      {kindPosten.map(renderPosten)}
                    </div>
                  ) : null}
                </div>
              );
            })}

            <p className="maint-builder__hint">{t("settings.wartung.builder.rootHint")}</p>

            <div className="maint-dialog__actions">
              <button
                type="button"
                className="maint-button"
                onClick={zurueck}
              >
                {t("settings.wartung.confirm.back")}
              </button>
              <button
                type="button"
                className="maint-button maint-button--danger"
                onClick={zurBestaetigung}
                disabled={items.length === 0}
                title={
                  items.length === 0
                    ? t("settings.wartung.builder.nothingSelected")
                    : undefined
                }
              >
                {t("settings.wartung.builder.deleteSelected")}
              </button>
            </div>
          </div>
        ) : zeigeBestaetigung ? (
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

            {/* Secrets-Kästchen NUR bei Werkszustand. */}
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
        ) : null}
      </div>
    </div>
  );
}
