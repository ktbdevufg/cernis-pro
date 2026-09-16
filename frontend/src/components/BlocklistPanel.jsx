// Listen-Verwaltungs-Panel (CERNIS PRO 2.0)
//
// Die Funktion hinter der Verwaltungs-Kachel „Listen-Verwaltung": verwaltet die
// extern gepflegten Blocklists (Quellen sehen/aktivieren/laden/loeschen, Strenge +
// Gruppen-Feinschalter einstellen, hinzufuegen/hochladen, pruefen, Werkszustand).
// Markup-/CSS-Konventionen wie DeviceManagementPanel.jsx (CSS-Tokens, keine festen
// Farben, dm-table-artige Tabelle -> hier bl-*).
//
// Daten laden in einem useEffect ueber einen gemeinsamen useCallback-Pfad (laden);
// Reload nach jeder Aktion. t/i18n NIE in useEffect-Dependencies (Render-Loop),
// Muster wie CveView.jsx/DeviceManagementPanel.jsx.
//
// Vision-Leitlinie (rote Linie, prominent im Kopf): Die Einordnung stammt aus der
// jeweils genannten Liste, NICHT von CERNIS. CERNIS bildet sie nur ab.

import { RefreshCw, ShieldCheck, Stethoscope, Upload } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import {
  addSource,
  deleteSource,
  fetchHealth,
  fetchSettings,
  fetchSources,
  refreshDue,
  refreshSource,
  resetDefaults,
  updateSource,
  uploadSource,
  writeSettings,
} from "../api/blocklist.js";
import { CODES, mitCode } from "../lib/fehlercodes.js";
import { AddSourceDialog, HealthDialog, UploadSourceDialog } from "./BlocklistDialogs.jsx";
import "./BlocklistPanel.css";

// Die drei Strenge-Stufen (Wire-Werte aus backend/domain/blocklist.py). Reihenfolge
// von „streng" nach „offen".
const STRICTNESS = ["critical_only", "recommended", "all"];

// Ein roher Unix-ts (float, Sekunden) -> kurzes lokales Datum+Uhrzeit. Bei
// fehlendem/unparsbarem Wert -> null (Aufrufer zeigt dann „noch nie"). Kein
// erfundenes Datum.
function lokalesDatum(ts) {
  if (ts === null || ts === undefined) {
    return null;
  }
  const d = new Date(ts * 1000);
  return Number.isNaN(d.getTime()) ? null : d.toLocaleString();
}

// Status-Badge (NEVER/OK/BROKEN) als sprechende Marke mit Token-Farben.
function StatusBadge({ status }) {
  const { t } = useTranslation();
  return (
    <span className="bl-status" data-status={status}>
      {t(`verwaltung.blocklist.status.${status}`)}
    </span>
  );
}

export default function BlocklistPanel() {
  const { t } = useTranslation();

  const [sources, setSources] = useState([]);
  const [settings, setSettings] = useState(null);
  const [laden, setLaden] = useState(true);
  const [fehler, setFehler] = useState(null);

  // Welcher Dialog offen ist: null | "add" | "upload" | "health".
  const [dialog, setDialog] = useState(null);
  // Health-Befunde fuer den Health-Dialog (erst nach „Listen pruefen" gefuellt).
  const [healthIssues, setHealthIssues] = useState([]);
  // Ruhiger „alles in Ordnung"-Hinweis nach Health-Pruefung ohne Befund.
  const [healthOk, setHealthOk] = useState(false);

  // ids mit gerade laufendem Einzel-Refresh (Spinner + Knopf gesperrt).
  const [refreshBusy, setRefreshBusy] = useState(new Set());
  // ids mit gerade laufendem enabled-Toggle / Loeschen (Knopf gesperrt).
  const [zeileBusy, setZeileBusy] = useState(new Set());
  // id der Quelle mit offener Inline-Loesch-Rueckfrage; null = keine.
  const [loeschFrage, setLoeschFrage] = useState(null);

  // Settings-Speichern-Feedback: laeuft + ruhiger „gespeichert"-Hinweis.
  const [settingsBusy, setSettingsBusy] = useState(false);
  const [settingsGespeichert, setSettingsGespeichert] = useState(false);

  // Sammel-Aktionen (refresh-due / reset-defaults) + deren ruhige Zusammenfassung.
  const [sammelBusy, setSammelBusy] = useState(false);
  // null | { aktualisiert, fehlgeschlagen } — Ergebnis von „alle faelligen".
  const [refreshDueErgebnis, setRefreshDueErgebnis] = useState(null);
  // id der offenen Reset-Inline-Rueckfrage-Sicht (bool).
  const [resetFrage, setResetFrage] = useState(false);

  // Quellen + Settings laden. Gemeinsamer Pfad fuer Mount und Reload nach Aktionen.
  // t/i18n NICHT in den Dependencies.
  const laden0 = useCallback(async () => {
    setLaden(true);
    setFehler(null);
    try {
      const [quellen, einstellungen] = await Promise.all([fetchSources(), fetchSettings()]);
      setSources(quellen);
      setSettings(einstellungen);
    } catch (ursache) {
      console.error("Listen-Verwaltung laden fehlgeschlagen:", ursache);
      setFehler("ladeFehler");
    } finally {
      setLaden(false);
    }
  }, []);

  useEffect(() => {
    laden0();
  }, [laden0]);

  // Eine id in einem Busy-Set sperren/freigeben.
  const markiere = (setter, id, an) => {
    setter((prev) => {
      const next = new Set(prev);
      if (an) {
        next.add(id);
      } else {
        next.delete(id);
      }
      return next;
    });
  };

  // ── Settings ─────────────────────────────────────────────────────────────────
  // Sofort schreiben, ruhiges „gespeichert"-Feedback. Bei Fehler: zurueck laden
  // (kein stiller Falsch-Stand) + dezenter Fehlerhinweis.
  const speichereSettings = useCallback(
    async (patch) => {
      // Optimistisch im UI setzen, damit Radio/Toggle sofort reagieren.
      setSettings((prev) => (prev ? { ...prev, ...patch } : prev));
      setSettingsBusy(true);
      setSettingsGespeichert(false);
      try {
        await writeSettings(patch);
        setSettingsGespeichert(true);
      } catch (ursache) {
        console.error("Listen-Einstellung speichern fehlgeschlagen:", ursache);
        setFehler("settingsFehler");
        // Echten Stand wiederherstellen.
        try {
          const frisch = await fetchSettings();
          setSettings(frisch);
        } catch {
          /* Lade-Fehler wird oben bereits angezeigt; nicht doppelt melden. */
        }
      } finally {
        setSettingsBusy(false);
      }
    },
    [],
  );

  // ── Zeilen-Aktionen ────────────────────────────────────────────────────────────
  const handleToggleAktiv = useCallback(
    async (quelle) => {
      setFehler(null);
      markiere(setZeileBusy, quelle.id, true);
      try {
        await updateSource(quelle.id, { enabled: !quelle.enabled });
        await laden0();
      } catch (ursache) {
        console.error("Quelle aktivieren/deaktivieren fehlgeschlagen:", ursache);
        setFehler("aktionFehler");
      } finally {
        markiere(setZeileBusy, quelle.id, false);
      }
    },
    [laden0],
  );

  const handleRefresh = useCallback(
    async (id) => {
      setFehler(null);
      markiere(setRefreshBusy, id, true);
      try {
        await refreshSource(id);
        await laden0();
      } catch (ursache) {
        console.error("Quelle aktualisieren fehlgeschlagen:", ursache);
        setFehler("aktionFehler");
      } finally {
        markiere(setRefreshBusy, id, false);
      }
    },
    [laden0],
  );

  const handleLoeschen = useCallback(
    async (id) => {
      setFehler(null);
      markiere(setZeileBusy, id, true);
      try {
        await deleteSource(id);
        setLoeschFrage(null);
        await laden0();
      } catch (ursache) {
        console.error("Quelle loeschen fehlgeschlagen:", ursache);
        setFehler("aktionFehler");
      } finally {
        markiere(setZeileBusy, id, false);
      }
    },
    [laden0],
  );

  // ── Sammel-Aktionen ──────────────────────────────────────────────────────────
  const handleRefreshDue = useCallback(async () => {
    setFehler(null);
    setRefreshDueErgebnis(null);
    setSammelBusy(true);
    try {
      const { results } = await refreshDue();
      const fehlgeschlagen = results.filter((r) => !r.ok).length;
      setRefreshDueErgebnis({
        aktualisiert: results.length - fehlgeschlagen,
        fehlgeschlagen,
      });
      await laden0();
    } catch (ursache) {
      console.error("Faellige Quellen aktualisieren fehlgeschlagen:", ursache);
      setFehler("aktionFehler");
    } finally {
      setSammelBusy(false);
    }
  }, [laden0]);

  const handleReset = useCallback(async () => {
    setFehler(null);
    setSammelBusy(true);
    try {
      await resetDefaults();
      setResetFrage(false);
      await laden0();
    } catch (ursache) {
      console.error("Werkszustand der Listen herstellen fehlgeschlagen:", ursache);
      setFehler("aktionFehler");
    } finally {
      setSammelBusy(false);
    }
  }, [laden0]);

  // ── Health ───────────────────────────────────────────────────────────────────
  const handleHealth = useCallback(async () => {
    setFehler(null);
    setHealthOk(false);
    setSammelBusy(true);
    try {
      const { issues } = await fetchHealth();
      if (issues.length === 0) {
        setHealthOk(true);
      } else {
        setHealthIssues(issues);
        setDialog("health");
      }
    } catch (ursache) {
      console.error("Listen pruefen fehlgeschlagen:", ursache);
      setFehler("aktionFehler");
    } finally {
      setSammelBusy(false);
    }
  }, []);

  // Health-Dialog-Aktionen: nach Loeschen/Aktivieren Sources + Health neu laden.
  // Bleiben keine Befunde offen, schliesst sich der Dialog von selbst.
  const healthLoeschen = useCallback(
    async (id) => {
      await deleteSource(id);
      await laden0();
      const { issues } = await fetchHealth();
      setHealthIssues(issues);
      if (issues.length === 0) {
        setDialog(null);
      }
    },
    [laden0],
  );

  const healthAktivieren = useCallback(
    async (id) => {
      await updateSource(id, { enabled: true });
      await laden0();
      const { issues } = await fetchHealth();
      setHealthIssues(issues);
      if (issues.length === 0) {
        setDialog(null);
      }
    },
    [laden0],
  );

  // ── Render-Hilfen ──────────────────────────────────────────────────────────────
  // Map id -> Quelle (Health-Dialog loest Ersatzvorschlag/origin darueber auf).
  const quellenNachId = new Map(sources.map((q) => [q.id, q]));

  // Eine Quelle ist loeschbar, wenn sie NICHT mitgeliefert ist (USER_URL/UPLOAD).
  const istLoeschbar = (quelle) => quelle.origin !== "builtin";

  if (laden && sources.length === 0 && settings === null) {
    return (
      <div className="bl-panel">
        <p className="bl-loading">{t("verwaltung.blocklist.loading")}</p>
      </div>
    );
  }

  return (
    <div className="bl-panel">
      {/* 1 — Ruhiger Erklaer-Kopf mit prominenter roter Linie. */}
      <section className="bl-intro">
        <p className="bl-intro__desc">{t("verwaltung.blocklist.intro")}</p>
        <p className="bl-intro__redline">{t("verwaltung.blocklist.redLine")}</p>
      </section>

      {/* Globaler, dezenter Fehlerhinweis (Lade-/Aktions-Fehler). */}
      {fehler ? (
        <p className="bl-error" role="alert">
          {/* Nur der Aktions-Fehler traegt einen Schema-Code (E-503); Lade-/
              Settings-Fehler bleiben ohne Code. */}
          {fehler === "aktionFehler"
            ? mitCode(t(`verwaltung.blocklist.${fehler}`), CODES.E_503)
            : t(`verwaltung.blocklist.${fehler}`)}
        </p>
      ) : null}

      {/* 2 — Strenge-Einstellung + Gruppen-Feinschalter. */}
      {settings ? (
        <section className="bl-section">
          <h3 className="bl-section__title">{t("verwaltung.blocklist.settings.title")}</h3>

          <div className="bl-strictness" role="radiogroup" aria-label={t("verwaltung.blocklist.settings.strictnessLabel")}>
            {STRICTNESS.map((stufe) => {
              const aktiv = settings.strictness === stufe;
              return (
                <button
                  key={stufe}
                  type="button"
                  role="radio"
                  aria-checked={aktiv}
                  className={`bl-strictness__option${aktiv ? " bl-strictness__option--active" : ""}`}
                  onClick={() => speichereSettings({ strictness: stufe })}
                  disabled={settingsBusy}
                >
                  <span className="bl-strictness__name">
                    {t(`verwaltung.blocklist.strictness.${stufe}.label`)}
                  </span>
                  <span className="bl-strictness__hint">
                    {t(`verwaltung.blocklist.strictness.${stufe}.hint`)}
                  </span>
                </button>
              );
            })}
          </div>

          <div className="bl-toggles">
            <label className="bl-toggle">
              <input
                type="checkbox"
                className="bl-toggle__box"
                checked={settings.groupTrackerAdsEnabled}
                onChange={(e) =>
                  speichereSettings({ groupTrackerAdsEnabled: e.target.checked })
                }
                disabled={settingsBusy}
              />
              <span className="bl-toggle__label">
                {t("verwaltung.blocklist.settings.groupTrackerAds")}
              </span>
            </label>
            <label className="bl-toggle">
              <input
                type="checkbox"
                className="bl-toggle__box"
                checked={settings.groupThreatEnabled}
                onChange={(e) => speichereSettings({ groupThreatEnabled: e.target.checked })}
                disabled={settingsBusy}
              />
              <span className="bl-toggle__label">
                {t("verwaltung.blocklist.settings.groupThreat")}
              </span>
            </label>
          </div>

          {settingsGespeichert ? (
            <span className="bl-saved" role="status" aria-live="polite">
              {t("verwaltung.blocklist.settings.saved")}
            </span>
          ) : null}
        </section>
      ) : null}

      {/* 4 — Aktionsleiste. */}
      <section className="bl-section">
        <div className="bl-actions">
          <button type="button" className="bl-action" onClick={() => setDialog("add")}>
            <ShieldCheck size={15} aria-hidden="true" />
            {t("verwaltung.blocklist.actions.add")}
          </button>
          <button type="button" className="bl-action" onClick={() => setDialog("upload")}>
            <Upload size={15} aria-hidden="true" />
            {t("verwaltung.blocklist.actions.upload")}
          </button>
          <button
            type="button"
            className="bl-action"
            onClick={handleRefreshDue}
            disabled={sammelBusy}
          >
            <RefreshCw size={15} aria-hidden="true" />
            {t("verwaltung.blocklist.actions.refreshDue")}
          </button>
          <button
            type="button"
            className="bl-action"
            onClick={handleHealth}
            disabled={sammelBusy}
          >
            <Stethoscope size={15} aria-hidden="true" />
            {t("verwaltung.blocklist.actions.health")}
          </button>
          <button
            type="button"
            className="bl-action bl-action--danger"
            onClick={() => setResetFrage(true)}
            disabled={sammelBusy}
          >
            {t("verwaltung.blocklist.actions.reset")}
          </button>
        </div>

        {refreshDueErgebnis ? (
          <span className="bl-saved" role="status" aria-live="polite">
            {t("verwaltung.blocklist.refreshDueResult", {
              updated: refreshDueErgebnis.aktualisiert,
              failed: refreshDueErgebnis.fehlgeschlagen,
            })}
          </span>
        ) : null}

        {healthOk ? (
          <span className="bl-saved" role="status" aria-live="polite">
            {t("verwaltung.blocklist.health.allFine")}
          </span>
        ) : null}

        {/* Inline-Rueckfrage Werkszustand (kein window.confirm). */}
        {resetFrage ? (
          <div className="bl-confirm" role="alertdialog" aria-label={t("verwaltung.blocklist.confirm.resetTitle")}>
            <p className="bl-confirm__text">{t("verwaltung.blocklist.confirm.resetText")}</p>
            <div className="bl-confirm__actions">
              <button
                type="button"
                className="bl-confirm__btn"
                onClick={() => setResetFrage(false)}
                disabled={sammelBusy}
              >
                {t("verwaltung.blocklist.confirm.cancel")}
              </button>
              <button
                type="button"
                className="bl-confirm__btn bl-confirm__btn--danger"
                onClick={handleReset}
                disabled={sammelBusy}
              >
                {t("verwaltung.blocklist.confirm.resetConfirm")}
              </button>
            </div>
          </div>
        ) : null}
      </section>

      {/* 3 — Quellen-Tabelle (eine Tabelle mit Gruppen-Spalte). */}
      <section className="bl-section">
        <h3 className="bl-section__title">{t("verwaltung.blocklist.sources.title")}</h3>
        {sources.length === 0 ? (
          <p className="bl-empty">{t("verwaltung.blocklist.sources.empty")}</p>
        ) : (
          <div className="bl-table-wrap">
            <table className="bl-table">
              <thead>
                <tr>
                  <th className="bl-table__th">{t("verwaltung.blocklist.col.name")}</th>
                  <th className="bl-table__th">{t("verwaltung.blocklist.col.group")}</th>
                  <th className="bl-table__th">{t("verwaltung.blocklist.col.format")}</th>
                  <th className="bl-table__th">{t("verwaltung.blocklist.col.status")}</th>
                  <th className="bl-table__th bl-table__th--num">
                    {t("verwaltung.blocklist.col.entries")}
                  </th>
                  <th className="bl-table__th">{t("verwaltung.blocklist.col.fetched")}</th>
                  <th className="bl-table__th">{t("verwaltung.blocklist.col.license")}</th>
                  <th className="bl-table__th">{t("verwaltung.blocklist.col.active")}</th>
                  <th className="bl-table__th bl-table__th--action" />
                </tr>
              </thead>
              <tbody>
                {sources.map((quelle) => {
                  const gesehen = lokalesDatum(quelle.lastFetchedTs);
                  const refreshLaeuft = refreshBusy.has(quelle.id);
                  const zeileLaeuft = zeileBusy.has(quelle.id);
                  const loeschbar = istLoeschbar(quelle);
                  const frageOffen = loeschFrage === quelle.id;
                  return (
                    <tr key={quelle.id} className="bl-table__row">
                      <td className="bl-table__cell">{quelle.name}</td>
                      <td className="bl-table__cell">
                        <span className="bl-badge bl-badge--group">
                          {t(`verwaltung.blocklist.group.${quelle.group}`)}
                        </span>
                      </td>
                      <td className="bl-table__cell bl-table__cell--nowrap">
                        {t(`verwaltung.blocklist.format.${quelle.fmt}`)}
                      </td>
                      <td className="bl-table__cell">
                        <StatusBadge status={quelle.status} />
                      </td>
                      <td className="bl-table__cell bl-table__cell--num">
                        {quelle.entryCount ?? "—"}
                      </td>
                      <td className="bl-table__cell bl-table__cell--nowrap">
                        {gesehen || t("verwaltung.blocklist.never")}
                      </td>
                      <td className="bl-table__cell">
                        <span className="bl-license">{quelle.license}</span>
                        {quelle.attributionRequired ? (
                          <span className="bl-attrib">
                            {t("verwaltung.blocklist.attributionRequired")}
                          </span>
                        ) : null}
                      </td>
                      <td className="bl-table__cell">
                        <label className="bl-active">
                          <input
                            type="checkbox"
                            className="bl-active__box"
                            checked={quelle.enabled}
                            onChange={() => handleToggleAktiv(quelle)}
                            disabled={zeileLaeuft}
                            aria-label={t("verwaltung.blocklist.col.active")}
                          />
                        </label>
                      </td>
                      <td className="bl-table__cell bl-table__cell--action">
                        {frageOffen ? (
                          <span className="bl-row-confirm">
                            <span className="bl-row-confirm__text">
                              {t("verwaltung.blocklist.confirm.deleteText")}
                            </span>
                            <button
                              type="button"
                              className="bl-row-action bl-row-action--danger"
                              onClick={() => handleLoeschen(quelle.id)}
                              disabled={zeileLaeuft}
                            >
                              {t("verwaltung.blocklist.confirm.deleteConfirm")}
                            </button>
                            <button
                              type="button"
                              className="bl-row-action"
                              onClick={() => setLoeschFrage(null)}
                              disabled={zeileLaeuft}
                            >
                              {t("verwaltung.blocklist.confirm.cancel")}
                            </button>
                          </span>
                        ) : (
                          <span className="bl-row-actions">
                            <button
                              type="button"
                              className="bl-row-action"
                              onClick={() => handleRefresh(quelle.id)}
                              disabled={refreshLaeuft || zeileLaeuft}
                            >
                              <RefreshCw
                                size={13}
                                aria-hidden="true"
                                className={refreshLaeuft ? "bl-spin" : undefined}
                              />
                              {t("verwaltung.blocklist.actions.refresh")}
                            </button>
                            {loeschbar ? (
                              <button
                                type="button"
                                className="bl-row-action bl-row-action--danger"
                                onClick={() => setLoeschFrage(quelle.id)}
                                disabled={zeileLaeuft}
                              >
                                {t("verwaltung.blocklist.actions.delete")}
                              </button>
                            ) : null}
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Dialoge. */}
      {dialog === "add" ? (
        <AddSourceDialog
          onAdd={addSource}
          onSchliessen={() => setDialog(null)}
          onFertig={() => {
            setDialog(null);
            laden0();
          }}
        />
      ) : null}

      {dialog === "upload" ? (
        <UploadSourceDialog
          onUpload={uploadSource}
          onSchliessen={() => setDialog(null)}
          onFertig={() => {
            setDialog(null);
            laden0();
          }}
        />
      ) : null}

      {dialog === "health" ? (
        <HealthDialog
          issues={healthIssues}
          quellenNachId={quellenNachId}
          onLoeschen={healthLoeschen}
          onAktivieren={healthAktivieren}
          onSchliessen={() => setDialog(null)}
        />
      ) : null}
    </div>
  );
}
