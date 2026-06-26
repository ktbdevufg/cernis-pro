// Blocklist-Dialoge (CERNIS PRO 2.0)
//
// Drei Overlay-Dialoge fuer die Listen-Verwaltung, im selben Muster wie
// MaintenanceDialog (zentrierter Overlay, lokaler State, X-Schliessen, Escape,
// nur CSS-Tokens, dezenter Inline-Fehler — Dialog bleibt bei ApiError offen). Eine
// Datei, weil alle drei dieselbe Overlay-Schale (bd-*-CSS) teilen; das haelt das
// CSS knapp und die Muster konsistent.
//
//   D1 AddSourceDialog    — Quelle per URL anlegen. Nach Erfolg zeigt der Dialog
//                           einen optionalen Lizenz-Hinweis (license_hint) und
//                           schliesst per „Fertig" (die Quelle ist bereits angelegt).
//   D2 UploadSourceDialog — Quelle aus Datei ODER eingefuegtem Text anlegen.
//   D3 HealthDialog       — defekte Listen + Ersatzvorschlag, gefuehrte Nutzer-
//                           Aktionen (loeschen / Vorschlag aktivieren), keine
//                           Auto-Aktion.
//
// Backend-Aufrufe laufen ueber die als Props gereichten Callbacks aus dem Panel;
// das Panel haelt den Reload. Fehler kommen als ApiError zurueck -> Dialog bleibt
// offen, dezenter Hinweis, Knopf wieder klickbar.

import { X } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import "./BlocklistDialogs.css";

// Wire-Werte des Gruppen-/Format-Vokabulars (aus backend/domain/blocklist.py). Die
// Labels kommen aus i18n (keine Wire-Strings im JSX zeigen).
const GRUPPEN_WIRE = ["tracker_ads", "threat"];
const FORMAT_WIRE = ["hosts", "adblock", "domain_list", "ip_list", "csv_domain", "csv_ip"];

// Gemeinsame Overlay-Schale: Backdrop (Klick daneben schliesst, wenn kein Request
// laeuft), Karten-Dialog mit Kopf (Titel + X) und freiem Body. Escape schliesst
// ebenfalls. busy sperrt das Schliessen waehrend eines laufenden Requests.
function DialogShell({ titel, onSchliessen, busy, children }) {
  const { t } = useTranslation();

  useEffect(() => {
    const handler = (e) => {
      if (e.key === "Escape" && !busy) {
        onSchliessen();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [busy, onSchliessen]);

  return (
    <div
      className="bd-overlay"
      onMouseDown={() => {
        if (!busy) {
          onSchliessen();
        }
      }}
    >
      <div
        className="bd-dialog"
        role="dialog"
        aria-modal="true"
        aria-label={titel}
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="bd-dialog__head">
          <h2 className="bd-dialog__title">{titel}</h2>
          <button
            type="button"
            className="bd-dialog__close"
            aria-label={t("verwaltung.blocklist.dialog.close")}
            title={t("verwaltung.blocklist.dialog.close")}
            onClick={onSchliessen}
            disabled={busy}
          >
            <X size={18} aria-hidden="true" />
          </button>
        </div>
        <div className="bd-dialog__body">{children}</div>
      </div>
    </div>
  );
}

// Ein Gruppen-Select (Tracker/Ads, Threat). value = Wire-String.
function GruppenSelect({ value, onChange, disabled }) {
  const { t } = useTranslation();
  return (
    <select
      className="bd-field__input"
      value={value}
      onChange={(e) => onChange(e.target.value)}
      disabled={disabled}
    >
      {GRUPPEN_WIRE.map((g) => (
        <option key={g} value={g}>
          {t(`verwaltung.blocklist.group.${g}`)}
        </option>
      ))}
    </select>
  );
}

// Ein Format-Select (alle BlocklistFormat-Werte mit sprechenden Labels).
function FormatSelect({ value, onChange, disabled }) {
  const { t } = useTranslation();
  return (
    <select
      className="bd-field__input"
      value={value}
      onChange={(e) => onChange(e.target.value)}
      disabled={disabled}
    >
      {FORMAT_WIRE.map((f) => (
        <option key={f} value={f}>
          {t(`verwaltung.blocklist.format.${f}`)}
        </option>
      ))}
    </select>
  );
}

// ── D1 — Quelle per URL anlegen ────────────────────────────────────────────────
// onAdd({name,url,group,fmt}) -> { sourceId, licenseHint } (wirft ApiError bei 422).
// Nach Erfolg bleibt der Dialog offen und zeigt — falls vorhanden — den ruhigen
// Lizenz-Hinweis; „Fertig" loest dann den Reload im Panel aus und schliesst.
export function AddSourceDialog({ onAdd, onFertig, onSchliessen }) {
  const { t } = useTranslation();

  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [group, setGroup] = useState(GRUPPEN_WIRE[0]);
  const [fmt, setFmt] = useState(FORMAT_WIRE[0]);
  const [laeuft, setLaeuft] = useState(false);
  const [fehler, setFehler] = useState(false);
  // null = noch nicht angelegt; sonst { licenseHint } (Hinweis kann selbst null sein).
  const [erfolg, setErfolg] = useState(null);

  const eingabeOk = name.trim().length > 0 && url.trim().length > 0;

  const anlegen = async () => {
    setFehler(false);
    setLaeuft(true);
    try {
      const res = await onAdd({ name: name.trim(), url: url.trim(), group, fmt });
      setErfolg({ licenseHint: res?.licenseHint ?? null });
    } catch {
      setFehler(true);
    } finally {
      setLaeuft(false);
    }
  };

  // Nach dem Anlegen: Erfolgs-Ansicht mit optionalem Lizenz-Hinweis.
  if (erfolg) {
    return (
      <DialogShell
        titel={t("verwaltung.blocklist.add.title")}
        onSchliessen={onFertig}
        busy={false}
      >
        <p className="bd-success">{t("verwaltung.blocklist.add.successLead")}</p>
        {erfolg.licenseHint ? (
          <div className="bd-license-hint" role="note">
            {t("verwaltung.blocklist.add.licenseHint", { license: erfolg.licenseHint })}
          </div>
        ) : null}
        <div className="bd-actions">
          <button type="button" className="bd-button bd-button--primary" onClick={onFertig}>
            {t("verwaltung.blocklist.add.done")}
          </button>
        </div>
      </DialogShell>
    );
  }

  return (
    <DialogShell
      titel={t("verwaltung.blocklist.add.title")}
      onSchliessen={onSchliessen}
      busy={laeuft}
    >
      <p className="bd-lead">{t("verwaltung.blocklist.add.lead")}</p>

      <label className="bd-field">
        <span className="bd-field__label">{t("verwaltung.blocklist.add.name")}</span>
        <input
          className="bd-field__input"
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          disabled={laeuft}
        />
      </label>

      <label className="bd-field">
        <span className="bd-field__label">{t("verwaltung.blocklist.add.url")}</span>
        <input
          className="bd-field__input"
          type="url"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          disabled={laeuft}
          placeholder="https://"
        />
      </label>

      <div className="bd-field__row">
        <label className="bd-field">
          <span className="bd-field__label">{t("verwaltung.blocklist.add.group")}</span>
          <GruppenSelect value={group} onChange={setGroup} disabled={laeuft} />
        </label>
        <label className="bd-field">
          <span className="bd-field__label">{t("verwaltung.blocklist.add.format")}</span>
          <FormatSelect value={fmt} onChange={setFmt} disabled={laeuft} />
        </label>
      </div>

      {fehler ? (
        <span className="bd-error">{t("verwaltung.blocklist.add.error")}</span>
      ) : null}

      <div className="bd-actions">
        <button type="button" className="bd-button" onClick={onSchliessen} disabled={laeuft}>
          {t("verwaltung.blocklist.dialog.cancel")}
        </button>
        <button
          type="button"
          className="bd-button bd-button--primary"
          onClick={anlegen}
          disabled={laeuft || !eingabeOk}
        >
          {t("verwaltung.blocklist.add.submit")}
        </button>
      </div>
    </DialogShell>
  );
}

// ── D2 — Quelle hochladen (Datei ODER Text) ────────────────────────────────────
// onUpload({name,group,fmt,content}) -> { sourceId, entryCount }.
export function UploadSourceDialog({ onUpload, onFertig, onSchliessen }) {
  const { t } = useTranslation();

  const [name, setName] = useState("");
  const [group, setGroup] = useState(GRUPPEN_WIRE[0]);
  const [fmt, setFmt] = useState(FORMAT_WIRE[0]);
  const [inhalt, setInhalt] = useState("");
  const [dateiName, setDateiName] = useState("");
  const [laeuft, setLaeuft] = useState(false);
  const [fehler, setFehler] = useState(false);
  // null = noch nicht hochgeladen; sonst { entryCount }.
  const [erfolg, setErfolg] = useState(null);

  const eingabeOk = name.trim().length > 0 && inhalt.trim().length > 0;

  // Datei einlesen -> Text ins Textarea uebernehmen (FileReader.readAsText). Der
  // Nutzer kann den Text danach noch sehen/bearbeiten. Kein Auto-Upload.
  const dateiGewaehlt = (e) => {
    const datei = e.target.files?.[0];
    if (!datei) {
      return;
    }
    setDateiName(datei.name);
    if (!name.trim()) {
      setName(datei.name);
    }
    const reader = new FileReader();
    reader.onload = () => {
      setInhalt(typeof reader.result === "string" ? reader.result : "");
    };
    reader.readAsText(datei);
  };

  const hochladen = async () => {
    setFehler(false);
    setLaeuft(true);
    try {
      const res = await onUpload({ name: name.trim(), group, fmt, content: inhalt });
      setErfolg({ entryCount: res?.entryCount ?? 0 });
    } catch {
      setFehler(true);
    } finally {
      setLaeuft(false);
    }
  };

  if (erfolg) {
    return (
      <DialogShell
        titel={t("verwaltung.blocklist.upload.title")}
        onSchliessen={onFertig}
        busy={false}
      >
        <p className="bd-success">
          {t("verwaltung.blocklist.upload.success", { count: erfolg.entryCount })}
        </p>
        <div className="bd-actions">
          <button type="button" className="bd-button bd-button--primary" onClick={onFertig}>
            {t("verwaltung.blocklist.add.done")}
          </button>
        </div>
      </DialogShell>
    );
  }

  return (
    <DialogShell
      titel={t("verwaltung.blocklist.upload.title")}
      onSchliessen={onSchliessen}
      busy={laeuft}
    >
      <p className="bd-lead">{t("verwaltung.blocklist.upload.lead")}</p>

      <label className="bd-field">
        <span className="bd-field__label">{t("verwaltung.blocklist.add.name")}</span>
        <input
          className="bd-field__input"
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          disabled={laeuft}
        />
      </label>

      <div className="bd-field__row">
        <label className="bd-field">
          <span className="bd-field__label">{t("verwaltung.blocklist.add.group")}</span>
          <GruppenSelect value={group} onChange={setGroup} disabled={laeuft} />
        </label>
        <label className="bd-field">
          <span className="bd-field__label">{t("verwaltung.blocklist.add.format")}</span>
          <FormatSelect value={fmt} onChange={setFmt} disabled={laeuft} />
        </label>
      </div>

      <label className="bd-field">
        <span className="bd-field__label">{t("verwaltung.blocklist.upload.file")}</span>
        <input
          className="bd-field__file"
          type="file"
          accept=".txt,.csv,.hosts,.list,text/plain"
          onChange={dateiGewaehlt}
          disabled={laeuft}
        />
        {dateiName ? <span className="bd-field__hint">{dateiName}</span> : null}
      </label>

      <label className="bd-field">
        <span className="bd-field__label">{t("verwaltung.blocklist.upload.text")}</span>
        <textarea
          className="bd-field__textarea"
          value={inhalt}
          onChange={(e) => setInhalt(e.target.value)}
          disabled={laeuft}
          rows={8}
          placeholder={t("verwaltung.blocklist.upload.textPlaceholder")}
        />
      </label>

      {fehler ? (
        <span className="bd-error">{t("verwaltung.blocklist.upload.error")}</span>
      ) : null}

      <div className="bd-actions">
        <button type="button" className="bd-button" onClick={onSchliessen} disabled={laeuft}>
          {t("verwaltung.blocklist.dialog.cancel")}
        </button>
        <button
          type="button"
          className="bd-button bd-button--primary"
          onClick={hochladen}
          disabled={laeuft || !eingabeOk}
        >
          {t("verwaltung.blocklist.upload.submit")}
        </button>
      </div>
    </DialogShell>
  );
}

// ── D3 — Listen pruefen (Health) ───────────────────────────────────────────────
// issues: [{sourceId,name,group,suggestedReplacementId}]. quellenNachId: Map id ->
// source (zur Aufloesung von Name/Herkunft des Vorschlags). onLoeschen(id) /
// onAktivieren(id) rufen das Panel; bei BUILTIN ist Loeschen gesperrt (Hinweis).
// Keine Auto-Aktion — der Nutzer entscheidet je Befund.
export function HealthDialog({ issues, quellenNachId, onLoeschen, onAktivieren, onSchliessen }) {
  const { t } = useTranslation();
  // id der gerade laufenden Aktion (Knopf-Sperre + Spinner-Text); null = keine.
  const [busyId, setBusyId] = useState(null);
  const [fehler, setFehler] = useState(false);

  const laufen = async (id, aktion) => {
    setFehler(false);
    setBusyId(id);
    try {
      await aktion();
      // Erfolg: das Panel laedt Health + Sources neu (schliesst ggf. den Dialog,
      // wenn keine Befunde mehr offen sind).
    } catch {
      setFehler(true);
      setBusyId(null);
    }
  };

  return (
    <DialogShell
      titel={t("verwaltung.blocklist.health.title")}
      onSchliessen={onSchliessen}
      busy={busyId !== null}
    >
      <p className="bd-lead">{t("verwaltung.blocklist.health.lead")}</p>

      <ul className="bd-health">
        {issues.map((issue) => {
          // Die defekte Quelle selbst (fuer origin -> ist sie loeschbar?).
          const quelle = quellenNachId.get(issue.sourceId) ?? null;
          const istBuiltin = quelle ? quelle.origin === "builtin" : false;
          // Ersatzvorschlag aufloesen: Name + ob er bereits als Quelle vorliegt.
          const ersatz = issue.suggestedReplacementId
            ? (quellenNachId.get(issue.suggestedReplacementId) ?? null)
            : null;
          const busy = busyId === issue.sourceId;

          return (
            <li key={issue.sourceId} className="bd-health__item">
              <div className="bd-health__head">
                <span className="bd-health__name">{issue.name}</span>
                <span className="bd-badge bd-badge--group">
                  {t(`verwaltung.blocklist.group.${issue.group}`)}
                </span>
                <span className="bd-badge bd-badge--broken">
                  {t("verwaltung.blocklist.status.broken")}
                </span>
              </div>

              {ersatz ? (
                <p className="bd-health__suggest">
                  {t("verwaltung.blocklist.health.suggest", { name: ersatz.name })}
                </p>
              ) : null}

              {istBuiltin ? (
                <p className="bd-health__builtin">
                  {t("verwaltung.blocklist.health.builtinNote")}
                </p>
              ) : null}

              <div className="bd-health__actions">
                {istBuiltin ? null : (
                  <button
                    type="button"
                    className="bd-button bd-button--danger bd-button--sm"
                    onClick={() => laufen(issue.sourceId, () => onLoeschen(issue.sourceId))}
                    disabled={busy}
                  >
                    {t("verwaltung.blocklist.health.delete")}
                  </button>
                )}
                {ersatz && !ersatz.enabled ? (
                  <button
                    type="button"
                    className="bd-button bd-button--sm"
                    onClick={() =>
                      laufen(issue.sourceId, () => onAktivieren(issue.suggestedReplacementId))
                    }
                    disabled={busy}
                  >
                    {t("verwaltung.blocklist.health.activate")}
                  </button>
                ) : null}
              </div>
            </li>
          );
        })}
      </ul>

      {fehler ? (
        <span className="bd-error">{t("verwaltung.blocklist.health.error")}</span>
      ) : null}

      <div className="bd-actions">
        <button
          type="button"
          className="bd-button bd-button--primary"
          onClick={onSchliessen}
          disabled={busyId !== null}
        >
          {t("verwaltung.blocklist.health.close")}
        </button>
      </div>
    </DialogShell>
  );
}
