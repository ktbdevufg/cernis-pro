// CVE-Abgleich-Ansicht (CERNIS PRO 2.0)
// Zeigt die aktiven (nicht quittierten) CVE-Befunde des Geräte-Bestands hinter der
// "CVE-Abgleich"-Kachel unter „Untersuchen" (Etappe 2, ADR 0037). Ein gedrosselter
// Hintergrund-Worker prüft die gefundenen Geräte nach und nach; Befunde erscheinen
// also verzögert. Diese Ansicht macht den Bestand + den Worker-Status sichtbar.
//
// Zwei umschaltbare Gruppierungen (Default „nach Schwere"):
//   * „Nach Schwere": flache, gerätübergreifende Liste, severity-sortiert
//     (CRITICAL → HIGH → MEDIUM → LOW → UNKNOWN; innerhalb nach cvssScore absteigend).
//   * „Nach Gerät": pro Host (ip||mac) gruppiert, aufklappbar, Host-Kopf mit Anzahl
//     + höchster Severity.
//
// Zwei farbliche Belange bewusst getrennt (eigene CSS-Tokens):
//   * Severity (wie gefährlich) → --cve-crit / --sev-high|med|low / unknown-neutral.
//   * isNew (neu seit 24h)      → türkises „NEU"-Badge + Rand (--cve-new-*).
//
// Geräte-Anzeige = ip||mac: die CVE-Wire-Form (backend/api/cve.py) liefert KEINEN
// Hostnamen. Statt eine zweite Geräte-Naht zu öffnen, zeigen wir den ehrlich
// vorhandenen Wert (kein erfundener Hostname).
//
// Acknowledge: nur „ack" (quittieren) — der Befund verschwindet nach dem Neuladen
// aus der Liste. „unack/Reaktivieren" ist hier NICHT abbildbar: es gibt keinen
// Endpunkt, der quittierte Befunde LISTET (das Backend KANN unack, aber es fehlt
// der Lesepfad). Als Nachzügler dokumentiert (siehe ADR 0037 / Auftrag).
//
// i18n: alle Texte über t(); t/i18n NIE in useEffect-Dependencies (Render-Loop).

import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Check, ExternalLink, ShieldAlert, ShieldOff } from "lucide-react";

import { acknowledgeCve, fetchCveFindings, fetchCveStatus } from "../api/cve.js";
import "./CveView.css";

// Severity-Rang für die Sortierung. Höher = gefährlicher = weiter oben. Ein
// unbekannter/leerer Wert landet als UNKNOWN ganz unten (kein Raten).
const SEVERITY_RANG = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };

// Normalisiert die Backend-Severity auf einen der bekannten Schlüssel. Alles
// Unbekannte/Fehlende -> "UNKNOWN" (ehrlich, statt zu erfinden).
function severityKey(severity) {
  const k = (severity ?? "").toUpperCase();
  return k in SEVERITY_RANG ? k : "UNKNOWN";
}

// Ein roher ISO/epoch-Wert -> kurzes lokales Datum (nur Datum, keine Uhrzeit). Bei
// fehlendem/unparsbarem Wert -> null (Aufrufer zeigt dann „—“). Kein erfundenes Datum.
function kurzDatum(roh) {
  if (!roh) {
    return null;
  }
  const d = new Date(roh);
  return Number.isNaN(d.getTime()) ? null : d.toLocaleDateString();
}

// Geräte-Label eines Befunds: ip||mac (die Wire-Form kennt keinen Hostnamen).
function geraetLabel(befund) {
  return befund.ip || befund.mac || "—";
}

// Severity-Badge: farbige Kennzeichnung über die CVE/sev-Tokens (per data-Attribut
// im CSS gewählt). Zeigt den lokalisierten Severity-Namen.
function SeverityBadge({ severity }) {
  const { t } = useTranslation();
  const key = severityKey(severity);
  return (
    <span className="cve-badge cve-badge--sev" data-sev={key}>
      {t(`untersuchen.cve.severity.${key.toLowerCase()}`)}
    </span>
  );
}

// Eine Befund-Zeile: CVE-ID (verlinkt), Severity-Badge, „NEU“-Badge, CVSS, Gerät,
// Port/Service, Beschreibung, Veröffentlichungsdatum, Quittieren-Knopf.
function BefundZeile({ befund, zeigeGeraet, onAck, quittiert }) {
  const { t } = useTranslation();
  const published = kurzDatum(befund.published);

  return (
    <div className={befund.isNew ? "cve-row cve-row--new" : "cve-row"}>
      <div className="cve-row__head">
        {befund.url ? (
          <a
            className="cve-row__id"
            href={befund.url}
            target="_blank"
            rel="noopener noreferrer"
          >
            {befund.cveId ?? "—"}
            <ExternalLink size={12} aria-hidden="true" />
          </a>
        ) : (
          <span className="cve-row__id">{befund.cveId ?? "—"}</span>
        )}
        <SeverityBadge severity={befund.severity} />
        {befund.isNew && (
          <span className="cve-badge cve-badge--new">
            {t("untersuchen.cve.newBadge")}
          </span>
        )}
        {befund.cvssScore !== null && (
          <span className="cve-row__cvss" title={t("untersuchen.cve.cvssLabel")}>
            {Number(befund.cvssScore).toFixed(1)}
          </span>
        )}
        <span className="cve-row__spacer" />
        <button
          className="cve-row__ack"
          type="button"
          onClick={() => onAck(befund)}
          disabled={quittiert}
        >
          <Check size={13} aria-hidden="true" />
          {quittiert
            ? t("untersuchen.cve.acking")
            : t("untersuchen.cve.ack")}
        </button>
      </div>

      <div className="cve-row__meta">
        {zeigeGeraet && (
          <span className="cve-row__device">
            {geraetLabel(befund)}
            <span className="cve-row__mac">{befund.mac}</span>
          </span>
        )}
        <span className="cve-row__port">
          {t("untersuchen.cve.portLabel", { port: befund.port ?? "—" })}
          {befund.service ? ` · ${befund.service}` : ""}
        </span>
        {published && (
          <span className="cve-row__published">
            {t("untersuchen.cve.publishedLabel", { date: published })}
          </span>
        )}
      </div>

      {befund.description && (
        <div className="cve-row__desc">{befund.description}</div>
      )}
    </div>
  );
}

// „Nach Gerät“: ein aufklappbarer Host-Block. Kopf zeigt ip||mac, Anzahl Befunde
// und die höchste Severity des Hosts.
function HostBlock({ label, mac, befunde, onAck, quittierte }) {
  const { t } = useTranslation();
  const [offen, setOffen] = useState(true);
  // Höchste Severity im Block (für die Kopf-Kennzeichnung).
  const hoechste = befunde.reduce((max, b) => {
    const r = SEVERITY_RANG[severityKey(b.severity)];
    return r > max.rang ? { rang: r, key: severityKey(b.severity) } : max;
  }, { rang: -1, key: "UNKNOWN" });

  return (
    <div className="cve-host">
      <button
        className="cve-host__head"
        type="button"
        onClick={() => setOffen((v) => !v)}
        aria-expanded={offen}
      >
        <span className="cve-host__name">{label}</span>
        <span className="cve-host__mac">{mac}</span>
        <span className="cve-host__spacer" />
        <span className="cve-badge cve-badge--sev" data-sev={hoechste.key}>
          {t(`untersuchen.cve.severity.${hoechste.key.toLowerCase()}`)}
        </span>
        <span className="cve-host__count">
          {t("untersuchen.cve.findingCount", { count: befunde.length })}
        </span>
      </button>
      {offen && (
        <div className="cve-host__body">
          {befunde.map((b) => (
            <BefundZeile
              key={`${b.cveId}-${b.port}`}
              befund={b}
              zeigeGeraet={false}
              onAck={onAck}
              quittiert={quittierte.has(`${b.mac}|${b.cveId}|${b.port}`)}
            />
          ))}
        </div>
      )}
    </div>
  );
}

// Sortiert Befunde nach Severity-Rang absteigend, innerhalb nach cvssScore
// absteigend (null-Score zählt als 0 → ans Block-Ende). Reine Funktion.
function sortiereNachSchwere(befunde) {
  return [...befunde].sort((a, b) => {
    const ra = SEVERITY_RANG[severityKey(a.severity)];
    const rb = SEVERITY_RANG[severityKey(b.severity)];
    if (rb !== ra) {
      return rb - ra;
    }
    return (b.cvssScore ?? 0) - (a.cvssScore ?? 0);
  });
}

// Gruppiert Befunde je Host (mac). Liefert eine Liste { mac, label, befunde },
// sortiert nach der höchsten Severity des Hosts absteigend.
function gruppiereNachGeraet(befunde) {
  const proMac = new Map();
  for (const b of befunde) {
    const key = b.mac ?? "—";
    if (!proMac.has(key)) {
      proMac.set(key, { mac: key, label: geraetLabel(b), befunde: [] });
    }
    proMac.get(key).befunde.push(b);
  }
  const gruppen = [...proMac.values()];
  for (const g of gruppen) {
    g.befunde = sortiereNachSchwere(g.befunde);
  }
  // Hosts nach ihrer höchsten Severity absteigend.
  gruppen.sort((a, b) => {
    const ra = SEVERITY_RANG[severityKey(a.befunde[0]?.severity)];
    const rb = SEVERITY_RANG[severityKey(b.befunde[0]?.severity)];
    return rb - ra;
  });
  return gruppen;
}

export default function CveView() {
  const { t } = useTranslation();
  const [befunde, setBefunde] = useState(null); // null = noch nicht geladen
  const [status, setStatus] = useState(null);
  const [laedt, setLaedt] = useState(true);
  const [fehler, setFehler] = useState(false);
  const [gruppierung, setGruppierung] = useState("severity"); // "severity" | "device"
  // (mac|cveId|port)-Keys, die gerade quittiert werden (Knopf gesperrt).
  const [quittierte, setQuittierte] = useState(new Set());

  // Befunde + Status laden. In einem useCallback, damit der Reload nach einem
  // ack denselben Pfad nimmt. t/i18n bewusst NICHT in den Dependencies.
  const laden = useCallback(async () => {
    setLaedt(true);
    setFehler(false);
    try {
      const [bf, st] = await Promise.all([fetchCveFindings(), fetchCveStatus()]);
      setBefunde(bf);
      setStatus(st);
    } catch {
      setFehler(true);
      setBefunde(null);
      setStatus(null);
    } finally {
      setLaedt(false);
    }
  }, []);

  useEffect(() => {
    laden();
  }, [laden]);

  // Einen Befund quittieren (action="ack"). Nach Erfolg die Liste neu laden — der
  // Befund verschwindet dann (das Backend liefert nur noch aktive Befunde).
  const quittieren = useCallback(
    async (befund) => {
      const key = `${befund.mac}|${befund.cveId}|${befund.port}`;
      setQuittierte((prev) => new Set(prev).add(key));
      try {
        await acknowledgeCve(befund.mac, befund.cveId, befund.port, "ack");
        await laden();
      } catch {
        // Quittieren fehlgeschlagen: Knopf wieder freigeben, Befund bleibt sichtbar.
        setFehler(true);
      } finally {
        setQuittierte((prev) => {
          const next = new Set(prev);
          next.delete(key);
          return next;
        });
      }
    },
    [laden],
  );

  // ── Render ──────────────────────────────────────────────────────────────

  if (laedt && befunde === null) {
    return <div className="cve__state">{t("untersuchen.cve.loading")}</div>;
  }

  if (fehler && befunde === null) {
    return <div className="cve__state cve__state--error">{t("untersuchen.cve.error")}</div>;
  }

  const hatBefunde = Array.isArray(befunde) && befunde.length > 0;
  const keinScan = status !== null && status.hostsTotal === 0;

  return (
    <div className="cve">
      {status !== null && (
        <div className="cve__status" role="status">
          <span className={status.sleeping ? "cve__pulse cve__pulse--idle" : "cve__pulse"} />
          <span className="cve__status-text">
            {status.sleeping
              ? t("untersuchen.cve.status.sleeping")
              : t("untersuchen.cve.status.checking", { due: status.hostsDue ?? 0 })}
          </span>
          <span className="cve__status-sep">·</span>
          <span className="cve__status-text">
            {t("untersuchen.cve.status.hosts", {
              checked: status.hostsChecked ?? 0,
              total: status.hostsTotal ?? 0,
            })}
          </span>
          <span className="cve__status-sep">·</span>
          <span className="cve__status-text">
            {t("untersuchen.cve.status.active", { count: status.findingsActive ?? 0 })}
          </span>
        </div>
      )}

      {hatBefunde && (
        <div className="cve__toolbar">
          <div className="cve__seg" role="group" aria-label={t("untersuchen.cve.groupLabel")}>
            <button
              type="button"
              className={gruppierung === "severity" ? "cve__seg-btn cve__seg-btn--on" : "cve__seg-btn"}
              onClick={() => setGruppierung("severity")}
              aria-pressed={gruppierung === "severity"}
            >
              {t("untersuchen.cve.bySeverity")}
            </button>
            <button
              type="button"
              className={gruppierung === "device" ? "cve__seg-btn cve__seg-btn--on" : "cve__seg-btn"}
              onClick={() => setGruppierung("device")}
              aria-pressed={gruppierung === "device"}
            >
              {t("untersuchen.cve.byDevice")}
            </button>
          </div>
        </div>
      )}

      {!hatBefunde ? (
        <div className="cve__empty">
          <ShieldAlert size={28} aria-hidden="true" />
          <span>
            {keinScan
              ? t("untersuchen.cve.emptyNoScan")
              : t("untersuchen.cve.emptyNoFindings")}
          </span>
          <span className="cve__empty-hint">{t("untersuchen.cve.emptyHint")}</span>
        </div>
      ) : gruppierung === "severity" ? (
        <div className="cve__list">
          {sortiereNachSchwere(befunde).map((b) => (
            <BefundZeile
              key={`${b.mac}-${b.cveId}-${b.port}`}
              befund={b}
              zeigeGeraet
              onAck={quittieren}
              quittiert={quittierte.has(`${b.mac}|${b.cveId}|${b.port}`)}
            />
          ))}
        </div>
      ) : (
        <div className="cve__hosts">
          {gruppiereNachGeraet(befunde).map((g) => (
            <HostBlock
              key={g.mac}
              label={g.label}
              mac={g.mac}
              befunde={g.befunde}
              onAck={quittieren}
              quittierte={quittierte}
            />
          ))}
        </div>
      )}

      <div className="cve__footnote">
        <ShieldOff size={12} aria-hidden="true" />
        {t("untersuchen.cve.ackOnlyNote")}
      </div>
    </div>
  );
}
