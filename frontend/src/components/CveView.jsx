// CVE-Abgleich-Ansicht (CERNIS PRO 2.0)
// Zeigt die aktiven (nicht quittierten) CVE-Befunde des Geräte-Bestands hinter der
// "CVE-Abgleich"-Kachel unter „Untersuchen" (Etappe 2, ADR 0037). Der Abgleich läuft
// gedrosselt im Hintergrund und arbeitet die gefundenen Geräte nach und nach ab;
// Befunde erscheinen also verzögert. Diese Ansicht macht den Bestand + den Stand des
// Abgleichs sichtbar und lädt nach, solange der Abgleich läuft (S86-A5).
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
// Acknowledge (Etappe 3a): „ack" blendet einen Befund aus (verschwindet aus der
// aktiven Liste nach dem Neuladen). Der Rückweg ist jetzt gebaut: ein aufklappbarer
// Bereich „Ausgeblendete Befunde" lädt die quittierten Befunde (GET /api/cve/acknowledged)
// und bietet pro Befund „Wieder einblenden" (action="unack") — der Befund wandert
// zurück in die aktive Liste. Beide Listen werden nach jeder Aktion neu geladen.
//
// i18n: alle Texte über t(); t/i18n NIE in useEffect-Dependencies (Render-Loop).

import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import {
  Check,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  RotateCcw,
  ShieldAlert,
  ShieldOff,
} from "lucide-react";

import {
  acknowledgeCve,
  fetchAcknowledgedCveFindings,
  fetchCveFindings,
  fetchCveStatus,
} from "../api/cve.js";
import { fetchScanDetail, fetchScanHistory } from "../api/scan.js";
import "./CveView.css";

// Erster nicht-leerer (getrimmter) String aus den Argumenten, sonst "". Reine
// Hilfsfunktion für die Namens-Priorität (kein Raten, kein Platzhalter).
function ersterNichtLeer(...werte) {
  for (const w of werte) {
    const s = typeof w === "string" ? w.trim() : "";
    if (s) {
      return s;
    }
  }
  return "";
}

// Löst über die MAC den Anzeige-Namen eines Befunds aus der Scan-Map auf.
// Priorität: label -> hostname -> smbName. Kein Treffer -> "" (Aufrufer fällt
// dann ehrlich auf die IP zurück).
function anzeigeName(befund, nameByMac) {
  const mac = (befund.mac ?? "").toLowerCase();
  const eintrag = mac ? nameByMac.get(mac) : undefined;
  if (!eintrag) {
    return "";
  }
  return ersterNichtLeer(eintrag.label, eintrag.hostname, eintrag.smbName);
}

// Läuft der Abgleich gerade bzw. steht noch etwas aus? Genau EINE Ableitung für den
// Statustext UND das Nachladen — damit beide nie auseinanderlaufen können.
//
// Die Oder-Verknüpfung ist bewusst und deckt die zwei verbotenen Fälle ab:
//   * checking wahr, hostsDue == 0: das letzte Gerät wird gerade behandelt. Ohne den
//     checking-Teil stünde hier schon der Ruhetext, obwohl der Abgleich noch läuft.
//   * checking falsch, hostsDue > 0: es ist noch etwas offen (Abgleich zwischen zwei
//     Geräten oder gedrosselt). Ruhetext wäre gelogen.
// Umgekehrt gilt der Ruhetext nur, wenn BEIDES verneint ist — deshalb kann der
// Lauftext nie "noch 0 von N" zeigen: hostsDue == 0 erreicht den Lauftext ausschliesslich
// zusammen mit checking, und dann ist das Nachladen ohnehin gleich mit einer neuen Zahl da.
// Unbekannter Status (null) zählt als "läuft nicht": kein erfundener Laufzustand.
function istAbgleichAktiv(status) {
  if (status === null) {
    return false;
  }
  return Boolean(status.checking) || (status.hostsDue ?? 0) > 0;
}

// Abstand des Nachladens, solange ein Abgleich läuft (zehn Sekunden, S86-A5/B3).
const NACHLADE_ABSTAND_MS = 10_000;

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
// Port/Service, Beschreibung, Veröffentlichungsdatum, Aktions-Knopf. ``modus``
// steuert den Knopf: "active" -> Quittieren (ack), "hidden" -> Wieder einblenden
// (unack). ``busy`` sperrt den Knopf während die Aktion läuft.
function BefundZeile({ befund, zeigeGeraet, name = "", modus = "active", onAction, busy }) {
  const { t } = useTranslation();
  const published = kurzDatum(befund.published);
  const istHidden = modus === "hidden";

  // Kopf-Grid: ohne Geräte-Spalte (im Host-Block) eine Spalte weniger, damit die
  // Struktur bündig bleibt statt zu zerreißen.
  const kopfClass = zeigeGeraet
    ? "cve-row__head"
    : "cve-row__head cve-row__head--ohne-geraet";

  return (
    <div className={befund.isNew ? "cve-row cve-row--new" : "cve-row"}>
      <div className={kopfClass}>
        {/* Spalte 1: CVE-ID + Link, darunter die Badges. */}
        <div className="cve-row__col cve-row__col--cve">
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
          <div className="cve-row__badges">
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
          </div>
          {published && (
            <span className="cve-row__published">
              {t("untersuchen.cve.publishedLabel", { date: published })}
            </span>
          )}
        </div>

        {/* Spalte 2: Gerät (nur wenn nicht schon im Host-Block-Kopf). */}
        {zeigeGeraet && (
          <div className="cve-row__col cve-row__col--device">
            {name ? (
              <span className="cve-row__hostname">{name}</span>
            ) : (
              <span className="cve-row__hostname">{geraetLabel(befund)}</span>
            )}
            {name && befund.ip && <span className="cve-row__ip">{befund.ip}</span>}
            {befund.mac && <span className="cve-row__mac">{befund.mac}</span>}
          </div>
        )}

        {/* Spalte 3: Port + Service. */}
        <div className="cve-row__col cve-row__col--port">
          <span className="cve-row__port">
            {t("untersuchen.cve.portLabel", { port: befund.port ?? "—" })}
          </span>
          {befund.service && (
            <span className="cve-row__service">{befund.service}</span>
          )}
        </div>

        {/* Spalte 4: Aktion. */}
        <div className="cve-row__col cve-row__col--action">
          <button
            className="cve-row__ack"
            type="button"
            onClick={() => onAction(befund)}
            disabled={busy}
          >
            {istHidden ? (
              <RotateCcw size={13} aria-hidden="true" />
            ) : (
              <Check size={13} aria-hidden="true" />
            )}
            {istHidden
              ? busy
                ? t("untersuchen.cve.reactivating")
                : t("untersuchen.cve.reactivate")
              : busy
                ? t("untersuchen.cve.acking")
                : t("untersuchen.cve.ack")}
          </button>
        </div>
      </div>

      {/* Voll-breiter Fuß: nur noch die Beschreibung, durch eine dünne Linie abgesetzt. */}
      {befund.description && (
        <div className="cve-row__foot">
          <span className="cve-row__desc">{befund.description}</span>
        </div>
      )}
    </div>
  );
}

// „Nach Gerät“: ein aufklappbarer Host-Block. Kopf zeigt ip||mac, Anzahl Befunde
// und die höchste Severity des Hosts.
function HostBlock({ label, ip, name = "", mac, befunde, onAction, busyKeys }) {
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
        {name ? (
          <>
            <span className="cve-host__name">{name}</span>
            {ip && <span className="cve-host__ip">{ip}</span>}
          </>
        ) : (
          <span className="cve-host__name">{label}</span>
        )}
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
              modus="active"
              onAction={onAction}
              busy={busyKeys.has(`${b.mac}|${b.cveId}|${b.port}`)}
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
      proMac.set(key, { mac: key, ip: b.ip ?? null, label: geraetLabel(b), befunde: [] });
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
  const [ausgeblendete, setAusgeblendete] = useState([]); // quittierte Befunde
  // MAC (lowercase) -> { label, hostname, smbName } aus dem letzten Scan. Quelle
  // für den prominenten Geräte-Namen; bleibt leer, wenn kein Scan ladbar ist
  // (dann fällt die Anzeige ehrlich auf die IP zurück).
  const [nameByMac, setNameByMac] = useState(() => new Map());
  const [status, setStatus] = useState(null);
  const [laedt, setLaedt] = useState(true);
  const [fehler, setFehler] = useState(false);
  const [gruppierung, setGruppierung] = useState("severity"); // "severity" | "device"
  const [zeigeAusgeblendete, setZeigeAusgeblendete] = useState(false);
  // (mac|cveId|port)-Keys, die gerade eine ack/unack-Aktion laufen haben (Knopf gesperrt).
  const [beschaeftigt, setBeschaeftigt] = useState(new Set());

  // Aktive Befunde + Status + ausgeblendete Befunde laden. In einem useCallback, damit
  // der Reload nach einer Aktion denselben Pfad nimmt. t/i18n NICHT in den Dependencies.
  //
  // ``still`` = stilles Nachladen (B3): kein Umschalten auf den Ladezustand und —
  // wichtiger — KEIN Zurücksetzen auf null im Fehlerfall. Ein fehlgeschlagener
  // Nachladeversuch darf den Anwender nicht aus der gefüllten Ansicht werfen; die
  // zuletzt gezeigten Daten bleiben einfach stehen und der nächste Tick versucht es
  // erneut. Nur das laute Laden (Öffnen, ack/unack) räumt bei einem Fehler auf.
  const laden = useCallback(async (still = false) => {
    if (!still) {
      setLaedt(true);
      setFehler(false);
    }
    try {
      const [bf, st, hidden] = await Promise.all([
        fetchCveFindings(),
        fetchCveStatus(),
        fetchAcknowledgedCveFindings(),
      ]);
      setBefunde(bf);
      setStatus(st);
      setAusgeblendete(hidden);
      setFehler(false);
    } catch {
      if (!still) {
        setFehler(true);
        setBefunde(null);
        setStatus(null);
        setAusgeblendete([]);
      }
    } finally {
      if (!still) {
        setLaedt(false);
      }
    }
  }, []);

  useEffect(() => {
    laden();
  }, [laden]);

  // Läuft der Abgleich (oder steht noch etwas aus)? Steuert Statustext, Puls und das
  // Nachladen unten — eine einzige Wahrheit für alle drei.
  const aktiv = istAbgleichAktiv(status);

  // Nachladen, AUSSCHLIESSLICH solange ein Abgleich läuft (B3). Ist der Ruhezustand
  // erreicht, läuft ``aktiv`` auf false, der Effekt räumt seinen Zeitgeber ab und legt
  // keinen neuen an — das Nachladen hört von selbst auf.
  //
  // Kein zweiter Zeitgeber: der Effekt hängt NUR an ``aktiv`` (einem Boolean) und an
  // ``laden`` (stabil, leere Deps). Ein Wechsel der Zahlen (hostsDue 7 -> 6) ändert
  // ``aktiv`` nicht, der Effekt läuft also nicht neu und der bestehende Zeitgeber bleibt
  // der einzige. Läuft er doch neu, räumt das Cleanup den alten vorher weg.
  useEffect(() => {
    if (!aktiv) {
      return undefined;
    }
    const id = setInterval(() => {
      // Stilles Nachladen: Fehler werden in ``laden`` geschluckt, der Zeitgeber läuft
      // weiter. Ein Aussetzer beendet das Nachladen also nicht.
      laden(true);
    }, NACHLADE_ABSTAND_MS);
    return () => clearInterval(id);
  }, [aktiv, laden]);

  // Letzten Scan EINMALIG laden (wie die Beobachten-Ansicht: Historie → jüngste
  // scan_id → Detail) und daraus die MAC→Name-Tabelle bauen. Eigener Effekt mit
  // leeren Deps: t/i18n NIE hier rein (sonst Re-Fetch bei jedem Sprachwechsel/Render).
  // Schlägt der Scan-Load fehl, bleibt die Map leer → Anzeige fällt auf „nur IP".
  useEffect(() => {
    let abgebrochen = false;
    (async () => {
      try {
        const liste = await fetchScanHistory(1);
        if (abgebrochen || liste.length === 0) {
          return;
        }
        const detail = await fetchScanDetail(liste[0].id);
        if (abgebrochen) {
          return;
        }
        const map = new Map();
        for (const g of detail.geraete) {
          if (g.mac) {
            map.set(g.mac.toLowerCase(), {
              label: g.label ?? "",
              hostname: g.hostname ?? "",
              smbName: g.smbName ?? "",
            });
          }
        }
        setNameByMac(map);
      } catch {
        // Kein Scan erreichbar / Fehler: Map bleibt leer, CVE-Anzeige unberührt.
      }
    })();
    return () => {
      abgebrochen = true;
    };
  }, []);

  // Eine ack/unack-Aktion auf einen Befund ausführen, dann beide Listen neu laden.
  // "ack" blendet aus (Befund wandert in die ausgeblendete Liste), "unack" reaktiviert
  // (Befund wandert zurück in die aktive Liste). Reiner gemeinsamer Pfad.
  const wendeAktionAn = useCallback(
    async (befund, action) => {
      const key = `${befund.mac}|${befund.cveId}|${befund.port}`;
      setBeschaeftigt((prev) => new Set(prev).add(key));
      try {
        await acknowledgeCve(befund.mac, befund.cveId, befund.port, action);
        await laden();
      } catch {
        // Aktion fehlgeschlagen: Knopf wieder freigeben, Zustand bleibt unverändert.
        setFehler(true);
      } finally {
        setBeschaeftigt((prev) => {
          const next = new Set(prev);
          next.delete(key);
          return next;
        });
      }
    },
    [laden],
  );

  const quittieren = useCallback((b) => wendeAktionAn(b, "ack"), [wendeAktionAn]);
  const reaktivieren = useCallback((b) => wendeAktionAn(b, "unack"), [wendeAktionAn]);

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
          {/* Puls und Text hängen an DERSELBEN Ableitung (istAbgleichAktiv), damit
              nie ein ruhender Punkt neben einem Lauftext steht (oder umgekehrt). */}
          <span className={aktiv ? "cve__pulse" : "cve__pulse cve__pulse--idle"} />
          <span className="cve__status-text">
            {aktiv
              ? t("untersuchen.cve.status.checking", {
                  offen: status.hostsDue ?? 0,
                  gesamt: status.hostsTotal ?? 0,
                })
              : t("untersuchen.cve.status.sleeping")}
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
              name={anzeigeName(b, nameByMac)}
              modus="active"
              onAction={quittieren}
              busy={beschaeftigt.has(`${b.mac}|${b.cveId}|${b.port}`)}
            />
          ))}
        </div>
      ) : (
        <div className="cve__hosts">
          {gruppiereNachGeraet(befunde).map((g) => (
            <HostBlock
              key={g.mac}
              label={g.label}
              ip={g.ip}
              name={anzeigeName(g.befunde[0], nameByMac)}
              mac={g.mac}
              befunde={g.befunde}
              onAction={quittieren}
              busyKeys={beschaeftigt}
            />
          ))}
        </div>
      )}

      {/* Ausgeblendete (quittierte) Befunde: dezenter Aufklapp-Bereich. Der Knopf
          zeigt die Anzahl; ist nichts ausgeblendet, ist er ausgegraut und deaktiviert
          (ehrlicher Zustand statt verstecktem Element). */}
      <div className="cve__hidden">
        <button
          type="button"
          className="cve__hidden-toggle"
          onClick={() => setZeigeAusgeblendete((v) => !v)}
          aria-expanded={zeigeAusgeblendete}
          disabled={ausgeblendete.length === 0}
        >
          {ausgeblendete.length === 0 ? (
            <ShieldOff size={13} aria-hidden="true" />
          ) : zeigeAusgeblendete ? (
            <ChevronDown size={14} aria-hidden="true" />
          ) : (
            <ChevronRight size={14} aria-hidden="true" />
          )}
          {ausgeblendete.length === 0
            ? t("untersuchen.cve.noHidden")
            : zeigeAusgeblendete
              ? t("untersuchen.cve.hideHidden")
              : t("untersuchen.cve.hiddenHeading", { count: ausgeblendete.length })}
        </button>

        {zeigeAusgeblendete && ausgeblendete.length > 0 && (
          <div className="cve__hidden-body">
            {sortiereNachSchwere(ausgeblendete).map((b) => (
              <BefundZeile
                key={`${b.mac}-${b.cveId}-${b.port}`}
                befund={b}
                zeigeGeraet
                name={anzeigeName(b, nameByMac)}
                modus="hidden"
                onAction={reaktivieren}
                busy={beschaeftigt.has(`${b.mac}|${b.cveId}|${b.port}`)}
              />
            ))}
          </div>
        )}
      </div>

      <div className="cve__footnote">
        <ShieldOff size={12} aria-hidden="true" />
        {t("untersuchen.cve.ackOnlyNote")}
      </div>
    </div>
  );
}
