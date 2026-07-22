// DNS-Vertrauens-Panel (CERNIS PRO 2.0, E6 + D4 E4, Variante H)
//
// Die Funktion hinter der Verwaltungs-Kachel „DNS-Server & Vertrauen" (ADR 0043):
// DREI Bereiche statt Kategorie-Gruppen:
//   1. „Erwartet — geordnet":  alle trusted-Server, sortiert nach expectedRank
//      (0 = unrangiert ans Ende), mit Rang-Badge + Hoch/Runter/Entfernen.
//   2. „Erkannt, noch nicht erwartet": alle neutral-Server, mit „Als erwartet".
//   3. „Abgelehnt": alle rejected-Server, eingeklappt (nur wenn vorhanden).
// Als Entscheidungshilfe zeigt jede Zeile deskriptive Plausibilitaets-Indizien
// (Bestand, Hersteller, offene Ports); ein Bedrohungslisten-Treffer macht das
// Erwarten zur warnenden Aktion. Reines Frontend gegen api/dnsTrust.js.
// Markup-/CSS-Konventionen wie BlocklistPanel (CSS-Tokens, keine festen Farben).
//
// Daten laden in einem useEffect ueber einen gemeinsamen useCallback-Pfad (laden0);
// Reload nach jeder Entscheidung/Rang-Aktion (kein lokales Raten). t/i18n NIE in
// useEffect/useMemo-Dependencies (Render-Loop), Muster wie BlocklistPanel.jsx.
//
// Produkt-These (Ton): zeigen + einordnen, nicht urteilen. CERNIS ist passiv. Die
// Reihenfolge ist eine ERWARTUNG des Nutzers, keine Messung.

import { ChevronDown, ChevronUp, X } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import {
  fetchDnsTrustServers,
  setDnsTrustDecision,
  setDnsTrustRank,
} from "../api/dnsTrust.js";
import { CODES, mitCode } from "../lib/fehlercodes.js";
import "./DnsTrustPanel.css";

// Ein Kategorie-Label (Wire-Wert -> i18n-Schluessel). Dient nur der Anzeige der
// rohen Kategorie je Zeile.
function kategorieSchluessel(category) {
  return `verwaltung.dnsTrust.category.${category}`;
}

// Deskriptive Plausibilitaets-Indizien einer Zeile (best-effort, nur vorhandene).
// Rein beschreibend, KEIN Urteil. Fehlt der ganze Block oder ist der Server nicht
// im Bestand, steht dort ehrlich „nicht im Bestand".
function PlausibilitaetsIndizien({ plausibility }) {
  const { t } = useTranslation();

  // Kein Block ODER nicht im Bestand -> ein ehrlicher „nicht im Bestand"-Hinweis.
  if (!plausibility || !plausibility.inInventory) {
    return (
      <span className="dt-hint dt-hint--absent">
        {t("verwaltung.dnsTrust.plausibility.notInInventory")}
      </span>
    );
  }

  const teile = [];
  if (plausibility.firstSeenDays !== null && plausibility.firstSeenDays !== undefined) {
    teile.push(
      <span key="days" className="dt-hint">
        {t("verwaltung.dnsTrust.plausibility.inInventorySince", {
          days: plausibility.firstSeenDays,
        })}
      </span>,
    );
  }
  if (plausibility.vendor) {
    teile.push(
      <span key="vendor" className="dt-hint">
        {t("verwaltung.dnsTrust.plausibility.vendor", { vendor: plausibility.vendor })}
      </span>,
    );
  }
  if (plausibility.openPorts && plausibility.openPorts.length > 0) {
    teile.push(
      <span key="ports" className="dt-hint">
        {t("verwaltung.dnsTrust.plausibility.openPorts", {
          ports: plausibility.openPorts.join(", "),
        })}
      </span>,
    );
  }

  // Im Bestand, aber ohne weitere Details: dann wenigstens das ehrlich sagen.
  if (teile.length === 0) {
    return (
      <span className="dt-hint">
        {t("verwaltung.dnsTrust.plausibility.inInventoryPlain")}
      </span>
    );
  }

  return <span className="dt-hints">{teile}</span>;
}

// Gemeinsamer Identitaets-Block einer Zeile: Name/IP, Kategorie-Marke (+ ggf.
// Platzhalter-Marke) und die Plausibilitaets-Indizien. Von allen drei Bereichen
// genutzt; die Aktionen unterscheiden sich je Bereich (rechts daneben).
function ZeilenIdent({ server, mitIndizien = true }) {
  const { t } = useTranslation();
  const anzeigeName = server.displayName || server.ip;
  const nameIstIp = !server.displayName;

  return (
    <div className="dt-row__ident">
      <span className="dt-row__name">{anzeigeName}</span>
      {/* Rohe IP dezent -- entfaellt, wenn der Name ohnehin die IP ist. */}
      {nameIstIp ? null : <span className="dt-row__ip">{server.ip}</span>}
      <span className="dt-row__meta">
        <span className="dt-badge">{t(kategorieSchluessel(server.category))}</span>
        {/* Informative Marke NEBEN der Kategorie: funktionsloser Windows-
            Vorgabe-Platzhalter. Kategorie bleibt unveraendert. */}
        {server.isPlatformPlaceholder ? (
          <span className="dt-badge dt-badge--placeholder">
            {t("verwaltung.dnsTrust.placeholder.badge")}
          </span>
        ) : null}
      </span>
      {mitIndizien ? <PlausibilitaetsIndizien plausibility={server.plausibility} /> : null}
    </div>
  );
}

// Bereich 1: eine „Erwartet"-Zeile mit Rang-Badge (laufende Position 1..N) und den
// Rang-/Entfernen-Aktionen. position ist 1-basiert; Hoch/Runter setzen den Rang
// auf position∓1 (das Backend haelt die Sequenz kompakt, die View laedt neu).
function ErwartetZeile({ server, position, istErste, istLetzte, busy, onRang, onEntscheidung }) {
  const { t } = useTranslation();

  return (
    <div className="dt-row">
      <span className="dt-rank" aria-hidden="true">
        {position}
      </span>
      <ZeilenIdent server={server} />
      <div className="dt-row__actions">
        <button
          type="button"
          className="dt-rank-btn"
          onClick={() => onRang(server.ip, position - 1)}
          disabled={busy || istErste}
          aria-label={t("verwaltung.dnsTrust.actions.rankUp")}
          title={t("verwaltung.dnsTrust.actions.rankUp")}
        >
          <ChevronUp size={15} aria-hidden="true" />
        </button>
        <button
          type="button"
          className="dt-rank-btn"
          onClick={() => onRang(server.ip, position + 1)}
          disabled={busy || istLetzte}
          aria-label={t("verwaltung.dnsTrust.actions.rankDown")}
          title={t("verwaltung.dnsTrust.actions.rankDown")}
        >
          <ChevronDown size={15} aria-hidden="true" />
        </button>
        <button
          type="button"
          className="dt-rank-btn dt-rank-btn--remove"
          onClick={() => onEntscheidung(server.ip, "reset")}
          disabled={busy}
          aria-label={t("verwaltung.dnsTrust.actions.removeExpected")}
          title={t("verwaltung.dnsTrust.actions.removeExpected")}
        >
          <X size={15} aria-hidden="true" />
        </button>
      </div>
    </div>
  );
}

// Bereich 2: eine „Erkannt"-Zeile mit „Als erwartet" + dezentem „Ablehnen"
// (fuehrt in Bereich 3). Bei threat_listed ist NUR der Vertrauen-Knopf die
// warnende Aktion (sev-high-Optik), Ablehnen bleibt normal verfuegbar; beim
// funktionslosen Platzhalter stehen KEINE Knoepfe, nur der dezente Hinweis.
function ErkanntZeile({ server, busy, onEntscheidung }) {
  const { t } = useTranslation();
  const istThreat = server.category === "threat_listed";

  return (
    <div className="dt-row">
      <ZeilenIdent server={server} />
      <div className="dt-row__actions">
        {server.isPlatformPlaceholder ? (
          <span className="dt-actions-note">
            {t("verwaltung.dnsTrust.placeholder.noDecisionNeeded")}
          </span>
        ) : (
          <>
            <button
              type="button"
              className={`dt-action ${istThreat ? "dt-action--warn" : "dt-action--trust"}`}
              onClick={() => onEntscheidung(server.ip, "trust")}
              disabled={busy}
            >
              {istThreat
                ? t("verwaltung.dnsTrust.actions.trustDespiteThreat")
                : t("verwaltung.dnsTrust.actions.markExpected")}
            </button>
            <button
              type="button"
              className="dt-action dt-action--reject"
              onClick={() => onEntscheidung(server.ip, "reject")}
              disabled={busy}
            >
              {t("verwaltung.dnsTrust.actions.reject")}
            </button>
          </>
        )}
      </div>
    </div>
  );
}

// Bereich 3: eine „Abgelehnt"-Zeile (ohne Indizien, nur Ident + Zuruecksetzen).
function AbgelehntZeile({ server, busy, onEntscheidung }) {
  const { t } = useTranslation();

  return (
    <div className="dt-row">
      <ZeilenIdent server={server} mitIndizien={false} />
      <div className="dt-row__actions">
        <button
          type="button"
          className="dt-action dt-action--reset"
          onClick={() => onEntscheidung(server.ip, "reset")}
          disabled={busy}
        >
          {t("verwaltung.dnsTrust.actions.reset")}
        </button>
      </div>
    </div>
  );
}

export default function DnsTrustPanel() {
  const { t } = useTranslation();

  const [servers, setServers] = useState([]);
  const [laden, setLaden] = useState(true);
  const [fehler, setFehler] = useState(null);
  // IPs mit gerade laufender Entscheidung/Rang-Aktion (Knoepfe der Zeile gesperrt).
  const [busy, setBusy] = useState(new Set());
  // Bereich 3 („Abgelehnt") ist per Default eingeklappt.
  const [abgelehntOffen, setAbgelehntOffen] = useState(false);

  // Server laden. Gemeinsamer Pfad fuer Mount und Reload nach einer Aktion.
  // t/i18n NICHT in den Dependencies.
  const laden0 = useCallback(async () => {
    setLaden(true);
    setFehler(null);
    try {
      const liste = await fetchDnsTrustServers();
      setServers(liste);
    } catch (ursache) {
      console.error("DNS-Vertrauen laden fehlgeschlagen:", ursache);
      setFehler("ladeFehler");
    } finally {
      setLaden(false);
    }
  }, []);

  useEffect(() => {
    laden0();
  }, [laden0]);

  // Eine Entscheidung senden, danach die Liste neu laden (kein lokales Raten des
  // Folge-Zustands). Die betroffene IP wird waehrend des Aufrufs gesperrt.
  const handleEntscheidung = useCallback(
    async (ip, decision) => {
      setFehler(null);
      setBusy((prev) => new Set(prev).add(ip));
      try {
        await setDnsTrustDecision(ip, decision);
        await laden0();
      } catch (ursache) {
        console.error("DNS-Vertrauens-Entscheidung fehlgeschlagen:", ursache);
        setFehler("aktionFehler");
      } finally {
        setBusy((prev) => {
          const next = new Set(prev);
          next.delete(ip);
          return next;
        });
      }
    },
    [laden0],
  );

  // Eine Rang-Aktion senden (analog handleEntscheidung): busy-Sperre der Zeile,
  // setDnsTrustRank, danach laden0 (das Backend haelt die 1..N-Sequenz kompakt).
  const handleRang = useCallback(
    async (ip, position) => {
      setFehler(null);
      setBusy((prev) => new Set(prev).add(ip));
      try {
        await setDnsTrustRank(ip, position);
        await laden0();
      } catch (ursache) {
        console.error("DNS-Rang setzen fehlgeschlagen:", ursache);
        setFehler("aktionFehler");
      } finally {
        setBusy((prev) => {
          const next = new Set(prev);
          next.delete(ip);
          return next;
        });
      }
    },
    [laden0],
  );

  // Die drei H-Bereiche aus servers ableiten (Dependencies NUR [servers]):
  //   erwartet:  trusted, sortiert nach expectedRank aufsteigend (0/unrangiert ans
  //              ENDE), bei Gleichstand nach firstSeen aufsteigend.
  //   erkannt:   neutral (jede Kategorie).
  //   abgelehnt: rejected.
  const bereiche = useMemo(() => {
    const erwartet = servers
      .filter((server) => server.trustState === "trusted")
      .sort((a, b) => {
        const rangA = a.expectedRank > 0 ? a.expectedRank : Number.POSITIVE_INFINITY;
        const rangB = b.expectedRank > 0 ? b.expectedRank : Number.POSITIVE_INFINITY;
        if (rangA !== rangB) {
          return rangA - rangB;
        }
        return (a.firstSeen ?? 0) - (b.firstSeen ?? 0);
      });
    const erkannt = servers.filter((server) => server.trustState === "neutral");
    const abgelehnt = servers.filter((server) => server.trustState === "rejected");
    return { erwartet, erkannt, abgelehnt };
  }, [servers]);

  // Gibt es mindestens einen funktionslosen Plattform-Platzhalter? Nur dann erscheint
  // der einmalige Erklaertext unterhalb der Liste (nicht pro Zeile wiederholt).
  const hatPlatzhalter = useMemo(
    () => servers.some((server) => server.isPlatformPlaceholder),
    [servers],
  );

  if (laden && servers.length === 0) {
    return (
      <div className="dt-panel">
        <p className="dt-loading">{t("verwaltung.dnsTrust.loading")}</p>
      </div>
    );
  }

  return (
    <div className="dt-panel">
      {/* Ruhiger Erklaer-Kopf: was diese Rubrik zeigt und dass CERNIS passiv ist. */}
      <section className="dt-intro">
        <p className="dt-intro__desc">{t("verwaltung.dnsTrust.intro")}</p>
        <p className="dt-intro__redline">{t("verwaltung.dnsTrust.redLine")}</p>
      </section>

      {/* Dezenter Lade-/Aktions-Fehlerhinweis. */}
      {fehler ? (
        <p className="dt-error" role="alert">
          {/* Nur der Aktions-Fehler traegt einen Schema-Code (E-503); der
              Lade-Fehler bleibt ohne Code. */}
          {fehler === "aktionFehler"
            ? mitCode(t(`verwaltung.dnsTrust.${fehler}`), CODES.E_503)
            : t(`verwaltung.dnsTrust.${fehler}`)}
        </p>
      ) : null}

      {/* Ehrlicher Leerzustand, wenn (noch) keine Server erkannt wurden. */}
      {servers.length === 0 ? (
        <p className="dt-empty">{t("verwaltung.dnsTrust.empty")}</p>
      ) : (
        <>
          {/* Bereich 1: Erwartet — geordnet (alle trusted, Rang-Reihenfolge). */}
          <section className="dt-group" data-ton="ok">
            <h3 className="dt-group__title">
              {t("verwaltung.dnsTrust.groups.expected.title")}
            </h3>
            <p className="dt-group__lead">
              {t("verwaltung.dnsTrust.groups.expected.lead")}
            </p>
            <div className="dt-group__rows">
              {bereiche.erwartet.map((server, index) => (
                <ErwartetZeile
                  key={server.ip}
                  server={server}
                  position={index + 1}
                  istErste={index === 0}
                  istLetzte={index === bereiche.erwartet.length - 1}
                  busy={busy.has(server.ip)}
                  onRang={handleRang}
                  onEntscheidung={handleEntscheidung}
                />
              ))}
              {bereiche.erwartet.length === 0 ? (
                <p className="dt-group__empty">
                  {t("verwaltung.dnsTrust.groups.expected.empty")}
                </p>
              ) : null}
            </div>
          </section>

          {/* Bereich 2: Erkannt, noch nicht erwartet (alle neutral). */}
          {bereiche.erkannt.length > 0 ? (
            <section className="dt-group" data-ton="neutral">
              <h3 className="dt-group__title">
                {t("verwaltung.dnsTrust.groups.detected.title")}
              </h3>
              <p className="dt-group__lead">
                {t("verwaltung.dnsTrust.groups.detected.lead")}
              </p>
              <div className="dt-group__rows">
                {bereiche.erkannt.map((server) => (
                  <ErkanntZeile
                    key={server.ip}
                    server={server}
                    busy={busy.has(server.ip)}
                    onEntscheidung={handleEntscheidung}
                  />
                ))}
              </div>
            </section>
          ) : null}

          {/* Bereich 3: Abgelehnt — nur wenn vorhanden, eingeklappt per Default. */}
          {bereiche.abgelehnt.length > 0 ? (
            <section className="dt-group dt-collapsible" data-ton="danger">
              <button
                type="button"
                className="dt-collapsible__head"
                onClick={() => setAbgelehntOffen((offen) => !offen)}
                aria-expanded={abgelehntOffen}
              >
                <span className="dt-group__title">
                  {t("verwaltung.dnsTrust.groups.rejected.title")}{" "}
                  {t("verwaltung.dnsTrust.rejected.count", {
                    count: bereiche.abgelehnt.length,
                  })}
                </span>
                <span className="dt-collapsible__toggle">
                  {abgelehntOffen
                    ? t("verwaltung.dnsTrust.rejected.toggleHide")
                    : t("verwaltung.dnsTrust.rejected.toggleShow")}
                </span>
              </button>
              {abgelehntOffen ? (
                <>
                  <p className="dt-group__lead">
                    {t("verwaltung.dnsTrust.groups.rejected.lead")}
                  </p>
                  <div className="dt-group__rows">
                    {bereiche.abgelehnt.map((server) => (
                      <AbgelehntZeile
                        key={server.ip}
                        server={server}
                        busy={busy.has(server.ip)}
                        onEntscheidung={handleEntscheidung}
                      />
                    ))}
                  </div>
                </>
              ) : null}
            </section>
          ) : null}

          {/* EINMALIGER Erklaertext unterhalb der Liste -- nur wenn mindestens ein
              funktionsloser Plattform-Platzhalter vorhanden ist (nicht pro Zeile). */}
          {hatPlatzhalter ? (
            <p className="dt-placeholder-note">
              {t("verwaltung.dnsTrust.placeholder.note")}
            </p>
          ) : null}
        </>
      )}
    </div>
  );
}
