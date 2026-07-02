// DNS-Vertrauens-Panel (CERNIS PRO 2.0, E6)
//
// Die Funktion hinter der Verwaltungs-Kachel „DNS-Server & Vertrauen" (ADR 0043):
// listet die erkannten DNS-Server nach Kategorie gruppiert auf und laesst je Server
// vertrauen / ablehnen / zuruecksetzen. Als Entscheidungshilfe zeigt jede Zeile
// deskriptive Plausibilitaets-Indizien (Bestand, Hersteller, offene Ports); ein
// Bedrohungslisten-Treffer bekommt einen deutlichen Warnbefund. Reines Frontend
// gegen die E5-api (api/dnsTrust.js). Markup-/CSS-Konventionen wie BlocklistPanel
// (CSS-Tokens, keine festen Farben; dt-* statt bl-*).
//
// Daten laden in einem useEffect ueber einen gemeinsamen useCallback-Pfad (laden0);
// Reload nach jeder Entscheidung. t/i18n NIE in useEffect/useMemo-Dependencies
// (Render-Loop), Muster wie BlocklistPanel.jsx.
//
// Produkt-These (Ton): zeigen + einordnen, nicht urteilen. CERNIS ist passiv. Die
// Indizien sind rein deskriptiv, die Entscheidung trifft der muendige Nutzer.

import { useCallback, useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";

import { fetchDnsTrustServers, setDnsTrustDecision } from "../api/dnsTrust.js";
import "./DnsTrustPanel.css";

// Die Gruppen in ihrer verbindlichen Anzeige-Reihenfolge. Jeder Server landet in
// GENAU einer Gruppe -- die Zuordnung (siehe gruppeFuer) prueft in exakt dieser
// Reihenfolge, damit bei Konflikt die spezifischere/warnende Gruppe gewinnt:
//   threat vor rejected vor trusted vor den neutralen Kategorien.
// „warn"/„danger" faerben die Gruppen-Ueberschrift (Bedrohung/Ablehnung).
const GRUPPEN = [
  { id: "trusted", ton: "ok" },
  { id: "localPrivate", ton: "neutral" },
  { id: "publicResolver", ton: "neutral" },
  { id: "unknown", ton: "neutral" },
  { id: "threat", ton: "warn" },
  { id: "rejected", ton: "danger" },
];

// Ein Server -> die id GENAU einer Gruppe (oder null, falls unerwartet nichts
// passt; solche Server werden bewusst NICHT still verschluckt, sondern unter
// „unknown" einsortiert -- siehe unten). Reihenfolge = Prioritaet: die warnende/
// spezifischere Gruppe gewinnt.
//   1. threat_listed -> immer „threat" (Warnung schlaegt alles).
//   2. rejected      -> „rejected".
//   3. gateway ODER trusted -> „trusted" (Auto-Vertrauen + manuell vertraut).
//   4. neutral je Kategorie: local_private / public_resolver / unknown.
function gruppeFuer(server) {
  if (server.category === "threat_listed") {
    return "threat";
  }
  if (server.trustState === "rejected") {
    return "rejected";
  }
  if (server.category === "gateway" || server.trustState === "trusted") {
    return "trusted";
  }
  if (server.trustState === "neutral") {
    if (server.category === "local_private") {
      return "localPrivate";
    }
    if (server.category === "public_resolver") {
      return "publicResolver";
    }
  }
  // Rest (neutral/unknown oder ein unerwarteter Zustand): ehrlich unter „unklar".
  return "unknown";
}

// Ein Kategorie-Label (Wire-Wert -> i18n-Schluessel). Dient nur der Anzeige der
// rohen Kategorie je Zeile; die Gruppierung laeuft ueber gruppeFuer, nicht hierueber.
function kategorieSchluessel(category) {
  return `verwaltung.dnsTrust.category.${category}`;
}

// Ein Zustands-Label (Wire-Wert -> i18n-Schluessel).
function zustandSchluessel(trustState) {
  return `verwaltung.dnsTrust.state.${trustState}`;
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

// Eine Server-Zeile mit Namen/IP, Kategorie- + Zustands-Marke, Indizien und den
// zustandsabhaengigen Aktions-Knoepfen. threat_listed macht „Vertrauen" zur
// warnenden Aktion (sev-high-Optik), nicht zur neutralen Wahl.
function ServerZeile({ server, busy, onEntscheidung }) {
  const { t } = useTranslation();

  const anzeigeName = server.displayName || server.ip;
  const nameIstIp = !server.displayName;
  const istThreat = server.category === "threat_listed";
  const istGateway = server.category === "gateway";

  // Welche Aktionen die Zeile anbietet (aus dem Zustand abgeleitet):
  //   „Vertrauen"     bei neutral/rejected (noch nicht vertraut).
  //   „Ablehnen"      bei trusted/neutral (noch nicht abgelehnt).
  //   „Zuruecksetzen" bei getroffener Entscheidung (trusted/rejected).
  const kannVertrauen = server.trustState === "neutral" || server.trustState === "rejected";
  const kannAblehnen = server.trustState === "trusted" || server.trustState === "neutral";
  const kannZuruecksetzen =
    server.trustState === "trusted" || server.trustState === "rejected";

  return (
    <div className="dt-row">
      <div className="dt-row__ident">
        <span className="dt-row__name">{anzeigeName}</span>
        {/* Rohe IP dezent -- entfaellt, wenn der Name ohnehin die IP ist. */}
        {nameIstIp ? null : <span className="dt-row__ip">{server.ip}</span>}
        <span className="dt-row__meta">
          <span className="dt-badge">{t(kategorieSchluessel(server.category))}</span>
          <span className="dt-badge dt-badge--state" data-state={server.trustState}>
            {t(zustandSchluessel(server.trustState))}
          </span>
        </span>
        <PlausibilitaetsIndizien plausibility={server.plausibility} />
      </div>

      <div className="dt-row__actions">
        {/* threat_listed: „Vertrauen" nur als klar warnende Aktion. */}
        {kannVertrauen ? (
          istThreat ? (
            <button
              type="button"
              className="dt-action dt-action--warn"
              onClick={() => onEntscheidung(server.ip, "trust")}
              disabled={busy}
            >
              {t("verwaltung.dnsTrust.actions.trustDespiteThreat")}
            </button>
          ) : (
            <button
              type="button"
              className="dt-action dt-action--trust"
              onClick={() => onEntscheidung(server.ip, "trust")}
              disabled={busy}
            >
              {t("verwaltung.dnsTrust.actions.trust")}
            </button>
          )
        ) : null}

        {kannAblehnen ? (
          <button
            type="button"
            // Gateway (Auto-Vertrauen): Ablehnen bleibt technisch moeglich, aber
            // dezent (kein Zwang) -- daher der leisere „subtle"-Stil.
            className={`dt-action dt-action--reject${istGateway ? " dt-action--subtle" : ""}`}
            onClick={() => onEntscheidung(server.ip, "reject")}
            disabled={busy}
          >
            {t("verwaltung.dnsTrust.actions.reject")}
          </button>
        ) : null}

        {kannZuruecksetzen ? (
          <button
            type="button"
            className="dt-action dt-action--reset"
            onClick={() => onEntscheidung(server.ip, "reset")}
            disabled={busy}
          >
            {t("verwaltung.dnsTrust.actions.reset")}
          </button>
        ) : null}
      </div>
    </div>
  );
}

export default function DnsTrustPanel() {
  const { t } = useTranslation();

  const [servers, setServers] = useState([]);
  const [laden, setLaden] = useState(true);
  const [fehler, setFehler] = useState(null);
  // IPs mit gerade laufender Entscheidung (Knoepfe der Zeile gesperrt).
  const [busy, setBusy] = useState(new Set());

  // Server laden. Gemeinsamer Pfad fuer Mount und Reload nach einer Entscheidung.
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

  // Server in ihre Gruppen einsortieren (jeder in genau eine). Rein aus servers
  // abgeleitet -- t/i18n gehoert NICHT in diese Deps.
  const gruppiert = useMemo(() => {
    const koerbe = new Map(GRUPPEN.map((g) => [g.id, []]));
    for (const server of servers) {
      const id = gruppeFuer(server);
      koerbe.get(id).push(server);
    }
    return koerbe;
  }, [servers]);

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
          {t(`verwaltung.dnsTrust.${fehler}`)}
        </p>
      ) : null}

      {/* Ehrlicher Leerzustand, wenn (noch) keine Server erkannt wurden. */}
      {servers.length === 0 ? (
        <p className="dt-empty">{t("verwaltung.dnsTrust.empty")}</p>
      ) : (
        GRUPPEN.map((gruppe) => {
          const zeilen = gruppiert.get(gruppe.id);
          // Leere Gruppen ausblenden.
          if (!zeilen || zeilen.length === 0) {
            return null;
          }
          return (
            <section key={gruppe.id} className="dt-group" data-ton={gruppe.ton}>
              <h3 className="dt-group__title">
                {t(`verwaltung.dnsTrust.groups.${gruppe.id}.title`)}
              </h3>
              <p className="dt-group__lead">
                {t(`verwaltung.dnsTrust.groups.${gruppe.id}.lead`)}
              </p>
              <div className="dt-group__rows">
                {zeilen.map((server) => (
                  <ServerZeile
                    key={server.ip}
                    server={server}
                    busy={busy.has(server.ip)}
                    onEntscheidung={handleEntscheidung}
                  />
                ))}
              </div>
            </section>
          );
        })
      )}
    </div>
  );
}
