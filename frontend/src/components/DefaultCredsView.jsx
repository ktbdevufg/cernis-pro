// Standardzugangs-Prüfansicht (CERNIS PRO 2.0, Etappe D)
//
// Geräte-/modellbasierter Prüf-Workflow — ersetzt den alten freie-Host-plus-
// blinde-Default-Ports-Flow. Der Weg geht jetzt vom GERÄT aus:
//   1. Gerät aus dem Scan wählen (fetchDevices) — oder Ziel manuell eingeben.
//   2. Hersteller (aus vendor) + optionales Modell -> ermittlePruefplan liefert
//      einen der drei Fälle.
//   3. Fallanzeige:
//        entwarnung  -> ruhige grüne Einordnung, KEINE Prüfung (nichts zu prüfen).
//        kandidaten  -> ankreuzbare Kandidaten mit Konfidenz-Badge.
//        keine_infos -> ehrlich „keine Infos", Hersteller-Nachschlag + präzisieren.
//   4. Prüfung der ANGEHAKTEN Kandidaten (pruefeKandidaten) -> rot (Fund) /
//      grün (kein Fund mit den geprüften Daten, NICHT „sicher") / 403 (ruhig).
//   5. Aufklappbare Historie (fetchDefaultCredsHistorie + Detail).
//
// Produkt-These: zeigen + einordnen, nie urteilen. „rot" = Fund/Handlungshinweis,
// nicht „böse"; „grün" = kein Fund mit den geprüften Daten, nicht „sicher".
//
// i18n alle Texte über t(); t/i18n NIE in useEffect-Dependencies (Projektregel).
// Diese View wird nur geöffnet, wenn die Kachel entsperrt ist (armed); ein
// dennoch auftretender 403 „nicht freigeschaltet" (Sitzung abgelaufen ODER Ziel
// nicht privat) wird sauber als Meldung gezeigt, kein Crash.

import {
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  KeyRound,
  Play,
  RotateCcw,
  ShieldCheck,
  ShieldQuestion,
} from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { ApiError } from "../api/client.js";
import { fetchDevices } from "../api/devices.js";
import {
  ermittlePruefplan,
  fetchDefaultCredsHistorie,
  fetchDefaultCredsHistorieDetail,
  pruefeKandidaten,
} from "../api/security.js";
import "./DefaultCredsView.css";

// Fallback-Portmenge NUR falls das gewählte Gerät keine offenen Ports trägt.
// Nicht mehr der Normalpfad — im Regelfall kommen die Ports aus openPorts.
const DEFAULT_PORTS = [
  { port: 80, service: "http" },
  { port: 443, service: "https" },
  { port: 21, service: "ftp" },
];

// Die drei Ablauf-Schritte der Ansicht. „modell" umfasst Ermittlung + Fallanzeige
// + Prüfung + Ergebnis (alles am gewählten Gerät); „geraet" ist die Vorauswahl.
const SCHRITT_GERAET = "geraet";
const SCHRITT_MODELL = "modell";

// Konfidenz-Wert (Backend) -> i18n-Schlüssel der Badge. Unbekannte Werte fallen
// neutral auf „vermutet" (kein erfundener Wert, aber kein Crash).
const KONFIDENZ_KEY = {
  gesichert: "konfidenzGesichert",
  auch_moeglich: "konfidenzAuchMoeglich",
  vermutet: "konfidenzVermutet",
  benutzer: "konfidenzBenutzer",
};

// Offene Ports eines Geräts -> [{ port, service }] für die Prüfung. openPorts aus
// dem Mapper kann Zahlen ODER Objekte ({ port, service }) tragen; beides robust
// normalisieren. Leere/unbrauchbare Menge -> DEFAULT_PORTS (Fallback).
function portsFuerPruefung(openPorts) {
  const liste = Array.isArray(openPorts) ? openPorts : [];
  const normiert = liste
    .map((eintrag) => {
      if (typeof eintrag === "number") {
        return { port: eintrag, service: "" };
      }
      if (eintrag && typeof eintrag === "object" && eintrag.port != null) {
        return { port: eintrag.port, service: eintrag.service ?? "" };
      }
      return null;
    })
    .filter((eintrag) => eintrag !== null);
  return normiert.length > 0 ? normiert : DEFAULT_PORTS;
}

// Offene Ports eines Geräts als kurze Anzeige-Zeichenkette (nur Port-Nummern).
// Leere Menge -> "" (der Aufrufer zeigt dann „keine").
function portsAlsText(openPorts) {
  const liste = Array.isArray(openPorts) ? openPorts : [];
  return liste
    .map((eintrag) =>
      typeof eintrag === "number" ? eintrag : eintrag?.port ?? null,
    )
    .filter((port) => port != null)
    .join(", ");
}

// Eine Kandidaten-Zeile: ankreuzbar, mit Konfidenz-Badge und Passwort-Anzeige
// („(leer)" wenn ""). Reine Präsentation; der Haken-Zustand liegt oben.
function KandidatZeile({ kandidat, angehakt, onToggle }) {
  const { t } = useTranslation();
  const konfidenzKey = KONFIDENZ_KEY[kandidat.konfidenz] ?? "konfidenzVermutet";
  const passwortAnzeige =
    kandidat.password === ""
      ? t("untersuchen.defaultCreds.kandidat.passwortLeer")
      : kandidat.password;

  return (
    <label className="defcreds__kandidat">
      <input
        type="checkbox"
        checked={angehakt}
        onChange={onToggle}
        className="defcreds__kandidat-check"
      />
      <span className="defcreds__kandidat-cred">
        <span className="defcreds__kandidat-user">{kandidat.username}</span>
        <span className="defcreds__kandidat-sep">/</span>
        <span className="defcreds__kandidat-pass">{passwortAnzeige}</span>
      </span>
      <span
        className={`defcreds__badge defcreds__badge--${kandidat.konfidenz ?? "vermutet"}`}
      >
        {t(`untersuchen.defaultCreds.kandidat.${konfidenzKey}`)}
      </span>
    </label>
  );
}

// Ein einzelner Fund (Prüf-Ergebnis, rot). Neutrale Einordnung: Standardzugang
// mit Benutzer/Passwort; eine note („selbstsigniertes Zertifikat") als ruhiger
// Zusatz — kein moralisches Urteil.
function FundZeile({ eintrag }) {
  const { t } = useTranslation();
  const note = typeof eintrag.note === "string" ? eintrag.note.trim() : "";
  const benutzer = eintrag.username ?? "";
  const passwort = eintrag.password ?? "";
  const zugang = [benutzer, passwort].filter((teil) => teil !== "").join(" / ");

  return (
    <li className="defcreds__fund">
      <span className="defcreds__fund-head">
        <KeyRound size={16} aria-hidden="true" />
        <span className="defcreds__fund-title">
          {t("untersuchen.defaultCreds.ergebnis.trefferTitle")}
        </span>
      </span>
      {eintrag.port ? (
        <span className="defcreds__fund-meta">
          {t("untersuchen.defaultCreds.portLabel", {
            port: eintrag.port,
            service: eintrag.service ?? "",
          })}
        </span>
      ) : null}
      {zugang !== "" ? (
        <span className="defcreds__fund-cred">{zugang}</span>
      ) : null}
      {note !== "" ? (
        <span className="defcreds__fund-note">
          {t("untersuchen.defaultCreds.ergebnis.note", { note })}
        </span>
      ) : null}
    </li>
  );
}

// Aufklappbarer Historie-Bereich. Lädt beim ersten Öffnen die Zusammenfassungen;
// Klick auf eine Zeile lädt (einmalig, gecacht) das Detail mit den Funden.
function Historie() {
  const { t } = useTranslation();
  const [offen, setOffen] = useState(false);
  const [geladen, setGeladen] = useState(false);
  const [laedt, setLaedt] = useState(false);
  const [fehler, setFehler] = useState(null);
  const [eintraege, setEintraege] = useState([]);
  // Detail-Cache je Eintrags-id: undefined = nicht geladen, { findings } | { fehler }.
  const [details, setDetails] = useState({});
  const [aufgeklappt, setAufgeklappt] = useState(null); // id oder null

  // Historie beim ersten Aufklappen laden (nicht in den Dependencies: t).
  useEffect(() => {
    if (!offen || geladen) {
      return;
    }
    let abgebrochen = false;
    setLaedt(true);
    setFehler(null);
    fetchDefaultCredsHistorie()
      .then((liste) => {
        if (abgebrochen) {
          return;
        }
        setEintraege(Array.isArray(liste) ? liste : []);
        setGeladen(true);
      })
      .catch(() => {
        if (!abgebrochen) {
          setFehler("load");
        }
      })
      .finally(() => {
        if (!abgebrochen) {
          setLaedt(false);
        }
      });
    return () => {
      abgebrochen = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [offen, geladen]);

  const detailLaden = useCallback(
    async (id) => {
      // Toggle: schon aufgeklappt -> zuklappen.
      if (aufgeklappt === id) {
        setAufgeklappt(null);
        return;
      }
      setAufgeklappt(id);
      if (details[id] !== undefined) {
        return; // bereits (erfolgreich oder fehlerhaft) geladen
      }
      try {
        const detail = await fetchDefaultCredsHistorieDetail(id);
        const findings = Array.isArray(detail?.findings) ? detail.findings : [];
        setDetails((vorher) => ({ ...vorher, [id]: { findings } }));
      } catch {
        setDetails((vorher) => ({ ...vorher, [id]: { fehler: true } }));
      }
    },
    [aufgeklappt, details],
  );

  return (
    <section className="defcreds__historie">
      <button
        type="button"
        className="defcreds__historie-toggle"
        onClick={() => setOffen((v) => !v)}
        aria-expanded={offen}
      >
        {offen ? (
          <ChevronDown size={16} aria-hidden="true" />
        ) : (
          <ChevronRight size={16} aria-hidden="true" />
        )}
        {t("untersuchen.defaultCreds.historie.title")}
      </button>

      {offen && (
        <div className="defcreds__historie-body">
          {laedt && (
            <div className="defcreds__muted">
              {t("untersuchen.defaultCreds.historie.loading")}
            </div>
          )}
          {fehler !== null && !laedt && (
            <div className="defcreds__error">
              {t("untersuchen.defaultCreds.historie.loadError")}
            </div>
          )}
          {!laedt && fehler === null && eintraege.length === 0 && (
            <div className="defcreds__muted">
              {t("untersuchen.defaultCreds.historie.leer")}
            </div>
          )}
          {!laedt && fehler === null && eintraege.length > 0 && (
            <ul className="defcreds__hist-liste">
              {eintraege.map((eintrag) => {
                const treffer = eintrag.treffer_count ?? 0;
                const modellText =
                  eintrag.modell && eintrag.modell !== ""
                    ? eintrag.modell
                    : t("untersuchen.defaultCreds.historie.modellLeer");
                const detail = details[eintrag.id];
                const istOffen = aufgeklappt === eintrag.id;
                return (
                  <li key={eintrag.id} className="defcreds__hist-item">
                    <button
                      type="button"
                      className="defcreds__hist-row"
                      onClick={() => detailLaden(eintrag.id)}
                      aria-expanded={istOffen}
                    >
                      <span className="defcreds__hist-zeit">
                        {eintrag.geprueft_at}
                      </span>
                      <span className="defcreds__hist-host">{eintrag.host}</span>
                      <span className="defcreds__hist-geraet">
                        {eintrag.hersteller || "—"}
                        {" / "}
                        {modellText}
                      </span>
                      <span
                        className={
                          treffer > 0
                            ? "defcreds__hist-treffer defcreds__hist-treffer--hit"
                            : "defcreds__hist-treffer defcreds__hist-treffer--ok"
                        }
                      >
                        {treffer > 0
                          ? t("untersuchen.defaultCreds.historie.treffer", {
                              count: treffer,
                            })
                          : t("untersuchen.defaultCreds.historie.keinTreffer")}
                      </span>
                    </button>
                    {istOffen && (
                      <div className="defcreds__hist-detail">
                        {detail === undefined ? (
                          <div className="defcreds__muted">
                            {t("untersuchen.defaultCreds.historie.loading")}
                          </div>
                        ) : detail.fehler ? (
                          <div className="defcreds__error">
                            {t(
                              "untersuchen.defaultCreds.historie.detailLoadError",
                            )}
                          </div>
                        ) : detail.findings.length === 0 ? (
                          <div className="defcreds__muted">
                            {t("untersuchen.defaultCreds.historie.detailLeer")}
                          </div>
                        ) : (
                          <ul className="defcreds__funde">
                            {detail.findings.map((f, i) => (
                              <FundZeile key={f.port ?? i} eintrag={f} />
                            ))}
                          </ul>
                        )}
                      </div>
                    )}
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      )}
    </section>
  );
}

export default function DefaultCredsView() {
  const { t } = useTranslation();

  // Ablauf-Schritt: Gerätewahl -> Modell/Ermittlung/Prüfung.
  const [schritt, setSchritt] = useState(SCHRITT_GERAET);

  // Geräteliste.
  const [geraete, setGeraete] = useState(null); // null = lädt noch
  const [geraeteFehler, setGeraeteFehler] = useState(false);

  // Gewähltes Ziel: { host, hersteller, ports:[{port,service}], portsText, label }.
  const [ziel, setZiel] = useState(null);
  const [manuelleIp, setManuelleIp] = useState("");

  // Modell-Ermittlung.
  const [herstellerEingabe, setHerstellerEingabe] = useState("");
  const [modellEingabe, setModellEingabe] = useState("");
  const [ermittelt, setErmittelt] = useState(false); // schon einmal ermittelt?
  const [ermittleLaeuft, setErmittleLaeuft] = useState(false);
  const [pruefplan, setPruefplan] = useState(null); // { fall, eintraege, quelle_urls }
  const [ermittlungFehler, setErmittlungFehler] = useState(false);

  // Kandidaten-Auswahl: Set der angehakten "user pass"-Schlüssel.
  const [angehakt, setAngehakt] = useState(() => new Set());

  // Prüfung + Ergebnis.
  const [pruefLaeuft, setPruefLaeuft] = useState(false);
  const [funde, setFunde] = useState(null); // null = noch nicht geprüft; sonst Array
  const [pruefFehler, setPruefFehler] = useState(null); // { text } oder null

  // Geräteliste beim Betreten der Gerätewahl laden (t NICHT in den Deps).
  useEffect(() => {
    if (schritt !== SCHRITT_GERAET) {
      return;
    }
    let abgebrochen = false;
    setGeraete(null);
    setGeraeteFehler(false);
    fetchDevices()
      .then((liste) => {
        if (!abgebrochen) {
          setGeraete(Array.isArray(liste) ? liste : []);
        }
      })
      .catch(() => {
        if (!abgebrochen) {
          setGeraete([]);
          setGeraeteFehler(true);
        }
      });
    return () => {
      abgebrochen = true;
    };
  }, [schritt]);

  // Ein eindeutiger Kandidaten-Schlüssel (user + pass), robust gegen leere Werte.
  const kandidatKey = useCallback(
    (k) => `${k.username ?? ""} ${k.password ?? ""}`,
    [],
  );

  // Alle Kandidaten aus allen eintraege des Prüfplans einsammeln (nach Schlüssel
  // dedupliziert; der erste gewinnt — mitgelieferte Reihenfolge bleibt).
  const kandidaten = (() => {
    if (!pruefplan || pruefplan.fall !== "kandidaten") {
      return [];
    }
    const gesehen = new Set();
    const liste = [];
    for (const eintrag of pruefplan.eintraege ?? []) {
      for (const kandidat of eintrag.kandidaten ?? []) {
        const key = kandidatKey(kandidat);
        if (!gesehen.has(key)) {
          gesehen.add(key);
          liste.push(kandidat);
        }
      }
    }
    return liste;
  })();

  // Prüfplan ermitteln. hersteller/modell aus den aktuellen Eingaben; setzt die
  // Kandidaten-Vorauswahl (gesichert vorangehakt, vermutet nicht). Fehler ehrlich.
  const ermitteln = useCallback(
    async (hersteller, modell) => {
      setErmittleLaeuft(true);
      setErmittlungFehler(false);
      setPruefplan(null);
      setFunde(null);
      setPruefFehler(null);
      try {
        const plan = await ermittlePruefplan(hersteller ?? "", modell ?? "");
        setPruefplan(plan);
        setErmittelt(true);
        // Vorauswahl: gesichert-Kandidaten vorangehakt, alles andere nicht.
        if (plan?.fall === "kandidaten") {
          const vorwahl = new Set();
          for (const eintrag of plan.eintraege ?? []) {
            for (const kandidat of eintrag.kandidaten ?? []) {
              if (kandidat.konfidenz === "gesichert") {
                vorwahl.add(`${kandidat.username ?? ""} ${kandidat.password ?? ""}`);
              }
            }
          }
          setAngehakt(vorwahl);
        } else {
          setAngehakt(new Set());
        }
      } catch {
        setErmittlungFehler(true);
      } finally {
        setErmittleLaeuft(false);
      }
    },
    [],
  );

  // Ein Gerät aus der Liste wählen -> Ziel setzen, in Schritt 2 wechseln und
  // sofort mit leerem Modell ermitteln (Hersteller aus vendor).
  const geraetWaehlen = useCallback(
    (geraet) => {
      const hersteller = geraet.vendor ?? "";
      const ports = portsFuerPruefung(geraet.openPorts);
      const portsText = portsAlsText(geraet.openPorts);
      const label =
        geraet.label || geraet.hostname || geraet.lastIp || geraet.mac || "";
      setZiel({
        host: geraet.lastIp ?? "",
        hersteller,
        ports,
        portsText,
        label,
      });
      setHerstellerEingabe(hersteller);
      setModellEingabe("");
      setErmittelt(false);
      setSchritt(SCHRITT_MODELL);
      ermitteln(hersteller, "");
    },
    [ermitteln],
  );

  // Manuelle IP übernehmen -> Ziel ohne Hersteller (Fallback-Ports), in Schritt 2.
  // Hersteller ist leer -> die Ermittlung fragt (via keine_infos / leerem Plan)
  // nach Hersteller/Modell; wir ermitteln NICHT automatisch (nichts zu ermitteln),
  // sondern zeigen direkt die Präzisieren-Eingabe.
  const manuellUebernehmen = useCallback(() => {
    const host = manuelleIp.trim();
    if (host === "") {
      return;
    }
    setZiel({
      host,
      hersteller: "",
      ports: DEFAULT_PORTS,
      portsText: "",
      label: host,
    });
    setHerstellerEingabe("");
    setModellEingabe("");
    setErmittelt(false);
    setPruefplan(null);
    setFunde(null);
    setPruefFehler(null);
    setErmittlungFehler(false);
    setSchritt(SCHRITT_MODELL);
  }, [manuelleIp]);

  // Zurück zur Gerätewahl: allen Modell-/Prüf-Zustand zurücksetzen.
  const zurueckZurWahl = useCallback(() => {
    setSchritt(SCHRITT_GERAET);
    setZiel(null);
    setManuelleIp("");
    setPruefplan(null);
    setErmittelt(false);
    setFunde(null);
    setPruefFehler(null);
    setErmittlungFehler(false);
    setAngehakt(new Set());
  }, []);

  // Einen Kandidaten an-/abhaken.
  const toggleKandidat = useCallback(
    (kandidat) => {
      const key = kandidatKey(kandidat);
      setAngehakt((vorher) => {
        const naechste = new Set(vorher);
        if (naechste.has(key)) {
          naechste.delete(key);
        } else {
          naechste.add(key);
        }
        return naechste;
      });
    },
    [kandidatKey],
  );

  // Die angehakten Kandidaten (als {username,password}) für die Prüfung.
  const angehakteKandidaten = kandidaten.filter((k) => angehakt.has(kandidatKey(k)));

  // Gezielte Prüfung der angehakten Kandidaten. host/ports aus dem Ziel;
  // hersteller/modell aus den Eingaben. 403 ist Fachfall (nicht armed / nicht
  // privat): Backend-message ruhig zeigen. Sonst generisch, ehrlich.
  const pruefen = useCallback(async () => {
    if (!ziel || angehakteKandidaten.length === 0) {
      return;
    }
    setPruefLaeuft(true);
    setPruefFehler(null);
    setFunde(null);
    try {
      const ergebnis = await pruefeKandidaten({
        host: ziel.host,
        ports: ziel.ports,
        kandidaten: angehakteKandidaten.map((k) => ({
          username: k.username ?? "",
          password: k.password ?? "",
        })),
        hersteller: herstellerEingabe,
        modell: modellEingabe,
      });
      setFunde(Array.isArray(ergebnis) ? ergebnis : []);
    } catch (ursache) {
      const istFachfall = ursache instanceof ApiError && ursache.status === 403;
      setFunde(null);
      setPruefFehler({
        text: istFachfall
          ? ursache.message
          : t("untersuchen.defaultCreds.error"),
      });
    } finally {
      setPruefLaeuft(false);
    }
  }, [ziel, angehakteKandidaten, herstellerEingabe, modellEingabe, t]);

  // Quelle-Links des Prüfplans (entwarnung/keine_infos): quelle_urls plus die
  // quelle_url je Eintrag, dedupliziert, nur nicht-leere http(s)-URLs.
  const quelleLinks = (() => {
    if (!pruefplan) {
      return [];
    }
    const gesehen = new Set();
    const liste = [];
    const hinzu = (url) => {
      if (typeof url === "string" && url.trim() !== "" && !gesehen.has(url)) {
        gesehen.add(url);
        liste.push(url);
      }
    };
    for (const url of pruefplan.quelle_urls ?? []) {
      hinzu(url);
    }
    for (const eintrag of pruefplan.eintraege ?? []) {
      hinzu(eintrag.quelle_url);
    }
    return liste;
  })();

  return (
    <div className="defcreds">
      {/* Ruhiger Hinweis: aktive Prüfung, nur eigene Geräte. */}
      <div className="defcreds__notice" role="note">
        {t("untersuchen.defaultCreds.notice")}
      </div>

      {schritt === SCHRITT_GERAET && (
        <div className="defcreds__step">
          <h3 className="defcreds__step-title">
            {t("untersuchen.defaultCreds.geraetewahl.title")}
          </h3>
          <p className="defcreds__step-hint">
            {t("untersuchen.defaultCreds.geraetewahl.hint")}
          </p>

          {geraete === null && (
            <div className="defcreds__muted">
              {t("untersuchen.defaultCreds.geraetewahl.loading")}
            </div>
          )}

          {geraeteFehler && (
            <div className="defcreds__error">
              {t("untersuchen.defaultCreds.geraetewahl.loadError")}
            </div>
          )}

          {geraete !== null && !geraeteFehler && geraete.length === 0 && (
            <div className="defcreds__muted">
              {t("untersuchen.defaultCreds.geraetewahl.leer")}
            </div>
          )}

          {geraete !== null && geraete.length > 0 && (
            <ul className="defcreds__geraete">
              <li className="defcreds__geraet defcreds__geraet--kopf">
                <span>{t("untersuchen.defaultCreds.geraetewahl.spalteGeraet")}</span>
                <span>{t("untersuchen.defaultCreds.geraetewahl.spalteIp")}</span>
                <span>
                  {t("untersuchen.defaultCreds.geraetewahl.spalteHersteller")}
                </span>
                <span>
                  {t("untersuchen.defaultCreds.geraetewahl.spaltePorts")}
                </span>
                <span aria-hidden="true" />
              </li>
              {geraete.map((geraet) => {
                const portsText = portsAlsText(geraet.openPorts);
                const name =
                  geraet.label ||
                  geraet.hostname ||
                  geraet.lastIp ||
                  geraet.mac;
                return (
                  <li key={geraet.mac} className="defcreds__geraet">
                    <span className="defcreds__geraet-name">{name}</span>
                    <span className="defcreds__geraet-ip">
                      {geraet.lastIp ?? "—"}
                    </span>
                    <span className="defcreds__geraet-vendor">
                      {geraet.vendor ||
                        t("untersuchen.defaultCreds.geraetewahl.keinHersteller")}
                    </span>
                    <span className="defcreds__geraet-ports">
                      {portsText ||
                        t("untersuchen.defaultCreds.geraetewahl.keinePorts")}
                    </span>
                    <button
                      type="button"
                      className="defcreds__geraet-pick"
                      onClick={() => geraetWaehlen(geraet)}
                      disabled={!geraet.lastIp}
                    >
                      {t("untersuchen.defaultCreds.geraetewahl.auswaehlen")}
                    </button>
                  </li>
                );
              })}
            </ul>
          )}

          {/* Fallback: manuelle IP-Eingabe (Gerät nicht in der Liste). */}
          <div className="defcreds__manuell">
            <h4 className="defcreds__manuell-title">
              {t("untersuchen.defaultCreds.geraetewahl.manuellTitle")}
            </h4>
            <p className="defcreds__step-hint">
              {t("untersuchen.defaultCreds.geraetewahl.manuellHint")}
            </p>
            <form
              className="defcreds__form"
              onSubmit={(e) => {
                e.preventDefault();
                manuellUebernehmen();
              }}
            >
              <input
                className="defcreds__input"
                type="text"
                value={manuelleIp}
                onChange={(e) => setManuelleIp(e.target.value)}
                placeholder={t(
                  "untersuchen.defaultCreds.geraetewahl.manuellPlaceholder",
                )}
                aria-label={t(
                  "untersuchen.defaultCreds.geraetewahl.manuellPlaceholder",
                )}
              />
              <button
                className="defcreds__start"
                type="submit"
                disabled={manuelleIp.trim() === ""}
              >
                {t("untersuchen.defaultCreds.geraetewahl.manuellUebernehmen")}
              </button>
            </form>
          </div>
        </div>
      )}

      {schritt === SCHRITT_MODELL && ziel !== null && (
        <div className="defcreds__step">
          <button
            type="button"
            className="defcreds__back"
            onClick={zurueckZurWahl}
          >
            <ChevronRight
              size={14}
              aria-hidden="true"
              style={{ transform: "rotate(180deg)" }}
            />
            {t("untersuchen.defaultCreds.geraetewahl.zurueck")}
          </button>

          {/* Gewähltes Ziel im Überblick. */}
          <div className="defcreds__ziel">
            <span className="defcreds__ziel-zeile">
              <span className="defcreds__ziel-label">
                {t("untersuchen.defaultCreds.modell.geraetLabel")}
              </span>
              <span className="defcreds__ziel-wert">
                {ziel.label} {ziel.host ? `(${ziel.host})` : ""}
              </span>
            </span>
            <span className="defcreds__ziel-zeile">
              <span className="defcreds__ziel-label">
                {t("untersuchen.defaultCreds.modell.herstellerLabel")}
              </span>
              <span className="defcreds__ziel-wert">
                {ziel.hersteller ||
                  t("untersuchen.defaultCreds.modell.herstellerLeer")}
              </span>
            </span>
          </div>

          {/* Modell-/Hersteller-Eingabe: optional präzisieren bzw. bei leerem
              Hersteller pflichtgemäß nachtragen. */}
          <form
            className="defcreds__modellform"
            onSubmit={(e) => {
              e.preventDefault();
              ermitteln(herstellerEingabe, modellEingabe);
            }}
          >
            {ziel.hersteller === "" && (
              <label className="defcreds__feld">
                <span className="defcreds__feld-label">
                  {t("untersuchen.defaultCreds.modell.herstellerLabel")}
                </span>
                <input
                  className="defcreds__input"
                  type="text"
                  value={herstellerEingabe}
                  onChange={(e) => setHerstellerEingabe(e.target.value)}
                  placeholder={t(
                    "untersuchen.defaultCreds.modell.herstellerPlaceholder",
                  )}
                />
              </label>
            )}
            <label className="defcreds__feld">
              <span className="defcreds__feld-label">
                {t("untersuchen.defaultCreds.modell.modellLabel")}
              </span>
              <input
                className="defcreds__input"
                type="text"
                value={modellEingabe}
                onChange={(e) => setModellEingabe(e.target.value)}
                placeholder={t(
                  "untersuchen.defaultCreds.modell.modellPlaceholder",
                )}
              />
            </label>
            <p className="defcreds__step-hint">
              {t("untersuchen.defaultCreds.modell.optionalHint")}
            </p>
            <button
              className="defcreds__start"
              type="submit"
              disabled={
                ermittleLaeuft ||
                (ziel.hersteller === "" && herstellerEingabe.trim() === "")
              }
            >
              <Play size={15} aria-hidden="true" />
              {ermittleLaeuft
                ? t("untersuchen.defaultCreds.modell.ermittelt")
                : ermittelt
                  ? t("untersuchen.defaultCreds.modell.erneutErmitteln")
                  : t("untersuchen.defaultCreds.modell.ermitteln")}
            </button>
          </form>

          {ermittlungFehler && (
            <div className="defcreds__error">
              {t("untersuchen.defaultCreds.error")}
            </div>
          )}

          {/* Fallanzeige. */}
          {pruefplan !== null && !ermittleLaeuft && (
            <div className="defcreds__fall">
              {pruefplan.fall === "entwarnung" && (
                <div className="defcreds__entwarnung">
                  <span className="defcreds__entwarnung-head">
                    <ShieldCheck size={18} aria-hidden="true" />
                    <span className="defcreds__entwarnung-title">
                      {t("untersuchen.defaultCreds.fall.entwarnungTitle")}
                    </span>
                  </span>
                  <p className="defcreds__entwarnung-text">
                    {t("untersuchen.defaultCreds.fall.entwarnungText")}
                  </p>
                  {quelleLinks.length > 0 && (
                    <div className="defcreds__links">
                      {quelleLinks.map((url) => (
                        <a
                          key={url}
                          className="defcreds__link"
                          href={url}
                          target="_blank"
                          rel="noreferrer noopener"
                        >
                          <ExternalLink size={14} aria-hidden="true" />
                          {t("untersuchen.defaultCreds.fall.herstellerLink")}
                        </a>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {pruefplan.fall === "keine_infos" && (
                <div className="defcreds__keineinfos">
                  <span className="defcreds__keineinfos-head">
                    <ShieldQuestion size={18} aria-hidden="true" />
                    <span className="defcreds__keineinfos-title">
                      {t("untersuchen.defaultCreds.fall.keineInfosTitle")}
                    </span>
                  </span>
                  <p className="defcreds__keineinfos-text">
                    {t("untersuchen.defaultCreds.fall.keineInfosText")}
                  </p>
                  {quelleLinks.length > 0 ? (
                    <div className="defcreds__links">
                      {quelleLinks.map((url) => (
                        <a
                          key={url}
                          className="defcreds__link"
                          href={url}
                          target="_blank"
                          rel="noreferrer noopener"
                        >
                          <ExternalLink size={14} aria-hidden="true" />
                          {t("untersuchen.defaultCreds.fall.herstellerLink")}
                        </a>
                      ))}
                    </div>
                  ) : (
                    <p className="defcreds__muted">
                      {t("untersuchen.defaultCreds.fall.keinLink")}
                    </p>
                  )}
                </div>
              )}

              {pruefplan.fall === "kandidaten" && (
                <div className="defcreds__kandidaten">
                  <span className="defcreds__kandidaten-head">
                    <KeyRound size={18} aria-hidden="true" />
                    <span className="defcreds__kandidaten-title">
                      {t("untersuchen.defaultCreds.fall.kandidatenTitle")}
                    </span>
                  </span>
                  <p className="defcreds__step-hint">
                    {t("untersuchen.defaultCreds.fall.kandidatenHint")}
                  </p>
                  <div className="defcreds__kandidaten-liste">
                    {kandidaten.map((kandidat) => {
                      const key = kandidatKey(kandidat);
                      return (
                        <KandidatZeile
                          key={key}
                          kandidat={kandidat}
                          angehakt={angehakt.has(key)}
                          onToggle={() => toggleKandidat(kandidat)}
                        />
                      );
                    })}
                  </div>
                  <button
                    type="button"
                    className="defcreds__start"
                    onClick={pruefen}
                    disabled={pruefLaeuft || angehakteKandidaten.length === 0}
                  >
                    <Play size={15} aria-hidden="true" />
                    {pruefLaeuft
                      ? t("untersuchen.defaultCreds.kandidat.pruefe")
                      : t("untersuchen.defaultCreds.kandidat.pruefen")}
                  </button>
                  {angehakteKandidaten.length === 0 && (
                    <p className="defcreds__muted">
                      {t("untersuchen.defaultCreds.kandidat.keineAngehakt")}
                    </p>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Prüf-Fehler (u. a. 403). */}
          {pruefFehler !== null && (
            <div className="defcreds__error">{pruefFehler.text}</div>
          )}

          {/* Prüf-Ergebnis: rot (Fund) oder ehrlich-grün (kein Fund). */}
          {funde !== null && pruefFehler === null && (
            <div className="defcreds__ergebnis">
              {funde.length === 0 ? (
                <div className="defcreds__ok">
                  <span className="defcreds__ok-head">
                    <CheckCircle2 size={18} aria-hidden="true" />
                    <span className="defcreds__ok-title">
                      {t("untersuchen.defaultCreds.ergebnis.keinTrefferTitle")}
                    </span>
                  </span>
                  <p className="defcreds__ok-text">
                    {t("untersuchen.defaultCreds.ergebnis.keinTrefferText")}
                  </p>
                </div>
              ) : (
                <ul className="defcreds__funde">
                  {funde.map((eintrag, i) => (
                    <FundZeile key={eintrag.port ?? i} eintrag={eintrag} />
                  ))}
                </ul>
              )}
              <button
                type="button"
                className="defcreds__back"
                onClick={() => {
                  setFunde(null);
                  setPruefFehler(null);
                }}
              >
                <RotateCcw size={14} aria-hidden="true" />
                {t("untersuchen.defaultCreds.ergebnis.erneut")}
              </button>
            </div>
          )}
        </div>
      )}

      {/* Historie: immer erreichbar, aufklappbar. */}
      <Historie />
    </div>
  );
}
