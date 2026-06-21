// Gäste-/Unbekannt-Wache (CERNIS PRO 2.0)
//
// Eigenständige "Beobachten"-Funktion: eine ruhige Sammelansicht neu gesehener,
// noch nicht eingeordneter Geräte (is_known=false UND watch_dismissed=false).
// Kein Alarm, kein Badge — ein ruhiger Zähler und eine Liste mit Inline-Aktionen
// je Zeile: "Vertraut" (ordnet ein -> aus der Wache), "Notiz" (kleines Notizfeld
// inline) und "Ausblenden" (legt das Gerät weg, rücknehmbar; es bleibt im
// Bestand, verschwindet nur aus der Wache).
//
// Datenquelle: api/devices.js (REST-Vorladung + Schreibpfade). Fehlertoleranz
// wie ScanInhalt/MonitorView: ein Patzer beim Laden kippt die Ansicht nicht
// (leere Liste statt Absturz). Farben strikt über Token-Variablen (tokens.css),
// nie feste Hex-Werte. Alle Texte über t().

import { Check, EyeOff, ShieldQuestion, StickyNote } from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import {
  dismissDevice,
  fetchUnclassifiedDevices,
  setTrustState,
  updateDeviceMeta,
} from "../api/devices.js";
import "./WatchView.css";

// Reiner Helfer: "vor X" aus einem ISO-Zeitstempel (firstSeen). Liefert den
// i18n-Schlüssel + Wert, die der Aufrufer über t() rendert — so bleiben die
// Sprachtexte (de/en) in den Übersetzungsdateien. Sehr grob (gerade/Minuten/
// Stunden/Tage), denn die Wache braucht keine Sekundengenauigkeit.
export function relativeSeit(iso, jetzt = Date.now()) {
  if (!iso) {
    return { key: "beobachten.watch.seenUnknown", value: null };
  }
  const dann = new Date(iso).getTime();
  if (Number.isNaN(dann)) {
    return { key: "beobachten.watch.seenUnknown", value: null };
  }
  const sekunden = Math.max(0, Math.round((jetzt - dann) / 1000));
  if (sekunden < 60) {
    return { key: "beobachten.watch.seenJustNow", value: null };
  }
  const minuten = Math.round(sekunden / 60);
  if (minuten < 60) {
    return { key: "beobachten.watch.seenMinutes", value: minuten };
  }
  const stunden = Math.round(minuten / 60);
  if (stunden < 24) {
    return { key: "beobachten.watch.seenHours", value: stunden };
  }
  const tage = Math.round(stunden / 24);
  return { key: "beobachten.watch.seenDays", value: tage };
}

// Anzeigename eines Geräts: Label > Hostname > IP > MAC. Kein erfundener Wert —
// fällt geordnet auf den nächsten vorhandenen zurück.
function anzeigeName(geraet) {
  return (
    geraet.label ||
    geraet.hostname ||
    geraet.lastIp ||
    geraet.mac ||
    ""
  );
}

// Eine Wache-Zeile mit Inline-Aktionen. Hält ihren eigenen Notiz-Auf/Zu-Zustand
// und ihren Notiz-Entwurf; das Speichern/Einordnen/Ausblenden meldet sie über
// Callbacks nach oben (die Liste entfernt das Gerät bzw. patcht es).
function WacheZeile({ geraet, jetzt, onEingeordnet, onAusgeblendet, onFehler }) {
  const { t } = useTranslation();
  const [notizOffen, setNotizOffen] = useState(false);
  const [notizEntwurf, setNotizEntwurf] = useState(geraet.notes ?? "");
  // Während eines Schreibvorgangs sperren wir die Aktionen dieser Zeile.
  const [busy, setBusy] = useState(false);

  const { key, value } = relativeSeit(geraet.firstSeen, jetzt);

  // "Vertraut": ordnet das Gerät ein (trust_state=trusted -> serverseitig
  // is_known=true). Danach gehört es nicht mehr in die Wache -> aus der Liste.
  const handleVertraut = async () => {
    if (busy) {
      return;
    }
    setBusy(true);
    try {
      await setTrustState(geraet.mac, "trusted");
      onEingeordnet(geraet.mac);
    } catch {
      onFehler(t("beobachten.watch.actionError"));
      setBusy(false);
    }
  };

  // "Ausblenden": legt das Gerät weg (dismissed=true). Bleibt im Bestand,
  // verschwindet nur aus der Wache -> aus der Liste.
  const handleAusblenden = async () => {
    if (busy) {
      return;
    }
    setBusy(true);
    try {
      await dismissDevice(geraet.mac, true);
      onAusgeblendet(geraet.mac);
    } catch {
      onFehler(t("beobachten.watch.actionError"));
      setBusy(false);
    }
  };

  // "Notiz" speichern: schreibt nur das Notizfeld; das Gerät bleibt in der Wache
  // (Notieren ist kein Einordnen). Schließt das Feld bei Erfolg.
  const handleNotizSpeichern = async () => {
    if (busy) {
      return;
    }
    setBusy(true);
    try {
      await updateDeviceMeta(geraet.mac, { notes: notizEntwurf });
      setNotizOffen(false);
    } catch {
      onFehler(t("beobachten.watch.actionError"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <li className="watch__zeile">
      <div className="watch__zeile-kopf">
        <ShieldQuestion
          className="watch__zeile-icon"
          size={18}
          aria-hidden="true"
        />
        <div className="watch__zeile-text">
          <span className="watch__zeile-name">{anzeigeName(geraet)}</span>
          <span className="watch__zeile-meta">
            {geraet.lastIp && (
              <span className="watch__mono">{geraet.lastIp}</span>
            )}
            <span className="watch__zeile-seit">{t(key, { count: value })}</span>
          </span>
        </div>

        <div className="watch__aktionen">
          <button
            type="button"
            className="watch__aktion watch__aktion--vertraut"
            onClick={handleVertraut}
            disabled={busy}
          >
            <Check size={15} aria-hidden="true" />
            {t("beobachten.watch.actionTrust")}
          </button>
          <button
            type="button"
            className="watch__aktion"
            onClick={() => setNotizOffen((offen) => !offen)}
            disabled={busy}
            aria-expanded={notizOffen}
          >
            <StickyNote size={15} aria-hidden="true" />
            {t("beobachten.watch.actionNote")}
          </button>
          <button
            type="button"
            className="watch__aktion"
            onClick={handleAusblenden}
            disabled={busy}
          >
            <EyeOff size={15} aria-hidden="true" />
            {t("beobachten.watch.actionDismiss")}
          </button>
        </div>
      </div>

      {notizOffen && (
        <div className="watch__notiz">
          <textarea
            className="watch__notiz-feld"
            value={notizEntwurf}
            onChange={(e) => setNotizEntwurf(e.target.value)}
            placeholder={t("beobachten.watch.notePlaceholder")}
            rows={2}
            disabled={busy}
          />
          <button
            type="button"
            className="watch__notiz-speichern"
            onClick={handleNotizSpeichern}
            disabled={busy}
          >
            {t("beobachten.watch.noteSave")}
          </button>
        </div>
      )}
    </li>
  );
}

export default function WatchView() {
  const { t } = useTranslation();
  const [geraete, setGeraete] = useState([]);
  const [geladen, setGeladen] = useState(false);
  const [fehler, setFehler] = useState(null);

  // Beim Öffnen die Wache laden. Fehler werden toleriert (leere Liste, dezenter
  // Hinweis); kein Absturz.
  useEffect(() => {
    let abgebrochen = false;
    (async () => {
      try {
        const liste = await fetchUnclassifiedDevices();
        if (abgebrochen) {
          return;
        }
        setGeraete(liste);
      } catch {
        if (!abgebrochen) {
          setFehler(t("beobachten.watch.loadError"));
        }
      } finally {
        if (!abgebrochen) {
          setGeladen(true);
        }
      }
    })();
    return () => {
      abgebrochen = true;
    };
  }, [t]);

  // Ein Gerät aus der Liste entfernen (eingeordnet ODER ausgeblendet -> beides
  // verlässt die Wache). Über die MAC, die in der Wache eindeutig ist.
  const entferne = (mac) => {
    setGeraete((aktuell) => aktuell.filter((g) => g.mac !== mac));
  };

  // Jetzt-Zeitpunkt EINMAL je Render bestimmen, damit alle "vor X"-Angaben
  // konsistent vom selben Bezugspunkt rechnen.
  const jetzt = Date.now();

  return (
    <div className="watch">
      {/* Ruhige Kopfzeile: Zähler + erklärender Satz. Kein Alarm-Badge. */}
      <div className="watch__kopf">
        <span className="watch__zaehler">
          {t("beobachten.watch.counter", { count: geraete.length })}
        </span>
        <span className="watch__unterzeile">
          {t("beobachten.watch.subtitle")}
        </span>
      </div>

      {fehler && (
        <div className="watch__fehler" role="note">
          {fehler}
        </div>
      )}

      {/* Ehrlicher Leerzustand: erst nach dem Laden, wenn wirklich nichts da ist
          und kein Fehler vorliegt. */}
      {geladen && geraete.length === 0 && !fehler ? (
        <p className="watch__leer">{t("beobachten.watch.empty")}</p>
      ) : (
        <ul className="watch__liste">
          {geraete.map((geraet) => (
            <WacheZeile
              key={geraet.mac}
              geraet={geraet}
              jetzt={jetzt}
              onEingeordnet={entferne}
              onAusgeblendet={entferne}
              onFehler={setFehler}
            />
          ))}
        </ul>
      )}
    </div>
  );
}
