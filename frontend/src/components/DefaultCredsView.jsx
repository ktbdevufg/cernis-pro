// Standardzugangs-Prüfansicht (CERNIS PRO 2.0, Etappe 2)
//
// Schlanke Prüf-Ansicht der scharfen Opt-in-Sonderfunktion „Standardzugänge
// prüfen". Der Nutzer gibt ein Ziel (Host/IP im eigenen Netz) ein; CERNIS prüft
// die üblichen Web-/FTP-Zugänge auf werksseitige Standardzugangsdaten und ordnet
// den Befund NEUTRAL ein (Produkt-These: einordnen, kein Urteil). Muster wie
// RouteView (Eingabe + Prüfen-Knopf + ehrliche Zustände).
//
// Der Nutzer muss keine Ports tippen — eine sinnvolle Default-Portmenge (Web/FTP)
// wird fest mitgesendet. Ergebnis-Zustände, alle ehrlich:
//   * Treffer   -> je Fund „Gerät nutzt Standardzugang (Benutzer/Passwort)";
//                  trägt der Fund eine note „selbstsigniertes Zertifikat",
//                  erscheint sie als ruhiger Zusatz.
//   * Kein Fund -> „Kein Standardzugang gefunden" (NICHT „sicher"/„alles gut").
//   * 403       -> die vom Backend gelieferte error-message ruhig anzeigen
//                  (z. B. Ziel nicht im privaten Netz ODER nicht freigeschaltet),
//                  kein Crash.
//
// i18n alle Texte über t(); t/i18n NIE in useEffect-Dependencies (Projektregel).
// Diese View wird nur geöffnet, wenn die Kachel entsperrt ist (armed); ein
// dennoch auftretender 403 „nicht freigeschaltet" (Sitzung inzwischen abgelaufen)
// wird sauber als Fehlermeldung gezeigt.

import { KeyRound, Play, ShieldQuestion } from "lucide-react";
import { useCallback, useState } from "react";
import { useTranslation } from "react-i18next";

import { ApiError } from "../api/client.js";
import { checkDefaultCreds } from "../api/security.js";
import "./DefaultCredsView.css";

// Feste Default-Portmenge (Web/FTP). Der Nutzer muss keine Ports tippen; das
// Backend erwartet je Port ein { port, service }-Objekt.
const DEFAULT_PORTS = [
  { port: 80, service: "http" },
  { port: 443, service: "https" },
  { port: 21, service: "ftp" },
];

// Ein einzelner Fund. Neutrale Einordnung: Standardzugang mit Benutzer/Passwort;
// eine note (z. B. „selbstsigniertes Zertifikat") erscheint als ruhiger Zusatz.
function FundZeile({ eintrag }) {
  const { t } = useTranslation();
  const note = typeof eintrag.note === "string" ? eintrag.note.trim() : "";
  // Benutzer/Passwort ehrlich zeigen, soweit geliefert; fehlt eins, bleibt es
  // leer (nicht erfunden).
  const benutzer = eintrag.username ?? eintrag.user ?? "";
  const passwort = eintrag.password ?? eintrag.pass ?? "";
  const zugang = [benutzer, passwort].filter((teil) => teil !== "").join(" / ");

  return (
    <li className="defcreds__fund">
      <span className="defcreds__fund-head">
        <KeyRound size={16} aria-hidden="true" />
        <span className="defcreds__fund-title">
          {t("untersuchen.defaultCreds.resultHit")}
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
          {t("untersuchen.defaultCreds.selfSigned", { note })}
        </span>
      ) : null}
    </li>
  );
}

export default function DefaultCredsView() {
  const { t } = useTranslation();
  const [ziel, setZiel] = useState("");
  const [funde, setFunde] = useState(null); // null = noch nicht geprüft; sonst Array
  const [laedt, setLaedt] = useState(false);
  const [fehler, setFehler] = useState(null); // { text } oder null

  // Die Prüfung starten. 403 ist ein Fachfall (nicht freigeschaltet / Ziel nicht
  // im privaten Netz): die vom Backend gelieferte message ruhig zeigen. Sonstige
  // Fehler ehrlich, aber generisch melden. Vendor bleibt leer (das Backend leitet
  // die Hersteller-Zuordnung selbst ab; das Feld wird dennoch mitgesendet).
  const pruefen = useCallback(async () => {
    const host = ziel.trim();
    if (!host) {
      return;
    }
    setLaedt(true);
    setFehler(null);
    setFunde(null);
    try {
      const ergebnis = await checkDefaultCreds(host, DEFAULT_PORTS, "");
      setFunde(Array.isArray(ergebnis) ? ergebnis : []);
    } catch (ursache) {
      // 403 -> Backend-message zeigen (Netz nicht privat / nicht freigeschaltet).
      // Alles andere -> generische, ehrliche Fehlermeldung.
      const istFachfall = ursache instanceof ApiError && ursache.status === 403;
      setFunde(null);
      setFehler({
        text: istFachfall
          ? ursache.message
          : t("untersuchen.defaultCreds.error"),
      });
    } finally {
      setLaedt(false);
    }
  }, [ziel, t]);

  return (
    <div className="defcreds">
      {/* Ruhiger Hinweis: aktive Prüfung, nur eigene Geräte. */}
      <div className="defcreds__notice" role="note">
        {t("untersuchen.defaultCreds.notice")}
      </div>

      <form
        className="defcreds__form"
        onSubmit={(e) => {
          e.preventDefault();
          pruefen();
        }}
      >
        <input
          className="defcreds__input"
          type="text"
          value={ziel}
          onChange={(e) => setZiel(e.target.value)}
          placeholder={t("untersuchen.defaultCreds.hostPlaceholder")}
          aria-label={t("untersuchen.defaultCreds.hostLabel")}
        />
        <button
          className="defcreds__start"
          type="submit"
          disabled={laedt || ziel.trim() === ""}
        >
          <Play size={15} aria-hidden="true" />
          {laedt
            ? t("untersuchen.defaultCreds.checking")
            : t("untersuchen.defaultCreds.checkButton")}
        </button>
      </form>

      {fehler !== null && (
        <div className="defcreds__error">{fehler.text}</div>
      )}

      {/* Ergebnis: Treffer als neutrale Einordnung ODER ehrlicher Leerbefund. */}
      {funde !== null && fehler === null && (
        funde.length === 0 ? (
          <div className="defcreds__none">
            {t("untersuchen.defaultCreds.resultNone")}
          </div>
        ) : (
          <ul className="defcreds__funde">
            {funde.map((eintrag, i) => (
              <FundZeile key={eintrag.port ?? i} eintrag={eintrag} />
            ))}
          </ul>
        )
      )}

      {/* Ruhezustand vor der ersten Prüfung. */}
      {funde === null && fehler === null && !laedt && (
        <div className="defcreds__hint">
          <ShieldQuestion size={28} aria-hidden="true" />
          <span>{t("untersuchen.defaultCreds.idle")}</span>
        </div>
      )}
    </div>
  );
}
