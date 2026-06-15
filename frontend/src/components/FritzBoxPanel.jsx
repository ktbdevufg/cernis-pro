// FRITZ!Box-Panel (CERNIS PRO 2.0)
// Die eigentliche Geräte-Ansicht hinter der FritzBox-Kachel. Eigener lokaler
// State, lädt beim Mount fetchFritzDetail() und entscheidet:
//
//   - laedt                         -> dezenter Lade-Hinweis
//   - detail.reachable === false    -> "Verbinden"-Maske
//       - detail.authError === true -> mit Auth-Fehlerzeile
//       - sonst                     -> neutraler Hinweis (keine Box verbunden)
//   - detail.reachable === true     -> reiche Detailansicht mit internen Reitern
//
// Die Verbinden-Maske schreibt Credentials über die bestehende settings.js
// (updateSetting host/user, updateSecret password) und lädt danach neu. Es gibt
// bewusst KEINEN "Detect"-Button (Auto-Detection ist nicht implementiert).
//
// Die internen Reiter sind ein eigener kleiner Tab-State, NICHT die globale
// TabNav. Werte aus dem gemappten Detail (camelCase), Formatierung über die
// reinen Helfer aus api/fritz.js.

import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import {
  fetchFritzDetail,
  formatBytes,
  formatUptime,
  mappeDetail,
} from "../api/fritz.js";
import {
  fetchSettings,
  secretGesetzt,
  updateSecret,
  updateSetting,
} from "../api/settings.js";
import "./FritzBoxPanel.css";

// Interne Reiter der Detailansicht. Reihenfolge ist verbindlich.
const REITER = ["overview", "wlanClients", "log", "portForwardings"];

// Kbit/s -> ganze Mbit/s.
function kbpsZuMbit(kbps) {
  return Math.round((Number(kbps) || 0) / 1000);
}

// Eine Feld-Zeile (Label links, Wert rechts) innerhalb einer Overview-Karte.
function Feld({ label, value, mono = false }) {
  return (
    <div className="fritz-card__field">
      <span className="fritz-card__field-label">{label}</span>
      <span
        className={
          mono
            ? "fritz-card__field-value fritz-panel__mono"
            : "fritz-card__field-value"
        }
      >
        {value}
      </span>
    </div>
  );
}

// Eine benannte Karte im Overview-Gitter.
function Karte({ title, children }) {
  return (
    <div className="fritz-card">
      <h4 className="fritz-card__title">{title}</h4>
      <div className="fritz-card__fields">{children}</div>
    </div>
  );
}

// Verbinden-Maske: schlicht, mittig. Lädt vorhandene Settings als Vorbelegung,
// schreibt sie beim Verbinden zurück und meldet über onVerbunden(), dass das
// Panel das Detail neu laden soll. authFehler steuert die dezente Hinweiszeile.
function VerbindenMaske({ authFehler, onVerbunden }) {
  const { t } = useTranslation();

  const [hostWert, setHostWert] = useState("fritz.box");
  const [userWert, setUserWert] = useState("");
  const [passwortWert, setPasswortWert] = useState("");
  const [passwortGesetzt, setPasswortGesetzt] = useState(false);
  const [arbeitet, setArbeitet] = useState(false);

  // Vorbelegung aus GET /api/settings: Host/User als Klartext, Passwort-Präsenz
  // als Marker (nie der Klartext selbst).
  useEffect(() => {
    let aktiv = true;
    (async () => {
      try {
        const settings = await fetchSettings();
        if (!aktiv) {
          return;
        }
        if (settings.fritz_host) {
          setHostWert(String(settings.fritz_host));
        }
        setUserWert(String(settings.fritz_user ?? ""));
        setPasswortGesetzt(secretGesetzt(settings, "fritz_password"));
      } catch (fehler) {
        console.error("FritzBox-Einstellungen laden fehlgeschlagen:", fehler);
      }
    })();
    return () => {
      aktiv = false;
    };
  }, []);

  const handleVerbinden = async () => {
    setArbeitet(true);
    try {
      await updateSetting("fritz_host", hostWert);
      await updateSetting("fritz_user", userWert);
      if (passwortWert !== "") {
        await updateSecret("fritz_password", passwortWert);
        setPasswortWert("");
        setPasswortGesetzt(true);
      }
      await onVerbunden();
    } catch (fehler) {
      console.error("FritzBox verbinden fehlgeschlagen:", fehler);
    } finally {
      setArbeitet(false);
    }
  };

  return (
    <div className="fritz-connect">
      <div className="fritz-connect__box">
        <h3 className="fritz-connect__title">
          {t("geraete.fritzbox.connectTitle")}
        </h3>
        <p className="fritz-connect__intro">
          {t("geraete.fritzbox.connectIntro")}
        </p>

        {authFehler ? (
          <p className="fritz-connect__auth-hint">
            {t("geraete.fritzbox.authHint")}
          </p>
        ) : (
          <p className="fritz-connect__neutral-hint">
            {t("geraete.fritzbox.notConnected")}
          </p>
        )}

        <label className="fritz-connect__field">
          <span className="fritz-connect__label">
            {t("geraete.fritzbox.addressLabel")}
          </span>
          <input
            className="fritz-connect__input"
            type="text"
            value={hostWert}
            onChange={(e) => setHostWert(e.target.value)}
          />
        </label>

        <label className="fritz-connect__field">
          <span className="fritz-connect__label">
            {t("geraete.fritzbox.userLabel")}
          </span>
          <input
            className="fritz-connect__input"
            type="text"
            value={userWert}
            onChange={(e) => setUserWert(e.target.value)}
          />
        </label>

        <label className="fritz-connect__field">
          <span className="fritz-connect__label">
            {t("geraete.fritzbox.passwordLabel")}
          </span>
          <input
            className="fritz-connect__input"
            type="password"
            autoComplete="new-password"
            value={passwortWert}
            onChange={(e) => setPasswortWert(e.target.value)}
          />
          {passwortGesetzt && passwortWert === "" ? (
            <span className="fritz-connect__set-hint">
              {t("geraete.fritzbox.passwordIsSet")}
            </span>
          ) : null}
        </label>

        <button
          type="button"
          className="fritz-connect__button"
          onClick={handleVerbinden}
          disabled={arbeitet}
        >
          {t("geraete.fritzbox.connectButton")}
        </button>

        <p className="fritz-connect__hint">{t("geraete.fritzbox.connectHint")}</p>
      </div>
    </div>
  );
}

// Overview-Reiter: vier+ Karten in einem Gitter. WAN, Fiber/DSL (je nach
// device.isFiber), WLAN 2,4/5 GHz und Gerät.
function OverviewReiter({ detail }) {
  const { t } = useTranslation();
  const { wan, dsl, wlan24, wlan5, device } = detail;

  return (
    <div className="fritz-grid">
      <Karte title={t("geraete.fritzbox.wan.title")}>
        <Feld
          label={t("geraete.fritzbox.wan.status")}
          value={
            wan.connected
              ? t("geraete.fritzbox.wan.connected")
              : t("geraete.fritzbox.wan.disconnected")
          }
        />
        <Feld
          label={t("geraete.fritzbox.wan.ipExternal")}
          value={wan.ipExternal || "—"}
          mono
        />
        {wan.ipExternalV6 ? (
          <Feld
            label={t("geraete.fritzbox.wan.ipExternalV6")}
            value={wan.ipExternalV6}
            mono
          />
        ) : null}
        <Feld
          label={t("geraete.fritzbox.wan.uptime")}
          value={formatUptime(wan.uptimeSecs)}
        />
        <Feld
          label={t("geraete.fritzbox.wan.sent")}
          value={formatBytes(wan.bytesSent)}
        />
        <Feld
          label={t("geraete.fritzbox.wan.recv")}
          value={formatBytes(wan.bytesRecv)}
        />
      </Karte>

      {device.isFiber ? (
        <Karte title={t("geraete.fritzbox.link.title")}>
          <Feld
            label={t("geraete.fritzbox.link.downstream")}
            value={t("geraete.fritzbox.unitMbit", {
              value: kbpsZuMbit(wan.downstreamKbps),
            })}
          />
          <Feld
            label={t("geraete.fritzbox.link.upstream")}
            value={t("geraete.fritzbox.unitMbit", {
              value: kbpsZuMbit(wan.upstreamKbps),
            })}
          />
        </Karte>
      ) : (
        <Karte title={t("geraete.fritzbox.dsl.title")}>
          <Feld
            label={t("geraete.fritzbox.dsl.sync")}
            value={
              dsl.sync
                ? t("geraete.fritzbox.dsl.syncYes")
                : t("geraete.fritzbox.dsl.syncNo")
            }
          />
          <Feld
            label={t("geraete.fritzbox.dsl.downstream")}
            value={t("geraete.fritzbox.unitMbit", {
              value: kbpsZuMbit(dsl.downstreamKbps),
            })}
          />
          <Feld
            label={t("geraete.fritzbox.dsl.upstream")}
            value={t("geraete.fritzbox.unitMbit", {
              value: kbpsZuMbit(dsl.upstreamKbps),
            })}
          />
          <Feld
            label={t("geraete.fritzbox.dsl.snr")}
            value={t("geraete.fritzbox.dsl.snrValue", {
              down: dsl.snrDownstream,
              up: dsl.snrUpstream,
            })}
          />
          <Feld
            label={t("geraete.fritzbox.dsl.attn")}
            value={t("geraete.fritzbox.dsl.attnValue", {
              down: dsl.attnDownstream,
              up: dsl.attnUpstream,
            })}
          />
        </Karte>
      )}

      <Karte title={t("geraete.fritzbox.wlan.title24")}>
        <Feld
          label={t("geraete.fritzbox.wlan.status")}
          value={
            wlan24.enabled
              ? t("geraete.fritzbox.wlan.on")
              : t("geraete.fritzbox.wlan.off")
          }
        />
        <Feld label={t("geraete.fritzbox.wlan.ssid")} value={wlan24.ssid || "—"} />
        <Feld
          label={t("geraete.fritzbox.wlan.channel")}
          value={wlan24.channel || "—"}
        />
        <Feld
          label={t("geraete.fritzbox.wlan.clients")}
          value={wlan24.clients}
        />
      </Karte>

      <Karte title={t("geraete.fritzbox.wlan.title5")}>
        <Feld
          label={t("geraete.fritzbox.wlan.status")}
          value={
            wlan5.enabled
              ? t("geraete.fritzbox.wlan.on")
              : t("geraete.fritzbox.wlan.off")
          }
        />
        <Feld label={t("geraete.fritzbox.wlan.ssid")} value={wlan5.ssid || "—"} />
        <Feld
          label={t("geraete.fritzbox.wlan.channel")}
          value={wlan5.channel || "—"}
        />
        <Feld label={t("geraete.fritzbox.wlan.clients")} value={wlan5.clients} />
      </Karte>

      <Karte title={t("geraete.fritzbox.device.title")}>
        <Feld
          label={t("geraete.fritzbox.device.model")}
          value={device.model || "—"}
        />
        <Feld
          label={t("geraete.fritzbox.device.firmware")}
          value={device.firmware || "—"}
        />
        <Feld
          label={t("geraete.fritzbox.device.totalHosts")}
          value={device.totalHosts}
        />
        <Feld
          label={t("geraete.fritzbox.device.wlanClients")}
          value={wlan24.clients + wlan5.clients}
        />
      </Karte>
    </div>
  );
}

// WLAN-Clients-Reiter: Tabelle. Leere Liste -> dezenter Hinweis.
function WlanClientsReiter({ clients }) {
  const { t } = useTranslation();

  if (clients.length === 0) {
    return (
      <p className="fritz-panel__empty">
        {t("geraete.fritzbox.clients.empty")}
      </p>
    );
  }

  return (
    <div className="fritz-table-wrap">
      <table className="fritz-table">
        <thead>
          <tr>
            <th className="fritz-table__th">
              {t("geraete.fritzbox.clients.hostname")}
            </th>
            <th className="fritz-table__th">
              {t("geraete.fritzbox.clients.ip")}
            </th>
            <th className="fritz-table__th">
              {t("geraete.fritzbox.clients.mac")}
            </th>
            <th className="fritz-table__th">
              {t("geraete.fritzbox.clients.band")}
            </th>
            <th className="fritz-table__th fritz-table__th--num">
              {t("geraete.fritzbox.clients.signal")}
            </th>
            <th className="fritz-table__th fritz-table__th--num">
              {t("geraete.fritzbox.clients.speed")}
            </th>
          </tr>
        </thead>
        <tbody>
          {clients.map((client) => (
            <tr key={client.mac} className="fritz-table__row">
              <td className="fritz-table__cell">{client.hostname || "—"}</td>
              <td className="fritz-table__cell fritz-panel__mono">
                {client.ip || "—"}
              </td>
              <td className="fritz-table__cell fritz-panel__mono">
                {client.mac || "—"}
              </td>
              <td className="fritz-table__cell">{client.band || "—"}</td>
              <td className="fritz-table__cell fritz-table__cell--num">
                {client.signalDbm}
              </td>
              <td className="fritz-table__cell fritz-table__cell--num">
                {client.speedMbps}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// Log-Reiter: Liste der Event-Log-Einträge. Leere Liste -> Hinweis.
function LogReiter({ log }) {
  const { t } = useTranslation();

  if (log.length === 0) {
    return <p className="fritz-panel__empty">{t("geraete.fritzbox.log.empty")}</p>;
  }

  return (
    <div className="fritz-table-wrap">
      <table className="fritz-table">
        <thead>
          <tr>
            <th className="fritz-table__th">
              {t("geraete.fritzbox.log.timestamp")}
            </th>
            <th className="fritz-table__th">
              {t("geraete.fritzbox.log.message")}
            </th>
          </tr>
        </thead>
        <tbody>
          {log.map((eintrag) => (
            <tr key={eintrag.id} className="fritz-table__row">
              <td className="fritz-table__cell fritz-panel__mono fritz-table__cell--nowrap">
                {eintrag.timestamp}
              </td>
              <td className="fritz-table__cell">{eintrag.message}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// Portfreigaben-Reiter: Tabelle. Leere Liste -> Hinweis.
function PortForwardingsReiter({ portForwardings }) {
  const { t } = useTranslation();

  if (portForwardings.length === 0) {
    return (
      <p className="fritz-panel__empty">
        {t("geraete.fritzbox.forwardings.empty")}
      </p>
    );
  }

  return (
    <div className="fritz-table-wrap">
      <table className="fritz-table">
        <thead>
          <tr>
            <th className="fritz-table__th">
              {t("geraete.fritzbox.forwardings.enabled")}
            </th>
            <th className="fritz-table__th">
              {t("geraete.fritzbox.forwardings.description")}
            </th>
            <th className="fritz-table__th">
              {t("geraete.fritzbox.forwardings.protocol")}
            </th>
            <th className="fritz-table__th">
              {t("geraete.fritzbox.forwardings.external")}
            </th>
            <th className="fritz-table__th">
              {t("geraete.fritzbox.forwardings.internal")}
            </th>
          </tr>
        </thead>
        <tbody>
          {portForwardings.map((pf, index) => (
            <tr key={`${pf.description}-${index}`} className="fritz-table__row">
              <td className="fritz-table__cell">
                {pf.enabled
                  ? t("geraete.fritzbox.forwardings.on")
                  : t("geraete.fritzbox.forwardings.off")}
              </td>
              <td className="fritz-table__cell">{pf.description || "—"}</td>
              <td className="fritz-table__cell">{pf.protocol || "—"}</td>
              <td className="fritz-table__cell fritz-panel__mono">
                {pf.externalPort}
              </td>
              <td className="fritz-table__cell fritz-panel__mono">
                {pf.internalIp}:{pf.internalPort}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// Reiche Detailansicht: Kopfzeile + interne Reiter + aktiver Reiter-Inhalt.
function DetailAnsicht({
  detail,
  onAktualisieren,
  onBearbeiten,
  onAbmelden,
  arbeitet,
}) {
  const { t } = useTranslation();
  const [reiter, setReiter] = useState("overview");

  const kopf = [detail.device.model, detail.device.firmware]
    .filter(Boolean)
    .join(" · ");

  return (
    <div className="fritz-detail">
      <div className="fritz-detail__header">
        <div className="fritz-detail__heading">
          <h3 className="fritz-detail__title">{kopf || detail.host}</h3>
          <span className="fritz-detail__host fritz-panel__mono">
            {detail.host}
          </span>
        </div>
        <div className="fritz-detail__actions">
          <button
            type="button"
            className="fritz-detail__action"
            onClick={onAktualisieren}
            disabled={arbeitet}
          >
            {t("geraete.fritzbox.refresh")}
          </button>
          <button
            type="button"
            className="fritz-detail__action"
            onClick={onBearbeiten}
          >
            {t("geraete.fritzbox.edit")}
          </button>
          <button
            type="button"
            className="fritz-detail__action"
            onClick={onAbmelden}
            disabled={arbeitet}
          >
            {t("geraete.fritzbox.logout")}
          </button>
        </div>
      </div>

      <div className="fritz-tabs" role="tablist">
        {REITER.map((id) => {
          const istAktiv = id === reiter;
          return (
            <button
              key={id}
              type="button"
              role="tab"
              aria-selected={istAktiv}
              className={
                istAktiv ? "fritz-tabs__tab fritz-tabs__tab--active" : "fritz-tabs__tab"
              }
              onClick={() => setReiter(id)}
            >
              {t(`geraete.fritzbox.tabs.${id}`)}
            </button>
          );
        })}
      </div>

      <div className="fritz-detail__body">
        {reiter === "overview" && <OverviewReiter detail={detail} />}
        {reiter === "wlanClients" && (
          <WlanClientsReiter clients={detail.wlanClients} />
        )}
        {reiter === "log" && <LogReiter log={detail.log} />}
        {reiter === "portForwardings" && (
          <PortForwardingsReiter portForwardings={detail.portForwardings} />
        )}
      </div>
    </div>
  );
}

export default function FritzBoxPanel() {
  const { t } = useTranslation();

  // ladeStatus: laedt | bereit | fehler. modus: ansicht | verbinden.
  const [ladeStatus, setLadeStatus] = useState("laedt");
  const [detail, setDetail] = useState(null);
  const [modus, setModus] = useState("ansicht");
  const [arbeitet, setArbeitet] = useState(false);

  // Detail laden und Lade-/Modus-State daraus ableiten. Wird beim Mount, beim
  // Aktualisieren und nach dem Verbinden aufgerufen.
  const ladeDetail = async () => {
    setArbeitet(true);
    try {
      const geladen = await fetchFritzDetail();
      setDetail(geladen);
      setModus(geladen.reachable ? "ansicht" : "verbinden");
      setLadeStatus("bereit");
    } catch (fehler) {
      console.error("FritzBox-Detail laden fehlgeschlagen:", fehler);
      setLadeStatus("fehler");
    } finally {
      setArbeitet(false);
    }
  };

  // Abmelden: löscht nur das Passwort (Host/User bleiben als Vorbelegung) und
  // setzt das Detail lokal auf einen sauberen Leer-Zustand ohne Auth-Fehler, so
  // dass die Verbinden-Maske ohne Fehlerzeile erscheint. Bei Fehler in der
  // Ansicht bleiben.
  const handleAbmelden = async () => {
    setArbeitet(true);
    try {
      await updateSecret("fritz_password", "");
      setDetail({ ...mappeDetail({}), reachable: false, authError: false });
      setModus("verbinden");
    } catch (fehler) {
      console.error("FritzBox abmelden fehlgeschlagen:", fehler);
    } finally {
      setArbeitet(false);
    }
  };

  useEffect(() => {
    let aktiv = true;
    (async () => {
      try {
        const geladen = await fetchFritzDetail();
        if (!aktiv) {
          return;
        }
        setDetail(geladen);
        setModus(geladen.reachable ? "ansicht" : "verbinden");
        setLadeStatus("bereit");
      } catch (fehler) {
        if (!aktiv) {
          return;
        }
        console.error("FritzBox-Detail laden fehlgeschlagen:", fehler);
        setLadeStatus("fehler");
      }
    })();
    return () => {
      aktiv = false;
    };
  }, []);

  if (ladeStatus === "laedt") {
    return (
      <div className="fritz-panel">
        <p className="fritz-panel__loading">{t("geraete.fritzbox.loading")}</p>
      </div>
    );
  }

  if (ladeStatus === "fehler") {
    return (
      <div className="fritz-panel">
        <p className="fritz-panel__empty">{t("geraete.fritzbox.loadError")}</p>
      </div>
    );
  }

  // Verbinden-Maske: entweder explizit gewählt (Bearbeiten) oder weil die Box
  // nicht erreichbar ist. authError steuert die Fehlerzeile.
  if (modus === "verbinden" || !detail.reachable) {
    return (
      <div className="fritz-panel">
        <VerbindenMaske authFehler={detail.authError} onVerbunden={ladeDetail} />
      </div>
    );
  }

  return (
    <div className="fritz-panel">
      <DetailAnsicht
        detail={detail}
        onAktualisieren={ladeDetail}
        onBearbeiten={() => setModus("verbinden")}
        onAbmelden={handleAbmelden}
        arbeitet={arbeitet}
      />
    </div>
  );
}
