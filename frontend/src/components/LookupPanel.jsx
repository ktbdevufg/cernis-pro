// Gegenstellen-Ansicht (CERNIS PRO 2.0)
// Wiederverwendbares seitliches Panel: zeigt neutrale Fakten zu einer
// IP/Gegenstelle aus MEHREREN Quellen (mehrstufige Auflösung) plus externe
// Links zum Weiterprüfen. CERNIS bewertet hier NICHT — es zeigt nur die rohen
// Befunde der einzelnen Auflösungsstufen. Wo Quellen sich unterscheiden, stehen
// beide Werte nebeneinander; ein Länder-Widerspruch wird zusätzlich oben getönt
// hervorgehoben.
//
// Die Komponente kennt nur ihre Props (ip, port, onClose). Die Fakten zieht sie
// über die Resolver-Domäne aus der echten API (api/resolver.js); früher kamen
// sie aus einem lokalen Mock. Gleiche Breite/Designsprache wie die übrigen
// Detail-Panels, eigener vertikaler Scroll.
//
// Faktenfelder kommen als { value, source } (oder null = nicht gefunden). Das
// Quellen-Kürzel (DNS | RDAP | TLS | GeoDB | DNSDB) erscheint als dezentes Badge
// rechts am Wert.

import {
  Building2,
  ChevronDown,
  ExternalLink,
  Globe,
  MapPin,
  Network,
  Plug,
  TriangleAlert,
  X,
} from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { fetchLookup } from "../api/resolver.js";
import "./LookupPanel.css";

// Eine Feld-Zeile: Label links, Wert rechts mit dezentem Quellen-Badge,
// Trennlinie. `feld` ist ein { value, source }-Objekt oder null. mono tönt den
// Wert monospace. Fehlende Werte (null) erscheinen als kursives, gedämpftes
// "nicht gefunden" — ohne Quellen-Badge.
function FeldZeile({ label, feld, mono }) {
  const { t } = useTranslation();
  const fehlt = feld === null || feld === undefined || feld.value === null;

  let wertKlasse = "lookup__field-value";
  if (mono && !fehlt) {
    wertKlasse += " lookup__mono";
  }
  if (fehlt) {
    wertKlasse += " lookup__field-value--missing";
  }

  return (
    <div className="lookup__field">
      <span className="lookup__field-label">{label}</span>
      <span className="lookup__field-right">
        <span className={wertKlasse}>
          {fehlt ? t("beobachten.lookup.notFound") : feld.value}
        </span>
        {!fehlt && (
          <span
            className="lookup__source"
            title={`${t("beobachten.lookup.sourceLabel")}: ${feld.source}`}
          >
            {feld.source}
          </span>
        )}
      </span>
    </div>
  );
}

// TLS-Zertifikat-Zeile: wie eine Feld-Zeile, aber anklickbar, wenn volle
// Zertifikatsdetails (`details`) vorliegen. Klick klappt einen Detailbereich
// UNTER der Zeile auf/zu (lokaler State). Ohne Details verhält sie sich wie eine
// normale, nicht-interaktive FeldZeile.
function TlsZeile({ label, feld, details }) {
  const { t } = useTranslation();
  const [offen, setOffen] = useState(false);

  const fehlt = feld === null || feld === undefined || feld.value === null;
  const aufklappbar = !fehlt && details !== null && details !== undefined;

  // Ohne Daten oder ohne Details: unveränderte, nicht-interaktive Zeile.
  if (!aufklappbar) {
    return <FeldZeile label={label} feld={feld} mono />;
  }

  return (
    <div className="lookup__tls">
      <button
        type="button"
        className="lookup__field lookup__tls-toggle"
        aria-expanded={offen}
        onClick={() => setOffen((v) => !v)}
      >
        <span className="lookup__field-label">{label}</span>
        <span className="lookup__field-right">
          <span className="lookup__field-value lookup__mono">{feld.value}</span>
          <span
            className="lookup__source"
            title={`${t("beobachten.lookup.sourceLabel")}: ${feld.source}`}
          >
            {feld.source}
          </span>
          <span
            className={`lookup__chevron${offen ? " lookup__chevron--open" : ""}`}
            aria-hidden="true"
          >
            <ChevronDown size={15} />
          </span>
        </span>
      </button>

      {offen && (
        <div className="lookup__tls-detail">
          <FeldZeile
            label={t("beobachten.lookup.resolution.tlsSubject")}
            feld={{ value: details.subjectCN, source: "TLS" }}
            mono
          />
          <div className="lookup__field">
            <span className="lookup__field-label">
              {t("beobachten.lookup.resolution.tlsSan")}
            </span>
            <span className="lookup__field-right">
              <span className="lookup__field-value lookup__mono lookup__tls-san">
                {details.subjectAltNames.join(", ")}
              </span>
            </span>
          </div>
          <FeldZeile
            label={t("beobachten.lookup.resolution.tlsIssuer")}
            feld={{ value: details.issuer, source: "TLS" }}
          />
          <FeldZeile
            label={t("beobachten.lookup.resolution.tlsValidFrom")}
            feld={{ value: details.validFrom, source: "TLS" }}
            mono
          />
          <FeldZeile
            label={t("beobachten.lookup.resolution.tlsValidUntil")}
            feld={{ value: details.validUntil, source: "TLS" }}
            mono
          />
          <FeldZeile
            label={t("beobachten.lookup.resolution.tlsSerial")}
            feld={{ value: details.serial, source: "TLS" }}
            mono
          />
          <div className="lookup__field">
            <span className="lookup__field-label">
              {t("beobachten.lookup.resolution.tlsFingerprint")}
            </span>
            <span className="lookup__field-right">
              <span className="lookup__field-value lookup__mono lookup__tls-fp">
                {details.fingerprintSha256}
              </span>
            </span>
          </div>
          {/* Reine Feststellung, kein Urteil. */}
          {details.selfSigned && (
            <p className="lookup__tls-selfsigned">
              {t("beobachten.lookup.resolution.tlsSelfSigned")}
            </p>
          )}
        </div>
      )}
    </div>
  );
}

// Eine externe Weiterprüf-Zeile: Label + Beschreibung links, external-link-Icon
// rechts. VORERST PLATZHALTER (kein echtes Ziel).
function ExternZeile({ label, hint, onClick }) {
  return (
    <button type="button" className="lookup__extern" onClick={onClick}>
      <span className="lookup__extern-text">
        <span className="lookup__extern-label">{label}</span>
        <span className="lookup__extern-hint">{hint}</span>
      </span>
      <span className="lookup__extern-icon" aria-hidden="true">
        <ExternalLink size={15} />
      </span>
    </button>
  );
}

export default function LookupPanel({ ip, port, onClose }) {
  const { t } = useTranslation();

  // Drei Zustände: "laedt" (Request läuft), "ok" (Fakten da), "fehler"
  // (Auflösung nicht erreichbar). Der Header zeigt immer ip:port aus den Props.
  const [status, setStatus] = useState("laedt");
  const [fakten, setFakten] = useState(null);

  useEffect(() => {
    // Bei Wechsel von ip/port die alte (evtl. noch laufende) Antwort verwerfen,
    // damit sie nicht den State der neuen Anfrage überschreibt.
    let ignorieren = false;
    setStatus("laedt");
    setFakten(null);

    fetchLookup(ip, port)
      .then((ergebnis) => {
        if (!ignorieren) {
          setFakten(ergebnis);
          setStatus("ok");
        }
      })
      .catch(() => {
        if (!ignorieren) {
          setStatus("fehler");
        }
      });

    return () => {
      ignorieren = true;
    };
  }, [ip, port]);

  // TEMP: externe Ziel-URLs werden mit echter Anbindung gesetzt (Datenhoheit/cpnetcheck).
  const handleExtern = () => {
    // Bewusst ohne Ziel (Platzhalter).
  };

  return (
    <aside className="lookup">
      <div className="lookup__header">
        <div className="lookup__heading">
          <span className="lookup__icon" aria-hidden="true">
            <Globe size={18} />
          </span>
          <div className="lookup__title-group">
            <h3 className="lookup__title">{t("beobachten.lookup.title")}</h3>
            <span className="lookup__subtitle lookup__mono">
              {ip}:{port}
            </span>
          </div>
        </div>
        <button
          type="button"
          className="lookup__close"
          onClick={onClose}
          aria-label={t("beobachten.lookup.close")}
          title={t("beobachten.lookup.close")}
        >
          <X size={18} />
        </button>
      </div>

      {status === "laedt" && (
        <div className="lookup__body">
          <p className="lookup__notice">{t("beobachten.lookup.loading")}</p>
        </div>
      )}

      {status === "fehler" && (
        <div className="lookup__body">
          <p className="lookup__notice">{t("beobachten.lookup.error")}</p>
        </div>
      )}

      {status === "ok" && fakten && (
      <div className="lookup__body">
        {/* Neutraler Hinweis: reine Fakten, kein Urteil. */}
        <p className="lookup__notice">{t("beobachten.lookup.notice")}</p>

        {/* Länder-Widerspruch: nur wenn aktiv, getönt in sev-med. */}
        {fakten.countryConflict !== null && (
          <p className="lookup__conflict">
            <TriangleAlert size={15} aria-hidden="true" />
            <span className="lookup__conflict-text">
              <span className="lookup__conflict-label">
                {t("beobachten.lookup.conflict.label")}
              </span>
              <span>{fakten.countryConflict.text}</span>
            </span>
          </p>
        )}

        {/* 1. Namensauflösung */}
        <section className="lookup__section">
          <h4 className="lookup__section-heading">
            <Network size={15} aria-hidden="true" />
            <span>{t("beobachten.lookup.resolution.heading")}</span>
          </h4>
          <div className="lookup__fields">
            <FeldZeile
              label={t("beobachten.lookup.resolution.ptr")}
              feld={fakten.ptr}
              mono
            />
            <FeldZeile
              label={t("beobachten.lookup.resolution.forward")}
              feld={fakten.forwardConfirmed}
            />
            <TlsZeile
              label={t("beobachten.lookup.resolution.tls")}
              feld={fakten.tlsCert}
              details={fakten.tlsCertDetails}
            />
            {/* DynDNS-Datenbank nur, wenn ein Treffer vorliegt. */}
            {fakten.dyndns !== null && (
              <FeldZeile
                label={t("beobachten.lookup.resolution.dyndns")}
                feld={fakten.dyndns}
                mono
              />
            )}
          </div>
        </section>

        {/* 2. Betreiber & Netz */}
        <section className="lookup__section">
          <h4 className="lookup__section-heading">
            <Building2 size={15} aria-hidden="true" />
            <span>{t("beobachten.lookup.operator.heading")}</span>
          </h4>
          <div className="lookup__fields">
            <FeldZeile
              label={t("beobachten.lookup.operator.org")}
              feld={fakten.org}
            />
            <FeldZeile
              label={t("beobachten.lookup.operator.netname")}
              feld={fakten.netname}
            />
            <FeldZeile
              label={t("beobachten.lookup.operator.netRange")}
              feld={fakten.netRange}
              mono
            />
            <FeldZeile
              label={t("beobachten.lookup.operator.asn")}
              feld={fakten.asn}
              mono
            />
            <FeldZeile
              label={t("beobachten.lookup.operator.asnOrg")}
              feld={fakten.asnOrg}
            />
            <FeldZeile
              label={t("beobachten.lookup.operator.abuse")}
              feld={fakten.abuseContact}
              mono
            />
          </div>
        </section>

        {/* 3. Standort — drei getrennte Quellen-Zeilen (Unterschiede sichtbar). */}
        <section className="lookup__section">
          <h4 className="lookup__section-heading">
            <MapPin size={15} aria-hidden="true" />
            <span>{t("beobachten.lookup.location.heading")}</span>
          </h4>
          <div className="lookup__fields">
            <FeldZeile
              label={t("beobachten.lookup.location.rdapNet")}
              feld={fakten.countryRdapNet}
            />
            <FeldZeile
              label={t("beobachten.lookup.location.orgAddress")}
              feld={fakten.countryOrgAddress}
            />
            <FeldZeile
              label={t("beobachten.lookup.location.geoDb")}
              feld={fakten.countryGeoDb}
            />
          </div>
        </section>

        {/* 4. Dienst am Port */}
        <section className="lookup__section">
          <h4 className="lookup__section-heading">
            <Plug size={15} aria-hidden="true" />
            <span>{t("beobachten.lookup.service.heading")}</span>
          </h4>
          <p className="lookup__service">{fakten.serviceHint}</p>
          <div className="lookup__fields">
            <FeldZeile
              label={t("beobachten.lookup.service.banner")}
              feld={fakten.banner}
              mono
            />
          </div>
        </section>

        {/* 5. Selbst weiterprüfen — externe Links (vorerst Platzhalter). */}
        <section className="lookup__section">
          <h4 className="lookup__section-heading">
            <ExternalLink size={15} aria-hidden="true" />
            <span>{t("beobachten.lookup.external.heading")}</span>
          </h4>
          <div className="lookup__externs">
            <ExternZeile
              label={t("beobachten.lookup.external.whois.label")}
              hint={t("beobachten.lookup.external.whois.hint")}
              onClick={handleExtern}
            />
            <ExternZeile
              label={t("beobachten.lookup.external.reputation.label")}
              hint={t("beobachten.lookup.external.reputation.hint")}
              onClick={handleExtern}
            />
            <ExternZeile
              label={t("beobachten.lookup.external.geo.label")}
              hint={t("beobachten.lookup.external.geo.hint")}
              onClick={handleExtern}
            />
          </div>
        </section>
      </div>
      )}
    </aside>
  );
}
