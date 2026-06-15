// Scan-Tabelle (CERNIS PRO 2.0)
// Dichte, technische Geräteliste. Bewusst kompakt — die Zielgruppe liest Tabellen.
//
// Prinzip "Auffälliges zuerst": Geräte mit isNew||notable stehen oben unter einer
// dezenten Zwischenüberschrift, darunter die bekannten Geräte. Innerhalb je
// Abschnitt nach IPv4 sortiert.
//
// Die Komponente kennt nur ihre Props (geraete, onSelect, selectedMac). Sie
// löst keine API auf und hält keinen eigenen Zustand. Klick auf eine Zeile ruft
// onSelect(geraet); selectedMac markiert die zum Detail-Panel gehörende Zeile.

import {
  Camera,
  Cpu,
  HardDrive,
  HelpCircle,
  Laptop,
  Lightbulb,
  Monitor,
  Printer,
  Router,
  Smartphone,
  Speaker,
  Thermometer,
} from "lucide-react";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import "./ScanTable.css";

// Abbildung der Mock-Icon-Schlüssel auf lucide-Komponenten.
// Hält den Mock frei von Komponenten-Referenzen.
const DEVICE_ICONS = {
  router: Router,
  nas: HardDrive,
  printer: Printer,
  laptop: Laptop,
  phone: Smartphone,
  tv: Monitor,
  speaker: Speaker,
  bulb: Lightbulb,
  camera: Camera,
  thermostat: Thermometer,
  iot: Cpu,
  unknown: HelpCircle,
};

// Wie viele Port-Chips voll angezeigt werden, bevor "+N" angehängt wird.
const MAX_PORT_CHIPS = 5;

// Abbildung sortKey -> Feld am Geräte-Objekt für die alphabetischen Spalten.
const ALPHA_FELD = {
  vendor: "vendor",
  hostname: "hostname",
  os: "osGuess",
};

// Sortiert nach IPv4 (numerisch je Oktett, nicht lexikografisch).
function nachIpv4(a, b) {
  const oktette = (ip) => ip.split(".").map((teil) => Number.parseInt(teil, 10));
  const links = oktette(a.ip);
  const rechts = oktette(b.ip);
  for (let i = 0; i < 4; i += 1) {
    if (links[i] !== rechts[i]) {
      return links[i] - rechts[i];
    }
  }
  return 0;
}

// Ist der Wert leer (null/undefined/leerer String)? Leerwerte sortieren immer
// ans Ende, unabhängig von der Richtung.
function istLeer(wert) {
  return wert === null || wert === undefined || wert === "";
}

// Alphabetischer, lokaleunabhängig stabiler Vergleich für vendor/hostname/os.
// Leerwerte landen stets unten; desc kehrt nur die Reihenfolge der nicht-leeren
// Werte um.
function nachAlpha(feld, sortDir) {
  return (a, b) => {
    const links = a[feld];
    const rechts = b[feld];
    const linksLeer = istLeer(links);
    const rechtsLeer = istLeer(rechts);
    if (linksLeer && rechtsLeer) {
      return 0;
    }
    if (linksLeer) {
      return 1;
    }
    if (rechtsLeer) {
      return -1;
    }
    const cmp = String(links ?? "").localeCompare(String(rechts ?? ""), undefined, {
      sensitivity: "base",
      numeric: true,
    });
    return sortDir === "desc" ? -cmp : cmp;
  };
}

// Port-Chips: bis MAX_PORT_CHIPS einzeln, Rest als "+N" zusammengefasst.
function PortChips({ ports }) {
  const { t } = useTranslation();

  if (ports.length === 0) {
    return <span className="scan-table__ports-leer">—</span>;
  }

  const sichtbar = ports.slice(0, MAX_PORT_CHIPS);
  const rest = ports.length - sichtbar.length;

  return (
    <span className="scan-table__ports">
      {sichtbar.map((port) => (
        <span key={`${port.num}/${port.proto}`} className="scan-table__chip">
          {port.num}
        </span>
      ))}
      {rest > 0 && (
        <span
          className="scan-table__chip scan-table__chip--mehr"
          title={t("beobachten.scan.morePortsTitle", { count: rest })}
        >
          {t("beobachten.scan.morePorts", { count: rest })}
        </span>
      )}
    </span>
  );
}

// Eine Geräte-Zeile. Klickbar; Klick meldet das Gerät an onSelect.
// selected hebt die zum offenen Detail-Panel gehörende Zeile hervor.
function GeraetZeile({ geraet, onSelect, selected }) {
  const { t } = useTranslation();
  const Icon = DEVICE_ICONS[geraet.icon] ?? HelpCircle;

  // Statuspunkt: tönt nach Auffälligkeit, ohne laute Ampel.
  const statusKlasse = geraet.isNew
    ? "scan-table__dot scan-table__dot--neu"
    : geraet.notable
      ? "scan-table__dot scan-table__dot--auffaellig"
      : "scan-table__dot scan-table__dot--bekannt";

  const rowKlasse = selected
    ? "scan-table__row scan-table__row--aktiv"
    : "scan-table__row";

  return (
    <tr className={rowKlasse} onClick={() => onSelect(geraet)}>
      <td className="scan-table__cell scan-table__cell--status">
        {selected && (
          // "Wanne" als Aktiv-Marker: vertikal, Wölbung nach innen zur Zeile
          // (analog zur Reiter-Wanne in TabNav, um 90° gedreht).
          <span className="scan-row__wanne" aria-hidden="true">
            <svg viewBox="0 0 10 100" preserveAspectRatio="none">
              <path d="M10,1 C5,1 3.5,5 3,13 L3,87 C3.5,95 5,99 10,99 C6,97 4.3,93 4,87 L4,13 C4.3,7 6,3 10,1 Z" />
            </svg>
          </span>
        )}
        <span className={statusKlasse} aria-hidden="true" />
      </td>
      <td className="scan-table__cell scan-table__cell--ip scan-table__mono">
        {geraet.ip}
      </td>
      <td className="scan-table__cell scan-table__mono">{geraet.mac}</td>
      <td className="scan-table__cell">
        <span className="scan-table__vendor">
          <span className="scan-table__vendor-icon" aria-hidden="true">
            <Icon size={15} />
          </span>
          <span className="scan-table__vendor-text">
            {geraet.vendor || "—"}
          </span>
        </span>
      </td>
      <td className="scan-table__cell">
        <span className="scan-table__hostname">
          {geraet.hostname || "—"}
          {geraet.isNew && (
            <span className="scan-table__pill scan-table__pill--neu">
              {t("beobachten.scan.newPill")}
            </span>
          )}
          {!geraet.isNew && geraet.notable && (
            <span className="scan-table__pill scan-table__pill--auffaellig">
              {t("beobachten.scan.notablePill")}
            </span>
          )}
        </span>
      </td>
      <td className="scan-table__cell">
        <PortChips ports={geraet.ports} />
      </td>
      <td className="scan-table__cell scan-table__cell--os">
        {geraet.osGuess || "—"}
      </td>
      <td className="scan-table__cell scan-table__cell--ping scan-table__mono">
        {geraet.pingMs === null || geraet.pingMs === undefined
          ? "—"
          : geraet.pingMs === 0
            ? t("beobachten.scan.pingSubMs")
            : t("beobachten.scan.pingUnit", { value: geraet.pingMs })}
      </td>
    </tr>
  );
}

export default function ScanTable({ geraete, onSelect, selectedMac }) {
  const { t } = useTranslation();

  // Aktive Spaltensortierung. Wirkt INNERHALB jeder Sektion, nicht über sie
  // hinweg. Start: IP aufsteigend.
  const [sortKey, setSortKey] = useState("ip");
  const [sortDir, setSortDir] = useState("asc");

  // Klick/Tastatur auf einem sortierbaren Spaltenkopf: aktive Spalte kehrt die
  // Richtung um, inaktive Spalte wird aktiv und startet aufsteigend.
  const sortiereNach = (key) => {
    if (key === sortKey) {
      setSortDir((dir) => (dir === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("asc");
    }
  };

  // Tastaturbedienung: Enter/Space lösen denselben Sort aus wie ein Klick.
  const beiTaste = (event, key) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      sortiereNach(key);
    }
  };

  // Zentrale Sortierung nach aktuellem sortKey/sortDir. .slice() schützt vor
  // In-Place-Mutation der Prop. IP nutzt weiterhin nachIpv4 (desc kehrt um).
  const sortiere = (liste) => {
    if (sortKey === "ip") {
      return liste
        .slice()
        .sort((a, b) => (sortDir === "desc" ? -nachIpv4(a, b) : nachIpv4(a, b)));
    }
    return liste.slice().sort(nachAlpha(ALPHA_FELD[sortKey], sortDir));
  };

  // "Auffälliges zuerst": zwei Gruppen, je nach aktiver Sortierung geordnet.
  const auffaellig = sortiere(geraete.filter((g) => g.isNew || g.notable));
  const bekannt = sortiere(geraete.filter((g) => !g.isNew && !g.notable));

  // Eine Tabellen-Sektion mit Zwischenüberschrift (als volle Zeile).
  const renderSektion = (titel, liste) => {
    if (liste.length === 0) {
      return null;
    }
    return (
      <>
        <tr className="scan-table__section">
          <th colSpan={8} className="scan-table__section-heading">
            {titel}
          </th>
        </tr>
        {liste.map((geraet) => (
          <GeraetZeile
            key={geraet.mac}
            geraet={geraet}
            onSelect={onSelect}
            selected={geraet.mac === selectedMac}
          />
        ))}
      </>
    );
  };

  return (
    <div className="scan-table">
      <table className="scan-table__table">
        <thead className="scan-table__head">
          <tr>
            <th className="scan-table__th scan-table__th--status">
              <span className="scan-table__sr">
                {t("beobachten.scan.columns.status")}
              </span>
            </th>
            <th
              className="scan-table__th scan-table__th--sortierbar"
              role="button"
              tabIndex={0}
              aria-sort={
                sortKey === "ip"
                  ? sortDir === "asc"
                    ? "ascending"
                    : "descending"
                  : "none"
              }
              onClick={() => sortiereNach("ip")}
              onKeyDown={(event) => beiTaste(event, "ip")}
            >
              {t("beobachten.scan.columns.ip")}
              {sortKey === "ip" && (
                <span className="scan-table__sort-pfeil" aria-hidden="true">
                  {sortDir === "asc" ? "↑" : "↓"}
                </span>
              )}
            </th>
            <th className="scan-table__th">{t("beobachten.scan.columns.mac")}</th>
            <th
              className="scan-table__th scan-table__th--sortierbar"
              role="button"
              tabIndex={0}
              aria-sort={
                sortKey === "vendor"
                  ? sortDir === "asc"
                    ? "ascending"
                    : "descending"
                  : "none"
              }
              onClick={() => sortiereNach("vendor")}
              onKeyDown={(event) => beiTaste(event, "vendor")}
            >
              {t("beobachten.scan.columns.vendor")}
              {sortKey === "vendor" && (
                <span className="scan-table__sort-pfeil" aria-hidden="true">
                  {sortDir === "asc" ? "↑" : "↓"}
                </span>
              )}
            </th>
            <th
              className="scan-table__th scan-table__th--sortierbar"
              role="button"
              tabIndex={0}
              aria-sort={
                sortKey === "hostname"
                  ? sortDir === "asc"
                    ? "ascending"
                    : "descending"
                  : "none"
              }
              onClick={() => sortiereNach("hostname")}
              onKeyDown={(event) => beiTaste(event, "hostname")}
            >
              {t("beobachten.scan.columns.hostname")}
              {sortKey === "hostname" && (
                <span className="scan-table__sort-pfeil" aria-hidden="true">
                  {sortDir === "asc" ? "↑" : "↓"}
                </span>
              )}
            </th>
            <th className="scan-table__th">
              {t("beobachten.scan.columns.ports")}
            </th>
            <th
              className="scan-table__th scan-table__th--sortierbar"
              role="button"
              tabIndex={0}
              aria-sort={
                sortKey === "os"
                  ? sortDir === "asc"
                    ? "ascending"
                    : "descending"
                  : "none"
              }
              onClick={() => sortiereNach("os")}
              onKeyDown={(event) => beiTaste(event, "os")}
            >
              {t("beobachten.scan.columns.os")}
              {sortKey === "os" && (
                <span className="scan-table__sort-pfeil" aria-hidden="true">
                  {sortDir === "asc" ? "↑" : "↓"}
                </span>
              )}
            </th>
            <th className="scan-table__th scan-table__th--ping">
              {t("beobachten.scan.columns.ping")}
            </th>
          </tr>
        </thead>
        <tbody>
          {renderSektion(t("beobachten.scan.sections.notable"), auffaellig)}
          {renderSektion(t("beobachten.scan.sections.known"), bekannt)}
        </tbody>
      </table>
    </div>
  );
}
