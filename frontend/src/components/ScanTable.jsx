// Scan-Tabelle (CERNIS PRO 2.0)
// Dichte, technische Geräteliste. Bewusst kompakt — die Zielgruppe liest Tabellen.
//
// EINE schlichte Geräteliste, nach aktueller Sortierung geordnet (Start: IPv4).
// "neu" (isNew) kommt aus der Baseline (is_known) und wird über Statuspunkt-Farbe +
// Pille markiert — keine getrennten Sektionen. notable ist derzeit stets false
// (eigene Auffälligkeits-Quelle folgt in einem späteren Schnitt).
//
// Die Komponente kennt nur ihre Props (geraete, onSelect, selectedSchluessel,
// sichtbareSpalten). Sie löst keine API auf und hält keinen Persistenz-Zustand.
// Klick auf eine Zeile ruft onSelect(geraet); selectedSchluessel markiert die zum
// Detail-Panel gehörende Zeile (Schlüssel = MAC oder, ohne MAC, IP).
//
// Spalten sind datengetrieben: eine Definitionsliste (baueSpalten) liefert
// Kopf UND Zellen. Fixe Spalten (status, ip) sind immer sichtbar; umschaltbare
// folgen der Prop sichtbareSpalten (Set/Array der sichtbaren IDs). Reihenfolge
// ist fest durch die Definitionsreihenfolge.

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

// Umschaltbare Spalten-IDs in fester Anzeige-Reihenfolge. ipv6 ist NEU und
// standardmäßig AUS — der Default unten lässt es bewusst weg. ssdp steht direkt
// hinter mdns (beides Dienst-Erkennung, aber getrennte Verfahren) und ist
// ebenfalls standardmäßig AUS.
export const UMSCHALTBARE_SPALTEN = [
  "ipv6",
  "mac",
  "vendor",
  "hostname",
  "ports",
  "mdns",
  "ssdp",
  "os",
  "ping",
];

// Default-Sichtbarkeit: alle umschaltbaren Spalten AUSSER ipv6, mdns und ssdp.
export const DEFAULT_SICHTBARE_SPALTEN = UMSCHALTBARE_SPALTEN.filter(
  (id) => id !== "ipv6" && id !== "mdns" && id !== "ssdp",
);

// Formatiert den Ping-Wert (ms) für die Anzeige. Unverändert aus der bisherigen
// Zellenlogik gezogen, damit die Spalten-Definition sie nutzen kann.
function formatPing(geraet, t) {
  if (geraet.pingMs === null || geraet.pingMs === undefined) {
    return "—";
  }
  if (geraet.pingMs === 0) {
    return t("beobachten.scan.pingSubMs");
  }
  return t("beobachten.scan.pingUnit", { value: geraet.pingMs });
}

// Spalten-Definition (Reihenfolge = Anzeige-Reihenfolge). Jede Spalte:
//   { id, fix?, sortKey?, thClass?, tdClass?, render(geraet, ctx) }
// ctx = { t, selected, Icon }. Optik/Logik der Zellen sind 1:1 die bisherigen;
// nur die Struktur ist jetzt datengetrieben. IPv6 ist direkt nach IP einsortiert.
function baueSpalten() {
  return [
    {
      id: "status",
      fix: true,
      sortKey: null,
      thClass: "scan-table__th--status",
      tdClass: "scan-table__cell--status",
      render: (geraet, { t: _t, selected }) => {
        // Böppel = reiner Aktiv-Status: leuchtend grün bei aktiver Antwort
        // (source === "ping"), blass dunkelgrün bei inaktiven Importen (FritzBox).
        // "neu"/"auffällig" laufen NICHT über den Böppel (eigene Pillen).
        const istAktiv = geraet.source === "ping";
        const statusKlasse = istAktiv
          ? "scan-table__dot scan-table__dot--aktiv"
          : "scan-table__dot scan-table__dot--inaktiv";
        return (
          <>
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
          </>
        );
      },
    },
    {
      id: "ip",
      fix: true,
      sortKey: "ip",
      tdClass: "scan-table__cell--ip scan-table__mono",
      render: (geraet, { t }) => {
        // Achse A (Fakt): neu/geändert aus der Baseline. Disjunkt — höchstens eine.
        const hatAchseA = geraet.isNew || geraet.isChanged;
        // Achse B (Bewertung, ADR 0029+0030): auffällig/kritisch aus dem Frame.
        const achseB = geraet.analysisSeverity;
        // Trenner nur, wenn BEIDE Achsen eine Pille zeigen (keine leere Lücke).
        const zeigeTrenner = achseB !== null && hatAchseA;
        return (
          <span className="scan-table__ip-zelle">
            <span>{geraet.ip}</span>
            {/* Reihenfolge bedeutet Achse, nicht Severity: links Achse B
                (Bewertung), Trenner, rechts Achse A (Fakt). */}
            {achseB === "critical" ? (
              <span className="scan-table__pill scan-table__pill--kritisch">
                {t("beobachten.scan.kritischPill")}
              </span>
            ) : achseB === "notable" ? (
              <span className="scan-table__pill scan-table__pill--auffaellig">
                {t("beobachten.scan.auffaelligPill")}
              </span>
            ) : null}
            {zeigeTrenner && (
              <span className="scan-table__pill-trenner" aria-hidden="true" />
            )}
            {geraet.isNew ? (
              <span className="scan-table__pill scan-table__pill--neu">
                {t("beobachten.scan.newPill")}
              </span>
            ) : geraet.isChanged ? (
              <span className="scan-table__pill scan-table__pill--geaendert">
                {t("beobachten.scan.changedPill")}
              </span>
            ) : null}
          </span>
        );
      },
    },
    {
      id: "ipv6",
      sortKey: null,
      tdClass: "scan-table__mono",
      render: (geraet) => geraet.ipv6 || "—",
    },
    {
      id: "mac",
      sortKey: null,
      tdClass: "scan-table__mono",
      render: (geraet) => geraet.mac,
    },
    {
      id: "vendor",
      sortKey: "vendor",
      render: (geraet, { Icon }) => (
        <span className="scan-table__vendor">
          <span className="scan-table__vendor-icon" aria-hidden="true">
            <Icon size={15} />
          </span>
          <span className="scan-table__vendor-text">{geraet.vendor || "—"}</span>
        </span>
      ),
    },
    {
      id: "hostname",
      sortKey: "hostname",
      render: (geraet) => (
        <span className="scan-table__hostname">{geraet.hostname || "—"}</span>
      ),
    },
    {
      id: "ports",
      sortKey: null,
      render: (geraet) => (
        <PortChips ports={geraet.ports} flaggedPorts={geraet.flaggedPorts} />
      ),
    },
    {
      id: "mdns",
      sortKey: null,
      render: (geraet) => (
        <MdnsChips services={geraet.mdnsServices} isNdi={geraet.isNdi} />
      ),
    },
    {
      id: "ssdp",
      sortKey: null,
      render: (geraet) => <SsdpChips services={geraet.ssdpServices} />,
    },
    {
      id: "os",
      sortKey: "os",
      tdClass: "scan-table__cell--os",
      render: (geraet) => geraet.osGuess || "—",
    },
    {
      id: "ping",
      sortKey: null,
      thClass: "scan-table__th--ping",
      tdClass: "scan-table__cell--ping scan-table__mono",
      render: (geraet, { t }) => formatPing(geraet, t),
    },
  ];
}

// Filtert die volle Spalten-Definition auf die sichtbaren: fixe Spalten immer,
// umschaltbare nur, wenn ihre ID in sichtbar (Set) enthalten ist.
function sichtbareSpaltenAuswahl(alle, sichtbar) {
  return alle.filter((spalte) => spalte.fix || sichtbar.has(spalte.id));
}

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

// Severity eines Ports aus flaggedPorts (Achse B, Variante C): num in critical
// -> "kritisch", sonst in notable -> "auffaellig", sonst null. critical hat
// Vorrang, falls ein Port (theoretisch) in beiden Listen stünde. Liefert die
// passende Chip-Modifier-Klasse oder leeren String (neutral).
function chipSeverityKlasse(num, flaggedPorts) {
  const kritisch = flaggedPorts?.critical ?? [];
  const auffaellig = flaggedPorts?.notable ?? [];
  if (kritisch.includes(num)) {
    return " scan-table__chip--kritisch";
  }
  if (auffaellig.includes(num)) {
    return " scan-table__chip--auffaellig";
  }
  return "";
}

// Port-Chips: bis MAX_PORT_CHIPS einzeln, Rest als "+N" zusammengefasst.
// flaggedPorts (Achse B) färbt einzelne Chips orange/rot; die "+N"-
// Zusammenfassung trägt keine Färbung (best-effort, die wichtigsten Ports
// stehen vorne).
function PortChips({ ports, flaggedPorts }) {
  const { t } = useTranslation();

  if (ports.length === 0) {
    return <span className="scan-table__ports-leer">—</span>;
  }

  const sichtbar = ports.slice(0, MAX_PORT_CHIPS);
  const rest = ports.length - sichtbar.length;

  return (
    <span className="scan-table__ports">
      {sichtbar.map((port) => (
        <span
          key={`${port.num}/${port.proto}`}
          className={`scan-table__chip${chipSeverityKlasse(port.num, flaggedPorts)}`}
        >
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

// Kürzt einen mDNS-Service-Typ auf das lesbare Kernwort:
// "_googlecast._tcp.local." -> "googlecast", "_pdl-datastream._tcp.local."
// -> "pdl-datastream". Führenden Unterstrich entfernen, am ersten Punkt
// abschneiden. Leere/untypische Werte fallen unverändert durch.
function kuerzeMdnsTyp(typ) {
  if (!typ) return typ;
  const ohneUnterstrich = typ.startsWith("_") ? typ.slice(1) : typ;
  const ersterPunkt = ohneUnterstrich.indexOf(".");
  return ersterPunkt > 0 ? ohneUnterstrich.slice(0, ersterPunkt) : ohneUnterstrich;
}

// mDNS/NDI-Zelle: optionales NDI-Badge (hervorgehoben) gefolgt von gekürzten
// mDNS-Dienst-Chips. Leer -> "—". Begrenzung wie Ports (MAX_PORT_CHIPS) mit
// "+N"-Rest.
function MdnsChips({ services, isNdi }) {
  const { t } = useTranslation();
  const hatNichts = (!services || services.length === 0) && !isNdi;
  if (hatNichts) {
    return <span className="scan-table__ports-leer">—</span>;
  }
  const sichtbar = (services ?? []).slice(0, MAX_PORT_CHIPS);
  const rest = (services ?? []).length - sichtbar.length;
  return (
    <span className="scan-table__ports">
      {isNdi && (
        <span className="scan-table__chip scan-table__chip--ndi">NDI</span>
      )}
      {sichtbar.map((typ) => (
        <span
          key={typ}
          className="scan-table__chip scan-table__chip--mdns"
          // Die Kürzung ist eine Anzeigehilfe, kein Informationsverlust: der
          // vollständige Diensttyp bleibt am selben Chip erreichbar.
          title={typ}
        >
          {kuerzeMdnsTyp(typ)}
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

// Beschriftung eines SSDP-Chips: server, wenn vorhanden, sonst st. Ist beides
// leer, liefert die Funktion einen leeren String — der Eintrag wird dann NICHT
// dargestellt (kein Ersatzwert, keine Erfindung). Exportiert, damit das
// Detail-Panel dieselbe Regel nutzt statt sie zu kopieren.
export function ssdpChipText(dienst) {
  return dienst?.server || dienst?.st || "";
}

// SSDP-/UPnP-Zelle: eigene Komponente statt Wiederverwendung von MdnsChips, weil
// SSDP andere Felder trägt (server/st/location statt Dienst-Typ). Optik und
// Kürzungsverhalten folgen MdnsChips: bis MAX_PORT_CHIPS einzeln, Rest als "+N".
// SSDP hat eine eigene Farbfamilie (--chip-ssdp-*); der Chip-Text ist server,
// sonst st. Leer -> "—" wie bei mDNS/Ports.
function SsdpChips({ services }) {
  const { t } = useTranslation();
  // Einträge ohne jeden Text (weder server noch st) fallen VOR der Begrenzung
  // heraus, damit "+N" die tatsächlich darstellbaren Dienste zählt.
  const darstellbar = (services ?? []).filter((dienst) => ssdpChipText(dienst));
  if (darstellbar.length === 0) {
    return <span className="scan-table__ports-leer">—</span>;
  }
  const sichtbar = darstellbar.slice(0, MAX_PORT_CHIPS);
  const rest = darstellbar.length - sichtbar.length;
  return (
    <span className="scan-table__ports">
      {sichtbar.map((dienst, index) => (
        <span
          // Kein fachlicher Schlüssel vorhanden: server/st sind pro Gerät nicht
          // garantiert eindeutig. Text + Index hält die Liste stabil.
          key={`${ssdpChipText(dienst)}#${index}`}
          className="scan-table__chip scan-table__chip--ssdp"
          // Gegenstück zum Detail: die Tabelle zeigt nur server/st, die Location
          // bleibt hier erreichbar. Ohne Location kein leerer Tooltip.
          title={dienst.location || undefined}
        >
          {ssdpChipText(dienst)}
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
// selected hebt die zum offenen Detail-Panel gehörende Zeile hervor. Die Zellen
// kommen aus spalten (sichtbare Spalten-Definition) via spalte.render.
function GeraetZeile({ geraet, onSelect, selected, spalten }) {
  const { t } = useTranslation();
  const Icon = DEVICE_ICONS[geraet.icon] ?? HelpCircle;
  const ctx = { t, selected, Icon };

  const rowKlasse = selected
    ? "scan-table__row scan-table__row--aktiv"
    : "scan-table__row";

  return (
    <tr className={rowKlasse} onClick={() => onSelect(geraet)}>
      {spalten.map((spalte) => (
        <td
          key={spalte.id}
          className={
            spalte.tdClass
              ? `scan-table__cell ${spalte.tdClass}`
              : "scan-table__cell"
          }
        >
          {spalte.render(geraet, ctx)}
        </td>
      ))}
    </tr>
  );
}

// Ein Spaltenkopf. Sortierbare Köpfe (sortKey != null) behalten das bestehende
// Verhalten (role=button, tabIndex, aria-sort, Pfeil). Status-Kopf bleibt rein
// visuell (Screenreader-Label); übrige nicht-sortierbare Köpfe sind schlicht.
function SpaltenKopf({ spalte, sortKey, sortDir, sortiereNach, beiTaste, t }) {
  const basisKlasse = spalte.thClass
    ? `scan-table__th ${spalte.thClass}`
    : "scan-table__th";
  const label = t(`beobachten.scan.columns.${spalte.id}`);

  if (spalte.id === "status") {
    return (
      <th className={basisKlasse}>
        <span className="scan-table__sr">{label}</span>
      </th>
    );
  }

  if (!spalte.sortKey) {
    return <th className={basisKlasse}>{label}</th>;
  }

  const aktiv = sortKey === spalte.sortKey;
  return (
    <th
      className={`${basisKlasse} scan-table__th--sortierbar`}
      role="button"
      tabIndex={0}
      aria-sort={aktiv ? (sortDir === "asc" ? "ascending" : "descending") : "none"}
      onClick={() => sortiereNach(spalte.sortKey)}
      onKeyDown={(event) => beiTaste(event, spalte.sortKey)}
    >
      {label}
      {aktiv && (
        <span className="scan-table__sort-pfeil" aria-hidden="true">
          {sortDir === "asc" ? "↑" : "↓"}
        </span>
      )}
    </th>
  );
}

export default function ScanTable({
  geraete,
  onSelect,
  selectedSchluessel,
  sichtbareSpalten,
}) {
  const { t } = useTranslation();

  // Sichtbare umschaltbare Spalten als Set (fixe Spalten kommen immer dazu).
  // Fehlt die Prop, gilt der Default (alle umschaltbaren außer ipv6).
  const sichtbarSet = new Set(sichtbareSpalten ?? DEFAULT_SICHTBARE_SPALTEN);
  const spalten = sichtbareSpaltenAuswahl(baueSpalten(), sichtbarSet);

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

  // EINE schlichte Geräteliste in aktueller Sortierung (keine Sektionen mehr).
  const sortierteGeraete = sortiere(geraete);

  return (
    <div className="scan-table">
      <table className="scan-table__table">
        <thead className="scan-table__head">
          <tr>
            {spalten.map((spalte) => (
              <SpaltenKopf
                key={spalte.id}
                spalte={spalte}
                sortKey={sortKey}
                sortDir={sortDir}
                sortiereNach={sortiereNach}
                beiTaste={beiTaste}
                t={t}
              />
            ))}
          </tr>
        </thead>
        <tbody>
          {sortierteGeraete.map((geraet) => (
            <GeraetZeile
              key={geraet.schluessel}
              geraet={geraet}
              onSelect={onSelect}
              selected={geraet.schluessel === selectedSchluessel}
              spalten={spalten}
            />
          ))}
        </tbody>
      </table>
    </div>
  );
}
