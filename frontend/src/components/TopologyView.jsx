// Radialer Topologie-Graph (CERNIS PRO 2.0)
//
// Zeigt das lokale Heimnetz als radialen Graphen: Gateway im Zentrum, alle
// übrigen Knoten auf einem Kreis ringsum. Kantenmodell "beides kombiniert":
//   durchgezogene Linie = measured (gemessene LLDP/CDP-Nachbarschaft)
//   gestrichelte Linie  = assumed  (angenommene Sternverbindung zum Gateway)
//
// Reines SVG (Linien/Kreise/Text), KEINE npm-Graph-Bibliothek — Stil wie
// RttGraph.jsx/RttSparkline.jsx. Farben ausschließlich über CSS-Variablen
// (TopologyView.css), keine Hardcodes. Eigener Fetch beim Öffnen (fetchTopology);
// ehrlicher Leerzustand, wenn weder Scan-Hosts noch LLDP-Daten vorliegen.
//
// WICHTIG (Render-Loop-Falle): t/i18n aus useTranslation() NIE in das
// useEffect-Dependency-Array — der Lade-Effekt hängt nur an einem Reload-Zähler.

import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { fetchTopology } from "../api/topology.js";
import "./TopologyView.css";

// viewBox-Quadrat. preserveAspectRatio sorgt für gleichmäßige Skalierung; das
// interne Raster bleibt fix, das Layout ist rein geometrisch (kein Pixel-Maß).
const VB = 600;
const ZENTRUM = VB / 2;
// Radius des Geräte-Kreises und der Knoten-Punkte (im viewBox-Raster).
const RING_RADIUS = 230;
const KNOTEN_R = 7;
const GATEWAY_R = 13;

// Beschriftung eines Knotens: Hostname bevorzugt, sonst IP, sonst gekürzte MAC.
function knotenLabel(node) {
  return node.hostname || node.ip || node.mac || node.id || "?";
}

// Übersetzungsschlüssel des Knoten-Typs (host/gateway/switch/network).
function typLabelKey(type) {
  if (type === "gateway") return "beobachten.topology.typGateway";
  if (type === "switch") return "beobachten.topology.typSwitch";
  if (type === "network") return "beobachten.topology.typNetwork";
  return "beobachten.topology.typHost";
}

// Berechnet die Pixel-Position jedes Knotens: das Gateway ins Zentrum, alle
// übrigen gleichmäßig auf den Ring verteilt. Gibt eine Map id -> {x, y, node}.
function berechnePositionen(nodes) {
  const gateway = nodes.find((n) => n.type === "gateway") ?? null;
  const ringNodes = nodes.filter((n) => n !== gateway);
  const positionen = new Map();
  if (gateway) {
    positionen.set(gateway.id, { x: ZENTRUM, y: ZENTRUM, node: gateway });
  }
  const anzahl = ringNodes.length || 1;
  ringNodes.forEach((node, i) => {
    // Start oben (-90°), im Uhrzeigersinn gleichmäßig verteilt.
    const winkel = (i / anzahl) * 2 * Math.PI - Math.PI / 2;
    positionen.set(node.id, {
      x: ZENTRUM + RING_RADIUS * Math.cos(winkel),
      y: ZENTRUM + RING_RADIUS * Math.sin(winkel),
      node,
    });
  });
  return positionen;
}

export default function TopologyView() {
  const { t } = useTranslation();

  const [graph, setGraph] = useState({ nodes: [], edges: [] });
  const [ladend, setLadend] = useState(true);
  const [fehler, setFehler] = useState(null);
  // Reload-Zähler: Erhöhung triggert den Lade-Effekt erneut (kein t im Dep-Array).
  const [reload, setReload] = useState(0);
  // Host-Quelle (Nutzer-Wahl): "last_scan" (Default, Live-Bild des jüngsten Scans)
  // oder "all_known" (gesamter bekannter Bestand). Eine Änderung lädt neu — daher
  // im Dep-Array; es ist ein primitiver State, NICHT t/i18n (die bleiben draußen).
  const [quelle, setQuelle] = useState("last_scan");

  useEffect(() => {
    let abgebrochen = false;
    setLadend(true);
    setFehler(null);
    fetchTopology(quelle)
      .then((daten) => {
        if (abgebrochen) return;
        setGraph(daten);
      })
      .catch(() => {
        if (abgebrochen) return;
        setFehler(true);
      })
      .finally(() => {
        if (abgebrochen) return;
        setLadend(false);
      });
    return () => {
      abgebrochen = true;
    };
  }, [reload, quelle]);

  // Segmented Control für die Host-Quelle. Auswahl setzt ``quelle`` -> Lade-Effekt
  // feuert (quelle steht im Dep-Array). Die aktive Schaltfläche trägt --aktiv +
  // aria-pressed; der Untertext darunter erklärt zielgruppengerecht, was gilt.
  const quellWahl = (
    <div className="topology__quelle" role="group" aria-label={t("beobachten.topology.quelleLabel")}>
      <button
        type="button"
        className={`topology__quelle-knopf${quelle === "last_scan" ? " topology__quelle-knopf--aktiv" : ""}`}
        aria-pressed={quelle === "last_scan"}
        onClick={() => setQuelle("last_scan")}
        disabled={ladend}
      >
        {t("beobachten.topology.quelleLetzterScan")}
      </button>
      <button
        type="button"
        className={`topology__quelle-knopf${quelle === "all_known" ? " topology__quelle-knopf--aktiv" : ""}`}
        aria-pressed={quelle === "all_known"}
        onClick={() => setQuelle("all_known")}
        disabled={ladend}
      >
        {t("beobachten.topology.quelleAlleBekannten")}
      </button>
    </div>
  );

  const quellHinweis = (
    <p className="topology__quelle-hinweis">
      {quelle === "last_scan"
        ? t("beobachten.topology.quelleHinweisLetzterScan")
        : t("beobachten.topology.quelleHinweisAlleBekannten")}
    </p>
  );

  const kopf = (
    <div className="topology__kopf">
      <span className="topology__titel">{t("beobachten.topology.titel")}</span>
      <div className="topology__kopf-rechts">
        {quellWahl}
        {graph.nodes.length > 0 ? (
          <span className="topology__anzahl">
            {t("beobachten.topology.knotenAnzahl", { count: graph.nodes.length })}
          </span>
        ) : null}
        <button
          type="button"
          className="topology__reload"
          onClick={() => setReload((n) => n + 1)}
          disabled={ladend}
        >
          {t("beobachten.topology.neuLaden")}
        </button>
      </div>
    </div>
  );

  if (fehler) {
    return (
      <div className="topology">
        {kopf}
        {quellHinweis}
        <p className="topology__leer">{t("beobachten.topology.ladeFehler")}</p>
      </div>
    );
  }

  if (graph.nodes.length === 0) {
    return (
      <div className="topology">
        {kopf}
        {quellHinweis}
        <p className="topology__leer">{t("beobachten.topology.leer")}</p>
      </div>
    );
  }

  const positionen = berechnePositionen(graph.nodes);

  // Nur Kanten zeichnen, deren beide Endpunkte eine Position haben (defensiv —
  // das Backend liefert ohnehin nur Kanten zwischen vorhandenen Knoten).
  const kanten = graph.edges
    .map((edge, i) => {
      const a = positionen.get(edge.source);
      const b = positionen.get(edge.target);
      if (!a || !b) return null;
      return { ...edge, a, b, key: `edge-${i}` };
    })
    .filter(Boolean);

  return (
    <div className="topology">
      {kopf}
      {quellHinweis}
      <div className="topology__legende">
        <span className="topology__legende-item">
          <svg className="topology__legende-svg" viewBox="0 0 28 8" aria-hidden="true">
            <line className="topology__kante topology__kante--measured" x1="1" y1="4" x2="27" y2="4" />
          </svg>
          {t("beobachten.topology.legendeGemessen")}
        </span>
        <span className="topology__legende-item">
          <svg className="topology__legende-svg" viewBox="0 0 28 8" aria-hidden="true">
            <line className="topology__kante topology__kante--assumed" x1="1" y1="4" x2="27" y2="4" />
          </svg>
          {t("beobachten.topology.legendeAngenommen")}
        </span>
      </div>
      <svg
        className="topology__svg"
        viewBox={`0 0 ${VB} ${VB}`}
        role="img"
        aria-label={t("beobachten.topology.titel")}
      >
        {/* Kanten zuerst (unter den Knoten). */}
        {kanten.map((edge) => (
          <line
            key={edge.key}
            className={`topology__kante topology__kante--${edge.kind === "measured" ? "measured" : "assumed"}`}
            x1={edge.a.x.toFixed(2)}
            y1={edge.a.y.toFixed(2)}
            x2={edge.b.x.toFixed(2)}
            y2={edge.b.y.toFixed(2)}
            vectorEffect="non-scaling-stroke"
          />
        ))}
        {/* Knoten samt Beschriftung. */}
        {[...positionen.values()].map(({ x, y, node }) => {
          const istGateway = node.type === "gateway";
          const r = istGateway ? GATEWAY_R : KNOTEN_R;
          // Beschriftung mittig unter dem Knoten, am Zentrum etwas tiefer.
          const labelY = y + r + 14;
          return (
            <g key={`node-${node.id}`} className={`topology__knoten topology__knoten--${node.type}`}>
              <title>{`${knotenLabel(node)} · ${t(typLabelKey(node.type))}`}</title>
              <circle
                className="topology__knoten-kreis"
                cx={x.toFixed(2)}
                cy={y.toFixed(2)}
                r={r}
                vectorEffect="non-scaling-stroke"
              />
              <text
                className="topology__knoten-label"
                x={x.toFixed(2)}
                y={labelY.toFixed(2)}
                textAnchor="middle"
              >
                {knotenLabel(node)}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
