// Topologie-Mapper (CERNIS PRO 2.0)
//
// Übersetzt die Backend-Antwort von GET /api/topology (radialer Heimnetz-Graph,
// snake_case-frei: nodes/edges sind bereits flach) in die View-Form (camelCase).
// Stil bewusst wie api/interfaces.js / api/scan.js: kleine reine Helfer, kein
// erfundener Fallback (fehlt ein Feld -> leer). Der ehrliche Leerzustand des
// Backends ({nodes:[], edges:[]}) wird 1:1 durchgereicht.
//
// Wire-Form (aus backend/api/capture.py, ADR 0035):
//   nodes: { id, type, ip, mac, hostname, vendor, description, port, protocol }
//   edges: { source, target, kind }  // kind: "measured" | "assumed"

import { apiGet } from "./client.js";

// Ein Wire-Knoten -> View-Knoten. ``type`` ist host | gateway | switch | network.
function mappeNode(node) {
  return {
    id: node.id ?? "",
    type: node.type ?? "host",
    ip: node.ip ?? "",
    mac: node.mac ?? "",
    hostname: node.hostname ?? "",
    vendor: node.vendor ?? "",
    description: node.description ?? "",
    port: node.port ?? "",
    protocol: node.protocol ?? "",
  };
}

// Eine Wire-Kante -> View-Kante. ``kind`` ist measured (gemessen, durchgezogen)
// oder assumed (angenommen, gestrichelt).
function mappeEdge(edge) {
  return {
    source: edge.source ?? "",
    target: edge.target ?? "",
    kind: edge.kind ?? "assumed",
  };
}

// Ruft GET /api/topology und übersetzt nodes/edges in die View-Form.
// ``source`` waehlt die Host-Quelle (Backend-Default "last_scan"):
//   "last_scan" -> nur die Hosts des juengsten gespeicherten Scans (Live-Bild),
//   "all_known" -> der gesamte bekannte Geraete-Bestand (auch offline).
// Wird der Param ausgelassen, entscheidet der Backend-Default.
export async function fetchTopology(source = "last_scan") {
  const backend = await apiGet("/api/topology", { source });
  return {
    nodes: (backend?.nodes ?? []).map(mappeNode),
    edges: (backend?.edges ?? []).map(mappeEdge),
  };
}

export default { fetchTopology };
