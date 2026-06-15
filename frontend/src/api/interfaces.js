// Interface-Mapper (CERNIS PRO 2.0)
//
// Übersetzt die Backend-Antwort von GET /api/interfaces (Liste der lokalen
// Netzwerk-Schnittstellen, snake_case) in die View-Form (camelCase). Quelle der
// Wahrheit für die Scan-View: das primäre Interface liefert das Vorauswahl-CIDR.
// Stil bewusst wie api/traffic.js / api/scan.js: kleine reine Helfer, kein
// erfundener Fallback (fehlt ein Feld -> leer/null).
//
// Wire-Form (aus backend/api/interfaces.py):
//   { name, ipv4, ipv4_prefix, mac, gateway, mtu, network_cidr, host_count,
//     is_primary, type, status, subnet_cidr, network, broadcast, is_loopback, … }

import { apiGet } from "./client.js";

// Ein Wire-Interface -> View-Interface. snake_case -> camelCase. scanbar wird
// ABGELEITET: ein Interface ist nur dann fürs Scannen brauchbar, wenn es ein
// nicht-leeres networkCidr hat UND kein Loopback ist. Es werden trotzdem ALLE
// Interfaces zurückgegeben — die View entscheidet (zeigt nicht-scanbare als
// deaktivierte Optionen), was wählbar ist.
function mappeInterface(iface) {
  const networkCidr = iface.network_cidr ?? "";
  const istLoopback = iface.is_loopback === true;
  return {
    name: iface.name,
    ipv4: iface.ipv4 ?? "",
    ipv4Prefix: iface.ipv4_prefix ?? null,
    mac: iface.mac ?? "",
    gateway: iface.gateway ?? "",
    mtu: iface.mtu ?? null,
    networkCidr,
    hostCount: iface.host_count ?? null,
    isPrimary: iface.is_primary === true,
    type: iface.type ?? "",
    status: iface.status ?? "",
    // Scanbar nur mit echtem Netz und nicht als Loopback.
    scanbar: Boolean(networkCidr) && !istLoopback,
  };
}

// Ruft GET /api/interfaces und übersetzt die Liste in die View-Form.
export async function fetchInterfaces() {
  const backend = await apiGet("/api/interfaces");
  return (backend ?? []).map(mappeInterface);
}

// Reine Funktion: wählt aus einer Interface-Liste das für die Scan-Vorauswahl
// passende Interface. Priorität: das als primär markierte (isPrimary===true);
// sonst das erste scanbare; sonst null. Bewusst testbar exportiert.
export function primaeresInterface(interfaces) {
  const liste = interfaces ?? [];
  return (
    liste.find((iface) => iface.isPrimary === true) ??
    liste.find((iface) => iface.scanbar === true) ??
    null
  );
}

export default { fetchInterfaces, primaeresInterface };
