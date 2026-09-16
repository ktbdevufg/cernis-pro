// Route-zum-Ziel-Mapper (CERNIS PRO 2.0)
//
// Bindet die zwei Backend-Nähte der "Route zum Ziel"-Funktion an (ADR 0036):
//   * fetchRoute(target, privileged) -> lokaler Hauptpfad: traceroute-Hops je
//     IP mit Land + ASN-Nummer (lokal, schnell, kein Root-Zwang). asn_org ist
//     im Hauptpfad immer null (die lokale Geo-DB kennt es nicht).
//   * fetchRouteOrgs(ips) -> OPTIONALE Nachladung: Betreibername je Hop-IP über
//     RDAP (Internet-Abfrage), nur auf expliziten Nutzer-Wunsch.
//   * fetchTraceroutePermission() -> { ok, error }: privilegiert ist genauer,
//     unprivilegiert läuft trotzdem (keine Sackgasse).
//
// Backend snake_case -> Frontend camelCase. Fehlende Werte bleiben null (kein
// erfundener Wert); eine null-IP/rtt ist eine ehrliche Lücke (nicht-antwortender
// Hop), KEIN Fehler.

import { apiGet } from "./client.js";

// Ein roher Hop-Eintrag aus GET /api/diagnostics/route -> View-Struktur.
// address/rttMs sind null bei einer Lücke; country/asn/asnOrg null, wenn die
// lokale Geo-DB nichts liefert (asnOrg im Hauptpfad immer null).
function mappeHop(hop) {
  return {
    hop: hop.hop,
    address: hop.address ?? null,
    rttMs: hop.rtt_ms ?? null,
    country: hop.country ?? null,
    asn: hop.asn ?? null,
    asnOrg: hop.asn_org ?? null,
  };
}

// Lokaler Hauptpfad: misst den Pfad zu target und reichert jeden Hop lokal mit
// Land + ASN an. privileged ist optional (Default false) — der unprivilegierte
// Pfad funktioniert ohne Root. Liefert { target, privileged, hops: [...] }.
export async function fetchRoute(target, privileged = false) {
  const backend = await apiGet("/api/diagnostics/route", { target, privileged });
  return {
    target: backend.target,
    privileged: Boolean(backend.privileged),
    hops: (backend.hops ?? []).map(mappeHop),
  };
}

// Optionale Org-Namen-Nachladung über RDAP (Internet-Abfrage). ips ist die Liste
// der antwortenden Hop-IPs; sie werden als wiederholter Query-Param ?ips=&ips=
// gesendet (apiGet kann das nicht, daher hier von Hand gebaut). Liefert eine
// { ip: org }-Map — nur IPs MIT gefundenem Namen. Streng fehlertolerant im
// Backend: eine IP ohne Treffer fehlt schlicht in der Map.
export async function fetchRouteOrgs(ips) {
  const query = new URLSearchParams();
  for (const ip of ips) {
    if (ip) {
      query.append("ips", ip);
    }
  }
  const backend = await apiGet(`/api/diagnostics/route/orgs?${query.toString()}`);
  return backend.orgs ?? {};
}

// Rechte-Status der genaueren traceroute-Methode. { ok, error } wird unverändert
// durchgereicht — der Text kommt direkt aus dem Backend (nicht neu erfinden); die
// View zeigt ihn bei ok===false als ruhigen Hinweis (keine Sackgasse).
export async function fetchTraceroutePermission() {
  const backend = await apiGet("/api/diagnostics/traceroute/permission");
  return { ok: Boolean(backend.ok), error: backend.error ?? null };
}
