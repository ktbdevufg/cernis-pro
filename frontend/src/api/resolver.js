// Resolver-Mapper (CERNIS PRO 2.0)
//
// Übersetzt die Backend-Antwort von GET /api/resolve (snake_case, jedes Feld
// als { value, source } mit lowercase-Quelle) in EXAKT die Struktur, die
// LookupPanel früher aus dem lokalen Mock bekam, jetzt aber aus der API —
// camelCase, Quellen-Kürzel in Anzeigeform, null = nicht gefunden. So bleibt
// das Panel-Markup praktisch unverändert.
//
// Wire-Form (aus backend/api/resolver.py): ptr, forward_confirmed, tls_cert,
// dyndns, org, netname, net_range, asn, asn_org, abuse_contact,
// country_rdap_net, country_org_address, country_geodb, service_hint, banner —
// alle als { value, source }; tls_cert.value verschachtelt (subject_cn, san[],
// issuer, valid_from, valid_until, serial, fingerprint_sha256, self_signed)
// oder null; country_conflict als bool.

import { apiGet } from "./client.js";

// Quellen-Kürzel auf die Anzeigeform normalisieren. Reiner Helfer.
function normSource(source) {
  const KARTE = {
    dns: "DNS",
    rdap: "RDAP",
    tls: "TLS",
    geodb: "GeoDB",
    dnsdb: "DNSDB",
  };
  return KARTE[source] ?? source;
}

// Backend-Feld { value, source } -> Frontend { value, source: normSource(...) }.
// Wenn value null/leer ist, das ganze Feld auf null setzen (Mock-Konvention:
// null = nicht gefunden, kein Badge).
function feld(backendField) {
  if (
    backendField === null ||
    backendField === undefined ||
    backendField.value === null ||
    backendField.value === undefined ||
    backendField.value === ""
  ) {
    return null;
  }
  return { value: backendField.value, source: normSource(backendField.source) };
}

// --- Länder-Widerspruch (Logik früher im Mock, hierher übernommen) --------

// Extrahiert aus einem Länder-Feld nur das Land-Kürzel für den Vergleich
// (z. B. "ES (Alicante)" -> "ES"). null bleibt null.
function landKuerzel(landFeld) {
  if (landFeld === null) {
    return null;
  }
  return String(landFeld.value).trim().slice(0, 2).toUpperCase();
}

// Leitet aus den drei Länder-Quellen einen Widerspruch ab. Liefert null, wenn
// alle vorhandenen Quellen dasselbe Land nennen, sonst { text } mit einem
// neutralen Klartext, der die abweichenden Quellen benennt.
function laenderKonflikt(countryRdapNet, countryOrgAddress, countryGeoDb) {
  const quellen = [
    { label: "RDAP-Netz", land: landKuerzel(countryRdapNet), voll: countryRdapNet },
    { label: "Organisation", land: landKuerzel(countryOrgAddress), voll: countryOrgAddress },
    { label: "Geo-DB", land: landKuerzel(countryGeoDb), voll: countryGeoDb },
  ].filter((q) => q.land !== null);

  const verschieden = new Set(quellen.map((q) => q.land));
  if (verschieden.size < 2) {
    return null;
  }

  // Klartext: jede Quelle mit ihrem (vollen) Länder-Wert benennen.
  const teile = quellen.map((q) => `${q.label} nennt ${q.voll.value}`);
  return { text: teile.join(", ") };
}

// Neutrales { text }, das die vorhandenen Länderwerte nebeneinanderstellt —
// ohne von einem erkannten Widerspruch auszugehen. Greift, wenn der Backend-bool
// country_conflict true ist, die obige Klartext-Logik aber null liefern würde
// (z. B. weil < 2 verschiedene Länder erkennbar sind). Der Backend-bool hat
// Vorrang für die Sichtbarkeit.
function neutralerLaenderText(countryRdapNet, countryOrgAddress, countryGeoDb) {
  const quellen = [
    { label: "RDAP-Netz", voll: countryRdapNet },
    { label: "Organisation", voll: countryOrgAddress },
    { label: "Geo-DB", voll: countryGeoDb },
  ].filter((q) => q.voll !== null);

  if (quellen.length === 0) {
    return { text: "Länder-Angaben weichen ab" };
  }
  const teile = quellen.map((q) => `${q.label} nennt ${q.voll.value}`);
  return { text: teile.join(", ") };
}

// --- TLS-Zertifikat ---------------------------------------------------------

// Kurz-Zusammenfassung für die zusammengeklappte TLS-Zeile.
function tlsKurzform(details) {
  if (details.subject_cn) {
    return `CN=${details.subject_cn}`;
  }
  return "TLS-Zertifikat";
}

// Verschachteltes Detail-Objekt -> camelCase. None-Felder zu leerem String /
// leerem Array glätten, damit das Panel-Markup (z. B. subjectAltNames.join)
// nicht bricht.
function tlsDetails(details) {
  return {
    subjectCN: details.subject_cn ?? "",
    subjectAltNames: details.san ?? [],
    issuer: details.issuer ?? "",
    validFrom: details.valid_from ?? "",
    validUntil: details.valid_until ?? "",
    serial: details.serial ?? "",
    fingerprintSha256: details.fingerprint_sha256 ?? "",
    selfSigned: Boolean(details.self_signed),
  };
}

// --- Haupt-Einstieg ---------------------------------------------------------

// Ruft GET /api/resolve und übersetzt die Antwort in die Panel-Struktur.
export async function fetchLookup(ip, port) {
  const backend = await apiGet("/api/resolve", { ip, port });

  const countryRdapNet = feld(backend.country_rdap_net);
  const countryOrgAddress = feld(backend.country_org_address);
  const countryGeoDb = feld(backend.country_geodb);

  // tls_cert: Panel will tlsCert (Kurz-Fact) UND tlsCertDetails (oder null).
  const tlsValue = backend.tls_cert?.value ?? null;
  let tlsCert = null;
  let tlsCertDetails = null;
  if (tlsValue !== null) {
    tlsCert = {
      value: tlsKurzform(tlsValue),
      source: normSource(backend.tls_cert.source),
    };
    tlsCertDetails = tlsDetails(tlsValue);
  }

  // countryConflict: Backend-bool hat Vorrang. true -> { text } (Klartext aus
  // den drei Ländern; notfalls neutral nebeneinander), false -> null.
  let countryConflict = null;
  if (backend.country_conflict) {
    countryConflict =
      laenderKonflikt(countryRdapNet, countryOrgAddress, countryGeoDb) ??
      neutralerLaenderText(countryRdapNet, countryOrgAddress, countryGeoDb);
  }

  return {
    ip,
    port,
    proto: "TCP",
    ptr: feld(backend.ptr),
    forwardConfirmed: feld(backend.forward_confirmed),
    tlsCert,
    tlsCertDetails,
    dyndns: feld(backend.dyndns),
    org: feld(backend.org),
    netname: feld(backend.netname),
    netRange: feld(backend.net_range),
    asn: feld(backend.asn),
    asnOrg: feld(backend.asn_org),
    abuseContact: feld(backend.abuse_contact),
    countryRdapNet,
    countryOrgAddress,
    countryGeoDb,
    // serviceHint ist ein PLAIN STRING (kein { value, source }) — das Panel
    // rendert ihn als reinen Text.
    serviceHint: backend.service_hint?.value ?? "",
    // banner liefert der Resolver leer -> auf null mappen.
    banner: null,
    countryConflict,
  };
}

export default { fetchLookup };
