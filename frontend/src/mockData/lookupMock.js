// PLATZHALTER — bei Anbindung an echte API (mehrstufige Resolver-Domäne) entfernen.
//
// Liefert zu einer (ip, port) neutrale Fakten aus MEHREREN Quellen für die
// Gegenstellen-Ansicht (LookupPanel). KEIN Urteil — nur die rohen Befunde der
// einzelnen Auflösungsstufen. Bei echter Anbindung ersetzt die Resolver-Domäne
// diese Funktion; das Panel kennt nur das zurückgegebene Fakten-Objekt, nicht
// dessen Herkunft.
//
// STRUKTUR DER FAKTEN
// -------------------
// Jedes inhaltliche Faktenfeld ist ein Objekt { value, source } oder null:
//   value   String|null  — der Befund (null = von dieser Quelle nichts gefunden)
//   source  String       — Quellen-Kürzel, woher der Wert stammt. Erlaubte
//                          Kürzel: DNS | RDAP | TLS | GeoDB | DNSDB.
// Ein Feld, das insgesamt fehlt (gar keine Quelle hatte etwas), ist null statt
// eines Objekts. Das Panel zeigt dann "nicht gefunden" ohne Quellen-Badge.
//
// Faktenfelder:
//   Namensauflösung
//     ptr              Reverse-DNS (PTR)                 (DNS)
//     forwardConfirmed Forward-Bestätigung des PTR       (DNS)
//     tlsCert          TLS-Zertifikats-Kurzform          (TLS)
//     dyndns           Treffer in DynDNS-Datenbank       (DNSDB)
//
//   tlsCertDetails ist KEIN { value, source }-Feld, sondern ein eigenes Objekt
//   mit den vollen Zertifikatsdetails (oder null, wenn kein TLS vorliegt):
//     subjectCN         String        — Subject Common Name
//     subjectAltNames   String[]      — SAN-Einträge
//     issuer            String        — Aussteller (Issuer)
//     validFrom         String        — Gültig ab
//     validUntil        String        — Gültig bis
//     serial            String        — Seriennummer
//     fingerprintSha256 String        — SHA-256-Fingerprint
//     selfSigned        Boolean       — selbstsigniert (reine Feststellung)
//   Die Kurzform (tlsCert) bleibt für die zusammengeklappte Zeile + Badge.
//   Betreiber & Netz
//     org              Betreiber/Organisation            (RDAP)
//     netname          Netz-Kurzname                     (RDAP)
//     netRange         Netz-Bereich                      (RDAP)
//     asn              Autonomes System                  (RDAP)
//     asnOrg           Betreiber des AS                  (RDAP)
//     abuseContact     Abuse-Kontakt                     (RDAP)
//   Standort (bewusst drei getrennte Quellen — Unterschiede sollen sichtbar sein)
//     countryRdapNet    Land laut RDAP-Netz              (RDAP)
//     countryOrgAddress Land laut Org-Adresse            (RDAP)
//     countryGeoDb      Land laut Geo-Datenbank          (GeoDB)
//   Dienst am Port
//     serviceHint      neutrale Port-Einordnung (immer gesetzt, ohne Quelle)
//     banner           beobachteter Dienst-Banner        (z. B. TLS)
//
// ABGELEITETE WIDERSPRUCHS-ERKENNUNG
//   countryConflict  null               — keine widersprüchlichen Länder
//                    { text }           — Klartext, der den Konflikt benennt
//   Wird aus den drei Länder-Quellen berechnet (siehe laenderKonflikt()).
//
// Keine React-Imports hier.

// Neutrale, urteilsfreie Port-Hinweise. Reiner Nachschlage-Charakter.
const PORT_HINWEISE = {
  22: "22 — SSH (Fernzugriff / verschlüsselte Konsole)",
  53: "53 — DNS (Namensauflösung)",
  80: "80 — HTTP (unverschlüsseltes Web)",
  443: "443 — HTTPS (verschlüsseltes Web)",
  465: "465 — SMTPS (Mailversand, verschlüsselt)",
  993: "993 — IMAPS (Mailabruf, verschlüsselt)",
  8443: "8443 — häufig alternatives HTTPS / Web-Verwaltung",
};

function serviceHintFuer(port) {
  return PORT_HINWEISE[port] ?? `${port} — kein gängiger Standard-Dienst`;
}

// Kleiner Helfer: baut ein { value, source }-Feld. Bei value === null gibt es
// null zurück (Feld fehlt insgesamt, kein Quellen-Badge im Panel).
function feld(value, source) {
  return value === null ? null : { value, source };
}

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

// Baut das vollständige Fakten-Objekt inkl. abgeleitetem Länder-Widerspruch.
// Erwartet die rohen Felder bereits als { value, source }|null.
function bauen(ip, port, rohdaten) {
  const {
    proto = "TCP",
    ptr = null,
    forwardConfirmed = null,
    tlsCert = null,
    tlsCertDetails = null,
    dyndns = null,
    org = null,
    netname = null,
    netRange = null,
    asn = null,
    asnOrg = null,
    abuseContact = null,
    countryRdapNet = null,
    countryOrgAddress = null,
    countryGeoDb = null,
    banner = null,
  } = rohdaten;

  return {
    ip,
    port,
    proto,
    ptr,
    forwardConfirmed,
    tlsCert,
    tlsCertDetails,
    dyndns,
    org,
    netname,
    netRange,
    asn,
    asnOrg,
    abuseContact,
    countryRdapNet,
    countryOrgAddress,
    countryGeoDb,
    serviceHint: serviceHintFuer(port),
    banner,
    countryConflict: laenderKonflikt(countryRdapNet, countryOrgAddress, countryGeoDb),
  };
}

// Hinterlegte Beispiel-Gegenstellen, jeweils nach "ip:port" geschlüsselt.
// Rohdaten als { value, source }; null = von keiner Quelle gefunden.
const BEISPIELE = {
  // Google: vollständig aufgelöst, kein Länder-Widerspruch.
  "142.250.74.196:443": {
    proto: "TCP",
    ptr: feld("fra16s52-in-f4.1e100.net", "DNS"),
    forwardConfirmed: feld("fra16s52-in-f4.1e100.net → 142.250.74.196 (bestätigt)", "DNS"),
    tlsCert: feld("*.google.com (vertrauenswürdiger Aussteller)", "TLS"),
    tlsCertDetails: {
      subjectCN: "*.google.com",
      subjectAltNames: ["*.google.com", "*.googleapis.com", "google.com"],
      issuer: "Google Trust Services (WR2)",
      validFrom: "2026-04-28",
      validUntil: "2026-07-21",
      serial: "00:a1:3f:9c:7e:2b:04:dd",
      fingerprintSha256:
        "8f:2a:1c:6d:4b:0e:93:77:a5:11:cd:38:e0:62:9f:4a:7b:18:c2:50:6e:31:88:db:0a:f4:19:55:2c:7d:e3:11",
      selfSigned: false,
    },
    dyndns: null,
    org: feld("Google LLC", "RDAP"),
    netname: feld("GOOGLE", "RDAP"),
    netRange: feld("142.250.0.0 - 142.251.255.255", "RDAP"),
    asn: feld("AS15169", "RDAP"),
    asnOrg: feld("Google LLC", "RDAP"),
    abuseContact: feld("network-abuse@google.com", "RDAP"),
    countryRdapNet: feld("US", "RDAP"),
    countryOrgAddress: feld("US (Mountain View)", "RDAP"),
    countryGeoDb: feld("US", "GeoDB"),
    banner: feld("HTTP/2, gws (Google Web Server)", "TLS"),
  },

  // FIRST SERVER / AEZA: Länder-Widerspruch aktiv (RDAP-Netz RU,
  // Org-Adresse ES, Geo-DB RU). Aus echten WHOIS-Daten.
  "45.142.122.61:8443": {
    proto: "TCP",
    ptr: null,
    forwardConfirmed: null,
    tlsCert: feld("CN=selfsigned", "TLS"),
    tlsCertDetails: {
      subjectCN: "selfsigned",
      subjectAltNames: ["selfsigned", "localhost"],
      issuer: "CN=selfsigned",
      validFrom: "2025-11-03",
      validUntil: "2035-10-31",
      serial: "4e:2d:9a:00:f1:6b:c3:88",
      fingerprintSha256:
        "3c:7f:e9:14:aa:52:60:8d:bb:09:1f:42:d7:6e:30:c8:95:21:0b:4f:e2:7a:18:33:90:cc:5d:71:46:b2:08:9e",
      selfSigned: true,
    },
    dyndns: null,
    org: feld("FIRST SERVER, SOCIEDAD LIMITADA", "RDAP"),
    netname: feld("FIRSTSERVER", "RDAP"),
    netRange: feld("45.142.122.0 - 45.142.122.255", "RDAP"),
    asn: feld("AS205090", "RDAP"),
    asnOrg: feld("AEZA INTERNATIONAL LTD", "RDAP"),
    abuseContact: feld("abuse@first-server.net", "RDAP"),
    countryRdapNet: feld("RU", "RDAP"),
    countryOrgAddress: feld("ES (Alicante)", "RDAP"),
    countryGeoDb: feld("RU", "GeoDB"),
    banner: null,
  },

  // Deutsche Telekom: DynDNS-Treffer, kein Länder-Widerspruch.
  "89.246.12.7:22": {
    proto: "TCP",
    ptr: null,
    forwardConfirmed: null,
    tlsCert: null,
    dyndns: feld("home-1234.dyndns-server.net (über DNS-Datenbank gefunden)", "DNSDB"),
    org: feld("Deutsche Telekom AG", "RDAP"),
    netname: feld("DTAG-DIAL", "RDAP"),
    netRange: feld("89.244.0.0 - 89.247.255.255", "RDAP"),
    asn: feld("AS3320", "RDAP"),
    asnOrg: feld("Deutsche Telekom AG", "RDAP"),
    abuseContact: feld("abuse@telekom.de", "RDAP"),
    countryRdapNet: feld("DE", "RDAP"),
    countryOrgAddress: feld("DE (Bonn)", "RDAP"),
    countryGeoDb: feld("DE", "GeoDB"),
    banner: null,
  },
};

// Liefert das Fakten-Objekt zu (ip, port). Unbekannte Gegenstellen: alles null
// außer dem stets vorhandenen serviceHint (mehrstufige Auflösung ohne Treffer).
export function lookupGegenstelle(ip, port) {
  const beispiel = BEISPIELE[`${ip}:${port}`];
  if (beispiel) {
    return bauen(ip, port, beispiel);
  }
  return bauen(ip, port, {});
}

export default { lookupGegenstelle };
