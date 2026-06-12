// PLATZHALTER — bei Anbindung an echte API entfernen.
//
// Einzige Datenquelle der Per-App-Verkehr-Ansicht (Beobachten → Per-App-Verkehr).
// Die View kennt nur diese Struktur, nicht ihre Herkunft. Bei echter Anbindung
// wird der Import in ObserveView.jsx auf den API-Datenfluss umgestellt und diese
// Datei gelöscht.
//
// Icon-Namen sind Strings (kein React-Import hier); das Mapping auf lucide-
// Komponenten liegt in der View. So bleibt der Mock frei von Komponenten.
//
// Felder je App:
//   name     String   — App-Name (Prozess/Anwendung)
//   icon     String   — Schlüssel fürs Icon-Mapping in der View
//   down     Zahl     — eingehende Datenrate in KB/s
//   up       Zahl     — ausgehende Datenrate in KB/s
//   notable  Bool     — auffällig (unbekanntes Ziel, ungewöhnliches Volumen)
//   conns    Array    — Verbindungen als { remote, port, service, state, notable, host }
//                       remote  String — Gegenstellen-IP (ohne Port)
//                       port    Zahl   — Ziel-Port
//                       service String — Fachbegriff: HTTPS, IMAPS, SSH, …
//                       state   String — Verbindungszustand, z. B. ESTABLISHED
//                       notable Bool   — auffällige Einzelverbindung
//                       host    String|null — aufgelöster Name (PTR) oder null
//
// Die View bündelt Verbindungen nach Ziel (host bzw. remote-IP) + port, daher
// tauchen gleiche Ziele bewusst mehrfach auf (z. B. firefox).

export const apps = [
  {
    name: "firefox",
    icon: "browser",
    down: 842,
    up: 96,
    notable: false,
    conns: [
      // Mehrere Ziele mit mehrfachen Verbindungen → sichtbare Bündelung.
      { remote: "142.250.74.196", port: 443, service: "HTTPS", state: "ESTABLISHED", notable: false, host: "fra16s52-in-f4.1e100.net" },
      { remote: "142.250.74.196", port: 443, service: "HTTPS", state: "ESTABLISHED", notable: false, host: "fra16s52-in-f4.1e100.net" },
      { remote: "142.250.74.196", port: 443, service: "HTTPS", state: "ESTABLISHED", notable: false, host: "fra16s52-in-f4.1e100.net" },
      { remote: "142.250.74.196", port: 443, service: "HTTPS", state: "ESTABLISHED", notable: false, host: "fra16s52-in-f4.1e100.net" },
      { remote: "142.250.74.196", port: 443, service: "HTTPS", state: "ESTABLISHED", notable: false, host: "fra16s52-in-f4.1e100.net" },
      { remote: "151.101.1.69", port: 443, service: "HTTPS", state: "ESTABLISHED", notable: false, host: "151.101.1.69.fastly-cdn.net" },
      { remote: "151.101.1.69", port: 443, service: "HTTPS", state: "ESTABLISHED", notable: false, host: "151.101.1.69.fastly-cdn.net" },
      { remote: "151.101.1.69", port: 443, service: "HTTPS", state: "ESTABLISHED", notable: false, host: "151.101.1.69.fastly-cdn.net" },
      { remote: "151.101.65.69", port: 443, service: "HTTPS", state: "ESTABLISHED", notable: false, host: null },
      { remote: "151.101.65.69", port: 443, service: "HTTPS", state: "TIME_WAIT", notable: false, host: null },
      { remote: "104.16.123.96", port: 443, service: "HTTPS", state: "ESTABLISHED", notable: false, host: "104.16.123.96.cloudflare.com" },
      { remote: "104.16.123.96", port: 443, service: "HTTPS", state: "ESTABLISHED", notable: false, host: "104.16.123.96.cloudflare.com" },
      { remote: "104.16.123.96", port: 443, service: "HTTPS", state: "ESTABLISHED", notable: false, host: "104.16.123.96.cloudflare.com" },
      { remote: "63.245.208.195", port: 443, service: "HTTPS", state: "ESTABLISHED", notable: false, host: "telemetry.mozilla.org" },
      { remote: "63.245.208.195", port: 443, service: "HTTPS", state: "ESTABLISHED", notable: false, host: "telemetry.mozilla.org" },
      { remote: "140.82.121.4", port: 443, service: "HTTPS", state: "ESTABLISHED", notable: false, host: "lb-140-82-121-4-fra.github.com" },
      { remote: "140.82.121.4", port: 443, service: "HTTPS", state: "ESTABLISHED", notable: false, host: "lb-140-82-121-4-fra.github.com" },
      { remote: "192.168.178.1", port: 53, service: "DNS", state: "ESTABLISHED", notable: false, host: "fritz.box" },
      { remote: "13.107.21.200", port: 80, service: "HTTP", state: "TIME_WAIT", notable: false, host: null },
      // Eine auffällige Verbindung zu unbekanntem Ziel ohne PTR.
      { remote: "45.142.122.61", port: 8443, service: "TCP", state: "ESTABLISHED", notable: true, host: null },
    ],
  },
  {
    name: "spotify",
    icon: "music",
    down: 318,
    up: 14,
    notable: false,
    conns: [
      { remote: "35.186.224.47", port: 443, service: "HTTPS", state: "ESTABLISHED", notable: false, host: "audio-fra2-1.spotify.com" },
      { remote: "35.186.224.47", port: 443, service: "HTTPS", state: "ESTABLISHED", notable: false, host: "audio-fra2-1.spotify.com" },
      { remote: "104.199.65.9", port: 4070, service: "TCP", state: "ESTABLISHED", notable: false, host: null },
    ],
  },
  {
    name: "thunderbird",
    icon: "mail",
    down: 22,
    up: 6,
    notable: false,
    conns: [
      { remote: "212.227.17.168", port: 993, service: "IMAPS", state: "ESTABLISHED", notable: false, host: "imap.mail.bach.world" },
      { remote: "212.227.15.183", port: 465, service: "SMTPS", state: "TIME_WAIT", notable: false, host: "smtp.mail.bach.world" },
    ],
  },
  {
    name: "ssh",
    icon: "terminal",
    down: 3,
    up: 2,
    notable: false,
    conns: [
      { remote: "192.168.178.32", port: 22, service: "SSH", state: "ESTABLISHED", notable: false, host: "nas.fritz.box" },
    ],
  },
  {
    name: "syncthing",
    icon: "refresh",
    down: 51,
    up: 188,
    notable: false,
    conns: [
      { remote: "192.168.178.45", port: 22000, service: "TCP", state: "ESTABLISHED", notable: false, host: null },
      { remote: "85.119.83.12", port: 443, service: "HTTPS", state: "ESTABLISHED", notable: false, host: "relay-de.syncthing.net" },
    ],
  },
  {
    name: "unbekannt-7f3a",
    icon: "unknown",
    down: 12,
    up: 2480,
    notable: true,
    conns: [
      { remote: "45.83.193.27", port: 8443, service: "TCP", state: "ESTABLISHED", notable: true, host: null },
      { remote: "45.83.193.27", port: 443, service: "HTTPS", state: "ESTABLISHED", notable: true, host: null },
    ],
  },
];

export default { apps };
