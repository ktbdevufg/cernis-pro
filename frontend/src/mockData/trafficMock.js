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
//   conns    Array    — Verbindungen als { remote, service, state, notable? }
//                       remote  String "ip:port"
//                       service String (Fachbegriff: HTTPS, IMAPS, SSH, …)
//                       state   String (Verbindungszustand, z. B. ESTABLISHED)
//                       notable Bool? — auffällige Einzelverbindung

export const apps = [
  {
    name: "firefox",
    icon: "browser",
    down: 842,
    up: 96,
    notable: false,
    conns: [
      {
        remote: "140.82.121.4:443",
        service: "HTTPS",
        state: "ESTABLISHED",
      },
      {
        remote: "151.101.1.69:443",
        service: "HTTPS",
        state: "ESTABLISHED",
      },
      {
        remote: "192.168.178.1:53",
        service: "DNS",
        state: "ESTABLISHED",
      },
    ],
  },
  {
    name: "spotify",
    icon: "music",
    down: 318,
    up: 14,
    notable: false,
    conns: [
      {
        remote: "35.186.224.47:443",
        service: "HTTPS",
        state: "ESTABLISHED",
      },
      {
        remote: "104.199.65.9:4070",
        service: "TCP",
        state: "ESTABLISHED",
      },
    ],
  },
  {
    name: "thunderbird",
    icon: "mail",
    down: 22,
    up: 6,
    notable: false,
    conns: [
      {
        remote: "212.227.17.168:993",
        service: "IMAPS",
        state: "ESTABLISHED",
      },
      {
        remote: "212.227.15.183:465",
        service: "SMTPS",
        state: "TIME_WAIT",
      },
    ],
  },
  {
    name: "ssh",
    icon: "terminal",
    down: 3,
    up: 2,
    notable: false,
    conns: [
      {
        remote: "192.168.178.32:22",
        service: "SSH",
        state: "ESTABLISHED",
      },
    ],
  },
  {
    name: "syncthing",
    icon: "refresh",
    down: 51,
    up: 188,
    notable: false,
    conns: [
      {
        remote: "192.168.178.45:22000",
        service: "TCP",
        state: "ESTABLISHED",
      },
      {
        remote: "85.119.83.12:443",
        service: "HTTPS",
        state: "ESTABLISHED",
      },
    ],
  },
  {
    name: "unbekannt-7f3a",
    icon: "unknown",
    down: 12,
    up: 2480,
    notable: true,
    conns: [
      {
        remote: "45.83.193.27:8443",
        service: "TCP",
        state: "ESTABLISHED",
        notable: true,
      },
      {
        remote: "45.83.193.27:443",
        service: "HTTPS",
        state: "ESTABLISHED",
        notable: true,
      },
    ],
  },
];

export default { apps };
