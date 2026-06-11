// PLATZHALTER — bei Anbindung an echte API entfernen.
//
// Einzige Datenquelle der Scan-Tabelle (Beobachten → Scan). Die View kennt nur
// diese Struktur, nicht ihre Herkunft. Bei echter Anbindung wird der Import in
// ObserveView.jsx auf den API-Datenfluss umgestellt und diese Datei gelöscht.
//
// Icon-Namen sind Strings (kein React-Import hier); das Mapping auf lucide-
// Komponenten liegt in der View. So bleibt der Mock frei von Komponenten.
//
// Felder je Gerät:
//   icon      String   — Schlüssel fürs Icon-Mapping in der View
//   ip        String   — IPv4
//   mac       String   — MAC-Adresse
//   vendor    String   — Hersteller
//   hostname  String   — Hostname (kann leer sein)
//   osGuess   String   — vermutetes Betriebssystem (kann leer sein)
//   ports     Array    — offene Ports als { num, proto }
//   pingMs    Zahl|null — Antwortzeit in ms (null = keine Antwort)
//   isNew     Bool     — bisher unbekanntes Gerät
//   notable   Bool     — anderweitig auffällig

export const geraete = [
  {
    icon: "router",
    ip: "192.168.178.1",
    mac: "3C:A6:2F:11:0A:8E",
    vendor: "AVM",
    hostname: "fritz.box",
    osGuess: "FRITZ!OS",
    ports: [
      { num: 53, proto: "udp" },
      { num: 80, proto: "tcp" },
      { num: 443, proto: "tcp" },
      { num: 5060, proto: "udp" },
    ],
    pingMs: 1,
    isNew: false,
    notable: false,
  },
  {
    icon: "nas",
    ip: "192.168.178.10",
    mac: "00:11:32:7C:4D:21",
    vendor: "Synology",
    hostname: "diskstation",
    osGuess: "Linux (DSM)",
    ports: [
      { num: 22, proto: "tcp" },
      { num: 139, proto: "tcp" },
      { num: 445, proto: "tcp" },
      { num: 5000, proto: "tcp" },
      { num: 5001, proto: "tcp" },
      { num: 5357, proto: "tcp" },
      { num: 9000, proto: "tcp" },
    ],
    pingMs: 2,
    isNew: false,
    notable: false,
  },
  {
    icon: "printer",
    ip: "192.168.178.23",
    mac: "30:CD:A7:55:1B:90",
    vendor: "Brother",
    hostname: "BRN30CDA7551B90",
    osGuess: "Embedded",
    ports: [
      { num: 80, proto: "tcp" },
      { num: 515, proto: "tcp" },
      { num: 631, proto: "tcp" },
      { num: 9100, proto: "tcp" },
    ],
    pingMs: 6,
    isNew: false,
    notable: false,
  },
  {
    icon: "laptop",
    ip: "192.168.178.31",
    mac: "F0:18:98:3A:7C:2D",
    vendor: "Apple",
    hostname: "macbook-karl",
    osGuess: "macOS",
    ports: [{ num: 7000, proto: "tcp" }],
    pingMs: 4,
    isNew: false,
    notable: false,
  },
  {
    icon: "laptop",
    ip: "192.168.178.34",
    mac: "8C:85:90:0E:F2:14",
    vendor: "Dell",
    hostname: "ubultsvm",
    osGuess: "Linux (Ubuntu)",
    ports: [
      { num: 22, proto: "tcp" },
      { num: 5173, proto: "tcp" },
      { num: 8000, proto: "tcp" },
    ],
    pingMs: 1,
    isNew: false,
    notable: false,
  },
  {
    icon: "phone",
    ip: "192.168.178.42",
    mac: "A4:83:E7:6B:09:CC",
    vendor: "Apple",
    hostname: "iphone-karl",
    osGuess: "iOS",
    ports: [],
    pingMs: 18,
    isNew: false,
    notable: false,
  },
  {
    icon: "tv",
    ip: "192.168.178.48",
    mac: "BC:E6:3F:21:7A:55",
    vendor: "Samsung",
    hostname: "tizen-tv",
    osGuess: "Tizen",
    ports: [
      { num: 8001, proto: "tcp" },
      { num: 8002, proto: "tcp" },
      { num: 9197, proto: "tcp" },
    ],
    pingMs: 9,
    isNew: false,
    notable: false,
  },
  {
    icon: "speaker",
    ip: "192.168.178.51",
    mac: "44:07:0B:33:8F:19",
    vendor: "Sonos",
    hostname: "sonos-wohnzimmer",
    osGuess: "Embedded",
    ports: [
      { num: 1400, proto: "tcp" },
      { num: 1443, proto: "tcp" },
    ],
    pingMs: 7,
    isNew: false,
    notable: false,
  },
  {
    icon: "bulb",
    ip: "192.168.178.60",
    mac: "EC:FA:BC:12:44:80",
    vendor: "Espressif",
    hostname: "",
    osGuess: "RTOS",
    ports: [{ num: 80, proto: "tcp" }],
    pingMs: 23,
    isNew: false,
    notable: false,
  },
  {
    icon: "camera",
    ip: "192.168.178.66",
    mac: "9C:8E:CD:05:7F:31",
    vendor: "Reolink",
    hostname: "cam-eingang",
    osGuess: "Linux (Embedded)",
    ports: [
      { num: 80, proto: "tcp" },
      { num: 554, proto: "tcp" },
      { num: 8000, proto: "tcp" },
      { num: 9000, proto: "tcp" },
    ],
    pingMs: 12,
    isNew: false,
    notable: true,
  },
  {
    icon: "thermostat",
    ip: "192.168.178.72",
    mac: "00:17:88:4A:2B:6E",
    vendor: "Signify (Philips Hue)",
    hostname: "hue-bridge",
    osGuess: "Embedded",
    ports: [
      { num: 80, proto: "tcp" },
      { num: 443, proto: "tcp" },
    ],
    pingMs: 5,
    isNew: false,
    notable: false,
  },
  {
    icon: "unknown",
    ip: "192.168.178.88",
    mac: "5E:2A:14:9D:7C:03",
    vendor: "",
    hostname: "",
    osGuess: "",
    ports: [
      { num: 23, proto: "tcp" },
      { num: 2323, proto: "tcp" },
    ],
    pingMs: 31,
    isNew: true,
    notable: true,
  },
  {
    icon: "phone",
    ip: "192.168.178.91",
    mac: "DA:A1:19:55:7E:42",
    vendor: "Google",
    hostname: "pixel-gast",
    osGuess: "Android",
    ports: [],
    pingMs: 27,
    isNew: true,
    notable: false,
  },
  {
    icon: "laptop",
    ip: "192.168.178.97",
    mac: "00:1A:11:40:6B:8D",
    vendor: "Liteon",
    hostname: "win-arbeitsplatz",
    osGuess: "Windows",
    ports: [
      { num: 135, proto: "tcp" },
      { num: 139, proto: "tcp" },
      { num: 445, proto: "tcp" },
      { num: 3389, proto: "tcp" },
    ],
    pingMs: 3,
    isNew: false,
    notable: false,
  },
  {
    icon: "iot",
    ip: "192.168.178.104",
    mac: "B8:27:EB:1F:9A:6C",
    vendor: "Raspberry Pi Foundation",
    hostname: "pi-hole",
    osGuess: "Linux (Raspbian)",
    ports: [
      { num: 22, proto: "tcp" },
      { num: 53, proto: "udp" },
      { num: 80, proto: "tcp" },
    ],
    pingMs: 2,
    isNew: false,
    notable: false,
  },
];

// Komplettes Mock-Scan-Ergebnis. Die View liest ausschließlich diese Struktur.
export const scanMock = {
  geraete,
};

export default scanMock;
