// Interne Port-Nachschlage-Tabelle (CERNIS PRO 2.0)
//
// Liefert zu einer Portnummer (+ Protokoll) einen STABILEN, sprachneutralen
// Schlüssel (z.B. "ssh", "https"), den der Dialog über i18n auflöst. So bleibt
// die Tabelle frei von Texten — die deutschen/englischen Beschreibungen stehen
// gepflegt in den Sprachdateien (beobachten.scan.detail.ports.lookupDialog.info.*).
//
// Produkt-These „mündiger Anwender / zeigen + einordnen, nicht urteilen": Die
// Beschreibungen (in i18n) informieren neutral, wofür der Dienst da ist, mit
// höchstens dezentem Hinweis auf unverschlüsselte/veraltete Protokolle — ohne
// Alarm oder Wertung.

// Tabelle der gängigsten Ports -> stabiler i18n-Schlüssel + Dienst-Kurzname.
// Der Dienst-Name ist ein neutraler, allgemein üblicher Bezeichner (dient auch
// als Fallback und speist die Wikipedia-Suche). Die eigentliche Beschreibung
// liegt in i18n unter dem key.
const PORT_TABELLE = {
  "21/tcp": { key: "ftp", dienst: "FTP" },
  "22/tcp": { key: "ssh", dienst: "SSH" },
  "23/tcp": { key: "telnet", dienst: "Telnet" },
  "25/tcp": { key: "smtp", dienst: "SMTP" },
  "53/tcp": { key: "dns", dienst: "DNS" },
  "53/udp": { key: "dns", dienst: "DNS" },
  "80/tcp": { key: "http", dienst: "HTTP" },
  "110/tcp": { key: "pop3", dienst: "POP3" },
  "139/tcp": { key: "netbios", dienst: "NetBIOS" },
  "143/tcp": { key: "imap", dienst: "IMAP" },
  "443/tcp": { key: "https", dienst: "HTTPS" },
  "445/tcp": { key: "smb", dienst: "SMB" },
  "631/tcp": { key: "ipp", dienst: "IPP" },
  "993/tcp": { key: "imaps", dienst: "IMAPS" },
  "995/tcp": { key: "pop3s", dienst: "POP3S" },
  "1883/tcp": { key: "mqtt", dienst: "MQTT" },
  "3306/tcp": { key: "mysql", dienst: "MySQL" },
  "3389/tcp": { key: "rdp", dienst: "RDP" },
  "5432/tcp": { key: "postgresql", dienst: "PostgreSQL" },
  "5900/tcp": { key: "vnc", dienst: "VNC" },
  "8080/tcp": { key: "http-alt", dienst: "HTTP-Alt" },
};

/**
 * Schlägt einen Port intern nach.
 *
 * @param {number|string} portNum Die Portnummer (z.B. 22).
 * @param {string} [proto] Das Protokoll ("tcp"/"udp"); Default "tcp".
 * @returns {{ key: string|null, dienst: string|null }} Bei bekanntem Port ein
 *   stabiler i18n-Schlüssel + Dienst-Kurzname; bei unbekanntem Port beide null.
 *   Der Dialog rendert dann den generischen Fall (nur Wikipedia-Link).
 */
export function portBeschreibung(portNum, proto = "tcp") {
  const p = String(proto || "tcp").toLowerCase();
  const treffer = PORT_TABELLE[`${portNum}/${p}`];
  if (!treffer) {
    return { key: null, dienst: null };
  }
  return { key: treffer.key, dienst: treffer.dienst };
}
