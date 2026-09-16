"""Kuratiertes Port->Service-Mapping als REINE DATEN (analysis-Domaene).

Reine Domaenenlogik (stdlib + dataclasses + typing, ADR 0002): kein I/O, keine Uhr,
kein Framework, KEIN ``/etc/services``-Parse (plattform- und frozen-build-unsicher --
die Tabelle ist bewusst statisch in den Code kuratiert, damit sie im gebuendelten Build
identisch verfuegbar ist).

Verwendung: die Einstellungs-UI (spaeterer Schnitt) laesst den Nutzer einen Port eingeben
und zeigt sofort den Service-Namen. Dafuer braucht das Backend ein breites, kuratiertes
Mapping -- kuratierte IANA-Well-Known- plus gaengige Registered-/Heimnetz-/Selfhoster-Ports.
Die Werte sind knappe, gaengige Service-Namen (kleingeschrieben), KEINE vollstaendige
IANA-Registry: ZEIGEN + EINORDNEN, NIE URTEILEN -- ein Service-Name ist eine wertneutrale
Einordnung, kein Urteil ueber Gefaehrlichkeit.

Ein nicht gelistetes Port ist ein gueltiger Leer-Zustand (``None``), KEIN Fehler.
"""

# Statisches, kuratiertes Port->Service-Mapping. Knapp und gaengig gehalten (kein
# Anspruch auf IANA-Vollstaendigkeit). Ein neuer Eintrag ist eine weitere Zeile in
# diesem dict -- keine Code-Verzweigung.
SERVICE_BY_PORT: dict[int, str] = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    37: "time",
    43: "whois",
    53: "dns",
    67: "dhcp",
    68: "dhcp",
    69: "tftp",
    80: "http",
    88: "kerberos",
    110: "pop3",
    111: "rpcbind",
    119: "nntp",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    138: "netbios-dgm",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    162: "snmp-trap",
    179: "bgp",
    194: "irc",
    389: "ldap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    500: "isakmp",
    514: "syslog",
    515: "printer",
    520: "rip",
    546: "dhcpv6-client",
    547: "dhcpv6-server",
    548: "afp",
    554: "rtsp",
    587: "submission",
    631: "ipp",
    636: "ldaps",
    873: "rsync",
    989: "ftps-data",
    990: "ftps",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1194: "openvpn",
    1433: "mssql",
    1434: "mssql-monitor",
    1521: "oracle",
    1701: "l2tp",
    1723: "pptp",
    1812: "radius",
    1813: "radius-acct",
    1883: "mqtt",
    1900: "ssdp",
    2049: "nfs",
    2082: "cpanel",
    2083: "cpanel-ssl",
    2086: "whm",
    2087: "whm-ssl",
    2181: "zookeeper",
    2222: "ssh-alt",
    2375: "docker",
    2376: "docker-tls",
    2483: "oracle-db",
    2484: "oracle-db-ssl",
    3000: "grafana",
    3128: "squid-proxy",
    3260: "iscsi",
    3306: "mysql",
    3389: "rdp",
    3478: "stun",
    4444: "metasploit",
    4500: "ipsec-nat-t",
    5000: "upnp",
    5001: "synology-dsm",
    5060: "sip",
    5061: "sip-tls",
    5222: "xmpp-client",
    5269: "xmpp-server",
    5353: "mdns",
    5355: "llmnr",
    5432: "postgresql",
    5601: "kibana",
    5683: "coap",
    5800: "vnc-http",
    5900: "vnc",
    5984: "couchdb",
    6379: "redis",
    6443: "kubernetes-api",
    6667: "irc",
    7000: "afs",
    8000: "http-alt",
    8006: "proxmox",
    8008: "chromecast",
    8009: "chromecast",
    8080: "http-proxy",
    8081: "http-alt",
    8083: "vestacp",
    8086: "influxdb",
    8096: "jellyfin",
    8123: "home-assistant",
    8443: "https-alt",
    8883: "mqtts",
    9000: "http-alt",
    9001: "tor-orport",
    9090: "prometheus",
    9091: "transmission",
    9100: "jetdirect",
    9200: "elasticsearch",
    9300: "elasticsearch-cluster",
    9418: "git",
    10000: "webmin",
    11211: "memcached",
    19999: "netdata",
    25565: "minecraft",
    27017: "mongodb",
    32400: "plex",
    51413: "transmission-peer",
    51820: "wireguard",
}


def service_for_port(port: int | None) -> str | None:
    """Liefert den gaengigen Service-Namen zu einem Port (``None``, wenn unbekannt).

    ``port is None`` -> ``None`` (kein Port, kein Service). Ein nicht gelistetes Port ist
    ein gueltiger Leer-Zustand (``None``), KEIN Fehler -- reiner Lookup.
    """
    if port is None:
        return None
    return SERVICE_BY_PORT.get(port)
