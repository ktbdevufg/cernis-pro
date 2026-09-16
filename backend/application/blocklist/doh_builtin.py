"""Eingebauter KLARTEXT-Inhalt der zwei DoH-Werkslisten (Etappe 3).

Reine Application-Daten -- KEINE Domaene-Aenderung. Da die beiden DOH-Werksquellen in
``DEFAULT_SOURCES`` ``url=None`` haben (mitgelieferter Inhalt statt Refresh-URL), braucht
der Bootstrap einen Weg, ihren Inhalt zu laden -- analog ``ImportUploadedSource`` parst er
``raw_text`` ueber ``parse_blocklist``. HIER stehen die rohen Textbloecke.

EINE Quelle der Wahrheit fuer die Kern-IPs: ``DEFAULT_DOH_PROVIDER_IPS`` (host-lokaler
Waechter, ``domain.dns_watch.defaults``) wird importiert und lokal um weitere gut
dokumentierte oeffentliche DoH-Resolver-IPs ergaenzt -- NICHT kopiert-und-divergiert. Der
IP-Text wird deterministisch aus (Kern-Satz + Zusatzliste) gejoint, eine IP je Zeile
(IP_LIST-Format). Die Domain-Liste fuehrt oeffentlich dokumentierte DoH-Endpunkt-
Hostnamen, eine je Zeile (DOMAIN_LIST-Format).
"""

from domain.dns_watch.defaults import DEFAULT_DOH_PROVIDER_IPS

__all__ = [
    "BUILTIN_DOH_CONTENT",
    "DOH_PROVIDER_DOMAINS_TEXT",
    "DOH_PROVIDER_IPS_TEXT",
]

# Zusaetzliche, gut dokumentierte oeffentliche DoH-Resolver-IPs -- Ergaenzung des
# Kern-Satzes ``DEFAULT_DOH_PROVIDER_IPS`` (Cloudflare/Google/Quad9). Reine IP-Strings.
_ADDITIONAL_DOH_PROVIDER_IPS: tuple[str, ...] = (
    # AdGuard
    "94.140.14.14",
    "94.140.15.15",
    # NextDNS (Anycast)
    "45.90.28.0",
    "45.90.30.0",
    # OpenDNS
    "208.67.222.222",
    "208.67.220.220",
    # CleanBrowsing
    "185.228.168.9",
    # Mullvad
    "194.242.2.2",
    # dns0.eu
    "193.110.81.0",
    "185.253.5.0",
)

# IP_LIST-Format: eine IP je Zeile. Deterministisch aus Kern-Satz + Zusatzliste gejoint --
# EINE Quelle der Wahrheit fuer die Kern-IPs (``DEFAULT_DOH_PROVIDER_IPS``).
DOH_PROVIDER_IPS_TEXT: str = "\n".join(DEFAULT_DOH_PROVIDER_IPS + _ADDITIONAL_DOH_PROVIDER_IPS)

# DOMAIN_LIST-Format: eine Domain je Zeile. Oeffentlich dokumentierte DoH-Endpunkt-
# Hostnamen -- klartext, keine Lizenzfrage.
_DOH_PROVIDER_DOMAINS: tuple[str, ...] = (
    "cloudflare-dns.com",
    "dns.google",
    "dns.quad9.net",
    "dns.adguard-dns.com",
    "dns.nextdns.io",
    "doh.opendns.com",
    "doh.cleanbrowsing.org",
    "dns.mullvad.net",
    "zero.dns0.eu",
    "mozilla.cloudflare-dns.com",
    "chrome.cloudflare-dns.com",
    "doh.dns.sb",
    "dns.controld.com",
    "freedns.controld.com",
)

DOH_PROVIDER_DOMAINS_TEXT: str = "\n".join(_DOH_PROVIDER_DOMAINS)

# id -> raw_text, fuer den Bootstrap (spiegelt die ids der DOH-Werksquellen in
# ``DEFAULT_SOURCES``).
BUILTIN_DOH_CONTENT: dict[str, str] = {
    "doh_providers_ip": DOH_PROVIDER_IPS_TEXT,
    "doh_providers_domain": DOH_PROVIDER_DOMAINS_TEXT,
}
