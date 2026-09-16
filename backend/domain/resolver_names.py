"""Statische Zuordnung bekannter oeffentlicher DNS-Resolver-IPs -> Anzeigename.

Reine Daten + reine Logik, KEIN I/O (Import-Regel: ``domain`` -> nur ``domain`` +
stdlib). Diese Tabelle deckt die grossen oeffentlichen Resolver ab (Google, Cloudflare,
Quad9, OpenDNS) samt gaengiger IPv6-Pendants. Sie ist die zweite Stufe der
Ziel-Resolver-Aufloesung im DNS-Umgehungs-Bericht (nach dem Geraete-Bestand, vor dem
Reverse-DNS) -- der Composition Root wendet die Prioritaet an, diese Domaene liefert nur
den statischen Namen.

EIGENSTAENDIG: KEIN Import aus einer anderen ``domain``-Subdomaene, kein Framework.
Die IPv6-Adressen sind in kanonischer, kleingeschriebener Kurzform hinterlegt und werden
beim Lookup normalisiert, damit unterschiedliche Schreibweisen (Grossschreibung,
fuehrende Nullen) denselben Treffer liefern.
"""

import ipaddress

__all__ = ["KNOWN_RESOLVERS", "known_resolver_name"]


# IP (kanonische Form) -> Anzeigename der grossen oeffentlichen Resolver. IPv4 steht
# schon kanonisch; die IPv6-Schluessel werden durch ``_canonical`` beim Aufbau ebenfalls
# kanonisiert, damit der Lookup schreibweise-unabhaengig trifft.
_RAW_RESOLVERS: dict[str, str] = {
    # Google Public DNS
    "8.8.8.8": "Google Public DNS",
    "8.8.4.4": "Google Public DNS",
    "2001:4860:4860::8888": "Google Public DNS",
    "2001:4860:4860::8844": "Google Public DNS",
    # Cloudflare
    "1.1.1.1": "Cloudflare DNS",
    "1.0.0.1": "Cloudflare DNS",
    "2606:4700:4700::1111": "Cloudflare DNS",
    "2606:4700:4700::1001": "Cloudflare DNS",
    # Quad9
    "9.9.9.9": "Quad9 DNS",
    "149.112.112.112": "Quad9 DNS",
    "2620:fe::fe": "Quad9 DNS",
    "2620:fe::9": "Quad9 DNS",
    # OpenDNS (Cisco)
    "208.67.222.222": "OpenDNS",
    "208.67.220.220": "OpenDNS",
    "2620:119:35::35": "OpenDNS",
    "2620:119:53::53": "OpenDNS",
}


def _canonical(ip: str) -> str | None:
    """Kanonisiert eine IP-Literal-Zeichenkette (ungueltig -> ``None``), rein.

    ``ipaddress.ip_address`` normalisiert IPv6 (Kleinschreibung, komprimierte Nullen)
    und IPv4 einheitlich; so trifft der Lookup unabhaengig von der Eingabe-Schreibweise.
    Kein IP-Literal (Hostname o. Ae.) -> ``None`` (der Aufrufer wertet das als "kein
    bekannter Resolver").
    """
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return None


# Beim Import einmal kanonisiert -- der Laufzeit-Lookup bleibt ein reiner dict-Zugriff.
KNOWN_RESOLVERS: dict[str, str] = {
    canonical: name
    for raw, name in _RAW_RESOLVERS.items()
    if (canonical := _canonical(raw)) is not None
}


def known_resolver_name(ip: str) -> str | None:
    """Liefert den Anzeigenamen eines bekannten oeffentlichen Resolvers oder ``None``.

    Kanonisiert die Eingabe zuerst (schreibweise-unabhaengig); steht die IP nicht in der
    Tabelle -- oder ist sie kein gueltiges IP-Literal --, gibt es ``None`` (kein Treffer,
    KEIN Fehler). Rein, kein I/O.
    """
    canonical = _canonical(ip)
    if canonical is None:
        return None
    return KNOWN_RESOLVERS.get(canonical)
