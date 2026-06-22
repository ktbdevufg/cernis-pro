"""Reine Klassifikations-Logik des DNS-Waechters (Block 2, Etappe 2d).

Reine, testbare Funktionen ohne I/O, ohne Uhr, ohne Framework (ADR 0002). Sie
entscheiden je ausgehender Verbindung DIESES Hosts, OB sie DNS-relevant ist und in
WELCHE Kategorie sie faellt -- quellen-agnostisch ueber ``RawDnsConnection``.

FACHLICHE REGEL (Karl-Vorgabe): eine ausgehende Verbindung wird DNS-relevant, wenn sie
Port 53 (Plain-DNS/DoT-nah, UDP/TCP) ODER Port 443 zu einer bekannten DoH-Anbieter-IP
ist. Klassifikation in genau eine von drei Kategorien:

- ``"erwartungsgemaess"``: Port-53-Verbindung zu einer IP aus der ERWARTETEN-DNS-Liste
  (z. B. Gateway/konfigurierter Resolver).
- ``"offen"``: Port-53-Verbindung zu einer IP, die NICHT erwartet ist (fremder Resolver
  / DNS-Umgeher).
- ``"moegliche_doh"``: Port-443-Verbindung zu einer IP aus der DoH-Anbieter-Liste.

Verbindungen, die weder Port 53 noch DoH-IP-443 sind, sind NICHT DNS-relevant
(``classify`` -> ``None``, kein Eintrag).
"""

from domain.dns_watch.models import RawDnsConnection

__all__ = [
    "CATEGORY_EXPECTED",
    "CATEGORY_OPEN",
    "CATEGORY_POSSIBLE_DOH",
    "classify",
    "is_dns_relevant",
]

# Die drei Kategorie-Schluessel (reine Daten -- der api-Rand/das Frontend macht daraus
# Anzeigetexte). Genau einer davon landet je Befund in ``DnsContact.category``.
CATEGORY_EXPECTED = "erwartungsgemaess"
CATEGORY_OPEN = "offen"
CATEGORY_POSSIBLE_DOH = "moegliche_doh"

_PORT_DNS = 53
_PORT_HTTPS = 443


def _normalize_ip(remote_ip: str) -> str:
    """Normalisiert eine IP fuer den defensiven Mengen-Vergleich (strip + lower).

    Reine Funktion, KEIN Netz-I/O: nur das, was ein robuster Vergleich gegen die
    erwarteten/DoH-Listen braucht (z. B. Gross-/Kleinschreibung bei IPv6, Rand-Whitespace).
    """
    return remote_ip.strip().lower()


def is_dns_relevant(conn: RawDnsConnection, doh_provider_ips: set[str]) -> bool:
    """True, wenn die Verbindung DNS-relevant ist.

    DNS-relevant ist sie bei ``remote_port == 53`` ODER bei ``remote_port == 443`` UND
    normalisierter ``remote_ip`` in ``doh_provider_ips``. ``doh_provider_ips`` wird vom
    Aufrufer bereits normalisiert erwartet (gleiche Form wie ``_normalize_ip``).
    """
    if conn.remote_port == _PORT_DNS:
        return True
    if conn.remote_port == _PORT_HTTPS:
        return _normalize_ip(conn.remote_ip) in doh_provider_ips
    return False


def classify(
    conn: RawDnsConnection,
    expected_server_ips: set[str],
    doh_provider_ips: set[str],
) -> str | None:
    """Klassifiziert die Verbindung in genau eine der drei Kategorien -- oder ``None``.

    Port 53 + ``remote_ip`` in ``expected_server_ips`` -> ``"erwartungsgemaess"``;
    Port 53 + nicht erwartet -> ``"offen"``;
    Port 443 + ``remote_ip`` in ``doh_provider_ips`` -> ``"moegliche_doh"``;
    sonst ``None`` (nicht DNS-relevant -> kein Eintrag).

    Der IP-Vergleich ist defensiv normalisiert (``_normalize_ip``); beide Mengen werden
    bereits normalisiert erwartet. Reine Funktion, kein Netz-I/O.
    """
    if conn.remote_port == _PORT_DNS:
        if _normalize_ip(conn.remote_ip) in expected_server_ips:
            return CATEGORY_EXPECTED
        return CATEGORY_OPEN
    if conn.remote_port == _PORT_HTTPS:
        if _normalize_ip(conn.remote_ip) in doh_provider_ips:
            return CATEGORY_POSSIBLE_DOH
        return None
    return None
