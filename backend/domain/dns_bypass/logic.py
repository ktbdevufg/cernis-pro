"""Reine Klassifikations-Logik des DNS-Umgehungs-Waechters (ADR 0042).

Reine, testbare Funktionen ohne I/O, ohne Uhr, ohne Framework (ADR 0002). Sie
entscheiden je DNS-Anfrage nur EINE Frage: ist ihr Ziel-Resolver eine Umgehung, also
NICHT in der erwarteten-Resolver-Menge? Quellen-agnostisch ueber ``RawDnsQuery``.

FACHLICHE REGEL (bewusst schlicht, ADR 0042): eine Anfrage ist eine Umgehung, wenn ihr
Ziel (``dst_ip``) NICHT in der erwarteten Menge liegt -- KEINE eigene Reputationslogik,
keine Blocklist, keine DoH-Bewertung. Die konkrete Ableitung der Menge aus der
Konfiguration existiert schon als ``domain.dns_watch.expected_servers_or_default`` und
wird erst im Composition Root genutzt; hier bekommt die Domaene die Menge fertig herein.
"""

from domain.dns_bypass.models import RawDnsQuery

__all__ = [
    "is_bypass",
]


def _normalize_ip(ip: str) -> str:
    """Normalisiert eine IP fuer den defensiven Mengen-Vergleich (strip + lower).

    Reine Funktion, KEIN Netz-I/O: nur das, was ein robuster Vergleich gegen die erwartete
    Menge braucht (z. B. Gross-/Kleinschreibung bei IPv6, Rand-Whitespace) -- gleiche Form
    wie in ``domain.dns_watch``.
    """
    return ip.strip().lower()


def is_bypass(query: RawDnsQuery, expected_ips: set[str]) -> bool:
    """True, wenn die Anfrage eine Umgehung ist -- ihr Ziel nicht in der erwarteten Menge.

    Die Regel ist bewusst "Ziel nicht in erwarteter Menge" -- KEINE eigene
    Reputationslogik. Der Vergleich normalisiert die ``dst_ip`` defensiv
    (``_normalize_ip``); ``expected_ips`` wird vom Aufrufer bereits normalisiert erwartet
    (gleiche Form). Leere ``expected_ips`` -> jede Anfrage ist Umgehung. Reine Funktion,
    kein Netz-I/O.
    """
    return _normalize_ip(query.dst_ip) not in expected_ips
