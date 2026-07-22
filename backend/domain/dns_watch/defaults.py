"""Reine Default-Listen-Logik des DNS-Waechters (Block 2, Etappe 2d).

Reine, testbare Funktionen OHNE I/O, OHNE Uhr, OHNE Framework (ADR 0002) -- sie
beantworten nur eine Fachfrage: welche erwarteten DNS-Server bzw. welche
DoH-Anbieter-IPs gelten, wenn der Nutzer nichts (oder etwas) konfiguriert hat. Reine
Fachdaten, deshalb in der Domaene.

Die Settings-Keys (``dns_expected_servers`` / ``dns_doh_providers``) und das Verdrahten
dieser Funktionen im Composition Root kommen in 2d-3 -- HIER nur die Bausteine.
"""

from collections.abc import Sequence

__all__ = [
    "DEFAULT_DOH_PROVIDER_IPS",
    "doh_providers_or_default",
    "expected_servers_or_default",
]

# Startliste bekannter oeffentlicher DoH-Resolver (reine IP-Strings, IPv4 + IPv6).
# Greift nur, wenn der Nutzer keine eigene DoH-Liste konfiguriert hat. Die Klassifikation
# normalisiert ohnehin (strip+lower), daher genuegen die rohen IPs hier.
DEFAULT_DOH_PROVIDER_IPS: tuple[str, ...] = (
    # Cloudflare
    "1.1.1.1",
    "1.0.0.1",
    "2606:4700:4700::1111",
    "2606:4700:4700::1001",
    # Google
    "8.8.8.8",
    "8.8.4.4",
    "2001:4860:4860::8888",
    "2001:4860:4860::8844",
    # Quad9
    "9.9.9.9",
    "149.112.112.112",
    "2620:fe::fe",
    "2620:fe::9",
)


def expected_servers_or_default(configured: Sequence[str]) -> tuple[str, ...]:
    """Die erwarteten DNS-Server: genau die konfigurierte Liste, sonst leer.

    Erwartet ist ausschliesslich, was der Nutzer gesetzt hat (als Tupel). Leere
    Konfiguration -> leeres Tupel -> jede Port-53-Verbindung gilt als "offen"
    (ehrlicher Default ohne Annahme, KEINE Gateway-Vermutung mehr). Reine
    Funktion, kein I/O.
    """
    return tuple(configured)


def doh_providers_or_default(configured: Sequence[str]) -> tuple[str, ...]:
    """Die DoH-Anbieter-IPs: Konfiguration gewinnt, sonst die Startliste.

    Ist ``configured`` nicht leer -> genau diese Liste (als Tupel). Sonst die fest
    eingebaute ``DEFAULT_DOH_PROVIDER_IPS``. Reine Funktion, kein I/O.
    """
    if configured:
        return tuple(configured)
    return DEFAULT_DOH_PROVIDER_IPS
