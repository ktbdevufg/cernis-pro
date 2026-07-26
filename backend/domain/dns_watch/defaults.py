"""Reine Default-Listen-Logik des DNS-Waechters (Block 2, Etappe 2d).

Reine, testbare Funktionen OHNE I/O, OHNE Uhr, OHNE Framework (ADR 0002) -- sie
beantworten nur eine Fachfrage: welche DoH-Anbieter-IPs gelten, wenn der Nutzer nichts
(oder etwas) konfiguriert hat. Reine Fachdaten, deshalb in der Domaene.

Der Settings-Key (``dns_doh_providers``) und das Verdrahten dieser Funktion im
Composition Root liegen dort -- HIER nur der Baustein.

Die frueher hier wohnende ``expected_servers_or_default`` ist ENTFALLEN (S62 L7a): die
erwartete DNS-Server-Menge wird nicht mehr aus einem Einstellungs-Schluessel abgeleitet,
sondern ist die Menge der als vertraut kuratierten Server aus der ``dns_trust``-Domaene
(``application.dns_trust.TrustedDnsServerIps``). Eine reine Ableitungsfunktion ist dafuer
nicht mehr noetig, darum steht hier keine zurueck.
"""

from collections.abc import Sequence

__all__ = [
    "DEFAULT_DOH_PROVIDER_IPS",
    "doh_providers_or_default",
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


def doh_providers_or_default(configured: Sequence[str]) -> tuple[str, ...]:
    """Die DoH-Anbieter-IPs: Konfiguration gewinnt, sonst die Startliste.

    Ist ``configured`` nicht leer -> genau diese Liste (als Tupel). Sonst die fest
    eingebaute ``DEFAULT_DOH_PROVIDER_IPS``. Reine Funktion, kein I/O.
    """
    if configured:
        return tuple(configured)
    return DEFAULT_DOH_PROVIDER_IPS
