"""Modelle des DNS-Server-Vertrauensmodells (Etappe 1, Fundament -- ADR 0043).

Ein abgestuftes, nutzer-kuratiertes Vertrauensmodell fuer DNS-Server: es ersetzt
die starre "erwartete Menge" des netzweiten Umgehungs-Waechters (0042) durch je
Server gepflegte Vertrauens-Zustaende. Diese Datei traegt NUR die Werte
(``DnsTrustState``/``DnsServerCategory``) und das Aggregat ``TrustedDnsServer``
samt seiner reinen Uebergangs-Funktionen -- die Konsistenz-/Ableitungsregeln
wohnen spaeter im Use-Case bzw. im Composition Root, nicht hier.

Reine Domaene (ADR 0002): nur stdlib (``dataclasses``, ``enum``) -- keine Uhr
(die Zeit kommt als ``now``-Parameter herein), keine Persistenz, KEIN Import
einer Fremd-Domaene (die dns_trust-Domaene ist ein eigenstaendiges Konzept und
gehoert NICHT in ``dns_watch``/``dns_bypass``).
"""

from dataclasses import dataclass, replace
from enum import StrEnum

__all__ = [
    "DnsServerCategory",
    "DnsServerOrigin",
    "DnsTrustState",
    "TrustedDnsServer",
]


class DnsTrustState(StrEnum):
    """Nutzer-kuratierte Vertrauens-Haltung gegenueber EINEM DNS-Server.

    Muster ``domain.devices.TrustState``: das Enum traegt NUR den Wert, die
    Konsistenz-Regeln (was ein Zustandswechsel sonst noch impliziert) gehoeren
    spaeter in den Use-Case, NICHT hierher.

    Default in den Records ist ``NEUTRAL`` -- noch keine Wertung abgegeben. Ein
    ``TRUSTED``/``REJECTED`` ist immer eine bewusste Nutzer- (oder, fuer das
    Gateway, Auto-)Entscheidung.
    """

    TRUSTED = "trusted"
    NEUTRAL = "neutral"
    REJECTED = "rejected"


class DnsServerCategory(StrEnum):
    """Faktische Einordnung eines DNS-Servers nach seiner Rolle/Herkunft.

    Rein deskriptiv (WAS der Server ist), NICHT wertend (die Wertung traegt
    ``DnsTrustState``). Die Ableitung dieser Kategorie ist reine Fachlogik
    (``logic.categorize_dns_server``); die echten Lookups (Topologie, DoH-Liste,
    THREAT-Blocklist) kommen erst im Composition Root als Flags herein.
    """

    GATEWAY = "gateway"
    LOCAL_PRIVATE = "local_private"
    PUBLIC_RESOLVER = "public_resolver"
    UNKNOWN = "unknown"
    THREAT_LISTED = "threat_listed"


class DnsServerOrigin(StrEnum):
    """Herkunft eines erfassten DNS-Servers -- WIE er in den Bestand gekommen ist.

    Rein deskriptiv (Muster ``DnsServerCategory``), KEINE Wertung: die Wertung
    traegt ``DnsTrustState``, die Rolle ``DnsServerCategory``. Diese Achse
    beantwortet allein die Frage, woher der Eintrag stammt.

    ``OBSERVED`` ist der Regelfall und der Default: der Server wurde real
    beobachtet (System-Resolver beim Start, Gateway, Umgehungs-Ziel eines
    Aufzeichnungs-Ticks). ``MANUAL`` kennzeichnet einen von Hand hinterlegten
    Server, der (noch) NIE beobachtet wurde -- der Nutzer erwartet ihn, gesehen
    hat ihn niemand. ``MIGRATED`` stammt aus der Einmal-Uebernahme des
    entfallenen Einstellungs-Schluessels ``dns_expected_servers`` (S62 L7a).

    Sobald ein ``MANUAL``- oder ``MIGRATED``-Eintrag real beobachtet wird, wird er
    ``OBSERVED``: die Herkunft "noch nie gesehen" trifft dann nicht mehr zu. Diesen
    Uebergang leistet der Sync-Use-Case, nicht dieses Modul.
    """

    OBSERVED = "observed"
    MANUAL = "manual"
    MIGRATED = "migrated"


@dataclass(frozen=True)
class TrustedDnsServer:
    """Aggregat: EIN kuratierter DNS-Server samt Kategorie + Vertrauens-Zustand.

    Schluessel ist ``ip`` (kanonisch -- die Kanonisierung leistet der Aufrufer/
    das Repository, das Aggregat traegt den Wert). ``category`` ist die faktische
    Einordnung, ``trust_state`` die Nutzer-Wertung (Default ``NEUTRAL``).
    ``first_seen``/``last_seen`` sind Unix-ts (float; die Uhr wohnt in den
    Adaptern, hier kommt ``now`` herein). ``display_name`` ist ein best-effort
    Resolver-/Geraetename (``""`` moeglich, wenn keiner ermittelt wurde),
    ``notes`` eine optionale Nutzer-Notiz (``""`` Default).

    ``is_platform_placeholder`` kennzeichnet, dass dieser Eintrag ein funktionsloser
    Plattform-Platzhalter ist (Windows meldet ueber die Adapter-API drei fest eingebaute
    IPv6-Adressen ``fec0:0:0:ffff::1..3`` als DNS-Server, die keine Anfragen beantworten).
    Das ist eine ANDERE Achse als ``category`` (Herkunft) -- hier geht es um die
    Funktionsfaehigkeit, nicht die Rolle. Default ``False`` (regulaerer, funktionierender
    Eintrag). Die Erkennung leistet die reine ``logic.is_platform_placeholder``.

    ``expected_rank`` ist die nutzergesetzte erwartete Prioritaet (1..N, kleiner =
    hoeher); ``0`` = kein Rang. Reine Nutzer-Angabe, KEINE Messung.

    ``origin`` haelt fest, WIE der Eintrag in den Bestand kam (beobachtet, von Hand
    hinterlegt, aus dem Altbestand uebernommen) -- eine dritte, von ``category``
    (Rolle) und ``trust_state`` (Wertung) unabhaengige Achse. Default ``OBSERVED``:
    der Regelfall ist die Erfassung aus realer Beobachtung.
    """

    ip: str
    category: DnsServerCategory
    first_seen: float
    last_seen: float
    trust_state: DnsTrustState = DnsTrustState.NEUTRAL
    display_name: str = ""
    notes: str = ""
    is_platform_placeholder: bool = False
    expected_rank: int = 0
    origin: DnsServerOrigin = DnsServerOrigin.OBSERVED


def trust(server: TrustedDnsServer, now: float) -> TrustedDnsServer:
    """Setzt ``server`` auf ``TRUSTED`` und ``last_seen=now`` (reine Funktion).

    ``dataclasses.replace`` liefert eine neue Instanz; Kategorie, ``first_seen``,
    ``display_name`` und ``notes`` bleiben unberuehrt.
    """
    return replace(server, trust_state=DnsTrustState.TRUSTED, last_seen=now)


def reject(server: TrustedDnsServer, now: float) -> TrustedDnsServer:
    """Setzt ``server`` auf ``REJECTED`` und ``last_seen=now`` (reine Funktion)."""
    return replace(server, trust_state=DnsTrustState.REJECTED, last_seen=now)


def reset(server: TrustedDnsServer, now: float) -> TrustedDnsServer:
    """Setzt ``server`` zurueck auf ``NEUTRAL`` und ``last_seen=now`` (reine Funktion)."""
    return replace(server, trust_state=DnsTrustState.NEUTRAL, last_seen=now)
