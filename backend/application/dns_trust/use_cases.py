"""Use-Cases des DNS-Server-Vertrauensmodells (ADR 0043, Etappe 3).

Der Application-Ring des Vertrauensmodells: erkannte DNS-Server (aus Waechter-Verkehr,
System-Resolvern, Gateway) werden kategorisiert (reine ``domain.dns_trust``-Logik),
mit Bestands-Indizien angereichert und persistiert (``ports.dns_trust``); Nutzer-
Aktionen (vertrauen/ablehnen/zuruecksetzen) sind eigene Use-Cases.

QUELLEN-AGNOSTISCH (Muster ``application/dns_bypass``): kennt NUR ``domain.dns_trust`` +
``ports.dns_trust``. KEIN ``infrastructure``-Import, KEIN ``modules``-Import (import-linter)
und KEINE Fremd-Domaene. Alle externen Nachschlage-Wege kommen als schmale, lokal
definierte Protocols/Callables per Constructor-Injection herein -- die echten Lookups
(Topologie, DoH-/Resolver-Liste, THREAT-Blocklist, Geraete-Bestand) faellt erst der
Composition Root (Regel 5). KEIN Fremd-Domaenentyp taucht in einer Signatur auf: die
Bestands-Indizien tragen einen EIGENEN, schlanken application-Datentraeger
(``DnsServerPlausibility``), NICHT ``domain.devices.Device``.
"""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import ClassVar

from domain.dns_trust import (
    DnsTrustState,
    TrustedDnsServer,
    categorize_dns_server,
    default_trust_for,
)
from ports.dns_trust import DnsTrustRepository

__all__ = [
    "DnsServerPlausibility",
    "GatewayProvider",
    "ListDnsTrustServers",
    "PlausibilityProvider",
    "PublicResolverCheck",
    "SetDnsServerTrust",
    "SyncDnsTrustServer",
    "ThreatCheck",
    "TrustedDnsServerIps",
]


# ── Schmale, injizierte Nahtstellen (lokal definiert, KEIN Fremd-Domaenentyp) ──

# Die Gateway-IP des Netzes (Muster ``_topology_gateway``); ``None`` bzw. leer, wenn
# keine ermittelbar ist. Async, weil der reale Weg (Interface-Discovery) ein Await ist.
GatewayProvider = Callable[[], Awaitable[str | None]]

# Ist die IP ein bekannter oeffentlicher Resolver? Der Composition Root fuellt das ueber
# die Resolver-Liste bzw. die aktive DoH-Quelle -- hier nur der reine bool-Test.
PublicResolverCheck = Callable[[str], bool]

# Steht die IP auf einer AKTIVEN THREAT-Blocklist? (Muster der Blocklist-Lookup-Naht.)
ThreatCheck = Callable[[str], bool]


@dataclass(frozen=True)
class DnsServerPlausibility:
    """Beschreibende Bestands-Indizien zu EINER DNS-Server-IP (application-Datentraeger).

    Ein schlanker, EIGENER application-Typ -- KEIN ``domain``-Typ und KEIN Fremd-
    Domaenentyp (``Device`` bleibt draussen): so importiert der Application-Ring keine
    Fremd-Domaene. Der Composition Root fuellt die Felder aus dem Geraete-Bestand (ueber
    die ``last_ip``-Naht), der Use-Case reicht sie nur durch.

    REIN DESKRIPTIV, KEINE Wertung: ``in_inventory`` (die IP ist ein bekanntes Geraet),
    ``first_seen_days`` (Alter des Geraets in ganzen Tagen, ``None`` wenn unbekannt),
    ``vendor``/``display_name`` (best-effort Namen, ``""`` moeglich), ``open_ports``
    (die bekannten offenen Ports des Geraets). Die WERTUNG bleibt dem Nutzer
    (``DnsTrustState``) -- diese Indizien legen ihm nur etwas vor.
    """

    in_inventory: bool
    first_seen_days: int | None
    vendor: str
    open_ports: tuple[int, ...]
    display_name: str


# Bestands-Indizien zur IP; kein Treffer -> ``None`` (die IP ist kein bekanntes Geraet).
PlausibilityProvider = Callable[[str], DnsServerPlausibility | None]


# ── Use-Cases ─────────────────────────────────────────────────────────────────


class SyncDnsTrustServer:
    """Erfasst/aktualisiert EINEN erkannten DNS-Server (Kategorie-Ableitung + Persistenz).

    Quellen-agnostisch: nimmt eine erkannte IP + ``now`` herein, loest ueber die injizierten
    Nahtstellen die drei Flags auf (``is_gateway`` = IP == Gateway-Ergebnis, ``is_public``
    = ``PublicResolverCheck``, ``is_threat`` = ``ThreatCheck``) und leitet die Kategorie ueber
    die reine ``domain.categorize_dns_server`` ab.

    Existiert der Server im Repo schon: ``category``/``last_seen``/``display_name``
    aktualisieren, ``trust_state`` NIE ueberschreiben (das ist User-gesteuert) und
    ``first_seen`` bewahren. Neu: ``TrustedDnsServer`` mit ``first_seen == last_seen == now``,
    ``trust_state`` ueber ``domain.default_trust_for(category)`` (nur GATEWAY -> TRUSTED,
    sonst NEUTRAL). In beiden Faellen ``repo.upsert`` und den (ggf. neuen) Record zurueck.

    ``display_name`` wird best-effort ueber den ``PlausibilityProvider`` beigestellt (die
    IP kann ein bekanntes Geraet sein); kein Treffer -> ``""`` beim Neuanlegen bzw. der
    bestehende Name beim Update bleibt erhalten, falls kein neuer ermittelt wurde.
    """

    def __init__(
        self,
        repo: DnsTrustRepository,
        gateway: GatewayProvider,
        is_public_resolver: PublicResolverCheck,
        is_threat_listed: ThreatCheck,
        plausibility: PlausibilityProvider,
    ) -> None:
        self._repo = repo
        self._gateway = gateway
        self._is_public_resolver = is_public_resolver
        self._is_threat_listed = is_threat_listed
        self._plausibility = plausibility

    async def __call__(self, ip: str, now: float) -> TrustedDnsServer:
        gateway_ip = await self._gateway()
        is_gateway = bool(gateway_ip) and ip == gateway_ip
        category = categorize_dns_server(
            ip,
            is_gateway=is_gateway,
            is_public_resolver=self._is_public_resolver(ip),
            is_threat_listed=self._is_threat_listed(ip),
        )
        # best-effort Anzeigename aus dem Bestand (kein Treffer -> "").
        indizien = self._plausibility(ip)
        detected_name = indizien.display_name if indizien is not None else ""

        existing = self._repo.get(ip)
        if existing is not None:
            # Update: Kategorie/last_seen/display_name pflegen, trust_state + first_seen
            # bewahren (trust_state ist User-gesteuert, NIE hier ueberschreiben). Ein leerer
            # neuer Name laesst den bestehenden stehen (kein Verschlechtern).
            updated = TrustedDnsServer(
                ip=existing.ip,
                category=category,
                first_seen=existing.first_seen,
                last_seen=now,
                trust_state=existing.trust_state,
                display_name=detected_name or existing.display_name,
                notes=existing.notes,
            )
            self._repo.upsert(updated)
            return updated

        # Neuanlage: first_seen == last_seen == now, Vor-Vertrauen ueber die reine Domaene.
        created = TrustedDnsServer(
            ip=ip,
            category=category,
            first_seen=now,
            last_seen=now,
            trust_state=default_trust_for(category),
            display_name=detected_name,
        )
        self._repo.upsert(created)
        return created


class ListDnsTrustServers:
    """Listet alle kuratierten Server samt beigestellter Bestands-Indizien (rein lesend).

    ``repo.list_all()`` (nach ``first_seen`` sortiert -- s. Port) und je Server die
    Plausibilitaet ueber den ``PlausibilityProvider`` beistellen. Rueckgabe: eine Liste aus
    ``(TrustedDnsServer, DnsServerPlausibility | None)`` -- kein Treffer im Bestand -> die
    Indizien-Seite ist ``None``. Keine Wertung, kein Schreiben.
    """

    def __init__(
        self,
        repo: DnsTrustRepository,
        plausibility: PlausibilityProvider,
    ) -> None:
        self._repo = repo
        self._plausibility = plausibility

    def __call__(self) -> list[tuple[TrustedDnsServer, DnsServerPlausibility | None]]:
        return [(server, self._plausibility(server.ip)) for server in self._repo.list_all()]


class SetDnsServerTrust:
    """Nutzer-Aktion vertrauen/ablehnen/zuruecksetzen -> ``repo.set_trust`` (idempotent).

    ``decision`` ist einer von ``"trust"``/``"reject"``/``"reset"`` und wird auf den
    passenden ``DnsTrustState`` abgebildet (trust -> TRUSTED, reject -> REJECTED, reset ->
    NEUTRAL). Der schmale Schreibpfad des Repos aendert NUR ``trust_state`` + ``last_seen``
    (Kategorie/``first_seen`` bleiben); eine unbekannte ``ip`` ist ein definierter No-Op
    (kein Wurf). Ein unbekannter ``decision``-Wert ist ein Fehler (kein stiller Fallback --
    Finding S3): ``ValueError``.
    """

    _DECISIONS: ClassVar[dict[str, DnsTrustState]] = {
        "trust": DnsTrustState.TRUSTED,
        "reject": DnsTrustState.REJECTED,
        "reset": DnsTrustState.NEUTRAL,
    }

    def __init__(self, repo: DnsTrustRepository) -> None:
        self._repo = repo

    def __call__(self, ip: str, decision: str, now: float) -> None:
        state = self._DECISIONS.get(decision)
        if state is None:
            raise ValueError(f"unbekannte Vertrauens-Entscheidung: {decision!r}")
        self._repo.set_trust(ip, state, now)


class TrustedDnsServerIps:
    """Liefert die IPs aller als ``TRUSTED`` kuratierten Server (rein lesend) -> ``set[str]``.

    ``repo.list_all()`` gefiltert auf ``trust_state == TRUSTED``. Das ist die kuenftige
    "erwartete Menge" fuer den Umgehungs-Waechter (E4) -- HIER nur bereitgestellt, NICHT
    verdrahtet (kein Umbau der bestehenden ``expected_servers``-Klassifikation).
    """

    def __init__(self, repo: DnsTrustRepository) -> None:
        self._repo = repo

    def __call__(self) -> set[str]:
        return {
            server.ip
            for server in self._repo.list_all()
            if server.trust_state is DnsTrustState.TRUSTED
        }
