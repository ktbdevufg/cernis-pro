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
    is_platform_placeholder,
)
from ports.dns_trust import DnsTrustRepository

__all__ = [
    "DnsServerPlausibility",
    "GatewayProvider",
    "ListDnsTrustServers",
    "PlausibilityProvider",
    "PublicResolverCheck",
    "SetDnsServerRank",
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

    ``is_platform_placeholder`` wird in BEIDEN Faellen (Neuanlage wie Update) ueber die reine
    ``domain.is_platform_placeholder`` je IP gesetzt -- die drei funktionslosen Windows-
    Platzhalter (``fec0:0:0:ffff::1..3``) werden so gekennzeichnet, statt herausgefiltert.
    Da die Pruefung rein von der IP abhaengt, bleibt ein bereits gespeicherter Eintrag beim
    erneuten Sync korrekt (derselbe IP -> derselbe Flag-Wert).
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

        # Funktionsloser Windows-Platzhalter? Rein aus der IP abgeleitet (reine Domaene) --
        # ein einziger Schreibvorgang, kein nachtraegliches Korrigieren im Composition Root.
        placeholder = is_platform_placeholder(ip)

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
                is_platform_placeholder=placeholder,
                # expected_rank ist User-gesteuert (wie trust_state) -- bewahren.
                expected_rank=existing.expected_rank,
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
            is_platform_placeholder=placeholder,
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
    """Die IPs aller als ``TRUSTED`` kuratierten Server, DETERMINISTISCH geordnet.

    ``repo.list_all()`` gefiltert auf ``trust_state == TRUSTED``. Das ist die EINE
    erwartete Menge BEIDER Waechter-Sichten (S62 L7a): der netzweite Umgehungs-Waechter
    UND der host-lokale DNS-Waechter beziehen sie hier -- eine Quelle, keine zweite
    Ableitung aus einem Einstellungs-Schluessel mehr.

    RUECKGABE IST EINE ``list``, KEIN ``set``: die Menge wird in Oberflaeche, Bericht und
    PDF ANGEZEIGT (Fusszeile "Erwartete DNS-Server: ..."). Ein ``set`` haette dort eine
    lauf-zu-lauf wechselnde Reihenfolge durchschlagen lassen -- derselbe Bestand haette
    je nach Prozess-Start anders ausgesehen. Die Ordnung ist darum fachlich begruendet
    und stabil:

    1. Rangierte Server (``expected_rank`` 1..N) VOR unrangierten -- der Rang ist die
       nutzergesetzte erwartete Prioritaet und gehoert an den Anfang.
    2. Innerhalb der Rangierten aufsteigend nach ``expected_rank`` (kleiner = hoeher).
    3. Alle uebrigen (``expected_rank == 0``) aufsteigend nach ``ip`` als Zeichenkette --
       ein rein mechanischer, aber vollstaendig reproduzierbarer Stichentscheid. Bewusst
       NICHT ``first_seen``: zwei Eintraege koennen denselben Zeitstempel tragen (ein
       Bootstrap schreibt sie in derselben Sekunde), die ``ip`` ist als Primaerschluessel
       dagegen eindeutig -- damit ist die Ordnung total, nicht nur teilweise.

    Rein lesend, keine Uhr, kein Schreiben.
    """

    def __init__(self, repo: DnsTrustRepository) -> None:
        self._repo = repo

    def __call__(self) -> list[str]:
        trusted = [
            server
            for server in self._repo.list_all()
            if server.trust_state is DnsTrustState.TRUSTED
        ]
        # Unrangierte hinter ALLE rangierten: rank 0 -> +inf als Sortier-Schluessel.
        trusted.sort(
            key=lambda server: (
                server.expected_rank if server.expected_rank > 0 else float("inf"),
                server.ip,
            )
        )
        return [server.ip for server in trusted]


class SetDnsServerRank:
    """Setzt den erwarteten Rang EINER ``ip`` und haelt die Rang-Sequenz kompakt (D4 E3).

    Der Rang ist die nutzergesetzte erwartete Prioritaet (1..N, kleiner = hoeher);
    ``rank == 0`` entfernt die ``ip`` aus der Rangordnung (unrangiert). Nach jedem
    Aufruf sind die Raenge der betroffenen Menge eine LUECKENLOSE 1..N-Folge ohne
    Doppelraenge: die Ziel-``ip`` landet auf dem gewuenschten Platz, die uebrigen
    ruecken in ihrer bisherigen Ordnung nach.

    Betroffen sind alle Server, die ``TRUSTED`` sind ODER bereits einen Rang tragen
    (``expected_rank > 0``) -- so bleibt ein Rang verlustfrei erhalten, auch wenn ein
    Server voruebergehend nicht trusted ist. ``rank < 0`` ist ein Fehler (kein stiller
    Fallback, S3): ``ValueError``. ``now`` kommt als Parameter herein (keine Uhr im
    Use-Case); geschrieben wird nur, was sich tatsaechlich aendert (``repo.set_rank``).
    """

    def __init__(self, repo: DnsTrustRepository) -> None:
        self._repo = repo

    def __call__(self, ip: str, rank: int, now: float) -> None:
        if rank < 0:
            raise ValueError(f"ungueltiger Rang (muss >= 0 sein): {rank}")

        # Betroffene Menge: trusted ODER bereits rangiert (verlustfrei).
        betroffen = [
            server
            for server in self._repo.list_all()
            if server.trust_state is DnsTrustState.TRUSTED or server.expected_rank > 0
        ]

        # Gewuenschter Rang je ip: die Ziel-ip bekommt den Wunsch, alle anderen ihren
        # bisherigen Rang. 0 heisst "aus der Ordnung raus" (bleibt/wird unrangiert).
        gewuenscht = {server.ip: server.expected_rank for server in betroffen}
        if ip in gewuenscht:
            gewuenscht[ip] = rank

        # Stabile Ordnung der zu rangierenden Server: (gewuenschter Rang, dann bisheriger
        # Rang, dann first_seen). Bei Rang-Kollision nimmt die Ziel-ip den Platz des
        # bisherigen Inhabers ein -- RICHTUNGSABHAENGIG: beim ABSENKEN (Wunsch >
        # bisheriger Rang) rueckt sie HINTER den Inhaber (sie will ja nach unten, der
        # Inhaber weicht nach vorn); beim ANHEBEN/Neuaufnehmen VOR ihn (der Inhaber
        # weicht nach hinten). Nur so ist der Pfeil-Tausch in BEIDE Richtungen ein
        # echter Tausch (ein fixes "Ziel immer vorn/hinten" macht je eine Richtung
        # zum No-Op).
        alter_rang = next((s.expected_rank for s in betroffen if s.ip == ip), 0)
        ziel_absenkung = alter_rang > 0 and rank > alter_rang
        zu_rangieren = [server for server in betroffen if gewuenscht[server.ip] > 0]
        zu_rangieren.sort(
            key=lambda server: (
                gewuenscht[server.ip],
                (1.0 if ziel_absenkung else 0.0) if server.ip == ip else 0.5,
                server.expected_rank if server.expected_rank > 0 else float("inf"),
                server.first_seen,
            )
        )

        # 1..N frisch durchnummerieren; alles andere (rank==0-Wunsch bzw. nicht-trusted
        # ohne Rang) erhaelt 0. Nur echte Aenderungen schreiben.
        neu: dict[str, int] = {server.ip: 0 for server in betroffen}
        for position, server in enumerate(zu_rangieren, start=1):
            neu[server.ip] = position
        for server in betroffen:
            if neu[server.ip] != server.expected_rank:
                self._repo.set_rank(server.ip, neu[server.ip], now)
