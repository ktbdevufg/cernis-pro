"""Use-Case der outbound-Aggregation (Block 2, Etappe 2a): ``BuildOutboundContacts``.

Fuehrt DREI Quellen zu einer Aussenkontakt-Sicht DIESES Hosts zusammen: die aktuellen
ausgehenden Verbindungen, die Namen (PTR/SNI) und die Geo/Betreiber/ASN-Anreicherung.
Kennt ``application/outbound`` (eigene ``models``) -- NIE ``infrastructure``, NIE
``modules``, NIE Domaenen-Interna anderer Domaenen (import-linter). Die drei Quellen
kommen quellen-AGNOSTISCH per Constructor-Injection als schmale, lokal definierte
Protocols/Callables herein (Muster ``BuildRouteGeo``: ``RunTraceroute`` + rohes
``GeoLookup``-Callable). So nennt dieser Ring weder traffic noch resolver noch sni --
die echte Verdrahtung der drei Quellen faellt erst im Composition Root (app.py).

FACHLICHE GRENZE (ehrlich, S3): die spaeter verdrahteten Quellen (traffic via
psutil/``ss``, sni via lokalem psutil-Poller) sehen NUR die Verbindungen DIESES
CERNIS-Hosts, NICHT netzweit. Die Aggregation ist also "Aussenkontakte DIESES
Rechners" -- nichts Netzweites wird vorgetaeuscht (``host_scope`` traegt den Marker).

ANREICHERUNG DEFENSIV (best-effort, S3): schlaegt eine Quelle fehl bzw. liefert sie
fuer eine IP nichts, bleibt das jeweilige Feld ``None`` -- der Use-Case wirft NICHT
und erfindet keinen Wert.
"""

from collections.abc import Awaitable, Callable, Sequence
from typing import Protocol

import structlog

from application.outbound.models import OutboundContact, OutboundOverview, RawConnection

__all__ = [
    "BuildOutboundContacts",
    "GeoOperatorProvider",
    "HostnameProvider",
    "OutboundConnectionsProvider",
]

_logger = structlog.get_logger(__name__)

# Fester Scope-Marker (reines Datum): die Kontakte stammen vom LOKALEN CERNIS-Host,
# nicht netzweit. Der api-Rand/das Frontend macht daraus den Anzeigetext (S3-ehrlich).
HOST_SCOPE_LOCAL = "local_host"


# ── Quellen-agnostische Nahtstellen (lokal definiert, KEINE Fremd-Domaenentypen) ──


class OutboundConnectionsProvider(Protocol):
    """Liefert die aktuellen ausgehenden Verbindungen DIESES Hosts (Snapshot).

    Quellen-AGNOSTISCH: gibt ``RawConnection``-Records zurueck (eigener schmaler Typ,
    KEIN ``traffic.Connection``). NUR Verbindungen mit Gegenstelle (``remote != None``,
    also ``remote_ip`` gesetzt) -- die Filterung liegt beim Adapter im Composition Root.
    Synchron, weil die echte Quelle (traffic via psutil/``ss``) ein lokaler Snapshot ist.
    """

    def __call__(self) -> Sequence[RawConnection]:
        """Aktuelle ausgehende Verbindungen DIESES Hosts (nur mit Gegenstelle)."""
        ...


# Quellen-AGNOSTISCHE Namens-Naht: IPs -> ``{ip: hostname | None}`` (PTR/SNI gemischt,
# der Composition Root entscheidet die Quelle). BEWUSST ein rohes dict (KEIN
# ``resolver.RemoteEndpointFacts``/``sni.ObservedSni``): dieser Ring nennt resolver/sni
# nicht. Async, weil die echte Quelle (PTR) Netz-I/O machen kann; STRENG fehlertolerant
# am Rand verdrahtet (eine IP ohne Namen fehlt schlicht / traegt ``None``).
HostnameProvider = Callable[[Sequence[str]], Awaitable[dict[str, str | None]]]

# Quellen-AGNOSTISCHE Geo/Betreiber/ASN-Naht: IP -> ``(country, operator, asn)``, jedes
# Feld optional. BEWUSST ein rohes Tupel (KEIN resolver-Domaenentyp). Async wie
# ``HostnameProvider`` (eine Quelle kann Netz-I/O sein); jedes fehlende Feld ist ``None``
# (S3: fehlende Quelle = None, kein erfundener Wert).
GeoOperatorProvider = Callable[[str], Awaitable[tuple[str | None, str | None, str | None]]]


class BuildOutboundContacts:
    """Aggregiert die Aussenkontakte DIESES Hosts aus den drei injizierten Quellen.

    Quellen-AGNOSTISCH (Muster ``BuildRouteGeo``): bekommt einen
    ``OutboundConnectionsProvider`` (ausgehende Verbindungen), einen ``HostnameProvider``
    (IPs -> Namen, PTR/SNI gemischt) und einen ``GeoOperatorProvider`` (IP ->
    Land/Betreiber/ASN) per Constructor-Injection -- keiner nennt eine Fremd-Domaene.
    Die echte Verdrahtung faellt erst im Composition Root.

    AGGREGATIONS-REGEL (rein, testbar): die Verbindungen werden nach ``remote_ip``
    gruppiert -- ein ``OutboundContact`` je IP. ``connection_count`` ist die Anzahl der
    Verbindungen zu dieser IP; ``remote_port``/``app_name``/``pid`` stammen aus der ERSTEN
    gesehenen Verbindung zu dieser IP (dokumentierte, deterministische Regel). Die
    Reihenfolge der Gruppen folgt dem ERSTEN Vorkommen je IP (stabil ueber den
    Eingabe-Snapshot).

    ANREICHERUNG DEFENSIV (best-effort, S3): ``hostname`` (ueber den ``HostnameProvider``,
    ein Batch-Aufruf ueber die eindeutigen IPs) und ``country``/``operator``/``asn`` (ueber
    den ``GeoOperatorProvider`` je IP) werden dazugefuegt -- fehlt die Quelle / liefert sie
    ``None``, bleibt das Feld ``None``. Der Use-Case wirft NICHT und erfindet nichts.

    REIHENFOLGE deterministisch: ``connection_count`` absteigend, dann ``remote_ip``
    aufsteigend (Tie-Breaker) -- so steht der "lauteste" Kontakt oben und gleiche Zaehler
    bleiben stabil/reproduzierbar.
    """

    def __init__(
        self,
        connections: OutboundConnectionsProvider,
        hostnames: HostnameProvider,
        geo_operator: GeoOperatorProvider,
    ) -> None:
        self._connections = connections
        self._hostnames = hostnames
        self._geo_operator = geo_operator

    async def __call__(self) -> OutboundOverview:
        """Baut die ``OutboundOverview`` DIESES Hosts (Gruppierung + Anreicherung).

        Holt den Verbindungs-Snapshot, gruppiert nach ``remote_ip`` (erste Verbindung
        liefert ``remote_port``/``app_name``/``pid``, ``connection_count`` zaehlt alle),
        reichert je IP Name (Batch) und Geo/Betreiber/ASN (je IP) defensiv an und gibt
        die deterministisch sortierten Kontakte mit ``host_scope = "local_host"`` zurueck.
        """
        grouped = self._group_by_ip(self._connections())
        if not grouped:
            # Kein ausgehender Kontakt -> leere, aber ehrlich markierte Sicht.
            return OutboundOverview(contacts=(), host_scope=HOST_SCOPE_LOCAL)

        ips = list(grouped.keys())
        hostnames = await self._resolve_hostnames(ips)

        contacts: list[OutboundContact] = []
        for ip, group in grouped.items():
            first, count = group
            country, operator, asn = await self._enrich_geo(ip)
            contacts.append(
                OutboundContact(
                    remote_ip=ip,
                    remote_port=first.remote_port,
                    hostname=hostnames.get(ip),
                    country=country,
                    operator=operator,
                    asn=asn,
                    app_name=first.app_name,
                    pid=first.pid,
                    connection_count=count,
                )
            )

        # Deterministisch: lauteste Kontakte zuerst, gleiche Zaehler stabil per IP.
        contacts.sort(key=lambda c: (-c.connection_count, c.remote_ip))
        return OutboundOverview(contacts=tuple(contacts), host_scope=HOST_SCOPE_LOCAL)

    @staticmethod
    def _group_by_ip(
        raw: Sequence[RawConnection],
    ) -> dict[str, tuple[RawConnection, int]]:
        """Gruppiert die Verbindungen nach ``remote_ip`` -> ``{ip: (erste, anzahl)}``.

        Die ERSTE gesehene Verbindung je IP bleibt als Repraesentant erhalten (liefert
        ``remote_port``/``app_name``/``pid``); ``anzahl`` zaehlt alle Verbindungen zu
        dieser IP. Einfuege-Reihenfolge des dict = erstes Vorkommen je IP (deterministisch).
        """
        grouped: dict[str, tuple[RawConnection, int]] = {}
        for conn in raw:
            existing = grouped.get(conn.remote_ip)
            if existing is None:
                grouped[conn.remote_ip] = (conn, 1)
            else:
                first, count = existing
                grouped[conn.remote_ip] = (first, count + 1)
        return grouped

    async def _resolve_hostnames(self, ips: Sequence[str]) -> dict[str, str | None]:
        """Holt die Namen-Map (Batch) defensiv -- ein Quellen-Fehler -> leere Map.

        Best-effort (S3): schlaegt der ``HostnameProvider`` fehl, wird das GELOGGT und es
        gilt eine leere Map (jedes ``hostname`` bleibt dann ``None``) -- der Use-Case wirft
        NICHT.
        """
        try:
            return await self._hostnames(ips)
        except Exception as exc:
            _logger.warning("outbound_hostname_lookup_failed", count=len(ips), error=str(exc))
            return {}

    async def _enrich_geo(self, ip: str) -> tuple[str | None, str | None, str | None]:
        """Holt ``(country, operator, asn)`` je IP defensiv -- ein Fehler -> alles ``None``.

        Best-effort (S3): schlaegt der ``GeoOperatorProvider`` fuer diese IP fehl, wird das
        GELOGGT und ``(None, None, None)`` zurueckgegeben -- der Use-Case wirft NICHT und
        erfindet keinen Wert.
        """
        try:
            return await self._geo_operator(ip)
        except Exception as exc:
            _logger.warning("outbound_geo_lookup_failed", ip=ip, error=str(exc))
            return (None, None, None)
