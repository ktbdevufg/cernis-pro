"""Use-Case des DNS-Waechters (Block 2, Etappe 2d-1): ``BuildDnsWatch``.

Fuehrt die VERBINDUNGS-Sicht DIESES Hosts mit zwei editierbaren Listen (erwartete
DNS-Server, DoH-Anbieter) und einer Namens-Anreicherung zu einer DNS-Befund-Sicht
zusammen. Datenquelle ist NICHT capture, sondern -- wie outbound -- die lokale
net_connections-Sicht (gleiche Naht). Kennt ``application/dns_watch`` und die reine
``domain/dns_watch`` (Modelle + Klassifikations-Logik) -- NIE ``infrastructure``, NIE
``modules`` (import-linter). Die Quellen kommen quellen-AGNOSTISCH per
Constructor-Injection als schmale, lokal definierte Protocols/Callables herein (Muster
``BuildOutboundContacts``). Die echte Verdrahtung faellt erst im Composition Root.

FACHLICHE GRENZE (ehrlich, S3): die spaeter verdrahtete Quelle sieht NUR die
ausgehenden Verbindungen DIESES CERNIS-Hosts, NICHT netzweit. Die Sicht ist also "die
DNS-relevanten Aussenkontakte DIESES Rechners" -- nichts Netzweites wird vorgetaeuscht
(``host_scope`` traegt den Marker).

ANREICHERUNG DEFENSIV (best-effort, S3): schlaegt der Namens-Provider fehl bzw. liefert
er fuer eine IP nichts, bleibt ``hostname`` ``None`` -- der Use-Case wirft NICHT und
erfindet keinen Wert. Persistenz/API/Frontend kommen in spaeteren Etappen.
"""

from collections.abc import Awaitable, Callable, Sequence
from typing import Protocol

import structlog

from domain.dns_watch import (
    ACKNOWLEDGED_COUNT_KEYS,
    CATEGORY_EXPECTED,
    CATEGORY_OPEN,
    CATEGORY_POSSIBLE_DOH,
    HOST_SCOPE_LOCAL,
    DnsContact,
    DnsWatchOverview,
    RawDnsConnection,
    acknowledged_count_key,
    classify,
)

__all__ = [
    "AcknowledgedProvider",
    "BuildDnsWatch",
    "DnsConnectionsProvider",
    "DohProvidersProvider",
    "ExpectedServersProvider",
    "HostnameProvider",
]

_logger = structlog.get_logger(__name__)

# Deterministische Kategorie-Reihenfolge fuer die Sortierung: Auffaelliges zuerst
# (offen < moegliche_doh < erwartungsgemaess). Reines Sortier-Datum.
_CATEGORY_ORDER = {
    CATEGORY_OPEN: 0,
    CATEGORY_POSSIBLE_DOH: 1,
    CATEGORY_EXPECTED: 2,
}


# ── Quellen-agnostische Nahtstellen (lokal definiert, KEINE Fremd-Domaenentypen) ──


class DnsConnectionsProvider(Protocol):
    """Liefert die aktuellen ausgehenden Verbindungen DIESES Hosts (Snapshot).

    Quellen-AGNOSTISCH: gibt ``RawDnsConnection``-Records zurueck (KEIN
    ``traffic.Connection``). NUR Verbindungen mit Gegenstelle (``remote != None``) -- die
    Filterung liegt beim Adapter im Composition Root. Synchron, weil die echte Quelle
    (die lokale net_connections-Sicht) ein lokaler Snapshot ist.
    """

    def __call__(self) -> Sequence[RawDnsConnection]:
        """Aktuelle ausgehende Verbindungen DIESES Hosts (nur mit Gegenstelle)."""
        ...


# Quellen-AGNOSTISCHE Namens-Naht: IPs -> ``{ip: hostname | None}`` (PTR/SNI gemischt,
# der Composition Root entscheidet die Quelle). BEWUSST ein rohes dict -- dieser Ring
# nennt resolver/sni nicht. Async, weil die echte Quelle (PTR) Netz-I/O machen kann;
# STRENG fehlertolerant am Rand verdrahtet (eine IP ohne Namen traegt ``None``).
HostnameProvider = Callable[[Sequence[str]], Awaitable[dict[str, str | None]]]

# Liefert die effektiv "als bekannt markierten" Befund-Schluessel. Schluessel-Form:
# ``f"{remote_ip}:{category}"`` (append-only abgeleitet, kommt aus der Persistenz in
# 2d-2). Sync -- ein lokaler Lese-Snapshot.
AcknowledgedProvider = Callable[[], set[str]]

# Liefern die editierbaren Listen (erwartete DNS-Server bzw. DoH-Anbieter-IPs).
# Defaults/Persistenz in 2d-2/2d-3 -- hier nur die Naht. Sync -- lokaler Lese-Snapshot.
ExpectedServersProvider = Callable[[], Sequence[str]]
DohProvidersProvider = Callable[[], Sequence[str]]


class BuildDnsWatch:
    """Aggregiert die DNS-relevanten Befunde DIESES Hosts aus den injizierten Quellen.

    Quellen-AGNOSTISCH (Muster ``BuildOutboundContacts``): bekommt einen
    ``DnsConnectionsProvider`` (ausgehende Verbindungen), einen ``HostnameProvider``
    (IPs -> Namen), einen ``AcknowledgedProvider`` (quittierte Befund-Schluessel) sowie
    ``ExpectedServersProvider`` und ``DohProvidersProvider`` (die editierbaren Listen) per
    Constructor-Injection -- keiner nennt eine Fremd-Domaene. Die echte Verdrahtung faellt
    erst im Composition Root.

    KLASSIFIKATION (rein, ``domain/dns_watch``): je Verbindung entscheidet ``classify``
    die Kategorie; nicht-relevante Verbindungen (``None``) werden uebersprungen.

    AGGREGATIONS-REGEL: die relevanten Verbindungen werden nach ``(remote_ip, category)``
    gruppiert -- ein ``DnsContact`` je Paar. ``connection_count`` zaehlt die Verbindungen
    der Gruppe; ``remote_port``/``app_name``/``pid`` stammen aus der ERSTEN gesehenen
    Verbindung der Gruppe (dokumentierte, deterministische Regel).

    ANREICHERUNG DEFENSIV (best-effort, S3): ``hostname`` (ein Batch-Aufruf ueber die
    eindeutigen IPs) wird dazugefuegt -- fehlt die Quelle / wirft sie, bleibt das Feld
    ``None`` und der Use-Case wirft NICHT. ``acknowledged`` ist True, wenn
    ``f"{remote_ip}:{category}"`` im quittierten Set liegt.

    ZAEHLUNG (Muster CVE ``findings_total``/``findings_active``): ein QUITTIERTER Befund
    zaehlt nicht mehr als offen. Er faellt aus dem Kategorie-Zaehler heraus und in den
    zusaetzlichen ``quittiert_<kategorie>``-Zaehler -- verlustfrei, denn der Bestand je
    Kategorie ist die Summe beider Zahlen. Die Liste ``contacts`` bleibt davon UNBERUEHRT
    vollstaendig: quittierte Gegenstellen werden weiter gezeigt und tragen ihr
    ``acknowledged``-Merkmal (es wird nichts ausgeblendet).

    REIHENFOLGE deterministisch: Kategorie (``offen`` < ``moegliche_doh`` <
    ``erwartungsgemaess``, Auffaelliges zuerst), dann ``connection_count`` absteigend,
    dann ``remote_ip`` aufsteigend (stabiler Tie-Breaker).
    """

    def __init__(
        self,
        connections: DnsConnectionsProvider,
        hostnames: HostnameProvider,
        acknowledged: AcknowledgedProvider,
        expected_servers: ExpectedServersProvider,
        doh_providers: DohProvidersProvider,
    ) -> None:
        self._connections = connections
        self._hostnames = hostnames
        self._acknowledged = acknowledged
        self._expected_servers = expected_servers
        self._doh_providers = doh_providers

    async def __call__(self) -> DnsWatchOverview:
        """Baut die ``DnsWatchOverview`` DIESES Hosts (Klassifikation + Aggregation).

        Holt die editierbaren Listen, klassifiziert jede Verbindung, gruppiert die
        relevanten nach ``(remote_ip, category)``, reichert die Namen defensiv (Batch) an,
        markiert quittierte Befunde, zaehlt die Kontakte je Kategorie -- AKTIVE unter dem
        Kategorie-Schluessel, QUITTIERTE unter ``quittiert_<kategorie>`` -- und gibt die
        deterministisch sortierten Befunde mit ``host_scope = "local_host"`` zurueck. Eine
        leere relevante Menge ergibt leere ``contacts`` und ``counts`` alle 0 -- die Listen
        sind trotzdem gefuellt (ehrlicher Beleg).
        """
        # Listen holen + defensiv in normalisierte Mengen ueberfuehren (gleiche Form wie
        # die domain-Logik vergleicht: strip + lower).
        expected_raw = tuple(self._expected_servers())
        doh_raw = tuple(self._doh_providers())
        expected_set = {ip.strip().lower() for ip in expected_raw}
        doh_set = {ip.strip().lower() for ip in doh_raw}

        grouped = self._group_relevant(self._connections(), expected_set, doh_set)

        # counts deckt IMMER alle drei Kategorien ab (auch bei 0) -- ehrlicher Beleg -- und
        # dazu die drei quittierten Zaehler ``quittiert_<kategorie>``.
        counts: dict[str, int] = {
            CATEGORY_EXPECTED: 0,
            CATEGORY_OPEN: 0,
            CATEGORY_POSSIBLE_DOH: 0,
        }
        counts.update(dict.fromkeys(ACKNOWLEDGED_COUNT_KEYS, 0))

        if not grouped:
            # Keine DNS-relevante Verbindung -> leere, aber ehrlich markierte Sicht.
            return DnsWatchOverview(
                contacts=(),
                host_scope=HOST_SCOPE_LOCAL,
                counts=counts,
                expected_servers=expected_raw,
                doh_providers=doh_raw,
            )

        unique_ips = list({ip for (ip, _category) in grouped})
        hostnames = await self._resolve_hostnames(unique_ips)
        acknowledged_keys = self._load_acknowledged()

        contacts: list[DnsContact] = []
        for (ip, category), group in grouped.items():
            first, count = group
            # Das Quittier-Merkmal steht VOR der Zaehlung fest: ein quittierter Befund
            # zaehlt nicht mehr in seiner Kategorie (dem AKTIVEN Warnstand), sondern in
            # ``quittiert_<kategorie>``. Weggerechnet wird nichts -- die Gegenstelle bleibt
            # in ``contacts`` und der Bestand ist die Summe beider Zahlen.
            acknowledged = f"{ip}:{category}" in acknowledged_keys
            if acknowledged:
                counts[acknowledged_count_key(category)] += 1
            else:
                counts[category] += 1
            contacts.append(
                DnsContact(
                    remote_ip=ip,
                    remote_port=first.remote_port,
                    category=category,
                    hostname=hostnames.get(ip),
                    app_name=first.app_name,
                    pid=first.pid,
                    connection_count=count,
                    acknowledged=acknowledged,
                )
            )

        contacts.sort(
            key=lambda c: (
                _CATEGORY_ORDER.get(c.category, len(_CATEGORY_ORDER)),
                -c.connection_count,
                c.remote_ip,
            )
        )
        return DnsWatchOverview(
            contacts=tuple(contacts),
            host_scope=HOST_SCOPE_LOCAL,
            counts=counts,
            expected_servers=expected_raw,
            doh_providers=doh_raw,
        )

    @staticmethod
    def _group_relevant(
        raw: Sequence[RawDnsConnection],
        expected_set: set[str],
        doh_set: set[str],
    ) -> dict[tuple[str, str], tuple[RawDnsConnection, int]]:
        """Gruppiert die DNS-relevanten Verbindungen nach ``(remote_ip, category)``.

        Nicht-relevante Verbindungen (``classify`` -> ``None``) werden uebersprungen. Die
        ERSTE gesehene Verbindung je Paar bleibt als Repraesentant erhalten (liefert
        ``remote_port``/``app_name``/``pid``); der Zaehler zaehlt alle Verbindungen des
        Paares. Einfuege-Reihenfolge = erstes Vorkommen je Paar (deterministisch).
        """
        grouped: dict[tuple[str, str], tuple[RawDnsConnection, int]] = {}
        for conn in raw:
            category = classify(conn, expected_set, doh_set)
            if category is None:
                continue
            key = (conn.remote_ip, category)
            existing = grouped.get(key)
            if existing is None:
                grouped[key] = (conn, 1)
            else:
                first, count = existing
                grouped[key] = (first, count + 1)
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
            _logger.warning("dns_watch_hostname_lookup_failed", count=len(ips), error=str(exc))
            return {}

    def _load_acknowledged(self) -> set[str]:
        """Holt das quittierte Befund-Set defensiv -- ein Quellen-Fehler -> leeres Set.

        Best-effort (S3): schlaegt der ``AcknowledgedProvider`` fehl, wird das GELOGGT und
        es gilt ein leeres Set (kein Befund gilt dann als quittiert) -- der Use-Case wirft
        NICHT.
        """
        try:
            return self._acknowledged()
        except Exception as exc:
            _logger.warning("dns_watch_acknowledged_lookup_failed", error=str(exc))
            return set()
