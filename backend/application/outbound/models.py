"""Ergebnistypen der outbound-Aggregation (Block 2, Etappe 2a).

Reine stdlib-frozen-dataclasses -- EIGENE ``Observed*``/``Raw*``-Typen, BEWUSST
KEINE Fremd-Domaenentypen (kein ``traffic.Connection``, kein
``resolver.RemoteEndpointFacts``, kein ``sni.ObservedSni``). Die Aggregation fuehrt
drei Quellen zusammen, OHNE deren Domaenen zu nennen -- die Naht laeuft im Use-Case
ueber quellen-agnostische Callables (Muster ``BuildRouteGeo``/``GeoLookup``), die
Typen hier sind ihr roher Ein-/Ausgaberand.

FACHLICHE GRENZE (ehrlich benannt, S3): die zugrundeliegenden Quellen (traffic ueber
psutil/``ss``, sni ueber den lokalen psutil-Poller) sehen NUR die Verbindungen DIESES
CERNIS-Hosts, NICHT netzweit. Eine ``OutboundOverview`` ist also "die Aussenkontakte
DIESES Rechners" -- ``host_scope`` traegt diesen Marker als reines Datum (der
api-Rand/das Frontend macht daraus den Anzeigetext, hier wird nichts vorgetaeuscht).
"""

from dataclasses import dataclass

__all__ = [
    "OutboundContact",
    "OutboundOverview",
    "RawConnection",
]


@dataclass(frozen=True)
class RawConnection:
    """Eine einzelne ausgehende Verbindung DIESES Hosts -- der rohe Eingaberand.

    Quellen-AGNOSTISCH (KEIN ``traffic.Connection``): der ``OutboundConnectionsProvider``
    liefert genau diese schmalen Felder, die echte Quelle (traffic-Use-Case) faellt erst
    im Composition Root. ``remote_ip`` ist immer gesetzt (der Provider liefert NUR
    Verbindungen mit Gegenstelle, ``remote != None``); ``remote_port``/``app_name``/``pid``
    sind optional (eine Quelle, die ein Feld nicht kennt, traegt ``None`` -- kein
    erfundener Wert, S3).
    """

    remote_ip: str
    remote_port: int | None
    app_name: str | None
    pid: int | None


@dataclass(frozen=True)
class OutboundContact:
    """Ein aggregierter Aussenkontakt = EINE Remote-IP DIESES Hosts, angereichert.

    Fasst alle Verbindungen zu derselben ``remote_ip`` zu einem Kontakt zusammen:
    ``connection_count`` ist die Anzahl dieser Verbindungen; ``remote_port``/``app_name``/
    ``pid`` stammen aus der ERSTEN gesehenen Verbindung zu dieser IP (dokumentierte,
    deterministische Regel im Use-Case). ``hostname`` (PTR/SNI) und ``country``/
    ``operator``/``asn`` sind die best-effort-Anreicherung -- fehlt die Quelle, bleibt
    das Feld ``None`` (kein geratener Wert, S3).
    """

    remote_ip: str
    remote_port: int | None
    hostname: str | None
    country: str | None
    operator: str | None
    asn: str | None
    app_name: str | None
    pid: int | None
    connection_count: int


@dataclass(frozen=True)
class OutboundOverview:
    """Die Gesamtsicht: alle Aussenkontakte DIESES Hosts + der Scope-Marker.

    ``contacts`` ist deterministisch sortiert (``connection_count`` absteigend, dann
    ``remote_ip`` aufsteigend -- s. Use-Case). ``host_scope`` ist ein FESTER
    Marker-Schluessel (``"local_host"``), der ehrlich festhaelt, dass dies die Kontakte
    DIESES Rechners sind und NICHT netzweit -- als reines Datum; die Anzeige macht der
    api-Rand/das Frontend.
    """

    contacts: tuple[OutboundContact, ...]
    host_scope: str
