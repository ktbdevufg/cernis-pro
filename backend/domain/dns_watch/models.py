"""Ergebnis- und Eingabetypen des DNS-Waechters (Block 2, Etappe 2d).

Reine stdlib-frozen-dataclasses -- EIGENE ``Dns*``/``Raw*``-Typen, BEWUSST KEINE
Fremd-Domaenentypen (kein ``traffic.Connection``). Der DNS-Waechter ist eine
host-lokale Sicht (Variante A): Datenquelle ist NICHT capture, sondern die
VERBINDUNGS-Sicht DIESES Hosts (gleiche Naht wie outbound: lokale net_connections).
Die Naht laeuft im application-Ring ueber quellen-agnostische Callables; die Typen
hier sind ihr roher Ein-/Ausgaberand.

FACHLICHE GRENZE (ehrlich benannt, S3): die zugrundeliegende Quelle sieht NUR die
ausgehenden Verbindungen DIESES CERNIS-Hosts, NICHT netzweit. Eine
``DnsWatchOverview`` ist also "die DNS-relevanten Aussenkontakte DIESES Rechners" --
``host_scope`` traegt diesen Marker als reines Datum (der api-Rand/das Frontend macht
daraus den Anzeigetext, hier wird nichts vorgetaeuscht).
"""

from dataclasses import dataclass

__all__ = [
    "HOST_SCOPE_LOCAL",
    "DnsContact",
    "DnsWatchOverview",
    "RawDnsConnection",
]

# Fester Scope-Marker (reines Datum): die Befunde stammen vom LOKALEN CERNIS-Host,
# nicht netzweit -- identisch zu outbound. Der api-Rand/das Frontend macht daraus den
# Anzeigetext (S3-ehrlich).
HOST_SCOPE_LOCAL = "local_host"


@dataclass(frozen=True)
class RawDnsConnection:
    """Eine einzelne ausgehende Verbindung DIESES Hosts -- der rohe Eingaberand.

    Quellen-AGNOSTISCH (KEIN ``traffic.Connection``, analog ``RawConnection`` in
    outbound): der ``DnsConnectionsProvider`` liefert genau diese schmalen Felder, die
    echte Quelle (die lokale net_connections-Sicht) faellt erst im Composition Root.
    ``remote_ip`` ist immer gesetzt (der Provider liefert NUR Verbindungen mit
    Gegenstelle); ``remote_port``/``l4``/``app_name``/``pid`` sind optional (eine Quelle,
    die ein Feld nicht kennt, traegt ``None`` -- kein erfundener Wert, S3).
    """

    remote_ip: str
    remote_port: int | None
    l4: str | None
    app_name: str | None
    pid: int | None


@dataclass(frozen=True)
class DnsContact:
    """Ein aggregierter DNS-relevanter Befund = EINE (Remote-IP, Kategorie) DIESES Hosts.

    Fasst alle DNS-relevanten Verbindungen zur selben ``remote_ip`` in derselben
    ``category`` zu einem Befund zusammen: ``connection_count`` ist die Anzahl dieser
    Verbindungen; ``remote_port``/``app_name``/``pid`` stammen aus der ERSTEN gesehenen
    Verbindung der Gruppe (dokumentierte, deterministische Regel im Use-Case).
    ``category`` ist genau eine von ``"erwartungsgemaess"``/``"offen"``/``"moegliche_doh"``.
    ``hostname`` ist die best-effort-Anreicherung (PTR/SNI) -- fehlt die Quelle, bleibt
    das Feld ``None`` (kein geratener Wert, S3). ``acknowledged`` markiert einen vom
    Nutzer als bekannt quittierten Befund (Persistenz in 2d-2; hier nur das Feld).
    """

    remote_ip: str
    remote_port: int | None
    category: str
    hostname: str | None
    app_name: str | None
    pid: int | None
    connection_count: int
    acknowledged: bool = False


@dataclass(frozen=True)
class DnsWatchOverview:
    """Die Gesamtsicht: alle DNS-relevanten Befunde DIESES Hosts + Marker und Listen.

    ``contacts`` ist deterministisch sortiert (Auffaelliges zuerst: Kategorie
    ``offen`` < ``moegliche_doh`` < ``erwartungsgemaess``, dann ``connection_count``
    absteigend, dann ``remote_ip`` aufsteigend -- s. Use-Case). ``counts`` haelt die
    Anzahl der KONTAKTE je Kategorie (nicht ``connection_count``). ``expected_servers``
    und ``doh_providers`` sind die zur Klassifikation genutzten, editierbaren Listen
    (als ehrlicher Beleg, was der Befund bedeutet). ``host_scope`` ist der FESTE
    Marker-Schluessel (``"local_host"``), der festhaelt, dass dies die Befunde DIESES
    Rechners sind und NICHT netzweit -- als reines Datum.
    """

    contacts: tuple[DnsContact, ...]
    host_scope: str
    counts: dict[str, int]
    expected_servers: tuple[str, ...]
    doh_providers: tuple[str, ...]
