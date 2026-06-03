"""Domaenenmodelle der monitoring-Domaene -- reine Wertobjekte (stdlib, ADR 0002).

Kein Framework, kein I/O, kein asyncio/WS/State, KEIN Import aus anderen Domaenen:
monitoring kennt nur seine eigenen Modelle. Die Datentraeger sind 1:1 aus dem
Altcode ``modules/monitor.py`` uebernommen (charakterisierungstreu, keine
verfruehte Verschlankung) -- mit zwei bewussten Abweichungen, die unten erklaert
sind: ``event`` ist als ``MonitorEventType``-StrEnum typisiert (statt freier str),
und ``MonitorEvent`` traegt KEINE ``.to_dict()``-Methode mehr.
"""

from dataclasses import dataclass, field
from enum import StrEnum


class MonitorEventType(StrEnum):
    """Benanntes Domaenen-Vokabular der Monitor-Uebergaenge.

    StrEnum (Py 3.12): die Member serialisieren direkt als ihr str-Wert
    (``MonitorEventType.UP == "up"``), also bleibt der Altcode-String
    ("up"/"down"/"degraded") an den Raendern (WS-Frame, DB-Spalte) erhalten --
    typsicher in der Domaene, serialisierungskompatibel nach aussen.
    """

    UP = "up"
    DOWN = "down"
    DEGRADED = "degraded"


@dataclass(frozen=True)
class MonitorTarget:
    """Ein zu ueberwachendes Ziel (1:1 aus Altcode ``MonitorTarget``)."""

    id: str
    label: str
    host: str
    interface: str
    enabled: bool = True


@dataclass(frozen=True)
class PingSample:
    """Aggregiertes Ergebnis eines Ping-Bursts (1:1 aus Altcode ``PingResult``).

    Charakterisierungstreu uebernommen, inkl. ``target_id``/``host`` (im Altcode
    Transport-/Loop-Kontext) und des RTT-Sentinels ``-1.0`` (= "keine RTT"). Den
    Sentinel hier bewusst NICHT zu ``None`` normalisiert (anders als
    ``DiscoveredHost.rtt_ms`` in scanning) -- ob/wie er an den Rand normalisiert
    wird, ist eine M.4/M.5-Adapter-Entscheidung, nicht M.2.
    """

    target_id: str
    host: str
    alive: bool
    rtt_ms: float = -1.0
    loss_pct: float = 0.0
    timestamp: float = 0.0


@dataclass(frozen=True)
class MonitorEvent:
    """Ein erkannter Uebergang (Datentraeger, aus Altcode ``MonitorEvent``).

    REINER Datentraeger ohne ``.to_dict()``: die Altcode-Methode formatierte den
    ``timestamp`` zu ``"%H:%M:%S"``. Das ist VIEW-Verhalten, kein Datum -- und das
    Format DIVERGIERT schon im Altcode: ``.to_dict()`` nutzt ``"%H:%M:%S"`` (WS),
    die DB-Spalte ``"%Y-%m-%d %H:%M:%S"`` (Persistenz). Die Domaene haelt nur den
    rohen ``timestamp: float`` und entscheidet NICHT, welche Sicht "richtig" ist;
    jeder Rand formatiert selbst (M.9 WS, M.4 DB).

    BEFUND (nicht hier fixen, fuer M.4/M.9): die zwei Zeitformate fuer denselben
    Event-Timestamp sind Altcode-IST. v2 entscheidet an den Raendern bewusst, ob
    beide Formate beibehalten oder vereinheitlicht werden -- NICHT in M.2.
    """

    target_id: str
    label: str
    event: MonitorEventType
    rtt_ms: float
    timestamp: float = field(default=0.0)
