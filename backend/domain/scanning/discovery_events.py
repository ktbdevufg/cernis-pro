"""Yield-Vokabular der Discovery-Phase (frozen dataclasses, ADR 0002).

Was ``HostDiscoveryPort.discover()`` als nativer async-Generator inkrementell
yieldet (Variante A): Fortschritt UND Funde im selben Strom, ohne Queue-Bruecke
und ohne ``modules.discover_subnet``-Callback. Der Adapter (S.4) besitzt die
Ping-Schleife selbst und yieldet pro abgearbeitetem Host einen ``DiscoveryTick``
sowie -- wenn der Host lebt -- einen ``DiscoveryHostFound``.

Wie ``ScanEvent`` (``events.py``) als Union (PEP-695-``type``-Alias) modelliert,
NICHT als Basisklasse: so kann mypy ein ``match`` ueber beide Event-Typen via
``typing.assert_never`` auf Vollstaendigkeit pruefen. Bewusst zwei getrennte
Typen statt eines ``host: DiscoveredHost | None`` -- ein Tick ohne Fund und ein
Fund sind verschiedene Ereignisse, nicht ein Feld, das mal gesetzt ist und mal
nicht.

KEINE Transport-/JSON-Details hier; die Uebersetzung in WS-Frames bleibt der
api-Schicht (S.6) ueber das davon getrennte ``ScanEvent``-Vokabular vorbehalten.
"""

from dataclasses import dataclass

from domain.scanning.models import DiscoveredHost


@dataclass(frozen=True)
class DiscoveryTick:
    """Ein abgearbeiteter Host der Ping-Schleife -- reiner Fortschritt.

    Wird pro gepingtem Host einmal geyieldet, unabhaengig davon, ob er lebt.
    ``completed``/``total`` speisen die Fortschrittsanzeige; ``total`` ist die
    Gesamtzahl der zu pingenden Adressen des CIDR.
    """

    completed: int
    total: int


@dataclass(frozen=True)
class DiscoveryHostFound:
    """Ein gefundener (lebender) Host. Folgt dem zugehoerigen ``DiscoveryTick``."""

    host: DiscoveredHost


type DiscoveryEvent = DiscoveryTick | DiscoveryHostFound
