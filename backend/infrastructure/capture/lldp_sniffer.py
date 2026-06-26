"""Adapter fuer ``LldpSnifferPort`` -- zeitbegrenzter LLDP/CDP-Sniff ueber den Helfer-IPC.

ETAPPE 3b (Privilege-Separation): Der Adapter faehrt scapy NICHT mehr selbst. Der rohe
LLDP/CDP-Sniff lebt im on-demand gestarteten Helfer ``cernis-sniffd``; der Adapter
spricht ihn ueber den ``LldpHelperClient`` an (``infrastructure/sniffd_client/``). Die
Parser (``_parse_lldp``/``_parse_cdp``) und der EtherType/MAC-Dispatch sind in den
Helfer gewandert (``sniffd.sniff_core``); hier bleibt nur die Client-Anbindung + der
``LLDPNeighbor``-Bau aus den rohen Nachbar-dicts.

Der Helfer-Client wartet BLOCKIEREND (mit Timeout etwas groesser als ``duration``) auf
die EINE NEIGHBORS-Nachricht; ``capture`` kapselt das ueber ``run_in_executor`` und
bleibt ``async`` (Port-Vertrag) -- GENAU wie zuvor der blockierende scapy-``sniff``.

S3-HEILUNG (Wire unveraendert): Spawn-/Connect-/Helfer-ERROR-Pfad gibt der Client
``[]`` zurueck (keine Nachbarn statt Crash); hier wird das ggf. mit einem
``structlog``-Warn quittiert. Das Original-``capture`` gab bei Sniff-Fehler ebenfalls
``[]`` zurueck -- gleiches Aussenverhalten, der Betreiber sieht es strukturiert.

INJIZIERBARE SPAWN-NAHT: Der Konstruktor nimmt optional eine ``client_factory``
(Default ``None`` -> baut intern einen ``LldpHelperClient``); Tests injizieren einen
Fake-Client -- KEIN echter Subprozess/scapy in Tests (Muster wie
``ScapySniSniffer.channel_factory``).

Plattform: NUR Linux x64 (der Helfer kapselt die plattformnahe Sniff-Technik).
"""

import asyncio
from collections.abc import Callable
from typing import Any, Protocol

import structlog

from domain.capture import LLDPNeighbor
from infrastructure.sniffd_client import LldpHelperClient

_logger = structlog.get_logger(__name__)


class LldpClient(Protocol):
    """Schmale Naht zum LLDP-Helfer-Client (Spawn + Einmal-Sniff liegen dahinter)."""

    def capture(self, interface: str | None, duration: float) -> list[dict[str, Any]]:
        """Blockierender Einmal-Sniff -> rohe Nachbar-dict-Liste (``[]`` bei Fehler)."""
        ...


class ScapyLldpSniffer:
    """Erfuellt ``LldpSnifferPort`` strukturell -- zeitbegrenzter Sniff via Helfer-Client.

    Der Name bleibt aus Naht-Treue (Port-Verdrahtung in ``app.py``), obwohl scapy
    jetzt im Helfer laeuft. ``client_factory`` ist die injizierbare Spawn-Naht:
    Default ``None`` -> intern ein ``LldpHelperClient``; Tests injizieren einen Fake.
    """

    def __init__(self, client_factory: Callable[[], LldpClient] | None = None) -> None:
        self._client_factory: Callable[[], LldpClient] = (
            client_factory if client_factory is not None else LldpHelperClient
        )

    async def capture(self, interface: str | None, duration: float) -> list[LLDPNeighbor]:
        """Lauscht ``duration`` Sekunden auf LLDP/CDP (im Helfer) und liefert die Nachbarn.

        Baut den Helfer-Client, ruft dessen blockierendes ``capture`` ueber
        ``run_in_executor`` (die Methode bleibt ``async``), und baut aus jedem rohen
        Nachbar-dict ein ``LLDPNeighbor``. Keine Nachbarn / Helfer-Fehler -> ``[]``
        (nie ``None``); ein kaputtes Nachbar-dict wird still uebersprungen + geloggt
        (S3-Heilung: kein Crash).
        """
        loop = asyncio.get_running_loop()
        client = self._client_factory()
        raw = await loop.run_in_executor(None, client.capture, interface, duration)

        neighbors: list[LLDPNeighbor] = []
        for entry in raw:
            neighbor = self._neighbor_from_dict(entry)
            if neighbor is not None:
                neighbors.append(neighbor)
        return neighbors

    @staticmethod
    def _neighbor_from_dict(entry: dict[str, Any]) -> LLDPNeighbor | None:
        """Baut aus einem rohen Helfer-Nachbar-dict ein ``LLDPNeighbor`` (defensiv).

        Die Felder des Helfer-dicts (``sniff_core._parse_lldp_neighbor`` /
        ``_parse_cdp_neighbor``) entsprechen EXAKT den ``LLDPNeighbor``-Feldern;
        fehlende fuellt die dataclass mit Defaults. Ein kaputtes dict (falscher Typ /
        unbekanntes Feld / fehlende ``source_mac``) ergibt ``None`` + Warn -- ein
        einzelner Murks-Eintrag darf die Liste nicht killen.
        """
        try:
            return LLDPNeighbor(**entry)
        except (TypeError, ValueError) as exc:
            _logger.warning("lldp_neighbor_malformed", error=str(exc))
            return None
