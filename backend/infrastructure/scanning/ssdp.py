"""Adapter fuer ``SsdpPort`` -- Wrapper um ``modules.ssdp.discover_ssdp``.

``discover_ssdp`` ist bereits ``async`` (kapselt das blockierende UDP-Socket-
Sammeln selbst im Executor) -- direkt awaiten, KEIN eigenes ``run_in_executor``.

``modules.SSDPDevice`` -> ``domain.SsdpService`` (verlustfrei, domaenenrein):

* uebernommen: ``server``, ``st``, ``location``.
* ``ip``, ``usn``, ``friendly_name`` (modules-Felder) gibt es im Domaenenmodell
  NICHT und werden bewusst verworfen (wie ``banner`` beim PortScanner) -- die
  IP-Zuordnung passiert spaeter im Use-Case (S.5), nicht hier.

Sicherheits-/Altmuster-Befund (geprueft, hier akzeptabel):

* SSDP ist passive Discovery (M-SEARCH senden, Antworten sammeln) -- KEIN
  ``subprocess``/Shell, also kein S2-Terrain.
* Stiller Leer-Fallback: ``discover_ssdp`` beendet die Sammelschleife bei
  ``socket.timeout`` und gibt die bis dahin gesammelten Geraete zurueck (leer,
  wenn keins geantwortet hat). Das ``socket.timeout`` ist hier KEIN verdecktes
  Scheitern, sondern der NORMALE Endpunkt des Sammelfensters -- ``[]`` =
  "kein Geraet geantwortet" ist der vertraglich vorgesehene Leer-Zustand (Port:
  "Nichts gefunden -> ``[]``"). Best-effort wie bei mDNS, kein definitiver Scan;
  daher KEIN Exception-Umbau wie bei ``NmapScanError``. Befund als bewusste
  Einschaetzung festgehalten, nicht still uebergangen.
"""

from typing import Any

from domain.scanning import SsdpService
from modules.ssdp import discover_ssdp


def _to_domain(raw: Any) -> SsdpService:
    """``modules.SSDPDevice`` -> ``domain.SsdpService``.

    ``raw`` ist ``Any`` -- ``modules`` ist untypisiert (mypy ``follow_imports=
    skip``); der Adapter liest die bekannten Felder direkt und mappt sie explizit.
    """
    return SsdpService(
        server=str(raw.server),
        st=str(raw.st),
        location=str(raw.location),
    )


class SsdpAdapter:
    """Erfuellt das ``SsdpPort``-Protocol strukturell."""

    async def discover(self, timeout: float) -> list[SsdpService]:
        """Sendet M-SEARCH, sammelt ``timeout`` Sekunden lang Antworten.

        ``discover_ssdp`` ist bereits async -- direkt awaiten. Nichts gefunden
        -> ``[]`` (siehe Modul-Docstring: best-effort, kein verdecktes Scheitern).
        """
        raw_devices = await discover_ssdp(timeout)
        return [_to_domain(raw) for raw in raw_devices]
