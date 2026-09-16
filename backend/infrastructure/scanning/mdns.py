"""Adapter fuer ``MdnsPort`` -- Wrapper um ``modules.mdns.discover_mdns``.

``discover_mdns`` ist bereits ``async`` (kapselt das blockierende ``zeroconf``
selbst im Executor) -- direkt awaiten, KEIN eigenes ``run_in_executor``.

``modules.MDNSService`` -> ``domain.MdnsService`` (verlustfrei, domaenenrein):

* ``service_type`` -> ``type`` (Feld heisst in der Domaene ``type``).
* ``properties`` (im Altcode bereits zu ``dict[str, str]`` dekodiert) ->
  ``tuple[tuple[str, str], ...]`` in dict-Reihenfolge (frozen-tauglich; Muster
  wie ``_str_pairs`` im ScanHistory-Adapter, ohne Umsortieren -- verlustfrei).
* ``ip`` wird uebernommen -- der Use-Case (S.5) ordnet die Dienste ueber die IP
  dem passenden Host zu (Aequivalent zum Altcode-``group_by_ip``). Das
  Domaenenmodell ``MdnsService`` traegt dafuer ein ``ip``-Feld (S.5-Vorbau,
  analog zum ``ipv6``-Vorbau in S.4e -- ein verworfenes Feld waere ein
  v1-Funktionsverlust).

Sicherheits-/Altmuster-Befund (geprueft, hier akzeptabel):

* mDNS ist passive Discovery -- KEIN ``subprocess``/Shell, also kein S2-Terrain.
* Stiller Leer-Fallback: ``discover_mdns`` gibt bei fehlendem ``zeroconf``
  (``HAS_ZEROCONF`` False) leer zurueck, und ``_on_service_added`` schluckt
  Lookup-Fehler (``except Exception: pass``). Beides ist von "nichts gefunden"
  ununterscheidbar. ANDERS als beim nmap-Scan ist das hier akzeptabel: mDNS-
  Discovery ist best-effort (lausche eine Weile, sammle was kommt), kein
  definitiver Scan mit Ja/Nein-Aussage -- ``[]`` = "kein Dienst geantwortet" ist
  der vertraglich vorgesehene Leer-Zustand (Port: "Nichts gefunden -> ``[]``").
  Daher KEIN Exception-Umbau wie bei ``NmapScanError``; der Befund ist als
  bewusste Einschaetzung festgehalten, nicht still uebergangen.
"""

import asyncio
from typing import Any

from domain.scanning import MdnsService
from modules.mdns import discover_mdns

# Wartezeit vor dem EINEN internen Wiederholungsversuch, wenn der erste Lauf
# nichts geliefert hat. 1.5 s ist konservativ: spuerbar genug, damit ein spaet
# antwortender Responder (frisch gestarteter Dienst, verzoegerte Multicast-
# Zustellung) noch in den zweiten Lauf faellt, aber unkritisch fuer die
# Gesamtdauer des Scans.
_RETRY_DELAY = 1.5


def _to_domain(raw: Any) -> MdnsService:
    """``modules.MDNSService`` -> ``domain.MdnsService``.

    ``raw`` ist ``Any`` -- ``modules`` ist untypisiert (mypy ``follow_imports=
    skip``); der Adapter liest die bekannten Felder direkt und mappt sie explizit.
    ``properties`` (dict) -> sortierungsfreie ``(key, value)``-Tupel.
    """
    properties = tuple((str(k), str(v)) for k, v in (raw.properties or {}).items())
    return MdnsService(
        name=str(raw.name),
        type=str(raw.service_type),
        port=int(raw.port),
        hostname=str(raw.hostname),
        is_ndi=bool(raw.is_ndi),
        properties=properties,
        ip=str(raw.ip),
    )


class MdnsAdapter:
    """Erfuellt das ``MdnsPort``-Protocol strukturell."""

    async def discover(self, duration: float) -> list[MdnsService]:
        """Lauscht ``duration`` Sekunden und liefert die gefundenen Dienste.

        ``discover_mdns`` ist bereits async -- direkt awaiten. Nichts gefunden
        -> ``[]`` (siehe Modul-Docstring: best-effort, kein verdecktes Scheitern).

        Bleibt der erste Lauf leer, wird GENAU EINMAL nach ``_RETRY_DELAY``
        wiederholt -- ohne zweiten Nutzerklick. Multicast-Discovery ist
        best-effort; ein leerer erster Durchlauf heisst oft nur, dass kein
        Responder im Fenster geantwortet hat. Der Retry ist verlustfrei: hat der
        erste Lauf schon etwas geliefert, passiert nichts. Genau ein Versuch --
        keine Schleife, keine Rekursion.
        """
        raw_services = await discover_mdns(duration)
        if not raw_services:
            await asyncio.sleep(_RETRY_DELAY)
            raw_services = await discover_mdns(duration)
        return [_to_domain(raw) for raw in raw_services]
