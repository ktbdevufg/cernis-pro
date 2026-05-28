"""Adapter fuer ``HostDiscoveryPort`` -- der Knackpunkt der scanning-Domaene.

VARIANTE A: Der Adapter besitzt die Ping-Schleife SELBST. Er ruft NICHT
``modules.discover_subnet`` auf (kein ``progress_cb``-Callback, keine
Queue-Bruecke) -- die Schleife ist neuer Code. Nur das EINZELNE ``ping_host``
(async) und ``get_arp_table`` (sync) kommen aus ``modules`` (ADR 0007 erlaubt das
in ``infrastructure.scanning``).

Ablauf (nativer async-Generator):

1. Alle Hosts des CIDR per ``ping_host`` parallel anpingen (``Semaphore`` als
   ``max_concurrent``-Drossel). Pro abgearbeitetem Host -- AUCH pro totem --
   einen ``DiscoveryTick(completed, total)`` yielden. ``total`` = alle Adressen
   des CIDR, ``completed`` zaehlt JEDEN abgearbeiteten Host (nicht nur lebende),
   exakt wie der Altcode-Zaehler in ``discover_subnet._scan_one``.
2. NACH der Schleife die ARP-Tabelle EINMAL holen (``get_arp_table`` ist
   blockierend -> ``run_in_executor``) und den lebenden Hosts ihre MAC zuordnen.
3. Erst DANN je lebenden Host einen ``DiscoveryHostFound`` MIT MAC yielden.

Bewusste Abweichung von der v1-Frame-Reihenfolge (dokumentiert): Im Altcode
ruft ``discover_subnet`` ``on_progress`` INNERHALB der Ping-Schleife auf, also
BEVOR die ARP-Anreicherung laeuft -- die ``host_found``-Frames trugen dort
LEEREN ``mac`` (``ping_host`` setzt nie eine MAC), die MAC kam erst spaeter aus
ARP ins ``host_detail``. Hier wird stattdessen kein leerer ``mac`` vorgetaeuscht:
die ``DiscoveryHostFound`` werden nach der ARP-Phase mit echter MAC ausgeliefert.
Die Tick-Semantik (Fortschritt ueber ALLE Hosts) bleibt verhaltenstreu; nur die
Funde sind vom Fortschritt entkoppelt und kommen am Stueck nach den Ticks.

Altmuster-Befunde (geprueft, beide unkritisch):

* KEINE Injection: ``ping_host`` nutzt ``asyncio.create_subprocess_exec(*cmd)``
  mit einer ARGUMENT-LISTE (``["ping", "-c", "1", ..., ip]``), ``get_arp_table``
  nutzt ``subprocess.run([...])`` -- beide OHNE ``shell=True``. ``ip`` ist ein
  Argument, kein interpolierter Shell-String. (≠ die S2-``osascript``-Faelle.)
* Die ``except ...: return DiscoveredHost(is_alive=False)`` / ``except: pass`` des
  Altcodes sind KEIN stiller Sicherheits-Fallback (S3): "Host antwortet nicht" /
  "keine ARP-Eintraege" sind die vom Vertrag vorgesehenen Leer-/Tot-Zustaende,
  kein verdecktes Scheitern. Wird daher beibehalten.
"""

import asyncio
from collections.abc import AsyncIterator
from ipaddress import ip_network
from typing import Any

from domain.scanning import DiscoveredHost, DiscoveryEvent, DiscoveryHostFound, DiscoveryTick
from modules.discovery import get_arp_table, ping_host


def _to_domain(raw: Any, mac: str) -> DiscoveredHost:
    """modules.DiscoveredHost -> domain.DiscoveredHost.

    ``raw`` ist ``Any`` -- ``modules`` ist untypisiert (mypy ``follow_imports=
    skip``); der Adapter liest die bekannten Felder direkt. Der ``rtt_ms``-
    Sentinel des Altcodes (``-1.0`` = "nicht gemessen") wird auf das
    domaenenreine ``None`` abgebildet; ``mac`` kommt aus der ARP-Zuordnung (leer,
    wenn der Host nicht in der ARP-Tabelle steht).
    """
    rtt = raw.rtt_ms
    return DiscoveredHost(
        ip=str(raw.ip),
        mac=mac,
        rtt_ms=None if rtt is None or rtt < 0 else float(rtt),
        is_alive=True,
        source=str(raw.source),
    )


class HostDiscoveryAdapter:
    """Erfuellt das ``HostDiscoveryPort``-Protocol strukturell (eigene Ping-Schleife)."""

    async def discover(
        self, cidr: str, ping_timeout: float, max_concurrent: int
    ) -> AsyncIterator[DiscoveryEvent]:
        """Pingt alle Adressen des ``cidr`` und yieldet Fortschritt + Funde.

        Invalides ``cidr`` ist ein Fehler (``ValueError`` aus ``ip_network``),
        keine stille Leer-Iteration -- die Formatpruefung liegt bereits in
        ``ScanConfig`` (domain), der Adapter darf sich darauf verlassen.
        """
        hosts = list(ip_network(cidr, strict=False).hosts())
        total = len(hosts)
        sem = asyncio.Semaphore(max_concurrent)

        async def scan_one(ip: object) -> Any:
            async with sem:
                return await ping_host(str(ip), ping_timeout)

        tasks = [asyncio.create_task(scan_one(ip)) for ip in hosts]

        alive: list[Any] = []
        for completed, coro in enumerate(asyncio.as_completed(tasks), start=1):
            raw = await coro
            # Fortschritt ueber ALLE Hosts (auch tote) -- altcode-treuer Zaehler.
            yield DiscoveryTick(completed=completed, total=total)
            if raw.is_alive:
                alive.append(raw)

        # ARP EINMAL holen (blockierend -> Executor), MACs zuordnen, dann die
        # Funde MIT echter MAC ausliefern.
        loop = asyncio.get_running_loop()
        arp = await loop.run_in_executor(None, get_arp_table)
        for raw in alive:
            mac = arp.get(str(raw.ip), "")
            yield DiscoveryHostFound(host=_to_domain(raw, mac))
