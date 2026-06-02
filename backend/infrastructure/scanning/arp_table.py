"""Adapter fuer ``ArpTablePort`` -- duenner Wrapper um ``modules.get_arp_table``.

Reiner Lese-Pfad: liefert den System-ARP-/Neighbor-Cache als ``{ip: mac}``.
``modules.discovery.get_arp_table`` ist SYNCHRON und blockierend (ruft auf Linux
``ip neigh`` per ``subprocess.run`` auf) -> der Adapter kapselt es ueber
``run_in_executor``, sodass die Port-Methode ``async`` bleibt (Muster wie der
host_discovery-/ipv6-/fritz-Adapter). Der modules-Import ist durch den
ADR-0007-Vertrag ``infrastructure.scanning.** -> modules`` abgedeckt -- keine
neue ``ignore_imports``-Zeile noetig.

Altmuster-Befunde (geprueft, beide unkritisch):

* KEINE Injection: ``get_arp_table`` nutzt ``subprocess.run(["ip", "neigh"])``
  mit einer ARGUMENT-LISTE, OHNE ``shell=True``. (≠ die S2-``osascript``-Faelle.)
  Identisch zur Bewertung im host_discovery-Adapter (S.4b), der dieselbe
  Funktion bereits konsumiert.
* Das ``except Exception: pass`` des Linux-Zweigs ist KEIN stiller
  Sicherheits-Fallback (S3): ein leerer/nicht lesbarer ARP-Cache liefert ``{}``,
  und ``{}`` ist hier der vom Vertrag vorgesehene Leer-Zustand ("keine
  Eintraege"), kein verdecktes Scheitern wie der nmap-Sentinel. Wird daher
  beibehalten -- KEIN Exception-Umbau (analog mDNS/SSDP, S.4d).
"""

import asyncio

from modules.discovery import get_arp_table


class ArpTableAdapter:
    """Erfuellt das ``ArpTablePort``-Protocol strukturell (Executor-Wrapper)."""

    async def get_arp_table(self) -> dict[str, str]:
        """Liefert den System-ARP-/Neighbor-Cache als ``{ip: mac}``.

        ``get_arp_table`` ist blockierend -> ``run_in_executor``. Leerer Cache
        -> ``{}`` (vertraglicher Leer-Zustand, kein Fehler).
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, get_arp_table)
