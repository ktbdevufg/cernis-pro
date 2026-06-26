"""Backend-seitige Helfer-Clients: spawnen ``cernis-sniffd`` + sprechen die IPC.

ETAPPE 3b: gemeinsamer Spawn-/Connect-/Teardown-Kern (``_BaseSubprocessHelper`` in
``base.py``) plus drei schmale Clients, die je ihren START-Befehl schicken und die
Helfer-Events nach ihrem Muster auswerten:

* ``SniHelperClient`` -- ``START`` -> HIT-Strom (poll_hits), ersetzt die alte
  SNI-spezifische ``SubprocessSniffHelper``-Logik.
* ``PcapHelperClient`` -- ``START_PCAP`` -> PACKET-Strom (Queue) + ``EXPORT_PCAP``
  -> bool + STOPPED-Strom-Ende.
* ``LldpHelperClient`` -- ``START_LLDP`` -> warte auf die EINE NEIGHBORS-Nachricht.

NAMENSGRENZE: ``infrastructure.sniffd_client`` ist die BACKEND-Seite (Client).
``infrastructure.sniffd`` ist die HELFER-Prozess-Seite (Server + Sniff-Kern).

``helper_entry_exists`` (Pfad-Check des Helfer-Einstiegs) ist hier re-exportiert --
die Adapter (``is_available``) nutzen ihn.
"""

from infrastructure.sniffd_client.base import helper_entry_exists
from infrastructure.sniffd_client.lldp_client import LldpHelperClient
from infrastructure.sniffd_client.pcap_client import PcapHelperClient
from infrastructure.sniffd_client.sni_client import SniHelperClient

__all__ = [
    "LldpHelperClient",
    "PcapHelperClient",
    "SniHelperClient",
    "helper_entry_exists",
]
