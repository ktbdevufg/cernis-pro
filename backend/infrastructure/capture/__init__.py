"""Infrastructure-Adapter der capture-Domaene (C.3 / Etappe 3b).

ETAPPE 3b (Privilege-Separation): Die Sniffer-Adapter fahren scapy NICHT mehr selbst.
Der rohe pcap-/LLDP-Sniff lebt im on-demand gestarteten Helfer ``cernis-sniffd`` (der
EINZIGE Prozess mit ``CAP_NET_RAW``); die Adapter sprechen ihn ueber die Helfer-Clients
an (``infrastructure/sniffd_client/``). Das scapy-Parsen ist in den Helfer gewandert
(``sniffd.sniff_core``); hier wird aus den rohen IPC-dicts nur noch das Domaenenmodell
(``PacketSummary``/``LLDPNeighbor``) gebaut.

Drei Adapter:

* ``ScapyPacketSniffer`` -- ``PacketSnifferPort`` (pcap-Dauer-Capture via Helfer;
  Thread->Loop-Naht ueber ``asyncio.Queue`` + ``call_soon_threadsafe``, Quelle ist
  jetzt der ``PcapHelperClient``-Reader-Thread statt scapy-prn).
* ``ScapyLldpSniffer`` -- ``LldpSnifferPort`` (zeitbegrenzter Sniff via Helfer-Client,
  blockierendes Einmal-Warten ueber ``run_in_executor``).
* ``WebSocketCaptureBroadcaster`` -- ``CaptureBroadcasterPort`` (WS-Fan-out, M.9-Stil).

``_scapy`` (Cache-Dir-Setup + Verfuegbarkeits-Probe) lebt jetzt in der Helfer-
Heimat (``infrastructure/sniffd/_scapy.py``) und wird nur noch vom Helfer-Sniff-Kern
(``sniffd.sniff_core``) genutzt -- nicht mehr im capture-Paket; ``errors`` haelt
``CaptureError`` (Start-Fehler des Stroms, S3-frei).
"""

from infrastructure.capture.broadcaster import WebSocketCaptureBroadcaster
from infrastructure.capture.errors import CaptureError
from infrastructure.capture.lldp_sniffer import ScapyLldpSniffer
from infrastructure.capture.packet_sniffer import ScapyPacketSniffer

__all__ = [
    "CaptureError",
    "ScapyLldpSniffer",
    "ScapyPacketSniffer",
    "WebSocketCaptureBroadcaster",
]
