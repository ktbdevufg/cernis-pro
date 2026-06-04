"""Infrastructure-Adapter der capture-Domaene (C.3).

v2-NATIV gegen scapy, KEIN ``modules``-Import (cve/tls-Stil, KEIN ADR 0007): der
scapy-gebundene Kern (Parser + Sniffer-Lifecycle + Permission-Probe) ist klein und
haengt an nichts Unportiertem; ``modules.pcap``/``modules.lldp`` zu wrappen waere
mehr Code (Mapping der mutablen Alt-dataclasses auf die frozen Domaenenmodelle) und
wuerde zudem den kaputten Alt-Broadcast-Pfad importieren, den C.3 gerade ersetzt.
Darum bleibt der ``modules/``-Contract fuer capture ohne ``ignore_imports``-Eintrag.

Drei Adapter:

* ``ScapyPacketSniffer`` -- ``PacketSnifferPort`` (Dauer-Capture als async-Strom;
  Thread->Loop-Naht ueber ``asyncio.Queue`` + ``call_soon_threadsafe``).
* ``ScapyLldpSniffer`` -- ``LldpSnifferPort`` (zeitbegrenzter Sniff via Executor).
* ``WebSocketCaptureBroadcaster`` -- ``CaptureBroadcasterPort`` (WS-Fan-out, M.9-Stil).

``_scapy`` kapselt das gemeinsame Cache-Dir-Setup + die Verfuegbarkeits-Probe;
``errors`` haelt ``CaptureError`` (Start-Fehler des Stroms, S3-frei).
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
