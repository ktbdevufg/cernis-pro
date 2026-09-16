"""Privilege-Separation-Sniff-Helfer (Wireshark/dumpcap-Modell).

Dieses Paket buendelt den separaten, minimal privilegierten Sniff-Helfer
``cernis-sniffd``: ein schlanker Standalone-Prozess, der spaeter als EINZIGE
Komponente ``CAP_NET_RAW`` traegt. Das grosse FastAPI-Backend bleibt
unprivilegiert und spricht den Helfer ueber eine schmale Unix-Domain-Socket-IPC
(AF_UNIX) an.

Der Helfer macht NUR den rohen scapy-Sniff + ClientHello-Parsing und streamt
rohe SNI-Hits ueber die IPC. Die teure Zuordnung (psutil-Poller, Snapshot-Match,
Prozessname) bleibt im Backend -- sie wird NICHT in den Helfer gezogen.

Keine Re-Exports: die Submodule (``protocol``, ``sniff_core``, ``server``) werden
direkt importiert.
"""
