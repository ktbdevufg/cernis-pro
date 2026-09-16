"""Gemeinsames scapy-Setup der capture-Adapter -- EINMAL, ohne ``modules``-Bezug.

Leitet den scapy-Cache in ein beschreibbares Verzeichnis um (``SCAPY_CACHE_DIR``
VOR dem ersten scapy-Import -- verhindert ``PermissionError`` beim Laden der
gepackten Layer-Caches, altcode-treu zu ``modules/pcap.py``/``modules/lldp.py``)
und probt die Verfuegbarkeit. ``except Exception`` (NICHT nur ``ImportError``):
scapy kann beim Import auch an Cache-/Plattform-Problemen scheitern, nicht nur am
fehlenden Paket -- der Altcode fing ebenfalls breit.

Zwei getrennte Probe-Zweige:

* **Kern** (``HAS_SCAPY``) -- ``scapy.all``-Symbole, die der ``ScapyPacketSniffer``
  und der LLDP-Sniff brauchen.
* **contrib** (``HAS_SCAPY_CONTRIB``) -- ``scapy.contrib.{lldp,cdp}``. Bewusst
  separat: ``contrib`` ist volatiler (Symbol-Umbenennungen ueber scapy-Versionen),
  sein Fehlen darf den Kern-Capture nicht ausschalten. Der LLDP-Sniffer prueft
  diesen Zweig eigenstaendig.

Bei nicht verfuegbarem scapy bleiben die Symbole ``None`` (lazy: die Adapter sind
trotzdem konstruierbar, ``is_available()`` meldet ``False`` -- kein Import-Fehler
beim App-Start, S3-frei, weil ``stream``/``capture`` den Fehlerfall explizit
behandeln statt still leer zu laufen).
"""

import os
import tempfile

# Cache-Dir VOR dem scapy-Import setzen (sonst greift scapy ein evtl. nicht
# beschreibbares Default-Verzeichnis und scheitert beim Layer-Cache-Laden).
if not os.environ.get("SCAPY_CACHE_DIR"):
    os.environ["SCAPY_CACHE_DIR"] = tempfile.gettempdir()

# scapy ist in mypy via follow_imports=skip ausgeklammert (partielle Stubs, siehe
# pyproject [[tool.mypy.overrides]]); die Symbole sind hier daher ``Any`` -- keine
# ``type: ignore`` noetig, der None-Fallback-Zweig ist ebenfalls untypisiert.
try:
    from scapy.all import (
        DNS,
        ICMP,
        IP,
        TCP,
        UDP,
        AsyncSniffer,
        Ether,
        IPv6,
        sniff,
        wrpcap,
    )

    # Dot3 ist die 802.3-Rahmenform (Laengenfeld statt EtherType) -- die Form, in
    # der CDP tatsaechlich auf dem Draht liegt (LLC/SNAP). scapy dissektiert einen
    # solchen Rahmen NICHT als ``Ether``, sondern als ``Dot3``; ohne dieses Symbol
    # kann die Rahmen-Erkennung die Absenderadresse dort nicht lesen. ``LLC`` und
    # ``SNAP`` sind die beiden Zwischenschichten dieses Rahmens -- sie tragen den
    # Protokollschluessel, den Ethernet II im EtherType fuehrt, und werden zum
    # Bauen eines echten CDP-Rahmens (Test) gebraucht.
    from scapy.layers.l2 import LLC, SNAP, Dot3

    HAS_SCAPY = True
except Exception:
    HAS_SCAPY = False
    DNS = ICMP = IP = TCP = UDP = AsyncSniffer = Ether = IPv6 = sniff = wrpcap = None
    Dot3 = LLC = SNAP = None

try:
    # CDPv2_HDR ist der CDP-Rahmenkopf: seine ANWESENHEIT ist das belastbare
    # Erkennungsmerkmal fuer CDP (die Multicast-Ziel-MAC ist nur Begleiterscheinung).
    from scapy.contrib.cdp import (
        CDPMsgDeviceID,
        CDPMsgPlatform,
        CDPMsgPortID,
        CDPMsgSoftwareVersion,
        CDPv2_HDR,
    )
    from scapy.contrib.lldp import (
        LLDPDUChassisID,
        LLDPDUPortDescription,
        LLDPDUPortID,
        LLDPDUSystemDescription,
        LLDPDUSystemName,
    )

    HAS_SCAPY_CONTRIB = True
except Exception:
    HAS_SCAPY_CONTRIB = False
    LLDPDUChassisID = LLDPDUPortID = LLDPDUSystemName = None
    LLDPDUSystemDescription = LLDPDUPortDescription = None
    CDPMsgDeviceID = CDPMsgPortID = CDPMsgSoftwareVersion = CDPMsgPlatform = None
    CDPv2_HDR = None

# Explizite Re-Exports: die Sniffer-Adapter greifen ueber ``_scapy.<Symbol>`` zu;
# mypy (strict, ``no_implicit_reexport``) verlangt dafuer ein explizites ``__all__``.
__all__ = [
    "DNS",
    "HAS_SCAPY",
    "HAS_SCAPY_CONTRIB",
    "ICMP",
    "IP",
    "LLC",
    "SNAP",
    "TCP",
    "UDP",
    "AsyncSniffer",
    "CDPMsgDeviceID",
    "CDPMsgPlatform",
    "CDPMsgPortID",
    "CDPMsgSoftwareVersion",
    "CDPv2_HDR",
    "Dot3",
    "Ether",
    "IPv6",
    "LLDPDUChassisID",
    "LLDPDUPortDescription",
    "LLDPDUPortID",
    "LLDPDUSystemDescription",
    "LLDPDUSystemName",
    "sniff",
    "wrpcap",
]
