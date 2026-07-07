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

    HAS_SCAPY = True

    # use_pcap=False -> scapy nutzt auf Linux den nativen AF_PACKET-Socket
    # (Kernel-BPF) statt libpcap fuer die Filter-Kompilierung. Noetig, weil im
    # frozen Bundle keine libpcap-Anbindung vorhanden ist und die
    # BPF-Filter-Kompilierung ueber libpcap sonst scheitert (Cannot compile
    # filter). Defensiv gekapselt: fehlt das Attribut in einer scapy-Version,
    # darf das weder crashen noch HAS_SCAPY zuruecksetzen.
    try:
        from scapy.config import conf as _scapy_conf

        if hasattr(_scapy_conf, "use_pcap"):
            _scapy_conf.use_pcap = False
    except Exception:
        pass
except Exception:
    HAS_SCAPY = False
    DNS = ICMP = IP = TCP = UDP = AsyncSniffer = Ether = IPv6 = sniff = wrpcap = None

try:
    from scapy.contrib.cdp import (
        CDPMsgDeviceID,
        CDPMsgPlatform,
        CDPMsgPortID,
        CDPMsgSoftwareVersion,
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

# Explizite Re-Exports: die Sniffer-Adapter greifen ueber ``_scapy.<Symbol>`` zu;
# mypy (strict, ``no_implicit_reexport``) verlangt dafuer ein explizites ``__all__``.
__all__ = [
    "DNS",
    "HAS_SCAPY",
    "HAS_SCAPY_CONTRIB",
    "ICMP",
    "IP",
    "TCP",
    "UDP",
    "AsyncSniffer",
    "CDPMsgDeviceID",
    "CDPMsgPlatform",
    "CDPMsgPortID",
    "CDPMsgSoftwareVersion",
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
