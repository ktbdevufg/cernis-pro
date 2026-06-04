"""Adapter fuer ``LldpSnifferPort`` -- zeitbegrenzter LLDP/CDP-Sniff (C.3).

v2-nativ gegen scapy, KEIN ``modules``-Import (wie ``packet_sniffer``). Die Parser
(``_parse_lldp``/``_parse_cdp``) und der EtherType/MAC-Dispatch wandern hierher --
sie erzeugen ``LLDPNeighbor`` aus den scapy-contrib-Layern; die Domaene kennt nur
``LLDPNeighbor``.

Der scapy-``sniff`` ist BLOCKIEREND (mit ``timeout=duration``); ``capture`` kapselt
ihn ueber ``run_in_executor`` und bleibt ``async`` (Port-Vertrag).

S3-HEILUNG (Muster i -- Wire unveraendert): Der Altcode (``modules/lldp.start_capture``)
fing den Sniff-Fehler mit einem nackten ``print`` und gab die (ggf. leere)
Nachbarliste zurueck. Hier wird der Fehler stattdessen GELOGGT (``structlog``-Warn)
statt geprintet -- gleiches Aussenverhalten (leere/teilweise Liste, kein Crash),
aber der Betreiber sieht den Fehler strukturiert. Fehlt ``scapy.contrib``
(``HAS_SCAPY_CONTRIB`` False), kann nicht geparst werden -> ``[]`` + Warn.

Plattform: NUR Linux x64. Interface ``None`` -> scapy-Default-Interface.
"""

import asyncio
from typing import Any

import structlog

from domain.capture import LLDPNeighbor
from infrastructure.capture import _scapy

_logger = structlog.get_logger(__name__)

# BPF-Filter AS-IS (modules/lldp.start_capture): LLDP-EtherType + CDP-Multicast-MAC.
_LLDP_CDP_FILTER = "ether proto 0x88cc or ether dst 01:00:0c:cc:cc:cc"


class ScapyLldpSniffer:
    """Erfuellt ``LldpSnifferPort`` strukturell -- zeitbegrenzter scapy-Sniff."""

    def _parse_lldp(self, pkt: Any) -> LLDPNeighbor | None:
        """LLDP-Paket -> ``LLDPNeighbor`` (AS-IS ``modules/lldp._parse_lldp``)."""
        try:
            kwargs: dict[str, Any] = {
                "source_mac": pkt[_scapy.Ether].src,
                "protocol": "LLDP",
            }
            if pkt.haslayer(_scapy.LLDPDUChassisID):
                kwargs["chassis_id"] = str(pkt[_scapy.LLDPDUChassisID].id)
            if pkt.haslayer(_scapy.LLDPDUPortID):
                kwargs["port_id"] = str(pkt[_scapy.LLDPDUPortID].id)
            if pkt.haslayer(_scapy.LLDPDUSystemName):
                kwargs["system_name"] = str(pkt[_scapy.LLDPDUSystemName].system_name)
            if pkt.haslayer(_scapy.LLDPDUSystemDescription):
                kwargs["system_desc"] = str(pkt[_scapy.LLDPDUSystemDescription].description)[:200]
            if pkt.haslayer(_scapy.LLDPDUPortDescription):
                kwargs["port_desc"] = str(pkt[_scapy.LLDPDUPortDescription].description)
            return LLDPNeighbor(**kwargs)
        except Exception as exc:
            _logger.warning("lldp_parse_failed", error=str(exc))
            return None

    def _parse_cdp(self, pkt: Any) -> LLDPNeighbor | None:
        """CDP-Paket -> ``LLDPNeighbor`` (AS-IS ``modules/lldp._parse_cdp``)."""
        try:
            src_mac = pkt[_scapy.Ether].src if pkt.haslayer(_scapy.Ether) else ""
            kwargs: dict[str, Any] = {"source_mac": src_mac, "protocol": "CDP"}
            if pkt.haslayer(_scapy.CDPMsgDeviceID):
                name = str(pkt[_scapy.CDPMsgDeviceID].val)
                kwargs["system_name"] = name
                kwargs["chassis_id"] = name
            if pkt.haslayer(_scapy.CDPMsgPortID):
                kwargs["port_id"] = str(pkt[_scapy.CDPMsgPortID].val)
            if pkt.haslayer(_scapy.CDPMsgSoftwareVersion):
                kwargs["system_desc"] = str(pkt[_scapy.CDPMsgSoftwareVersion].val)[:200]
            if pkt.haslayer(_scapy.CDPMsgPlatform):
                kwargs["capabilities"] = [str(pkt[_scapy.CDPMsgPlatform].val)]
            return LLDPNeighbor(**kwargs)
        except Exception as exc:
            _logger.warning("cdp_parse_failed", error=str(exc))
            return None

    def _dispatch(self, pkt: Any) -> LLDPNeighbor | None:
        """EtherType/MAC-Dispatch (AS-IS ``modules/lldp._handle_packet``).

        LLDP: EtherType ``0x88cc``. CDP: Ziel-MAC ``01:00:0c:cc:cc:cc``. Andere
        Pakete -> ``None`` (vom BPF-Filter eigentlich schon ausgeschlossen).
        """
        if not pkt.haslayer(_scapy.Ether):
            return None
        if pkt[_scapy.Ether].type == 0x88CC:
            return self._parse_lldp(pkt)
        if pkt[_scapy.Ether].dst.lower() == "01:00:0c:cc:cc:cc":
            return self._parse_cdp(pkt)
        return None

    async def capture(self, interface: str | None, duration: float) -> list[LLDPNeighbor]:
        """Lauscht ``duration`` Sekunden auf LLDP/CDP und liefert die Nachbarn.

        Blockierender scapy-``sniff`` ueber ``run_in_executor``. Keine Nachbarn /
        scapy fehlt / Sniff-Fehler -> ``[]`` (nie ``None``); Fehler werden GELOGGT
        (S3-Heilung Muster i: vorher nacktes ``print``, Wire unveraendert).
        """
        if not (_scapy.HAS_SCAPY and _scapy.HAS_SCAPY_CONTRIB):
            _logger.warning(
                "lldp_capture_unavailable",
                has_scapy=_scapy.HAS_SCAPY,
                has_contrib=_scapy.HAS_SCAPY_CONTRIB,
            )
            return []

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._sniff_blocking, interface, duration)

    def _sniff_blocking(self, interface: str | None, duration: float) -> list[LLDPNeighbor]:
        """Blockierender Sniff (laeuft im Executor-Thread); dedupliziert per source_mac.

        Letzter Eintrag je ``source_mac`` gewinnt -- AS-IS zum Altcode-``_neighbors``-
        dict (``source_mac`` -> Nachbar).
        """
        neighbors: dict[str, LLDPNeighbor] = {}

        def _handle(pkt: Any) -> None:
            neighbor = self._dispatch(pkt)
            if neighbor:
                neighbors[neighbor.source_mac] = neighbor

        try:
            kwargs: dict[str, Any] = {
                "filter": _LLDP_CDP_FILTER,
                "timeout": duration,
                "prn": _handle,
                "store": 0,
            }
            if interface:
                kwargs["iface"] = interface
            _scapy.sniff(**kwargs)
        except Exception as exc:
            _logger.warning("lldp_capture_failed", error=str(exc))

        return list(neighbors.values())
