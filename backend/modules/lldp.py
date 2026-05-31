"""
CERNIS PRO LLDP/CDP Topology Discovery
Passively listens for LLDP and CDP frames to build a network topology map.
Shows switch ports, VLANs, connected devices from switch perspective.
Requires scapy for packet capture.
"""
import asyncio
import threading
import time
from dataclasses import dataclass, field, asdict
from typing import Optional

try:
    # Scapy Cache in beschreibbares Verzeichnis umleiten (verhindert PermissionError)
    import os as _os, tempfile as _tmp
    if not _os.environ.get('SCAPY_CACHE_DIR'):
        _os.environ['SCAPY_CACHE_DIR'] = _tmp.gettempdir()
    from scapy.all import sniff, Ether, Dot3
    from scapy.contrib.lldp import LLDPDU, LLDPDUChassisID, LLDPDUPortID, LLDPDUSystemName, LLDPDUSystemDescription, LLDPDUPortDescription
    from scapy.contrib.cdp import CDPv2_HDR, CDPMsgDeviceID, CDPMsgPortID, CDPMsgSoftwareVersion, CDPMsgPlatform
    HAS_SCAPY = True
except Exception:
    HAS_SCAPY = False


# ── Data structures ───────────────────────────────────────────

@dataclass
class LLDPNeighbor:
    source_mac: str
    chassis_id: str       = ""
    port_id: str          = ""
    system_name: str      = ""
    system_desc: str      = ""
    port_desc: str        = ""
    protocol: str         = "LLDP"  # "LLDP" | "CDP"
    vlans: list           = field(default_factory=list)
    capabilities: list    = field(default_factory=list)
    mgmt_ip: str          = ""
    ttl: int              = 120
    last_seen: float      = field(default_factory=time.time)

    def to_dict(self):
        d = asdict(d)
        d["age_secs"] = int(time.time() - self.last_seen)
        return d


# ── Global neighbor table ─────────────────────────────────────

_neighbors: dict[str, LLDPNeighbor] = {}  # source_mac -> neighbor
_listeners: list = []
_running = False


def get_neighbors() -> list[dict]:
    """Return current LLDP/CDP neighbor table."""
    now = time.time()
    result = []
    for n in list(_neighbors.values()):
        d = asdict(n)
        d["age_secs"] = int(now - n.last_seen)
        d["expired"] = (now - n.last_seen) > n.ttl
        result.append(d)
    return result


# ── Packet parsers ────────────────────────────────────────────

def _parse_lldp(pkt) -> Optional[LLDPNeighbor]:
    """Parse an LLDP packet."""
    try:
        src_mac = pkt[Ether].src
        n = LLDPNeighbor(source_mac=src_mac, protocol="LLDP")

        if pkt.haslayer(LLDPDUChassisID):
            n.chassis_id = str(pkt[LLDPDUChassisID].id)
        if pkt.haslayer(LLDPDUPortID):
            n.port_id = str(pkt[LLDPDUPortID].id)
        if pkt.haslayer(LLDPDUSystemName):
            n.system_name = str(pkt[LLDPDUSystemName].system_name)
        if pkt.haslayer(LLDPDUSystemDescription):
            n.system_desc = str(pkt[LLDPDUSystemDescription].description)[:200]
        if pkt.haslayer(LLDPDUPortDescription):
            n.port_desc = str(pkt[LLDPDUPortDescription].description)
        return n
    except Exception:
        return None


def _parse_cdp(pkt) -> Optional[LLDPNeighbor]:
    """Parse a CDP packet."""
    try:
        src_mac = pkt[Ether].src if pkt.haslayer(Ether) else ""
        n = LLDPNeighbor(source_mac=src_mac, protocol="CDP")

        if pkt.haslayer(CDPMsgDeviceID):
            n.system_name = str(pkt[CDPMsgDeviceID].val)
            n.chassis_id = n.system_name
        if pkt.haslayer(CDPMsgPortID):
            n.port_id = str(pkt[CDPMsgPortID].val)
        if pkt.haslayer(CDPMsgSoftwareVersion):
            n.system_desc = str(pkt[CDPMsgSoftwareVersion].val)[:200]
        if pkt.haslayer(CDPMsgPlatform):
            n.capabilities = [str(pkt[CDPMsgPlatform].val)]
        return n
    except Exception:
        return None


def _handle_packet(pkt):
    """Process a captured packet."""
    neighbor = None

    # LLDP: EtherType 0x88cc
    if pkt.haslayer(Ether) and pkt[Ether].type == 0x88cc:
        neighbor = _parse_lldp(pkt)

    # CDP: dst MAC 01:00:0c:cc:cc:cc
    elif pkt.haslayer(Ether) and pkt[Ether].dst.lower() == "01:00:0c:cc:cc:cc":
        neighbor = _parse_cdp(pkt)

    if neighbor:
        _neighbors[neighbor.source_mac] = neighbor
        # Notify subscribers
        for cb in list(_listeners):
            try:
                cb(neighbor)
            except Exception:
                pass


def subscribe(callback):
    _listeners.append(callback)

def unsubscribe(callback):
    if callback in _listeners:
        _listeners.remove(callback)


def start_capture(interface: str = None, duration: float = 30.0) -> list[dict]:
    """
    Synchronously capture LLDP/CDP packets for `duration` seconds.
    Returns list of discovered neighbors.
    """
    if not HAS_SCAPY:
        return []

    try:
        filter_str = "ether proto 0x88cc or ether dst 01:00:0c:cc:cc:cc"
        kwargs = {"filter": filter_str, "timeout": duration, "prn": _handle_packet, "store": 0}
        if interface:
            kwargs["iface"] = interface
        sniff(**kwargs)
    except Exception as e:
        print(f"LLDP capture error: {e}")

    return get_neighbors()


async def capture_async(interface: str = None, duration: float = 30.0) -> list[dict]:
    """Async wrapper for LLDP/CDP capture."""
    if not HAS_SCAPY:
        return []
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None, lambda: start_capture(interface, duration)
    )


def topology_graph(neighbors: list[dict], hosts: list[dict]) -> dict:
    """
    Build a topology graph from LLDP neighbors + scan results.
    Returns nodes and edges for visualization.
    """
    nodes = []
    edges = []
    seen_ids = set()

    # Add known hosts as nodes
    for h in hosts:
        node_id = h.get("mac") or h.get("ip")
        if not node_id or node_id in seen_ids:
            continue
        seen_ids.add(node_id)
        nodes.append({
            "id": node_id,
            "ip": h.get("ip", ""),
            "mac": h.get("mac", ""),
            "hostname": h.get("hostname", ""),
            "vendor": h.get("vendor", ""),
            "type": "host",
        })

    # Add LLDP neighbors as switch/router nodes
    for n in neighbors:
        node_id = n.get("chassis_id") or n.get("source_mac")
        if not node_id or node_id in seen_ids:
            continue
        seen_ids.add(node_id)
        nodes.append({
            "id": node_id,
            "mac": n.get("source_mac", ""),
            "hostname": n.get("system_name", ""),
            "description": n.get("system_desc", "")[:60],
            "port": n.get("port_id", ""),
            "type": "switch" if "switch" in n.get("system_desc","").lower() else "network",
            "protocol": n.get("protocol", "LLDP"),
        })

        # Edge: this switch connects to us
        edges.append({
            "source": node_id,
            "target": "local",
            "port": n.get("port_id", ""),
            "protocol": n.get("protocol", "LLDP"),
        })

    return {"nodes": nodes, "edges": edges}
