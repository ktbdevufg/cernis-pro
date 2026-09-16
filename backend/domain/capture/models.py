"""Domaenenmodelle der capture-Domaene -- reine Wertobjekte (stdlib, ADR 0002).

Kein Framework, kein I/O, KEIN scapy-Import, KEIN Import aus anderen Domaenen:
capture kennt nur seine eigenen Modelle. Die Projektion in WS-/REST-dicts
(Altcode ``to_dict``) passiert spaeter im Adapter/Use-Case, bewusst NICHT hier
(keine Transport-/JSON-Details in der Domaene).

Alle Modelle sind ``frozen`` (Muster scanning/monitoring): die Akkumulation der
Statistik laeuft ueber die reine ``stats.apply_packet`` (neue ``CaptureStats``
statt In-place-Mutation des Altcodes). dict/list-Felder brauchen
``default_factory`` -- ein veraenderlicher Default waere auch in einer frozen
dataclass ein geteilter Klassenzustand.

Feldsatz exakt nach dem migrierten Altcode (``modules/pcap.py`` ``PacketSummary``/
``CaptureStats``, ``modules/lldp.py`` ``LLDPNeighbor``). Die kaputte
``LLDPNeighbor.to_dict`` (``asdict(d)`` vor Zuweisung -> ``UnboundLocalError``)
faellt ersatzlos weg -- sie war toter Code, ``get_neighbors`` baute das dict
ohnehin selbst.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class PacketSummary:
    """Zusammenfassung eines erfassten Pakets (ein REST-/WS-Listeneintrag)."""

    timestamp: float
    src_ip: str = ""
    dst_ip: str = ""
    src_mac: str = ""
    dst_mac: str = ""
    protocol: str = ""
    src_port: int = 0
    dst_port: int = 0
    length: int = 0
    info: str = ""
    is_ipv6: bool = False


@dataclass(frozen=True)
class CaptureStats:
    """Aggregierte Capture-Statistik -- frozen, fortgeschrieben via ``apply_packet``.

    ``protocols`` zaehlt je Protokoll, ``top_talkers`` summiert Bytes je Quell-IP,
    ``top_ports`` zaehlt je Ziel-Port (Schluessel als ``str``, wie der Altcode).
    Die Sortier-/Kapp-Sicht fuer die REST-Antwort liefert ``stats.stats_to_view``.
    """

    total_packets: int = 0
    total_bytes: int = 0
    protocols: dict[str, int] = field(default_factory=dict)
    top_talkers: dict[str, int] = field(default_factory=dict)
    top_ports: dict[str, int] = field(default_factory=dict)
    start_time: float = 0.0


@dataclass(frozen=True)
class LLDPNeighbor:
    """Ein per LLDP/CDP entdeckter Nachbar (Switch/Router aus dessen Sicht)."""

    source_mac: str
    chassis_id: str = ""
    port_id: str = ""
    system_name: str = ""
    system_desc: str = ""
    port_desc: str = ""
    protocol: str = "LLDP"  # "LLDP" | "CDP"
    vlans: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    mgmt_ip: str = ""
    ttl: int = 120
    last_seen: float = 0.0
