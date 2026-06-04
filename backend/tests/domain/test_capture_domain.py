"""Unit-Tests der capture-Domaene -- reine Logik, kein I/O, kein scapy.

Deckt die reinen Funktionen ab: ``apply_packet`` (inkl. ``"Other"``-Fallback und
fehlendem src_ip/dst_port), ``stats_to_view`` (Sortierung + Top-10/Top-20-Kappung
+ duration aus ``now``), ``ring_trim`` (unter/ueber cap), ``topology_graph``
(GEHEILT: keine dangling edges, Dedup) und ``neighbor_age`` (expired-Grenze).
"""

import dataclasses
from typing import cast

import pytest

from domain.capture import (
    CaptureStats,
    LLDPNeighbor,
    PacketSummary,
    apply_packet,
    neighbor_age,
    ring_trim,
    stats_to_view,
    topology_graph,
)

# ── Modelle / frozen ─────────────────────────────────────────────────────────


def test_models_are_frozen() -> None:
    ps = PacketSummary(timestamp=1.0)
    field_name = "protocol"
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(ps, field_name, "TCP")


def test_capture_stats_defaults() -> None:
    stats = CaptureStats()
    assert stats.total_packets == 0
    assert stats.total_bytes == 0
    assert stats.protocols == {}
    assert stats.top_talkers == {}
    assert stats.top_ports == {}
    assert stats.start_time == 0.0


def test_lldp_neighbor_defaults() -> None:
    n = LLDPNeighbor(source_mac="AA:BB:CC:DD:EE:01")
    assert n.protocol == "LLDP"
    assert n.ttl == 120
    assert n.vlans == []
    assert n.capabilities == []
    assert n.last_seen == 0.0


# ── apply_packet ─────────────────────────────────────────────────────────────


def test_apply_packet_accumulates_basic_fields() -> None:
    stats = CaptureStats(start_time=100.0)
    ps = PacketSummary(timestamp=1.0, src_ip="10.0.0.1", dst_port=443, protocol="HTTPS", length=120)
    new = apply_packet(stats, ps)
    assert new.total_packets == 1
    assert new.total_bytes == 120
    assert new.protocols == {"HTTPS": 1}
    assert new.top_talkers == {"10.0.0.1": 120}
    assert new.top_ports == {"443": 1}
    # start_time bleibt erhalten.
    assert new.start_time == 100.0


def test_apply_packet_returns_new_instance_and_does_not_mutate() -> None:
    stats = CaptureStats()
    ps = PacketSummary(timestamp=1.0, src_ip="10.0.0.1", dst_port=80, length=50)
    new = apply_packet(stats, ps)
    # Eingabe bleibt unveraendert (frozen + Kopie der dict-Felder).
    assert stats.total_packets == 0
    assert stats.protocols == {}
    assert stats.top_talkers == {}
    assert new is not stats
    assert new.protocols is not stats.protocols


def test_apply_packet_empty_protocol_falls_back_to_other() -> None:
    stats = CaptureStats()
    ps = PacketSummary(timestamp=1.0, protocol="", length=10)
    new = apply_packet(stats, ps)
    assert new.protocols == {"Other": 1}


def test_apply_packet_no_src_ip_skips_talkers() -> None:
    stats = CaptureStats()
    ps = PacketSummary(timestamp=1.0, src_ip="", dst_port=22, length=10)
    new = apply_packet(stats, ps)
    assert new.top_talkers == {}
    assert new.top_ports == {"22": 1}


def test_apply_packet_no_dst_port_skips_ports() -> None:
    stats = CaptureStats()
    ps = PacketSummary(timestamp=1.0, src_ip="10.0.0.1", dst_port=0, length=10)
    new = apply_packet(stats, ps)
    assert new.top_ports == {}
    assert new.top_talkers == {"10.0.0.1": 10}


def test_apply_packet_accumulates_over_multiple_packets() -> None:
    stats = CaptureStats()
    for _ in range(3):
        stats = apply_packet(
            stats,
            PacketSummary(
                timestamp=1.0, src_ip="10.0.0.1", dst_port=443, protocol="HTTPS", length=10
            ),
        )
    assert stats.total_packets == 3
    assert stats.total_bytes == 30
    assert stats.protocols == {"HTTPS": 3}
    assert stats.top_talkers == {"10.0.0.1": 30}
    assert stats.top_ports == {"443": 3}


# ── stats_to_view ────────────────────────────────────────────────────────────


def test_stats_to_view_duration_from_now() -> None:
    stats = CaptureStats(total_packets=5, total_bytes=500, start_time=100.0)
    view = stats_to_view(stats, now=112.34)
    assert view["total_packets"] == 5
    assert view["total_bytes"] == 500
    assert view["duration_secs"] == 12.3


def test_stats_to_view_sorts_descending() -> None:
    stats = CaptureStats(
        protocols={"TCP": 2, "UDP": 5, "DNS": 3},
        top_talkers={"a": 10, "b": 30, "c": 20},
        top_ports={"80": 1, "443": 9, "22": 5},
    )
    view = stats_to_view(stats, now=0.0)
    protocols = cast(dict[str, int], view["protocols"])
    top_talkers = cast(dict[str, int], view["top_talkers"])
    top_ports = cast(dict[str, int], view["top_ports"])
    assert list(protocols) == ["UDP", "DNS", "TCP"]
    assert list(top_talkers) == ["b", "c", "a"]
    assert list(top_ports) == ["443", "22", "80"]


def test_stats_to_view_caps_talkers_top10_and_ports_top20() -> None:
    talkers = {f"ip{i}": i for i in range(15)}  # 15 Talker
    ports = {str(i): i for i in range(25)}  # 25 Ports
    stats = CaptureStats(top_talkers=talkers, top_ports=ports)
    view = stats_to_view(stats, now=0.0)
    top_talkers = cast(dict[str, int], view["top_talkers"])
    top_ports = cast(dict[str, int], view["top_ports"])
    assert len(top_talkers) == 10
    assert len(top_ports) == 20
    # Die hoechsten Werte ueberleben die Kappung (absteigend sortiert, dann gekappt).
    assert next(iter(top_talkers)) == "ip14"
    assert next(iter(top_ports)) == "24"


# ── ring_trim ────────────────────────────────────────────────────────────────


def test_ring_trim_below_cap_returns_unchanged() -> None:
    packets = [PacketSummary(timestamp=float(i)) for i in range(5)]
    trimmed = ring_trim(packets, cap=10, keep=3)
    assert len(trimmed) == 5
    assert [p.timestamp for p in trimmed] == [0.0, 1.0, 2.0, 3.0, 4.0]


def test_ring_trim_above_cap_keeps_last() -> None:
    packets = [PacketSummary(timestamp=float(i)) for i in range(12)]
    trimmed = ring_trim(packets, cap=10, keep=4)
    assert len(trimmed) == 4
    # Die LETZTEN keep Eintraege bleiben.
    assert [p.timestamp for p in trimmed] == [8.0, 9.0, 10.0, 11.0]


def test_ring_trim_default_thresholds() -> None:
    # Genau am cap (10000) -> NICHT gekuerzt (Altcode: > 10000).
    at_cap = [PacketSummary(timestamp=1.0)] * 10000
    assert len(ring_trim(at_cap)) == 10000
    over_cap = [PacketSummary(timestamp=1.0)] * 10001
    assert len(ring_trim(over_cap)) == 5000


# ── topology_graph (GEHEILT) ─────────────────────────────────────────────────


def test_topology_graph_no_dangling_edges() -> None:
    neighbors = [
        {
            "source_mac": "AA:BB:CC:DD:EE:01",
            "chassis_id": "switch-1",
            "system_name": "core",
            "system_desc": "managed switch",
            "port_id": "Gi0/1",
            "protocol": "LLDP",
        }
    ]
    graph = topology_graph(neighbors, hosts=[])
    # GEHEILT: keine Kante zu einem nicht existierenden "local"-Knoten.
    assert graph["edges"] == []
    node_ids = {node["id"] for node in graph["nodes"]}
    # Jede Edge-Endpunkt muss ein vorhandener Knoten sein (hier: gar keine Edges).
    for edge in graph["edges"]:
        assert edge["source"] in node_ids
        assert edge["target"] in node_ids
    assert "local" not in node_ids


def test_topology_graph_builds_host_and_switch_nodes() -> None:
    hosts = [{"ip": "192.168.1.2", "mac": "11:22:33:44:55:66", "hostname": "pc"}]
    neighbors = [
        {
            "source_mac": "AA:BB:CC:DD:EE:01",
            "chassis_id": "switch-1",
            "system_name": "core",
            "system_desc": "managed switch model X",
            "port_id": "Gi0/1",
            "protocol": "LLDP",
        }
    ]
    graph = topology_graph(neighbors, hosts)
    by_id = {node["id"]: node for node in graph["nodes"]}
    assert by_id["11:22:33:44:55:66"]["type"] == "host"
    assert by_id["switch-1"]["type"] == "switch"  # "switch" im system_desc
    # description wird auf 60 Zeichen gekappt.
    assert len(by_id["switch-1"]["description"]) <= 60


def test_topology_graph_neighbor_without_switch_keyword_is_network() -> None:
    neighbors = [
        {"source_mac": "AA:BB:CC:DD:EE:02", "chassis_id": "rtr-1", "system_desc": "router"}
    ]
    graph = topology_graph(neighbors, hosts=[])
    assert graph["nodes"][0]["type"] == "network"


def test_topology_graph_dedup_over_seen_ids() -> None:
    # Host-mac und neighbor-chassis_id identisch -> nur EIN Knoten.
    hosts = [{"mac": "AA:BB:CC:DD:EE:01", "ip": "192.168.1.9"}]
    neighbors = [{"source_mac": "AA:BB:CC:DD:EE:01", "chassis_id": "AA:BB:CC:DD:EE:01"}]
    graph = topology_graph(neighbors, hosts)
    ids = [node["id"] for node in graph["nodes"]]
    assert ids.count("AA:BB:CC:DD:EE:01") == 1
    # Der Host gewinnt (zuerst aufgenommen).
    assert graph["nodes"][0]["type"] == "host"


def test_topology_graph_skips_nodes_without_id() -> None:
    hosts = [{"hostname": "kein-id"}]  # weder mac noch ip
    neighbors = [{"system_name": "kein-id"}]  # weder chassis_id noch source_mac
    graph = topology_graph(neighbors, hosts)
    assert graph["nodes"] == []
    assert graph["edges"] == []


# ── neighbor_age ─────────────────────────────────────────────────────────────


def test_neighbor_age_within_ttl_not_expired() -> None:
    age, expired = neighbor_age(now=160.0, last_seen=100.0, ttl=120)
    assert age == 60
    assert expired is False


def test_neighbor_age_at_ttl_boundary_not_expired() -> None:
    # Grenze: (now - last_seen) == ttl ist NICHT expired (Altcode: > ttl).
    age, expired = neighbor_age(now=220.0, last_seen=100.0, ttl=120)
    assert age == 120
    assert expired is False


def test_neighbor_age_past_ttl_expired() -> None:
    age, expired = neighbor_age(now=221.0, last_seen=100.0, ttl=120)
    assert age == 121
    assert expired is True
