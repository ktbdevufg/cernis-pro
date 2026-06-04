"""Tests fuer die capture-Use-Cases -- Fake-Ports, kein scapy/Raw-Socket.

Getestet: (1) ``RunCapture.run`` treibt ``apply_packet`` + ``ring_trim`` + Broadcast
(Stats akkumulieren, jeder ps gebroadcastet, ring_trim greift bei >10000); (2)
``stop()`` exportiert die pcap und merkt sich den Pfad -> ``status``/``pcap_path``;
(3) ``StartCapture`` liefert die ``{ok,error}``-Naht (verfuegbar/Rechte); (4)
``CaptureLldp`` merged in die Map, ``GetLldpNeighbors`` liest sie.

Async ueber ``asyncio.run`` (kein ``pytest-asyncio``, wie M.3/S.3). Die Ports sind
Fakes (strukturell, kein Protocol-Zwang).
"""

import asyncio
from collections.abc import AsyncIterator

from application.capture import CaptureLldp, GetLldpNeighbors, RunCapture, StartCapture
from domain.capture import LLDPNeighbor, PacketSummary

# ── Fakes ────────────────────────────────────────────────────────────────────


class _FakeSniffer:
    """PacketSnifferPort-Fake: yieldet die gefuetterten Pakete, merkt export/stop."""

    def __init__(
        self,
        packets: list[PacketSummary],
        *,
        available: bool = True,
        permission: str | None = None,
        export_ok: bool = True,
    ) -> None:
        self._packets = packets
        self._available = available
        self._permission = permission
        self._export_ok = export_ok
        self.exported_to: str | None = None
        self.stopped = False
        self._running = False

    async def stream(
        self, interface: str | None, bpf_filter: str, max_packets: int
    ) -> AsyncIterator[PacketSummary]:
        self._running = True
        for ps in self._packets:
            yield ps
        self._running = False

    def stop(self) -> None:
        self.stopped = True
        self._running = False

    def is_running(self) -> bool:
        return self._running

    def export_pcap(self, path: str) -> bool:
        if self._export_ok:
            self.exported_to = path
            return True
        return False

    def check_permission(self) -> str | None:
        return self._permission

    def is_available(self) -> bool:
        return self._available


class _FakeBroadcaster:
    """CaptureBroadcasterPort-Fake: sammelt die gebroadcasteten Pakete."""

    def __init__(self) -> None:
        self.broadcasted: list[PacketSummary] = []

    async def broadcast(self, packet: PacketSummary) -> None:
        self.broadcasted.append(packet)


class _FakeLldpSniffer:
    """LldpSnifferPort-Fake: gibt feste Nachbar-Runden zurueck (pro capture-Aufruf)."""

    def __init__(self, rounds: list[list[LLDPNeighbor]]) -> None:
        self._rounds = rounds
        self._i = 0

    async def capture(self, interface: str | None, duration: float) -> list[LLDPNeighbor]:
        result = self._rounds[self._i] if self._i < len(self._rounds) else []
        self._i += 1
        return result


def _packet(src_ip: str = "10.0.0.1", dst_port: int = 443, length: int = 100) -> PacketSummary:
    return PacketSummary(
        timestamp=1.0, src_ip=src_ip, dst_port=dst_port, protocol="HTTPS", length=length
    )


# ── RunCapture: der Loop treibt apply_packet + ring_trim + broadcast ──────────


def test_run_accumulates_stats_and_broadcasts_each_packet() -> None:
    packets = [_packet(length=100), _packet(length=200), _packet(src_ip="10.0.0.2", length=50)]
    sniffer = _FakeSniffer(packets)
    broadcaster = _FakeBroadcaster()
    uc = RunCapture(sniffer, broadcaster, "/tmp/x.pcap")

    asyncio.run(uc.run(interface=None, bpf_filter="", max_packets=10))

    # Jeder ps gebroadcastet, in Reihenfolge.
    assert broadcaster.broadcasted == packets
    # Stats akkumuliert: 3 Pakete, 350 bytes.
    status = uc.status(now=10.0)
    assert status["packets"] == 3
    assert status["stats"]["total_packets"] == 3
    assert status["stats"]["total_bytes"] == 350
    # top_talkers: zwei Quell-IPs.
    assert status["stats"]["top_talkers"] == {"10.0.0.1": 300, "10.0.0.2": 50}


def test_run_ring_trim_caps_at_10000_keeps_5000() -> None:
    # 10001 Pakete -> ring_trim greift, Puffer auf die letzten 5000.
    packets = [_packet(dst_port=1000 + i) for i in range(10001)]
    sniffer = _FakeSniffer(packets)
    uc = RunCapture(sniffer, _FakeBroadcaster(), "/tmp/x.pcap")

    asyncio.run(uc.run(interface=None, bpf_filter="", max_packets=20000))

    status = uc.status(now=1.0)
    # ring_trim: ueber 10000 -> letzte 5000 behalten.
    assert status["packets"] == 5000
    # recent_packets liefert aus dem getrimmten Puffer.
    assert len(uc.recent_packets(10000)) == 5000


def test_stop_exports_pcap_and_remembers_path() -> None:
    sniffer = _FakeSniffer([_packet()], export_ok=True)
    uc = RunCapture(sniffer, _FakeBroadcaster(), "/tmp/cernis_capture.pcap")
    asyncio.run(uc.run(interface=None, bpf_filter="", max_packets=10))

    uc.stop()

    assert sniffer.exported_to == "/tmp/cernis_capture.pcap"
    assert sniffer.stopped is True
    assert uc.pcap_path() == "/tmp/cernis_capture.pcap"
    status = uc.status(now=1.0)
    assert status["pcap_available"] is True
    assert status["pcap_path"] == "/tmp/cernis_capture.pcap"


def test_stop_no_packets_no_pcap_path() -> None:
    # export_pcap False (nichts zu schreiben) -> kein pcap_path, status spiegelt das.
    sniffer = _FakeSniffer([], export_ok=False)
    uc = RunCapture(sniffer, _FakeBroadcaster(), "/tmp/cernis_capture.pcap")
    asyncio.run(uc.run(interface=None, bpf_filter="", max_packets=10))

    uc.stop()

    assert uc.pcap_path() is None
    status = uc.status(now=1.0)
    assert status["pcap_available"] is False
    assert status["pcap_path"] is None


def test_status_error_field_always_empty() -> None:
    # totes Feld (AS-IS): error bleibt "" (Altcode setzte _capture_error nie).
    uc = RunCapture(_FakeSniffer([]), _FakeBroadcaster(), "/tmp/x.pcap")
    assert uc.status(now=1.0)["error"] == ""


# ── StartCapture: die {ok,error}-Naht ────────────────────────────────────────


def test_start_capture_available_no_permission_error_ok() -> None:
    uc = StartCapture(_FakeSniffer([], available=True, permission=None))
    assert uc() == {"ok": True, "error": ""}


def test_start_capture_permission_error_not_ok() -> None:
    uc = StartCapture(_FakeSniffer([], available=True, permission="needs CAP_NET_RAW"))
    result = uc()
    assert result["ok"] is False
    assert result["error"] == "needs CAP_NET_RAW"


def test_start_capture_unavailable_not_ok() -> None:
    uc = StartCapture(_FakeSniffer([], available=False))
    result = uc()
    assert result["ok"] is False
    assert "libpcap" in result["error"]


# ── CaptureLldp / GetLldpNeighbors: die akkumulierende Nachbartabelle ─────────


def test_capture_lldp_merges_into_map_and_returns_round() -> None:
    n1 = LLDPNeighbor(source_mac="aa:bb", system_name="sw1", last_seen=100.0)
    n2 = LLDPNeighbor(source_mac="cc:dd", system_name="sw2", last_seen=100.0)
    capture_lldp = CaptureLldp(_FakeLldpSniffer([[n1], [n2]]))

    # Runde 1: nur n1 zurueck, Map = {n1}.
    round1 = asyncio.run(capture_lldp(interface=None, duration=5.0))
    assert round1 == [n1]
    # Runde 2: nur n2 zurueck, aber Map akkumuliert {n1, n2}.
    round2 = asyncio.run(capture_lldp(interface=None, duration=5.0))
    assert round2 == [n2]

    get_neighbors = GetLldpNeighbors(capture_lldp)
    macs = {n.source_mac for n in get_neighbors()}
    assert macs == {"aa:bb", "cc:dd"}


def test_capture_lldp_last_entry_per_mac_wins() -> None:
    old = LLDPNeighbor(source_mac="aa:bb", system_name="old", last_seen=100.0)
    new = LLDPNeighbor(source_mac="aa:bb", system_name="new", last_seen=200.0)
    capture_lldp = CaptureLldp(_FakeLldpSniffer([[old], [new]]))
    asyncio.run(capture_lldp(interface=None, duration=5.0))
    asyncio.run(capture_lldp(interface=None, duration=5.0))

    neighbors = GetLldpNeighbors(capture_lldp)()
    assert len(neighbors) == 1
    assert neighbors[0].system_name == "new"
