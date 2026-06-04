"""Tests fuer ``ScapyLldpSniffer`` -- scapy/contrib gemockt.

Getestet: (1) Port-Konformitaet, (2) ``_parse_lldp``/``_parse_cdp`` gegen gemockte
Layer -> ``LLDPNeighbor``, (3) ``capture``: Sniff-Fehler -> ``structlog``-Warn +
leere Liste (kein ``print``, kein Crash), (4) fehlendes contrib -> ``[]`` + Warn.

Async ueber ``asyncio.run`` (kein ``pytest-asyncio``). Gemockt am Import-Ort
(``infrastructure.capture._scapy``).
"""

import asyncio
from typing import Any

import pytest

from domain.capture import LLDPNeighbor
from infrastructure.capture import _scapy
from infrastructure.capture.lldp_sniffer import ScapyLldpSniffer
from ports.capture import LldpSnifferPort


class _Layer:
    def __init__(self, name: str) -> None:
        self.name = name


_ETHER = _Layer("Ether")
_LLDP_CHASSIS = _Layer("LLDPDUChassisID")
_LLDP_PORT = _Layer("LLDPDUPortID")
_LLDP_NAME = _Layer("LLDPDUSystemName")
_LLDP_DESC = _Layer("LLDPDUSystemDescription")
_LLDP_PDESC = _Layer("LLDPDUPortDescription")
_CDP_DEV = _Layer("CDPMsgDeviceID")
_CDP_PORT = _Layer("CDPMsgPortID")
_CDP_SW = _Layer("CDPMsgSoftwareVersion")
_CDP_PLAT = _Layer("CDPMsgPlatform")


class _FakePacket:
    def __init__(self, layers: dict[Any, Any]) -> None:
        self._layers = layers

    def haslayer(self, layer: Any) -> bool:
        return layer in self._layers

    def __getitem__(self, layer: Any) -> Any:
        return self._layers[layer]


class _Fields:
    def __init__(self, **kw: Any) -> None:
        self.__dict__.update(kw)


@pytest.fixture
def patch_layers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_scapy, "HAS_SCAPY", True)
    monkeypatch.setattr(_scapy, "HAS_SCAPY_CONTRIB", True)
    monkeypatch.setattr(_scapy, "Ether", _ETHER)
    monkeypatch.setattr(_scapy, "LLDPDUChassisID", _LLDP_CHASSIS)
    monkeypatch.setattr(_scapy, "LLDPDUPortID", _LLDP_PORT)
    monkeypatch.setattr(_scapy, "LLDPDUSystemName", _LLDP_NAME)
    monkeypatch.setattr(_scapy, "LLDPDUSystemDescription", _LLDP_DESC)
    monkeypatch.setattr(_scapy, "LLDPDUPortDescription", _LLDP_PDESC)
    monkeypatch.setattr(_scapy, "CDPMsgDeviceID", _CDP_DEV)
    monkeypatch.setattr(_scapy, "CDPMsgPortID", _CDP_PORT)
    monkeypatch.setattr(_scapy, "CDPMsgSoftwareVersion", _CDP_SW)
    monkeypatch.setattr(_scapy, "CDPMsgPlatform", _CDP_PLAT)


def test_conforms_to_lldp_sniffer_protocol() -> None:
    _: LldpSnifferPort = ScapyLldpSniffer()


def test_parse_lldp_builds_neighbor(patch_layers: None) -> None:
    pkt = _FakePacket(
        {
            _ETHER: _Fields(src="aa:bb:cc:dd:ee:ff"),
            _LLDP_CHASSIS: _Fields(id="chassis-1"),
            _LLDP_PORT: _Fields(id="Gi0/1"),
            _LLDP_NAME: _Fields(system_name="switch-a"),
            _LLDP_DESC: _Fields(description="Cisco switch"),
            _LLDP_PDESC: _Fields(description="uplink"),
        }
    )
    n = ScapyLldpSniffer()._parse_lldp(pkt)
    assert isinstance(n, LLDPNeighbor)
    assert n.source_mac == "aa:bb:cc:dd:ee:ff"
    assert n.protocol == "LLDP"
    assert n.chassis_id == "chassis-1"
    assert n.port_id == "Gi0/1"
    assert n.system_name == "switch-a"
    assert n.system_desc == "Cisco switch"
    assert n.port_desc == "uplink"


def test_parse_cdp_builds_neighbor(patch_layers: None) -> None:
    pkt = _FakePacket(
        {
            _ETHER: _Fields(src="11:22:33:44:55:66"),
            _CDP_DEV: _Fields(val="router-b"),
            _CDP_PORT: _Fields(val="Fa0/0"),
            _CDP_SW: _Fields(val="IOS 15.2"),
            _CDP_PLAT: _Fields(val="C2960"),
        }
    )
    n = ScapyLldpSniffer()._parse_cdp(pkt)
    assert n is not None
    assert n.protocol == "CDP"
    assert n.source_mac == "11:22:33:44:55:66"
    assert n.system_name == "router-b"
    assert n.chassis_id == "router-b"  # DeviceID setzt name UND chassis_id
    assert n.port_id == "Fa0/0"
    assert n.system_desc == "IOS 15.2"
    assert n.capabilities == ["C2960"]


def test_dispatch_lldp_by_ethertype(patch_layers: None) -> None:
    pkt = _FakePacket(
        {
            _ETHER: _Fields(src="aa:bb", dst="ff:ff", type=0x88CC),
            _LLDP_NAME: _Fields(system_name="sw"),
        }
    )
    n = ScapyLldpSniffer()._dispatch(pkt)
    assert n is not None and n.protocol == "LLDP"


def test_dispatch_cdp_by_dst_mac(patch_layers: None) -> None:
    pkt = _FakePacket(
        {
            _ETHER: _Fields(src="aa:bb", dst="01:00:0C:CC:CC:CC", type=0x1234),
            _CDP_DEV: _Fields(val="rtr"),
        }
    )
    n = ScapyLldpSniffer()._dispatch(pkt)
    assert n is not None and n.protocol == "CDP"


def test_capture_sniff_error_logs_and_returns_empty(
    patch_layers: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    # S3-Heilung: Sniff-Fehler -> structlog-Warn (kein print), leere Liste, kein Crash.
    warnings: list[str] = []

    def _boom(**kw: Any) -> None:
        raise OSError("no such device")

    monkeypatch.setattr(_scapy, "sniff", _boom)

    class _Logger:
        def warning(self, event: str, **kw: Any) -> None:
            warnings.append(event)

    monkeypatch.setattr("infrastructure.capture.lldp_sniffer._logger", _Logger())

    result = asyncio.run(ScapyLldpSniffer().capture(interface="eth0", duration=1.0))
    assert result == []
    assert "lldp_capture_failed" in warnings


def test_capture_dedupes_by_source_mac(patch_layers: None, monkeypatch: pytest.MonkeyPatch) -> None:
    # Zwei LLDP-Frames derselben MAC -> ein Nachbar (letzter gewinnt).
    pkts = [
        _FakePacket(
            {
                _ETHER: _Fields(src="aa:bb", dst="ff", type=0x88CC),
                _LLDP_NAME: _Fields(system_name="first"),
            }
        ),
        _FakePacket(
            {
                _ETHER: _Fields(src="aa:bb", dst="ff", type=0x88CC),
                _LLDP_NAME: _Fields(system_name="second"),
            }
        ),
    ]

    def _fake_sniff(**kw: Any) -> None:
        prn = kw["prn"]
        for p in pkts:
            prn(p)

    monkeypatch.setattr(_scapy, "sniff", _fake_sniff)
    result = asyncio.run(ScapyLldpSniffer().capture(interface=None, duration=1.0))
    assert len(result) == 1
    assert result[0].system_name == "second"


def test_capture_without_contrib_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_scapy, "HAS_SCAPY", True)
    monkeypatch.setattr(_scapy, "HAS_SCAPY_CONTRIB", False)
    result = asyncio.run(ScapyLldpSniffer().capture(interface=None, duration=1.0))
    assert result == []
