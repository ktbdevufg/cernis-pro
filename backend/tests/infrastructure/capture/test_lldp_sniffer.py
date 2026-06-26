"""Tests fuer ``ScapyLldpSniffer`` -- Fake-Helfer-Client statt echtem Subprozess/scapy.

ETAPPE 3b (Privilege-Separation): Der Adapter parst LLDP/CDP nicht mehr selbst (das
ist in den Helfer gewandert), sondern baut aus den rohen Nachbar-dicts des Helfers ein
``LLDPNeighbor``. Wir injizieren einen Fake-Client (gibt rohe Nachbar-dicts ODER ``[]``
zurueck) und pruefen:

* Port-Konformitaet;
* ``capture`` baut aus den rohen dicts ``LLDPNeighbor`` (Felder durchgereicht);
* Helfer-Fehler (Client liefert ``[]``) -> leere Liste, kein Crash (S3-Heilung);
* ein kaputtes Nachbar-dict wird still uebersprungen (defensiv);
* die Argumente (interface/duration) werden an den Client durchgereicht.

Async ueber ``asyncio.run`` (kein ``pytest-asyncio``). KEIN echter scapy/Subprozess.
"""

import asyncio
from typing import Any

import pytest

from domain.capture import LLDPNeighbor
from infrastructure.capture.lldp_sniffer import ScapyLldpSniffer
from ports.capture import LldpSnifferPort


class _FakeLldpClient:
    """In-Memory-``LldpClient``: gibt feste rohe Nachbar-dicts zurueck (oder ``[]``)."""

    def __init__(self, neighbors: list[dict[str, Any]]) -> None:
        self._neighbors = neighbors
        self.calls: list[tuple[str | None, float]] = []

    def capture(self, interface: str | None, duration: float) -> list[dict[str, Any]]:
        self.calls.append((interface, duration))
        return self._neighbors


def test_conforms_to_lldp_sniffer_protocol() -> None:
    _: LldpSnifferPort = ScapyLldpSniffer()


def test_capture_builds_neighbors_from_dicts() -> None:
    fake = _FakeLldpClient(
        [
            {
                "source_mac": "aa:bb:cc:dd:ee:ff",
                "protocol": "LLDP",
                "chassis_id": "chassis-1",
                "port_id": "Gi0/1",
                "system_name": "switch-a",
                "system_desc": "Cisco switch",
                "port_desc": "uplink",
            },
            {
                "source_mac": "11:22:33:44:55:66",
                "protocol": "CDP",
                "system_name": "router-b",
                "chassis_id": "router-b",
                "port_id": "Fa0/0",
                "system_desc": "IOS 15.2",
                "capabilities": ["C2960"],
            },
        ]
    )
    result = asyncio.run(
        ScapyLldpSniffer(client_factory=lambda: fake).capture(interface="eth0", duration=2.0)
    )
    assert len(result) == 2
    assert all(isinstance(n, LLDPNeighbor) for n in result)
    lldp = result[0]
    assert lldp.source_mac == "aa:bb:cc:dd:ee:ff"
    assert lldp.protocol == "LLDP"
    assert lldp.system_name == "switch-a"
    assert lldp.port_desc == "uplink"
    cdp = result[1]
    assert cdp.protocol == "CDP"
    assert cdp.chassis_id == "router-b"
    assert cdp.capabilities == ["C2960"]
    # Argumente durchgereicht.
    assert fake.calls == [("eth0", 2.0)]


def test_capture_helper_error_returns_empty() -> None:
    # Client liefert [] (Helfer-ERROR/Spawn-Fehler) -> leere Liste, kein Crash.
    result = asyncio.run(
        ScapyLldpSniffer(client_factory=lambda: _FakeLldpClient([])).capture(
            interface=None, duration=1.0
        )
    )
    assert result == []


def test_capture_skips_malformed_neighbor(monkeypatch: pytest.MonkeyPatch) -> None:
    # Ein kaputtes Nachbar-dict (unbekanntes Feld) wird still uebersprungen, das gute
    # bleibt -- ein einzelner Murks-Eintrag killt die Liste nicht.
    fake = _FakeLldpClient(
        [
            {"nonsense_field": 1},
            {"source_mac": "aa:bb", "system_name": "good"},
        ]
    )
    result = asyncio.run(
        ScapyLldpSniffer(client_factory=lambda: fake).capture(interface=None, duration=1.0)
    )
    assert len(result) == 1
    assert result[0].system_name == "good"


def test_neighbor_from_dict_returns_none_on_bad_type() -> None:
    assert ScapyLldpSniffer._neighbor_from_dict({"unknown": "x"}) is None
    ok = ScapyLldpSniffer._neighbor_from_dict({"source_mac": "aa:bb"})
    assert ok is not None and ok.source_mac == "aa:bb"
