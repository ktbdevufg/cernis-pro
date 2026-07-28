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
import time
from typing import Any

import pytest

from application.capture import enrich_neighbor
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


# ── last_seen: der Zeitpunkt der letzten Sichtung ─────────────────────────────


def test_neighbor_from_dict_keeps_helper_last_seen() -> None:
    """Der vom Helfer gestempelte ``last_seen`` wird unveraendert uebernommen."""
    stamped = 1_785_263_168.5
    neighbor = ScapyLldpSniffer._neighbor_from_dict({"source_mac": "aa:bb", "last_seen": stamped})
    assert neighbor is not None
    assert neighbor.last_seen == stamped


def test_neighbor_from_dict_fills_missing_last_seen() -> None:
    """Fehlt ``last_seen``, bleibt es NICHT auf ``0.0`` (das waere die stille Luege).

    Der dataclass-Default ``0.0`` machte das Alter zur Unix-Zeit; der Empfangs-
    zeitpunkt wird an dieser Naht nachgetragen.
    """
    before = time.time()
    neighbor = ScapyLldpSniffer._neighbor_from_dict({"source_mac": "aa:bb"})
    after = time.time()
    assert neighbor is not None
    assert neighbor.last_seen != 0.0
    assert before <= neighbor.last_seen <= after


def test_freshly_captured_neighbor_is_not_expired() -> None:
    """Ein SOEBEN erfasster Nachbar gilt NICHT als abgelaufen und hat plausibles Alter.

    Das ist der gemeldete Mangel 2 im Ergebnis: ``last_seen = 0.0`` ergab
    ``age_secs = <Unix-Zeit>`` und ``expired = True`` fuer einen gerade gesehenen
    Nachbarn. Geprueft wird gegen dieselbe Rechnung, die der api-Rand fahrt.
    """
    fake = _FakeLldpClient(
        [{"source_mac": "aa:bb:cc:dd:ee:ff", "system_name": "Fritzchen", "last_seen": time.time()}]
    )
    result = asyncio.run(
        ScapyLldpSniffer(client_factory=lambda: fake).capture(interface=None, duration=1.0)
    )
    assert len(result) == 1
    age_secs, expired = enrich_neighbor(result[0], time.time())
    assert not expired
    assert 0 <= age_secs < 5  # Sekunden, nicht Unix-Zeit
