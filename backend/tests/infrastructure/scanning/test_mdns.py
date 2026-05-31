"""Tests fuer ``MdnsAdapter`` -- gemockte ``modules.mdns.discover_mdns``.

``discover_mdns`` wird AM IMPORT-ORT IM ADAPTER-MODUL gemockt (nicht in
``modules.mdns``), wie in S.4a-c. Der Mock liefert ROHDATEN (``modules.MDNSService``-
Shape), der Test prueft das verlustfreie Mapping auf ``domain.MdnsService``.

Schwerpunkte:
* Port-Konformitaet.
* Feld-Mapping inkl. ``service_type`` -> ``type`` und ``properties`` (dict) ->
  ``tuple[tuple[str, str], ...]`` in dict-Reihenfolge.
* ``ip`` (modules-Feld) wird verworfen -- existiert nicht in der Domaene.
* Edge: leeres Ergebnis -> leere Liste; leere ``properties`` -> leeres tuple.

Async-Smokes via ``asyncio.run`` (kein ``pytest-asyncio``, wie S.4a-c).
"""

import asyncio
from dataclasses import dataclass, field
from typing import Any

import pytest

from domain.scanning import MdnsService
from infrastructure.scanning import mdns
from infrastructure.scanning.mdns import MdnsAdapter
from ports.scanning import MdnsPort


# Fake der ``modules.MDNSService`` -- genau die vom Adapter gelesenen Felder.
@dataclass
class FakeMDNSService:
    ip: str
    name: str
    service_type: str
    port: int = 0
    hostname: str = ""
    properties: dict[str, str] = field(default_factory=dict)
    is_ndi: bool = False


def _patch(monkeypatch: pytest.MonkeyPatch, raw: list[Any]) -> None:
    async def fake_discover(duration: float) -> list[Any]:
        return raw

    monkeypatch.setattr(mdns, "discover_mdns", fake_discover)


# ── Struktureller Vertrag ─────────────────────────────────────────────────


def test_conforms_to_mdns_protocol() -> None:
    _: MdnsPort = MdnsAdapter()


# ── Mapping ──────────────────────────────────────────────────────────────────


def test_maps_all_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(
        monkeypatch,
        [
            FakeMDNSService(
                ip="10.0.0.5",
                name="Drucker._ipp._tcp.local.",
                service_type="_ipp._tcp.local.",
                port=631,
                hostname="drucker.local.",
                properties={"rp": "ipp/print", "ty": "HP LaserJet"},
                is_ndi=False,
            )
        ],
    )
    result = asyncio.run(MdnsAdapter().discover(5.0))

    assert result == [
        MdnsService(
            name="Drucker._ipp._tcp.local.",
            type="_ipp._tcp.local.",  # service_type -> type
            port=631,
            hostname="drucker.local.",
            is_ndi=False,
            properties=(("rp", "ipp/print"), ("ty", "HP LaserJet")),  # dict-Reihenfolge
        )
    ]


def test_ndi_flag_and_empty_properties(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(
        monkeypatch,
        [
            FakeMDNSService(
                ip="10.0.0.9",
                name="CAM1._ndi._tcp.local.",
                service_type="_ndi._tcp.local.",
                port=5960,
                is_ndi=True,
            )
        ],
    )
    result = asyncio.run(MdnsAdapter().discover(3.0))
    assert len(result) == 1
    assert result[0].is_ndi is True
    assert result[0].properties == ()  # leeres dict -> leeres tuple


def test_empty_result_is_empty_list(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, [])
    assert asyncio.run(MdnsAdapter().discover(5.0)) == []
