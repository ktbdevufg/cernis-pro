"""Tests fuer ``SsdpAdapter`` -- gemockte ``modules.ssdp.discover_ssdp``.

``discover_ssdp`` wird AM IMPORT-ORT IM ADAPTER-MODUL gemockt (nicht in
``modules.ssdp``), wie in S.4a-c. Der Mock liefert ROHDATEN (``modules.SSDPDevice``-
Shape), der Test prueft das verlustfreie Mapping auf ``domain.SsdpService``.

Schwerpunkte:
* Port-Konformitaet.
* Feld-Mapping: ``server``/``st``/``location``/``ip`` uebernommen (``ip`` als
  S.5-Vorbau fuer die Host-Zuordnung, analog ``ipv6`` in S.4e).
* ``usn``/``friendly_name`` (modules-Felder) werden verworfen -- existieren
  nicht in der Domaene.
* Edge: leeres Ergebnis -> leere Liste.

Async-Smokes via ``asyncio.run`` (kein ``pytest-asyncio``, wie S.4a-c).
"""

import asyncio
from dataclasses import dataclass
from typing import Any

import pytest

from domain.scanning import SsdpService
from infrastructure.scanning import ssdp
from infrastructure.scanning.ssdp import SsdpAdapter
from ports.scanning import SsdpPort


# Fake der ``modules.SSDPDevice`` -- inkl. der VERWORFENEN Felder (usn/
# friendly_name), damit der Test beweist, dass sie nicht in die Domaene
# durchsickern. ``ip`` wird hingegen jetzt uebernommen (S.5-Vorbau).
@dataclass
class FakeSSDPDevice:
    ip: str
    location: str = ""
    server: str = ""
    st: str = ""
    usn: str = ""
    friendly_name: str = ""


def _patch(monkeypatch: pytest.MonkeyPatch, raw: list[Any]) -> None:
    async def fake_discover(timeout: float) -> list[Any]:
        return raw

    monkeypatch.setattr(ssdp, "discover_ssdp", fake_discover)


# ── Struktureller Vertrag ─────────────────────────────────────────────────


def test_conforms_to_ssdp_protocol() -> None:
    _: SsdpPort = SsdpAdapter()


# ── Mapping ──────────────────────────────────────────────────────────────────


def test_maps_kept_fields_and_drops_others(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(
        monkeypatch,
        [
            FakeSSDPDevice(
                ip="10.0.0.7",
                location="http://10.0.0.7:1900/desc.xml",
                server="Linux/4.0 UPnP/1.0",
                st="upnp:rootdevice",
                usn="uuid:abc::upnp:rootdevice",
                friendly_name="Wohnzimmer-TV",
            )
        ],
    )
    result = asyncio.run(SsdpAdapter().discover(4.0))

    # server/st/location/ip wandern in die Domaene; usn/friendly_name nicht.
    # ip ist S.5-Vorbau (Host-Zuordnung), nicht mehr verworfen.
    assert result == [
        SsdpService(
            server="Linux/4.0 UPnP/1.0",
            st="upnp:rootdevice",
            location="http://10.0.0.7:1900/desc.xml",
            ip="10.0.0.7",
        )
    ]


def test_empty_result_is_empty_list(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, [])
    assert asyncio.run(SsdpAdapter().discover(4.0)) == []
