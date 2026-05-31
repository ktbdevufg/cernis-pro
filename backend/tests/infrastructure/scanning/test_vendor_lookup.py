"""Tests fuer ``VendorLookupAdapter`` -- gemockte ``modules.lookup_vendor``.

Der Adapter ist ein duenner sync Wrapper; getestet wird (1) strukturelle
Konformitaet zum Port, (2) dass ``lookup`` delegiert und das Ergebnis 1:1
durchreicht, (3) der vom Vertrag vorgesehene Leer-Zustand ``""``.

Gemockt wird ``lookup_vendor`` AM IMPORT-ORT IM ADAPTER-MODUL
(``infrastructure.scanning.vendor_lookup.lookup_vendor``) -- nicht in
``modules.vendor`` -- weil der Adapter den Namen beim Import gebunden hat.
"""

import pytest

from infrastructure.scanning import vendor_lookup
from infrastructure.scanning.vendor_lookup import VendorLookupAdapter
from ports.scanning import VendorLookupPort


def test_conforms_to_vendor_lookup_protocol() -> None:
    _: VendorLookupPort = VendorLookupAdapter()


def test_lookup_delegates_and_passes_through(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, str] = {}

    def fake_lookup(mac: str) -> str:
        seen["mac"] = mac
        return "ACME Corp"

    monkeypatch.setattr(vendor_lookup, "lookup_vendor", fake_lookup)
    assert VendorLookupAdapter().lookup("AA:BB:CC:00:00:00") == "ACME Corp"
    assert seen["mac"] == "AA:BB:CC:00:00:00"  # unveraendert durchgereicht


def test_lookup_unknown_returns_empty_string(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vendor_lookup, "lookup_vendor", lambda mac: "")
    assert VendorLookupAdapter().lookup("FF:FF:FF:FF:FF:FF") == ""
