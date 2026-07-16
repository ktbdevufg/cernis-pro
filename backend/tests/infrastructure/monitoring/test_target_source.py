"""Tests fuer ``CompositeTargetSource`` -- 3-Quellen-Komposition + Live-Reload.

Getestet: (1) Port-Konformitaet, (2) Komposition aus allen drei Quellen
(Interface-Gateways + hardcoded Internet-Targets + Custom-Settings), (3) ein
Interface OHNE gateway/ipv4 wird uebersprungen (Altcode-Bedingung), (4) keine
Custom-Settings -> nur die fest verdrahteten Targets, (5) Live-Reload: ``load()``
liest bei jedem Aufruf frisch (geaenderte Settings wirken sofort).

Die Interface-Gateways kommen ueber den nativen ``InterfaceDiscoveryPort``; hier
per In-Memory-Fake-Discovery-Adapter (``async def discover``) bedient. Der
SettingsRepository ist ein vertragstreuer In-Memory-Fake.
"""

import asyncio
from typing import Any

from domain.interfaces import NetworkInterface
from domain.monitoring import MonitorTarget
from domain.settings import Setting
from infrastructure.monitoring.target_source import CompositeTargetSource
from ports.interfaces import InterfaceDiscoveryPort
from ports.monitoring import MonitorTargetSource
from ports.settings import SettingsRepository


class _FakeDiscovery:
    """Vertragstreuer In-Memory-``InterfaceDiscoveryPort`` (nur ``discover``).

    Liefert die rohen ``NetworkInterface``-Objekte direkt aus dem Fake
    (``async def discover``) -- gleiche name/ipv4/gateway -> gleiche
    ``gw_<name>``-Gateway-Targets.
    """

    def __init__(self, ifaces: list[NetworkInterface]) -> None:
        self._ifaces = ifaces

    async def discover(self) -> list[NetworkInterface]:
        return list(self._ifaces)


class _FakeSettings:
    """Vertragstreuer In-Memory-SettingsRepository (nur ``get`` wird genutzt)."""

    def __init__(self, store: dict[str, Any] | None = None) -> None:
        self._store = store or {}

    def get_all(self) -> dict[str, Any]:
        return dict(self._store)

    def get(self, key: str) -> Setting | None:
        if key in self._store:
            return Setting(key=key, value=self._store[key])
        return None

    def set(self, setting: Setting) -> None:
        self._store[setting.key] = setting.value

    def delete(self, key: str) -> None:
        self._store.pop(key, None)

    def clear_all(self) -> None:
        """Leert den internen Settings-Speicher (No-op-Schreibpfad fuer den Fake)."""
        self._store.clear()


def _iface(name: str, *, ipv4: str | None = None, gateway: str | None = None) -> NetworkInterface:
    return NetworkInterface(name=name, ipv4=ipv4, gateway=gateway)


def test_conforms_to_target_source_protocol() -> None:
    settings: SettingsRepository = _FakeSettings()
    discovery: InterfaceDiscoveryPort = _FakeDiscovery([])
    _: MonitorTargetSource = CompositeTargetSource(settings, discovery)


def test_composition_all_three_sources() -> None:
    discovery = _FakeDiscovery([_iface("eth0", ipv4="192.168.1.50", gateway="192.168.1.1")])
    settings = _FakeSettings(
        {
            "monitor_custom_targets": [
                {"id": "nas", "label": "NAS", "host": "192.168.1.10"},
            ]
        }
    )
    targets = asyncio.run(CompositeTargetSource(settings, discovery).load())
    ids = [t.id for t in targets]
    # Gateway + 2 hardcoded + 1 custom.
    assert ids == ["gw_eth0", "internet_primary", "internet_secondary", "nas"]
    gw = targets[0]
    assert gw.host == "192.168.1.1"
    assert gw.interface == "eth0"
    assert gw.label == "Gateway (eth0)"
    nas = targets[-1]
    assert nas.host == "192.168.1.10"
    assert nas.interface == ""  # Default
    assert nas.enabled is True  # Default


def test_interface_without_gateway_or_ipv4_skipped() -> None:
    discovery = _FakeDiscovery(
        [
            _iface("lo", ipv4="127.0.0.1", gateway=None),  # kein gateway
            _iface("eth1", ipv4=None, gateway="10.0.0.1"),  # kein ipv4
        ]
    )
    targets = asyncio.run(CompositeTargetSource(_FakeSettings(), discovery).load())
    # Beide Interfaces uebersprungen -> nur die 2 hardcoded Internet-Targets.
    assert [t.id for t in targets] == ["internet_primary", "internet_secondary"]


def test_no_custom_targets_yields_only_hardcoded() -> None:
    discovery = _FakeDiscovery([])
    targets = asyncio.run(CompositeTargetSource(_FakeSettings(), discovery).load())
    assert [t.id for t in targets] == ["internet_primary", "internet_secondary"]
    assert all(isinstance(t, MonitorTarget) for t in targets)


def test_broken_custom_entry_skipped_rest_survives() -> None:
    # Best-effort pro Eintrag: ein kaputtes Custom-Target (dict OHNE "host") darf
    # nicht die ganze Liste reissen. Der gueltige Eintrag + die hardcoded Targets
    # kommen durch, der kaputte faellt raus -- load() wirft NICHT.
    discovery = _FakeDiscovery([])
    settings = _FakeSettings(
        {
            "monitor_custom_targets": [
                {"id": "broken", "label": "Broken"},  # KEIN host -> KeyError im Mapping
                {"id": "ok", "label": "OK", "host": "192.168.1.30"},
            ]
        }
    )
    targets = asyncio.run(CompositeTargetSource(settings, discovery).load())
    ids = [t.id for t in targets]
    # Hardcoded + der gueltige; der kaputte ("broken") ist raus.
    assert ids == ["internet_primary", "internet_secondary", "ok"]
    assert "broken" not in ids


def test_load_reads_fresh_each_call_live_reload() -> None:
    discovery = _FakeDiscovery([])
    settings = _FakeSettings()
    source = CompositeTargetSource(settings, discovery)

    # Erster load: keine Custom-Targets.
    assert [t.id for t in asyncio.run(source.load())] == [
        "internet_primary",
        "internet_secondary",
    ]

    # Settings aendern sich (wie via /api/monitor/targets) -> naechster load sieht es.
    settings.set(
        Setting(
            key="monitor_custom_targets",
            value=[{"id": "cam", "label": "Cam", "host": "192.168.1.20"}],
        )
    )
    ids_after = [t.id for t in asyncio.run(source.load())]
    assert "cam" in ids_after
