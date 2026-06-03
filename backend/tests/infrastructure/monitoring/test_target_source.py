"""Tests fuer ``CompositeTargetSource`` -- 3-Quellen-Komposition + Live-Reload.

Getestet: (1) Port-Konformitaet, (2) Komposition aus allen drei Quellen
(Interface-Gateways + hardcoded Internet-Targets + Custom-Settings), (3) ein
Interface OHNE gateway/ipv4 wird uebersprungen (Altcode-Bedingung), (4) keine
Custom-Settings -> nur die fest verdrahteten Targets, (5) Live-Reload: ``load()``
liest bei jedem Aufruf frisch (geaenderte Settings wirken sofort).

``modules.interfaces.get_interfaces`` wird am Import-Ort im Adapter-Modul gemockt;
der SettingsRepository ist ein vertragstreuer In-Memory-Fake.
"""

from dataclasses import dataclass
from typing import Any

import pytest

from domain.monitoring import MonitorTarget
from domain.settings import Setting
from infrastructure.monitoring import target_source
from infrastructure.monitoring.target_source import CompositeTargetSource
from ports.monitoring import MonitorTargetSource
from ports.settings import SettingsRepository


@dataclass
class _FakeIface:
    """Minimaler InterfaceInfo-Stand-in (nur die genutzten Felder)."""

    name: str
    ipv4: str = ""
    gateway: str = ""


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


def _patch_interfaces(monkeypatch: pytest.MonkeyPatch, ifaces: list[_FakeIface]) -> None:
    monkeypatch.setattr(target_source, "get_interfaces", lambda: ifaces)


def test_conforms_to_target_source_protocol() -> None:
    settings: SettingsRepository = _FakeSettings()
    _: MonitorTargetSource = CompositeTargetSource(settings)


def test_composition_all_three_sources(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_interfaces(
        monkeypatch, [_FakeIface(name="eth0", ipv4="192.168.1.50", gateway="192.168.1.1")]
    )
    settings = _FakeSettings(
        {
            "monitor_custom_targets": [
                {"id": "nas", "label": "NAS", "host": "192.168.1.10"},
            ]
        }
    )
    targets = CompositeTargetSource(settings).load()
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


def test_interface_without_gateway_or_ipv4_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_interfaces(
        monkeypatch,
        [
            _FakeIface(name="lo", ipv4="127.0.0.1", gateway=""),  # kein gateway
            _FakeIface(name="eth1", ipv4="", gateway="10.0.0.1"),  # kein ipv4
        ],
    )
    targets = CompositeTargetSource(_FakeSettings()).load()
    # Beide Interfaces uebersprungen -> nur die 2 hardcoded Internet-Targets.
    assert [t.id for t in targets] == ["internet_primary", "internet_secondary"]


def test_no_custom_targets_yields_only_hardcoded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_interfaces(monkeypatch, [])
    targets = CompositeTargetSource(_FakeSettings()).load()
    assert [t.id for t in targets] == ["internet_primary", "internet_secondary"]
    assert all(isinstance(t, MonitorTarget) for t in targets)


def test_broken_custom_entry_skipped_rest_survives(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Best-effort pro Eintrag: ein kaputtes Custom-Target (dict OHNE "host") darf
    # nicht die ganze Liste reissen. Der gueltige Eintrag + die hardcoded Targets
    # kommen durch, der kaputte faellt raus -- load() wirft NICHT.
    _patch_interfaces(monkeypatch, [])
    settings = _FakeSettings(
        {
            "monitor_custom_targets": [
                {"id": "broken", "label": "Broken"},  # KEIN host -> KeyError im Mapping
                {"id": "ok", "label": "OK", "host": "192.168.1.30"},
            ]
        }
    )
    targets = CompositeTargetSource(settings).load()
    ids = [t.id for t in targets]
    # Hardcoded + der gueltige; der kaputte ("broken") ist raus.
    assert ids == ["internet_primary", "internet_secondary", "ok"]
    assert "broken" not in ids


def test_load_reads_fresh_each_call_live_reload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_interfaces(monkeypatch, [])
    settings = _FakeSettings()
    source = CompositeTargetSource(settings)

    # Erster load: keine Custom-Targets.
    assert [t.id for t in source.load()] == ["internet_primary", "internet_secondary"]

    # Settings aendern sich (wie via /api/monitor/targets) -> naechster load sieht es.
    settings.set(
        Setting(
            key="monitor_custom_targets",
            value=[{"id": "cam", "label": "Cam", "host": "192.168.1.20"}],
        )
    )
    ids_after = [t.id for t in source.load()]
    assert "cam" in ids_after
