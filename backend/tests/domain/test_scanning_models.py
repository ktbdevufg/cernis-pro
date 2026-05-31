"""Unit-Tests der scanning-Domaenenmodelle -- reine Logik, kein I/O."""

import dataclasses

import pytest

from domain.scanning import (
    DiscoveredHost,
    EnrichedHost,
    HostClassification,
    PortInfo,
    ScanConfig,
)

# ── ScanConfig ───────────────────────────────────────────────────────────────


def test_scan_config_defaults() -> None:
    cfg = ScanConfig(cidrs=("192.168.1.0/24",))
    assert cfg.ping_timeout == 1.5
    assert cfg.port_scan is True
    assert cfg.port_mode == "socket"
    assert cfg.mdns_scan is True
    assert cfg.mdns_duration == 8.0
    assert cfg.resolve_hostnames is True
    assert cfg.smb_scan is False
    assert cfg.ssdp_scan is True
    assert cfg.max_concurrent_ping == 64
    assert cfg.max_concurrent_ports == 100
    assert cfg.custom_ports is None


def test_scan_config_accepts_multiple_cidrs() -> None:
    cfg = ScanConfig(cidrs=("192.168.1.0/24", "10.0.0.0/8"))
    assert cfg.cidrs == ("192.168.1.0/24", "10.0.0.0/8")


def test_scan_config_empty_cidrs_raises() -> None:
    with pytest.raises(ValueError):
        ScanConfig(cidrs=())


def test_scan_config_invalid_cidr_raises() -> None:
    with pytest.raises(ValueError, match="Invalid CIDR"):
        ScanConfig(cidrs=("nonsense",))


def test_scan_config_nonpositive_timeout_raises() -> None:
    with pytest.raises(ValueError):
        ScanConfig(cidrs=("192.168.1.0/24",), ping_timeout=0)


def test_scan_config_nonpositive_concurrency_raises() -> None:
    with pytest.raises(ValueError):
        ScanConfig(cidrs=("192.168.1.0/24",), max_concurrent_ping=0)


# ── EnrichedHost / PortInfo / DiscoveredHost / HostClassification ────────────


def test_enriched_host_tuples_stay_tuples() -> None:
    host = EnrichedHost(
        ip="192.168.1.2",
        mac="AA:BB:CC:DD:EE:01",
        ports=(PortInfo(port=22, state="open", service="SSH"),),
        tags=("prod", "core"),
    )
    assert isinstance(host.ports, tuple)
    assert isinstance(host.tags, tuple)
    assert host.ports[0].port == 22
    assert host.os_accuracy == 0
    assert host.scan_method == "socket"
    # IPv6-Anreicherungsfelder (S.4e-Vorbau): Defaults leer, ipv6_all ist tuple.
    assert host.ipv6 == ""
    assert host.ipv6_all == ()
    assert isinstance(host.ipv6_all, tuple)


def test_host_classification_fields() -> None:
    classification = HostClassification(os_guess="Linux Server", category="server")
    assert classification.os_guess == "Linux Server"
    assert classification.category == "server"


def test_models_are_frozen() -> None:
    host = DiscoveredHost(ip="192.168.1.2")
    # Attributname als Variable: vermeidet ruff B010 und den mypy-Frozen-Schreibfehler
    # eines direkten host.ip = ... (frozen wird zur Laufzeit geprueft).
    field_name = "ip"
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(host, field_name, "10.0.0.1")
