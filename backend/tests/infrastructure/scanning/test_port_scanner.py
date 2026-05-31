"""Tests fuer ``PortScannerAdapter`` -- gemockte ``modules.portscan``.

``scan_ports_socket`` (async) und ``scan_with_nmap`` (sync) werden AM IMPORT-ORT
IM ADAPTER-MODUL gemockt (nicht in ``modules.portscan``), wie in S.4a/S.4b. Die
Mocks liefern ROHDATEN (``HostPortScan`` mit ``PortResult``), der Test prueft das
verlustfreie Mapping auf ``PortInfo``.

Schwerpunkte:
* Port-Konformitaet.
* socket-Modus: async-Smoke via ``asyncio.run``, Argumente durchgereicht,
  Mapping (Port-Nummer, state, service), leere Liste = keine offenen Ports.
* nmap-Modus: SYNCHRONER Aufruf laeuft im Executor (nicht im Loop-Thread),
  Port-Spec aus ints gebaut, Mapping verlustfrei.
* Der KERN des S3-Fixes: nmap-Fehler-Sentinel -> ``NmapScanError`` (je Sentinel),
  ABER Erfolgsfall mit 0 Ports -> leere Liste, KEINE Exception.

Async-Smokes via ``asyncio.run`` (kein ``pytest-asyncio``, wie S.3/S.4a/S.4b).
"""

import asyncio
import threading
from dataclasses import dataclass, field

import pytest

from domain.scanning import PortInfo
from infrastructure.scanning import port_scanner
from infrastructure.scanning.port_scanner import NmapScanError, PortScannerAdapter
from ports.scanning import PortScannerPort


# Leichte Fakes der ``modules``-Rohtypen -- genau die vom Adapter gelesenen Felder.
@dataclass
class FakePortResult:
    port: int
    state: str
    service: str = ""
    banner: str = ""


@dataclass
class FakeHostPortScan:
    ip: str
    ports: list[FakePortResult] = field(default_factory=list)
    scan_method: str = "socket"
    os_guess: str = ""
    os_accuracy: int = 0


# ── Struktureller Vertrag ─────────────────────────────────────────────────


def test_conforms_to_port_scanner_protocol() -> None:
    _: PortScannerPort = PortScannerAdapter()


# ── socket-Modus ─────────────────────────────────────────────────────────────


def test_socket_maps_open_ports(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    async def fake_socket(ip, ports, max_concurrent, timeout):  # type: ignore[no-untyped-def]
        seen["ip"] = ip
        seen["ports"] = list(ports)
        seen["max_concurrent"] = max_concurrent
        seen["timeout"] = timeout
        return FakeHostPortScan(
            ip=ip,
            ports=[
                FakePortResult(port=22, state="open", service="SSH"),
                FakePortResult(port=443, state="open", service="HTTPS"),
            ],
            scan_method="socket",
        )

    monkeypatch.setattr(port_scanner, "scan_ports_socket", fake_socket)
    result = asyncio.run(
        PortScannerAdapter().scan("10.0.0.2", [22, 443], "socket", timeout=0.5, max_concurrent=50)
    )

    assert result == [
        PortInfo(port=22, state="open", service="SSH"),
        PortInfo(port=443, state="open", service="HTTPS"),
    ]
    # Argumente verlustfrei durchgereicht.
    assert seen == {
        "ip": "10.0.0.2",
        "ports": [22, 443],
        "max_concurrent": 50,
        "timeout": 0.5,
    }


def test_socket_no_open_ports_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_socket(ip, ports, max_concurrent, timeout):  # type: ignore[no-untyped-def]
        return FakeHostPortScan(ip=ip, ports=[], scan_method="socket")

    monkeypatch.setattr(port_scanner, "scan_ports_socket", fake_socket)
    result = asyncio.run(
        PortScannerAdapter().scan("10.0.0.2", [22], "socket", timeout=0.5, max_concurrent=10)
    )
    assert result == []  # leere Liste = keine offenen Ports, kein Fehler


def test_default_mode_uses_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    # Jeder Nicht-"nmap"-mode geht in den socket-Pfad.
    async def fake_socket(ip, ports, max_concurrent, timeout):  # type: ignore[no-untyped-def]
        return FakeHostPortScan(ip=ip, ports=[FakePortResult(80, "open", "HTTP")])

    monkeypatch.setattr(port_scanner, "scan_ports_socket", fake_socket)
    result = asyncio.run(
        PortScannerAdapter().scan("10.0.0.2", [80], "socket", timeout=1.0, max_concurrent=8)
    )
    assert result == [PortInfo(port=80, state="open", service="HTTP")]


# ── nmap-Modus: Executor + Mapping ──────────────────────────────────────────


def test_nmap_runs_in_executor_not_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    # Beweis: der blockierende nmap-Aufruf laeuft NICHT im Loop-Thread.
    call_thread: dict[str, int] = {}

    def fake_nmap(ip, port_spec):  # type: ignore[no-untyped-def]
        call_thread["tid"] = threading.get_ident()
        return FakeHostPortScan(
            ip=ip, ports=[FakePortResult(22, "open", "ssh OpenSSH")], scan_method="nmap"
        )

    monkeypatch.setattr(port_scanner, "scan_with_nmap", fake_nmap)

    async def _run() -> list[PortInfo]:
        loop_tid = threading.get_ident()
        result = await PortScannerAdapter().scan(
            "10.0.0.2", [22], "nmap", timeout=1.0, max_concurrent=1
        )
        assert call_thread["tid"] != loop_tid  # im Executor, nicht im Loop
        return result

    assert asyncio.run(_run()) == [PortInfo(port=22, state="open", service="ssh OpenSSH")]


def test_nmap_port_spec_built_from_ints(monkeypatch: pytest.MonkeyPatch) -> None:
    # Port-Spec wird aus den int-Ports gebaut (injektionsfrei), Default-Spec NICHT durchgereicht.
    seen: dict[str, object] = {}

    def fake_nmap(ip, port_spec):  # type: ignore[no-untyped-def]
        seen["ip"] = ip
        seen["port_spec"] = port_spec
        return FakeHostPortScan(ip=ip, ports=[], scan_method="nmap")

    monkeypatch.setattr(port_scanner, "scan_with_nmap", fake_nmap)
    asyncio.run(
        PortScannerAdapter().scan("10.0.0.2", [22, 80, 443], "nmap", timeout=1.0, max_concurrent=1)
    )
    assert seen == {"ip": "10.0.0.2", "port_spec": "22,80,443"}


def test_nmap_zero_ports_success_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    # ERFOLG mit 0 offenen Ports (scan_method == "nmap") -> leere Liste, KEINE Exception.
    def fake_nmap(ip, port_spec):  # type: ignore[no-untyped-def]
        return FakeHostPortScan(ip=ip, ports=[], scan_method="nmap")

    monkeypatch.setattr(port_scanner, "scan_with_nmap", fake_nmap)
    result = asyncio.run(
        PortScannerAdapter().scan("10.0.0.2", [22], "nmap", timeout=1.0, max_concurrent=1)
    )
    assert result == []


# ── nmap-Modus: S3-Fix -- Fehler-Sentinel werfen statt still leer ────────────


@pytest.mark.parametrize("sentinel", ["nmap_not_found", "nmap_timeout", "nmap_error"])
def test_nmap_error_sentinel_raises(monkeypatch: pytest.MonkeyPatch, sentinel: str) -> None:
    # Jeder Fehler-Sentinel -> NmapScanError (v2: kein stiller leerer Rueckfall).
    def fake_nmap(ip, port_spec):  # type: ignore[no-untyped-def]
        return FakeHostPortScan(ip=ip, ports=[], scan_method=sentinel)

    monkeypatch.setattr(port_scanner, "scan_with_nmap", fake_nmap)

    with pytest.raises(NmapScanError) as exc_info:
        asyncio.run(
            PortScannerAdapter().scan("10.0.0.7", [22], "nmap", timeout=1.0, max_concurrent=1)
        )
    # Fehler ist diagnostizierbar: traegt ip + Sentinel.
    assert exc_info.value.ip == "10.0.0.7"
    assert exc_info.value.scan_method == sentinel
