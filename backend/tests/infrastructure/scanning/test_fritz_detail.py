"""Tests fuer ``FritzDetailAdapter`` -- gemockte ``modules.fritzbox.FritzBox``.

Die ``FritzBox``-Klasse wird AM IMPORT-ORT IM ADAPTER-MODUL durch ein Fake
ersetzt (nicht in ``modules.fritzbox``), wie bei fritz_hosts. Das Fake bildet den
Konstruktor (host/port/user/password) + die vier read-only-Methoden nach und kann
die drei Faelle simulieren: erreichbar (volle Projektion), nicht erreichbar
(``reachable=False`` -> ``FritzDetail(reachable=False)``), Auth-Fehler
(``FritzAuthorizationError`` aus ``get_status`` durchschlagend).

Schwerpunkte:
* Port-Konformitaet.
* Erreichbar: FritzStatus + Listen -> FritzDetail (Feld fuer Feld projiziert).
* Nicht erreichbar -> FritzDetail(reachable=False), Sub-Objekte leer, Listen
  NICHT abgerufen.
* Auth-Fehler -> FritzAuthError mit host (KEIN stilles Leer, S3-Logik).
* Credentials werden an den Konstruktor durchgereicht.
* SYNCHRONER Aufruf laeuft im Executor (nicht im Loop-Thread).

Async-Smokes via ``asyncio.run`` (kein pytest-asyncio, wie bei fritz_hosts).
"""

import asyncio
import threading
from dataclasses import dataclass
from typing import Any

import pytest

from domain.fritz_detail import FritzDetail
from infrastructure.scanning import fritz_detail
from infrastructure.scanning.fritz_detail import FritzDetailAdapter
from infrastructure.scanning.fritz_hosts import FritzAuthError
from modules.fritzbox import FritzAuthorizationError
from ports.fritz_detail import FritzDetailPort

# ── Fakes: minimaler FritzStatus + v1-Client/Log-Objekte ────────────────────


@dataclass
class _FakeStatus:
    """Minimaler Stand-in fuer ``modules.fritzbox.FritzStatus`` (nur genutzte Felder)."""

    reachable: bool = True
    host: str = "fritz.box"
    auth_error: bool = False
    model: str = "FRITZ!Box 5590 Fiber"
    firmware: str = "8.00"
    is_fiber: bool = True
    total_hosts: int = 7
    wan_connected: bool = True
    wan_uptime_secs: int = 123456
    wan_ip_external: str = "203.0.113.5"
    wan_ip_external_v6: str = "2001:db8::1"
    wan_upstream_kbps: int = 1_000_000
    wan_downstream_kbps: int = 1_000_000
    wan_bytes_sent: int = 999
    wan_bytes_recv: int = 8888
    dsl_sync: bool = True
    dsl_downstream_kbps: int = 0
    dsl_upstream_kbps: int = 0
    dsl_snr_downstream: float = 6.0
    dsl_snr_upstream: float = 7.0
    dsl_attn_downstream: float = 9.0
    dsl_attn_upstream: float = 10.0
    wlan_24_enabled: bool = True
    wlan_24_ssid: str = "CernisNet"
    wlan_24_channel: int = 6
    wlan_24_clients: int = 3
    wlan_5_enabled: bool = True
    wlan_5_ssid: str = "CernisNet-5G"
    wlan_5_channel: int = 36
    wlan_5_clients: int = 5


@dataclass
class _FakeWlanClient:
    mac: str
    ip: str = "192.168.178.30"
    hostname: str = "laptop"
    signal_dbm: int = -55
    speed_mbps: int = 866
    band: str = "5 GHz"


@dataclass
class _FakeLogEntry:
    id: int
    timestamp: str = "15.06.26 10:00:00"
    message: str = "Internetverbindung wurde erfolgreich hergestellt."


def _install_fake_box(
    monkeypatch: pytest.MonkeyPatch,
    *,
    status: Any,
    wlan_clients: list[Any] | None = None,
    log: list[Any] | None = None,
    port_forwardings: list[dict[str, Any]] | None = None,
    auth_on_status: bool = False,
) -> dict[str, Any]:
    """Ersetzt ``FritzBox`` im Adapter durch ein Fake; gibt Konstruktor-Args + Aufrufe frei."""
    seen: dict[str, Any] = {"calls": []}

    class FakeFritzBox:
        def __init__(self, host: str, port: int = 49000, user: str = "", password: str = ""):
            seen["host"] = host
            seen["port"] = port
            seen["user"] = user
            seen["password"] = password

        def get_status(self) -> Any:
            seen["calls"].append("get_status")
            if auth_on_status:
                # _safe_call re-raised FritzAuthorizationError aus DeviceInfo1/GetInfo.
                raise FritzAuthorizationError("falsche Credentials")
            return status

        def get_wlan_clients(self) -> list[Any]:
            seen["calls"].append("get_wlan_clients")
            return wlan_clients or []

        def get_log(self, limit: int = 80) -> list[Any]:
            seen["calls"].append(("get_log", limit))
            return log or []

        def get_port_forwardings(self) -> list[dict[str, Any]]:
            seen["calls"].append("get_port_forwardings")
            return port_forwardings or []

    monkeypatch.setattr(fritz_detail, "FritzBox", FakeFritzBox)
    return seen


# ── Struktureller Vertrag ─────────────────────────────────────────────────


def test_conforms_to_fritz_detail_protocol() -> None:
    _: FritzDetailPort = FritzDetailAdapter("fritz.box")


# ── Erreichbar: volle Projektion ────────────────────────────────────────────


def test_reachable_maps_all_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    clients = [_FakeWlanClient(mac="AA:BB:CC:00:00:01")]
    log = [_FakeLogEntry(id=0), _FakeLogEntry(id=1, message="WLAN-Geraet angemeldet.")]
    forwardings = [
        {
            "enabled": True,
            "description": "HTTPS",
            "protocol": "TCP",
            "external_port": 443,
            "internal_ip": "192.168.178.10",
            "internal_port": 8443,
            "duration": 0,  # v1-Feld -- bewusst verworfen
        }
    ]
    _install_fake_box(
        monkeypatch,
        status=_FakeStatus(),
        wlan_clients=clients,
        log=log,
        port_forwardings=forwardings,
    )

    detail = asyncio.run(FritzDetailAdapter("fritz.box").get_detail())

    assert detail.reachable is True
    assert detail.host == "fritz.box"
    assert detail.auth_error is False
    # Device
    assert detail.device.model == "FRITZ!Box 5590 Fiber"
    assert detail.device.firmware == "8.00"
    assert detail.device.is_fiber is True
    assert detail.device.total_hosts == 7
    # WAN
    assert detail.wan.connected is True
    assert detail.wan.uptime_secs == 123456
    assert detail.wan.ip_external == "203.0.113.5"
    assert detail.wan.ip_external_v6 == "2001:db8::1"
    assert detail.wan.downstream_kbps == 1_000_000
    assert detail.wan.bytes_recv == 8888
    # DSL
    assert detail.dsl.sync is True
    assert detail.dsl.snr_downstream == 6.0
    assert detail.dsl.attn_upstream == 10.0
    # WLAN-Baender
    assert detail.wlan_24.ssid == "CernisNet"
    assert detail.wlan_24.channel == 6
    assert detail.wlan_24.clients == 3
    assert detail.wlan_5.ssid == "CernisNet-5G"
    assert detail.wlan_5.clients == 5
    # WLAN-Clients
    assert len(detail.wlan_clients) == 1
    assert detail.wlan_clients[0].mac == "AA:BB:CC:00:00:01"
    assert detail.wlan_clients[0].signal_dbm == -55
    assert detail.wlan_clients[0].band == "5 GHz"
    # Log
    assert [e.id for e in detail.log] == [0, 1]
    assert detail.log[1].message == "WLAN-Geraet angemeldet."
    # Portfreigaben (duration verworfen)
    assert len(detail.port_forwardings) == 1
    fwd = detail.port_forwardings[0]
    assert fwd.enabled is True
    assert fwd.protocol == "TCP"
    assert fwd.external_port == 443
    assert fwd.internal_ip == "192.168.178.10"
    assert fwd.internal_port == 8443
    assert not hasattr(fwd, "duration")


def test_log_pulled_with_limit_80(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _install_fake_box(monkeypatch, status=_FakeStatus())
    asyncio.run(FritzDetailAdapter("fritz.box").get_detail())
    assert ("get_log", 80) in seen["calls"]


def test_credentials_passed_to_constructor(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _install_fake_box(monkeypatch, status=_FakeStatus())
    asyncio.run(
        FritzDetailAdapter("10.0.0.1", user="admin", password="secret", port=49443).get_detail()
    )
    assert seen["host"] == "10.0.0.1"
    assert seen["port"] == 49443
    assert seen["user"] == "admin"
    assert seen["password"] == "secret"


# ── Nicht erreichbar -> Leer-Zustand (Listen NICHT abgerufen) ───────────────


def test_unreachable_returns_empty_detail(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _install_fake_box(monkeypatch, status=_FakeStatus(reachable=False, host="fritz.box"))
    detail = asyncio.run(FritzDetailAdapter("fritz.box").get_detail())

    assert detail == FritzDetail(reachable=False, host="fritz.box")
    # Bei nicht erreichbar werden Clients/Log/Forwardings NICHT abgerufen.
    assert seen["calls"] == ["get_status"]


def test_unreachable_uses_adapter_host_if_status_host_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_box(monkeypatch, status=_FakeStatus(reachable=False, host=""))
    detail = asyncio.run(FritzDetailAdapter("10.0.0.1").get_detail())
    assert detail.host == "10.0.0.1"


# ── Auth-Fehler -> wirft (KEIN stilles leeres Ergebnis, S3-Logik) ───────────


def test_auth_error_raises_not_silent(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_fake_box(monkeypatch, status=_FakeStatus(), auth_on_status=True)

    with pytest.raises(FritzAuthError) as exc_info:
        asyncio.run(FritzDetailAdapter("fritz.box").get_detail())
    assert exc_info.value.host == "fritz.box"  # diagnostizierbar


# ── Executor-Beweis ──────────────────────────────────────────────────────────


def test_runs_in_executor_not_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    call_thread: dict[str, int] = {}
    status = _FakeStatus()

    class _RecordingBox:
        def __init__(self, *args: Any, **kwargs: Any) -> None: ...

        def get_status(self) -> Any:
            call_thread["tid"] = threading.get_ident()
            return status

        def get_wlan_clients(self) -> list[Any]:
            return []

        def get_log(self, limit: int = 80) -> list[Any]:
            return []

        def get_port_forwardings(self) -> list[dict[str, Any]]:
            return []

    monkeypatch.setattr(fritz_detail, "FritzBox", _RecordingBox)

    async def _run() -> None:
        loop_tid = threading.get_ident()
        await FritzDetailAdapter("fritz.box").get_detail()
        assert call_thread["tid"] != loop_tid  # im Executor, nicht im Loop

    asyncio.run(_run())
