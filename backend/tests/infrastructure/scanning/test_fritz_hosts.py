"""Tests fuer ``FritzHostsAdapter`` -- gemockte ``modules.fritzbox.FritzBox``.

Die ``FritzBox``-Klasse wird AM IMPORT-ORT IM ADAPTER-MODUL durch ein Fake
ersetzt (nicht in ``modules.fritzbox``), wie in S.4a-d. Das Fake bildet den
Konstruktor (host/port/user/password) + ``get_hosts`` nach und kann die drei
Faelle simulieren: Erfolg (Roh-dicts), Verbindungsfehler (``[]``), Auth-Fehler
(``FritzAuthorizationError`` aus ``GetHostNumberOfEntries`` durchschlagend).

Schwerpunkte:
* Port-Konformitaet.
* Erfolg: Roh-dicts -> ``DiscoveredHost`` (ip/mac uebernommen, source="fritzbox",
  hostname/active/interface verworfen).
* Verbindungsfehler -> ``[]`` (vertraglicher Leer-Zustand).
* Auth-Fehler -> ``FritzAuthError`` mit host (KEIN stilles ``[]``, S3-Logik).
* Credentials werden an den Konstruktor durchgereicht.
* SYNCHRONER Aufruf laeuft im Executor (nicht im Loop-Thread).

Async-Smokes via ``asyncio.run`` (kein ``pytest-asyncio``, wie S.4a-d).
"""

import asyncio
import threading
from collections.abc import Callable
from typing import Any

import pytest

from domain.scanning import DiscoveredHost
from infrastructure.scanning import fritz_hosts
from infrastructure.scanning.fritz_hosts import FritzAuthError, FritzHostsAdapter
from modules.fritzbox import FritzAuthorizationError
from ports.scanning import FritzHostsPort


def _install_fake_box(
    monkeypatch: pytest.MonkeyPatch, get_hosts_impl: Callable[[], list[dict[str, Any]]]
) -> dict[str, Any]:
    """Ersetzt ``FritzBox`` im Adapter-Modul durch ein Fake; gibt die Konstruktor-Args frei."""
    seen: dict[str, Any] = {}

    class FakeFritzBox:
        def __init__(self, host: str, port: int = 49000, user: str = "", password: str = ""):
            seen["host"] = host
            seen["port"] = port
            seen["user"] = user
            seen["password"] = password

        def get_hosts(self) -> list[dict[str, Any]]:
            return get_hosts_impl()

    monkeypatch.setattr(fritz_hosts, "FritzBox", FakeFritzBox)
    return seen


# ── Struktureller Vertrag ─────────────────────────────────────────────────


def test_conforms_to_fritz_hosts_protocol() -> None:
    _: FritzHostsPort = FritzHostsAdapter("fritz.box")


# ── Erfolg: Mapping ──────────────────────────────────────────────────────────


def test_success_maps_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    def impl() -> list[dict[str, Any]]:
        return [
            {
                "ip": "192.168.178.20",
                "mac": "AA:BB:CC:DD:EE:01",
                "hostname": "laptop",
                "active": True,
                "interface": "WLAN",
            },
            {
                "ip": "192.168.178.21",
                "mac": "AA:BB:CC:DD:EE:02",
                "hostname": "nas",
                "active": False,
                "interface": "LAN",
            },
        ]

    _install_fake_box(monkeypatch, impl)
    result = asyncio.run(FritzHostsAdapter("fritz.box").get_hosts())

    # ip/mac uebernommen, source="fritzbox"; hostname/active/interface verworfen.
    assert result == [
        DiscoveredHost(ip="192.168.178.20", mac="AA:BB:CC:DD:EE:01", source="fritzbox"),
        DiscoveredHost(ip="192.168.178.21", mac="AA:BB:CC:DD:EE:02", source="fritzbox"),
    ]


def test_credentials_passed_to_constructor(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _install_fake_box(monkeypatch, lambda: [])
    asyncio.run(
        FritzHostsAdapter("10.0.0.1", user="admin", password="secret", port=49443).get_hosts()
    )
    assert seen == {"host": "10.0.0.1", "port": 49443, "user": "admin", "password": "secret"}


# ── Verbindungsfehler -> leere Liste (vertraglicher Leer-Zustand) ────────────


def test_unreachable_box_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    # ``get_hosts`` faengt Verbindungsfehler im Altcode selbst ab -> ``[]``.
    _install_fake_box(monkeypatch, lambda: [])
    assert asyncio.run(FritzHostsAdapter("fritz.box").get_hosts()) == []


# ── Auth-Fehler -> wirft (KEIN stilles leeres Ergebnis, S3-Logik) ───────────


def test_auth_error_raises_not_silent(monkeypatch: pytest.MonkeyPatch) -> None:
    def impl() -> list[dict[str, Any]]:
        # ``_safe_call`` re-raised FritzAuthorizationError aus GetHostNumberOfEntries.
        raise FritzAuthorizationError("falsche Credentials")

    _install_fake_box(monkeypatch, impl)

    with pytest.raises(FritzAuthError) as exc_info:
        asyncio.run(FritzHostsAdapter("fritz.box").get_hosts())
    assert exc_info.value.host == "fritz.box"  # diagnostizierbar


# ── Executor-Beweis ──────────────────────────────────────────────────────────


def test_runs_in_executor_not_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    call_thread: dict[str, int] = {}

    def impl() -> list[dict[str, Any]]:
        call_thread["tid"] = threading.get_ident()
        return []

    _install_fake_box(monkeypatch, impl)

    async def _run() -> None:
        loop_tid = threading.get_ident()
        await FritzHostsAdapter("fritz.box").get_hosts()
        assert call_thread["tid"] != loop_tid  # im Executor, nicht im Loop

    asyncio.run(_run())
