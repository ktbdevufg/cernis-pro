"""Tests fuer den ``_FritzHostsWiring``-Verdrahtungs-Wrapper (app.py, S.7c).

Der Wrapper buendelt zwei Verdrahtungs-Entscheidungen an einer Stelle:
* nicht konfiguriert (kein host / kein password) -> ``[]`` OHNE Adapter-Bau
  (kein TR-064-Verbindungsversuch),
* ``FritzAuthError`` des echten Adapters -> ``[]`` + Warn-Log (best-effort, 3C),
  NICHT propagiert.

Der echte ``FritzHostsAdapter`` wird am app-Import-Ort gemockt, damit kein Netz
laeuft. Async-Smokes via ``asyncio.run`` (kein pytest-asyncio).
"""

import asyncio
from typing import Any

import pytest

import app as app_module
from app import _FritzHostsWiring
from domain.scanning import DiscoveredHost
from infrastructure.scanning.fritz_hosts import FritzAuthError


def test_not_configured_returns_empty_without_building_adapter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Kein host -> [] und der echte Adapter wird gar nicht erst gebaut."""
    built: list[Any] = []

    def _spy_adapter(*args: Any, **kwargs: Any) -> Any:
        built.append(kwargs)
        raise AssertionError("FritzHostsAdapter darf bei fehlender Konfig NICHT gebaut werden")

    monkeypatch.setattr(app_module, "FritzHostsAdapter", _spy_adapter)

    wiring = _FritzHostsWiring(host="", user="", password="")
    assert asyncio.run(wiring.get_hosts()) == []
    assert built == []


def test_host_without_password_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    """host gesetzt, aber kein password -> [] (wie Altcode: nur bei host AND pass)."""
    monkeypatch.setattr(
        app_module,
        "FritzHostsAdapter",
        lambda **kwargs: (_ for _ in ()).throw(AssertionError("nicht bauen ohne password")),
    )
    wiring = _FritzHostsWiring(host="fritz.box", user="admin", password="")
    assert asyncio.run(wiring.get_hosts()) == []


def test_configured_delegates_to_adapter(monkeypatch: pytest.MonkeyPatch) -> None:
    """host UND password gesetzt -> echter Adapter wird gebaut + dessen Hosts kommen durch."""
    hosts = [DiscoveredHost(ip="192.168.1.5", mac="AA:BB:CC:00:00:01", source="fritzbox")]

    class _FakeAdapter:
        def __init__(self, **kwargs: Any) -> None:
            self.kwargs = kwargs

        async def get_hosts(self) -> list[DiscoveredHost]:
            return hosts

    monkeypatch.setattr(app_module, "FritzHostsAdapter", _FakeAdapter)

    wiring = _FritzHostsWiring(host="fritz.box", user="admin", password="secret")
    assert asyncio.run(wiring.get_hosts()) == hosts


def test_auth_error_swallowed_to_empty_and_logged(monkeypatch: pytest.MonkeyPatch) -> None:
    """FritzAuthError -> [] (best-effort, NICHT propagiert) UND geloggt (kein S3)."""

    class _RaisingAdapter:
        def __init__(self, **kwargs: Any) -> None: ...

        async def get_hosts(self) -> list[DiscoveredHost]:
            raise FritzAuthError("fritz.box")

    monkeypatch.setattr(app_module, "FritzHostsAdapter", _RaisingAdapter)

    logged: list[tuple[str, dict[str, Any]]] = []
    monkeypatch.setattr(
        app_module.logger,
        "warning",
        lambda event, **kw: logged.append((event, kw)),
    )

    wiring = _FritzHostsWiring(host="fritz.box", user="admin", password="wrong")
    # KEINE Exception -- best-effort.
    assert asyncio.run(wiring.get_hosts()) == []
    # Aber GELOGGT (Pflicht: ein stiller Auth-Fehler waere S3).
    assert logged == [("fritz_auth_failed", {"host": "fritz.box"})]
