"""Tests fuer ``GetFritzDetail`` -- mit Fake-Port (kein echter TR-064-Adapter).

Der Use-Case ist reine Delegation an den Port; die Tests belegen:
* erreichbarer Schnappschuss wird unveraendert durchgereicht,
* der Leer-Zustand (``reachable=False``) ist KEIN Fehler, kommt durch,
* eine Adapter-Exception (Auth-Fehler) wird NICHT gefangen -- der Use-Case faengt
  bewusst nichts (das HTTP-Mapping passiert im api-Ring).

Async-Smokes via ``asyncio.run`` (kein pytest-asyncio, projektweit so gehalten).
"""

import asyncio

import pytest

from application.fritz_detail import GetFritzDetail
from domain.fritz_detail import FritzDetail, FritzDeviceInfo


class _FakePort:
    """Erfuellt ``FritzDetailPort`` strukturell; liefert ein vorgegebenes Detail."""

    def __init__(self, detail: FritzDetail) -> None:
        self._detail = detail

    async def get_detail(self) -> FritzDetail:
        return self._detail


class _RaisingPort:
    """Port, der einen Adapter-Fehler wirft (simuliert FritzAuthError-Durchschlag)."""

    async def get_detail(self) -> FritzDetail:
        raise RuntimeError("auth failed")


def test_delegates_reachable_detail() -> None:
    detail = FritzDetail(
        reachable=True,
        host="fritz.box",
        device=FritzDeviceInfo(model="FRITZ!Box 5590 Fiber", is_fiber=True),
    )
    use_case = GetFritzDetail(_FakePort(detail))
    assert asyncio.run(use_case()) is detail


def test_empty_state_is_not_an_error() -> None:
    detail = FritzDetail(reachable=False, host="fritz.box")
    use_case = GetFritzDetail(_FakePort(detail))
    result = asyncio.run(use_case())
    assert result.reachable is False
    assert result.host == "fritz.box"


def test_adapter_error_propagates_uncaught() -> None:
    use_case = GetFritzDetail(_RaisingPort())
    with pytest.raises(RuntimeError):
        asyncio.run(use_case())
