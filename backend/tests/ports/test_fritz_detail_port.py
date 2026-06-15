"""Strukturtest des ``FritzDetailPort`` (analog test_scanning_ports.py).

Reine ``typing.Protocol``-Vertraege haben kein Verhalten -- der Verhaltenstest
kommt mit dem Adapter (test_fritz_detail.py). Hier nur die strukturelle
Konformitaet:

* **statisch (mypy):** ``_assert_fritz_detail`` nimmt den Port-TYP und bekommt das
  Fake uebergeben -- erfuellt das Fake das Protocol nicht, schlaegt mypy fehl.
* **dynamisch (pytest):** ein Smoke ruft ``get_detail`` einmal auf und prueft,
  dass ein ``FritzDetail`` herauskommt.

Async-Smoke via ``asyncio.run`` (stdlib), bewusst kein pytest-asyncio (Muster wie
test_scanning_ports.py).
"""

import asyncio

from domain.fritz_detail import FritzDetail
from ports.fritz_detail import FritzDetailPort


class _FakeFritzDetail:
    async def get_detail(self) -> FritzDetail:
        return FritzDetail(reachable=False, host="fritz.box")


def _assert_fritz_detail(_: FritzDetailPort) -> None: ...


def test_fake_satisfies_port_statically() -> None:
    """mypy-Beweis: das Fake genuegt dem Port (Konformitaet rein statisch)."""
    _assert_fritz_detail(_FakeFritzDetail())


def test_get_detail_returns_domain_type() -> None:
    port: FritzDetailPort = _FakeFritzDetail()
    result = asyncio.run(port.get_detail())
    assert isinstance(result, FritzDetail)
    assert result.reachable is False
