"""End-to-end-Tests des /api/fritz/detail-Endpunkts gegen app.py via TestClient.

Der HTTP-Ebenen-Beweis: der Endpunkt wird in der v2-App
(``app.py:create_app``) ueber ``GetFritzDetail`` bedient. Statt eines echten
TR-064-Adapters wird der Use-Case per ``dependency_overrides`` mit einem Fake
ersetzt (kein Netz). Geprueft:

* erreichbar -> 200 mit vollem Body-Shape (alle Sub-Objekte als verschachtelte
  dicts, tuple -> list),
* nicht erreichbar -> 200 mit ``reachable: false`` (KEIN Fehler),
* Auth-Fehler (``FritzDetailAuthError``) -> 502 mit klarer Meldung,
* ohne Verdrahtungs-Override greift der NotImplementedError-Platzhalter -> 500.

Der Auth-Fehlertyp ist der application-eigene ``FritzDetailAuthError`` -- den
faengt der Router (NICHT die infrastructure-``FritzAuthError``; die uebersetzt der
Composition Root, siehe ``test_detail_wiring_translates_auth_error``). Async-Use-
Cases werden ueber FastAPI normal awaited; das Fake stellt ``__call__`` als
``async`` bereit.
"""

import asyncio
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import app as app_module
from api.fritz import provide_get_fritz_detail
from app import _FritzDetailWiring, create_app
from application.fritz_detail import FritzDetailAuthError
from domain.fritz_detail import (
    FritzDetail,
    FritzDeviceInfo,
    FritzLogEntry,
    FritzPortForwarding,
    FritzWanStatus,
    FritzWlanBand,
    FritzWlanClient,
)
from infrastructure.config import AppConfig
from infrastructure.scanning.fritz_hosts import FritzAuthError


class _FakeGetFritzDetail:
    """Stand-in fuer GetFritzDetail: liefert ein vorgegebenes Detail oder wirft."""

    def __init__(self, detail: FritzDetail | None = None, error: Exception | None = None) -> None:
        self._detail = detail
        self._error = error

    async def __call__(self) -> FritzDetail:
        if self._error is not None:
            raise self._error
        assert self._detail is not None
        return self._detail


def _wired_app(use_case: _FakeGetFritzDetail) -> FastAPI:
    app = create_app(AppConfig())
    app.dependency_overrides[provide_get_fritz_detail] = lambda: use_case
    return app


def _full_detail() -> FritzDetail:
    return FritzDetail(
        reachable=True,
        host="fritz.box",
        device=FritzDeviceInfo(
            model="FRITZ!Box 5590 Fiber", firmware="8.00", is_fiber=True, total_hosts=7
        ),
        wan=FritzWanStatus(connected=True, ip_external="203.0.113.5", downstream_kbps=1_000_000),
        wlan_24=FritzWlanBand(enabled=True, ssid="CernisNet", channel=6, clients=3),
        wlan_5=FritzWlanBand(enabled=True, ssid="CernisNet-5G", channel=36, clients=5),
        wlan_clients=(FritzWlanClient(mac="AA:BB:CC:00:00:01", ip="192.168.178.30", band="5 GHz"),),
        log=(FritzLogEntry(id=0, timestamp="15.06.26 10:00:00", message="hergestellt."),),
        port_forwardings=(
            FritzPortForwarding(
                enabled=True,
                description="HTTPS",
                protocol="TCP",
                external_port=443,
                internal_ip="192.168.178.10",
                internal_port=8443,
            ),
        ),
    )


@pytest.fixture
def reachable_client() -> Iterator[TestClient]:
    with TestClient(_wired_app(_FakeGetFritzDetail(detail=_full_detail()))) as client:
        yield client


def test_reachable_returns_200_full_shape(reachable_client: TestClient) -> None:
    resp = reachable_client.get("/api/fritz/detail")
    assert resp.status_code == 200
    data = resp.json()
    assert data["reachable"] is True
    assert data["host"] == "fritz.box"
    assert data["auth_error"] is False
    assert data["device"] == {
        "model": "FRITZ!Box 5590 Fiber",
        "firmware": "8.00",
        "is_fiber": True,
        "total_hosts": 7,
    }
    assert data["wan"]["ip_external"] == "203.0.113.5"
    assert data["wan"]["downstream_kbps"] == 1_000_000
    assert data["wlan_24"] == {"enabled": True, "ssid": "CernisNet", "channel": 6, "clients": 3}
    assert data["wlan_5"]["ssid"] == "CernisNet-5G"
    # tuple -> list
    assert isinstance(data["wlan_clients"], list)
    assert data["wlan_clients"][0]["mac"] == "AA:BB:CC:00:00:01"
    assert isinstance(data["log"], list)
    assert data["log"][0]["id"] == 0
    assert data["port_forwardings"][0]["external_port"] == 443
    assert data["port_forwardings"][0]["internal_ip"] == "192.168.178.10"
    # duration ist im Wire-Vertrag NICHT enthalten (im Adapter verworfen)
    assert "duration" not in data["port_forwardings"][0]


def test_not_reachable_returns_200_reachable_false() -> None:
    use_case = _FakeGetFritzDetail(detail=FritzDetail(reachable=False, host="fritz.box"))
    with TestClient(_wired_app(use_case)) as client:
        resp = client.get("/api/fritz/detail")
    assert resp.status_code == 200
    data = resp.json()
    assert data["reachable"] is False
    assert data["host"] == "fritz.box"
    # Sub-Objekte sind im Leer-Zustand mit Defaults da (Body bleibt stabil).
    assert data["device"]["model"] == ""
    assert data["wlan_clients"] == []
    assert data["log"] == []
    assert data["port_forwardings"] == []


def test_auth_error_returns_502() -> None:
    use_case = _FakeGetFritzDetail(error=FritzDetailAuthError("fritz.box"))
    with TestClient(_wired_app(use_case)) as client:
        resp = client.get("/api/fritz/detail")
    assert resp.status_code == 502
    assert "Authentifizierung" in resp.json()["detail"]


def test_detail_wiring_translates_auth_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Der Composition-Root-Wrapper uebersetzt infrastructure-FritzAuthError -> application-Typ.

    Damit der api-Ring den Auth-Fehler fangen kann, ohne infrastructure zu
    importieren: ``_FritzDetailWiring`` faengt die Adapter-``FritzAuthError`` und
    wirft den application-eigenen ``FritzDetailAuthError`` (mit host).
    """

    class _RaisingAdapter:
        def __init__(self, **kwargs: Any) -> None: ...

        async def get_detail(self) -> FritzDetail:
            raise FritzAuthError("fritz.box")

    monkeypatch.setattr(app_module, "FritzDetailAdapter", _RaisingAdapter)

    wiring = _FritzDetailWiring(host="fritz.box", user="admin", password="wrong")
    with pytest.raises(FritzDetailAuthError) as exc_info:
        asyncio.run(wiring.get_detail())
    assert exc_info.value.host == "fritz.box"


def test_placeholder_without_override_yields_500() -> None:
    """Ohne den Verdrahtungs-Override greift der NotImplementedError-Platzhalter -> 500.

    create_app SETZT den Override selbst -> hier gezielt entfernen, damit der
    Platzhalter live wird und sein Vertrag (hart fehlschlagen, nicht still falsch)
    geprueft ist (Muster wie test_metrics_api).
    """
    app = create_app(AppConfig())
    del app.dependency_overrides[provide_get_fritz_detail]
    with TestClient(app, raise_server_exceptions=False) as client:
        resp = client.get("/api/fritz/detail")
    assert resp.status_code == 500
