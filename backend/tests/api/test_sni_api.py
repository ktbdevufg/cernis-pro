"""End-to-end-Tests der sni-REST-API (ADR 0017) gegen den sni_router.

Frische ``FastAPI`` mit nur dem ``sni_router``; die ``provide_*`` werden per
``dependency_overrides`` mit Fakes/echten-Use-Cases-auf-Fake-Port verdrahtet (kein
scapy, kein Raw-Socket). Belegt die Wire-Shapes: start ok -> 200, start ohne Rechte
-> 403, stop idempotent, status-Form, observed-Wire-Form.
"""

from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from api.sni import (
    provide_get_observed_sni,
    provide_sni_running,
    provide_start_sni,
    provide_start_sni_uc,
    provide_stop_sni,
)
from api.sni import router as sni_router
from application.sni import GetObservedSni, StartSniCapture
from domain.sni import ObservedSni
from infrastructure.sni.errors import SniError, SniPermissionError


class _FakeSniSniffer:
    """SniSnifferPort-Fake: available/permission/observed + running-Schalter."""

    def __init__(
        self,
        *,
        available: bool = True,
        permission: str | None = None,
        observed: list[ObservedSni] | None = None,
        running: bool = False,
    ) -> None:
        self._available = available
        self._permission = permission
        self._observed = observed or []
        self._running = running
        self.start_interfaces: list[str | None] = []

    def start(self, interface: str | None) -> None:
        self.start_interfaces.append(interface)
        self._running = True

    def stop(self) -> None:
        self._running = False

    def is_running(self) -> bool:
        return self._running

    def observed(self) -> list[ObservedSni]:
        return list(self._observed)

    def check_permission(self) -> str | None:
        return self._permission

    def is_available(self) -> bool:
        return self._available


def _build_client(fake: _FakeSniSniffer) -> TestClient:
    app = FastAPI()
    app.include_router(sni_router)

    # Der start-Runner ahmt _start_sni nach: StartSniCapture-Pruefung, bei ok start().
    def _start_runner(interface: str | None) -> dict[str, Any]:
        result = StartSniCapture(fake)()
        if result["ok"]:
            fake.start(interface)
        return result

    app.dependency_overrides[provide_start_sni] = lambda: _start_runner
    app.dependency_overrides[provide_stop_sni] = lambda: fake.stop
    app.dependency_overrides[provide_start_sni_uc] = lambda: StartSniCapture(fake)
    app.dependency_overrides[provide_sni_running] = lambda: fake.is_running
    app.dependency_overrides[provide_get_observed_sni] = lambda: GetObservedSni(fake)
    return TestClient(app)


# ── start ──────────────────────────────────────────────────────────────────────


def test_sni_start_ok() -> None:
    client = _build_client(_FakeSniSniffer(available=True, permission=None))
    resp = client.post("/api/sni/start", json={})
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "error": "", "available": True}


def test_sni_start_without_body() -> None:
    # curl ganz OHNE Body (kein content, kein json) -> 200, interface -> None
    # (der Adapter waehlt das Interface selbst). Muster pcap/start: Body optional.
    fake = _FakeSniSniffer(available=True, permission=None)
    resp = _build_client(fake).post("/api/sni/start")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "error": "", "available": True}
    assert fake.start_interfaces == [None]


def test_sni_start_forwards_interface() -> None:
    fake = _FakeSniSniffer(available=True, permission=None)
    resp = _build_client(fake).post("/api/sni/start", json={"interface": "ens33"})
    assert resp.status_code == 200
    assert fake.start_interfaces == ["ens33"]


def test_sni_start_without_permission_403() -> None:
    client = _build_client(_FakeSniSniffer(available=True, permission="needs root or CAP_NET_RAW"))
    resp = client.post("/api/sni/start", json={})
    assert resp.status_code == 403
    body = resp.json()
    assert body["ok"] is False
    assert body["error"] == "needs root or CAP_NET_RAW"
    # 403-Body bleibt UNVERAENDERT -- kein available-Key (Muster pcap/start).
    assert "available" not in body


def test_sni_start_not_available_403() -> None:
    client = _build_client(_FakeSniSniffer(available=False))
    resp = client.post("/api/sni/start", json={})
    assert resp.status_code == 403
    assert resp.json()["ok"] is False


# ── Exception-Handler-Naht (app.py): SniPermissionError -> 403, SniError -> 503 ──
# Die {ok,error}-Vorab-Naht oben greift mit dem Privilege-Separation-Helfer nicht
# mehr; der ECHTE Rechte-Fehler kommt erst aus start() heraus. Diese App bildet die
# beiden Handler aus app.py nach (SniPermissionError-Handler VOR dem generischen
# SniError-Handler registriert) und belegt das richtige HTTP-Mapping.


def _build_handler_client() -> TestClient:
    app = FastAPI()

    @app.exception_handler(SniPermissionError)
    async def _on_perm(_request: Request, exc: SniPermissionError) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.exception_handler(SniError)
    async def _on_sni(_request: Request, exc: SniError) -> JSONResponse:
        return JSONResponse(status_code=503, content={"detail": str(exc)})

    @app.post("/raise")
    def _raise(kind: str) -> None:
        if kind == "permission":
            raise SniPermissionError(
                "Permission denied -- SNI capture requires root or CAP_NET_RAW."
            )
        raise SniError("helper spawn failed -- device gone")

    return TestClient(app, raise_server_exceptions=False)


def test_sni_permission_error_maps_to_403() -> None:
    resp = _build_handler_client().post("/raise", params={"kind": "permission"})
    assert resp.status_code == 403
    assert "CAP_NET_RAW" in resp.json()["detail"]


def test_sni_generic_error_maps_to_503() -> None:
    resp = _build_handler_client().post("/raise", params={"kind": "other"})
    assert resp.status_code == 503


# ── stop (idempotent) ────────────────────────────────────────────────────────────


def test_sni_stop_idempotent() -> None:
    client = _build_client(_FakeSniSniffer(running=True))
    assert client.post("/api/sni/stop").json() == {"ok": True}
    # auch ohne laufenden Sniff -> {ok: True}
    assert client.post("/api/sni/stop").json() == {"ok": True}


# ── status ───────────────────────────────────────────────────────────────────────


def test_sni_status_shape() -> None:
    obs = [ObservedSni(hostname="a.io", remote_ip="1.2.3.4", remote_port=443, monotonic_ts=1.0)]
    client = _build_client(
        _FakeSniSniffer(available=True, permission="needs root", observed=obs, running=True)
    )
    body = client.get("/api/sni/status").json()
    assert body == {
        "running": True,
        "count": 1,
        "available": True,
        "permission_error": "needs root",
    }


def test_sni_status_permission_null_when_ok() -> None:
    client = _build_client(_FakeSniSniffer(available=True, permission=None))
    body = client.get("/api/sni/status").json()
    assert body["permission_error"] is None
    assert body["running"] is False
    assert body["count"] == 0


# ── observed (Wire-Form) ──────────────────────────────────────────────────────────


def test_sni_observed_wire_form() -> None:
    obs = [
        ObservedSni(
            hostname="example.com",
            remote_ip="93.184.216.34",
            remote_port=443,
            monotonic_ts=1.0,
            app_name="firefox",
            pid=42,
            delta_ms=80,
        ),
        ObservedSni(
            hostname="cdn.example.net",
            remote_ip="1.1.1.1",
            remote_port=443,
            monotonic_ts=2.0,
        ),
    ]
    client = _build_client(_FakeSniSniffer(observed=obs))
    rows = client.get("/api/sni/observed").json()
    assert len(rows) == 2
    first = rows[0]
    assert first["hostname"] == "example.com"
    assert first["remote_ip"] == "93.184.216.34"
    assert first["remote_port"] == 443
    assert first["app_name"] == "firefox"
    assert first["pid"] == 42
    assert first["delta_ms"] == 80
    assert "age_secs" in first
    assert isinstance(first["age_secs"], int)
    assert first["age_secs"] >= 0
    # monotonic_ts ist prozesslokal -> NICHT auf der Wire.
    assert "monotonic_ts" not in first
    # nicht zugeordneter Hit: app_name/pid/delta_ms null (ehrliche Luecke).
    second = rows[1]
    assert second["app_name"] is None
    assert second["pid"] is None
    assert second["delta_ms"] is None
