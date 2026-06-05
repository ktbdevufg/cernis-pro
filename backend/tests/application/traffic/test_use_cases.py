"""Tests der traffic-Use-Cases gegen In-Memory-Fakes der Ports.

Kein echtes psutil/sock_diag-Tooling noetig -- wir testen gegen die Protocols. Kern
der Behauptungen: ``ListAppTraffic`` delegiert die Buendelung an die Domaene
(``aggregate_by_app``), ``CheckTrafficPermission`` liefert die ``{ok, error}``-Naht
(verfuegbar/Recht/kein Recht), und ``MeasureThroughput`` rechnet zustandsfrei die
Raten aus zwei uebergebenen Messpunkten. Async via ``asyncio.run`` (Projektmuster,
kein pytest-asyncio).
"""

import asyncio

from application.traffic import (
    CheckTrafficPermission,
    ListAppTraffic,
    MeasureThroughput,
)
from domain.traffic import Connection, ConnSample, Endpoint

# ── In-Memory-Fakes der Ports ────────────────────────────────────────────────


class FakePerProcessTrafficProvider:
    """In-Memory-Implementierung des ``PerProcessTrafficProvider``-Protocols."""

    def __init__(
        self,
        connections: list[Connection] | None = None,
        samples: list[ConnSample] | None = None,
    ) -> None:
        self._connections = connections or []
        self._samples = samples or []
        self.list_connections_calls = 0
        self.sample_throughput_calls = 0

    async def list_connections(self) -> list[Connection]:
        self.list_connections_calls += 1
        return list(self._connections)

    async def sample_throughput(self) -> list[ConnSample]:
        self.sample_throughput_calls += 1
        return list(self._samples)


class FakeTrafficPermission:
    """In-Memory-Implementierung des ``TrafficPermissionPort``-Protocols."""

    def __init__(self, available: bool = True, permission_error: str | None = None) -> None:
        self._available = available
        self._permission_error = permission_error

    def is_available(self) -> bool:
        return self._available

    def check_permission(self) -> str | None:
        return self._permission_error


def _conn(app_name: str | None, pid: int | None = None, port: int = 443) -> Connection:
    return Connection(
        l4="tcp",
        status="established",
        local=Endpoint(ip="10.0.0.1", port=port),
        remote=Endpoint(ip="1.1.1.1", port=443),
        pid=pid,
        app_name=app_name,
    )


# ── ListAppTraffic ───────────────────────────────────────────────────────────


def test_list_app_traffic_groups_by_app() -> None:
    fake = FakePerProcessTrafficProvider(
        connections=[
            _conn("firefox", pid=10),
            _conn("firefox", pid=10, port=8443),
            _conn("ssh", pid=20),
            _conn(None),  # rootless nicht zuordenbar -> None-Gruppe
        ]
    )
    result = asyncio.run(ListAppTraffic(fake)())

    by_name = {a.app_name: a for a in result}
    assert set(by_name) == {"firefox", "ssh", None}
    assert by_name["firefox"].connection_count == 2
    assert by_name["ssh"].connection_count == 1
    # ehrliche None-Gruppe (rootless), nicht verworfen
    assert by_name[None].connection_count == 1
    # deterministische Sortierung: None ans Ende
    assert [a.app_name for a in result] == ["firefox", "ssh", None]


def test_list_app_traffic_empty() -> None:
    fake = FakePerProcessTrafficProvider(connections=[])
    result = asyncio.run(ListAppTraffic(fake)())
    assert result == []


def test_list_app_traffic_provider_called_once() -> None:
    fake = FakePerProcessTrafficProvider(connections=[_conn("app", pid=1)])
    asyncio.run(ListAppTraffic(fake)())
    assert fake.list_connections_calls == 1


# ── CheckTrafficPermission ───────────────────────────────────────────────────


def test_check_permission_available_and_allowed() -> None:
    fake = FakeTrafficPermission(available=True, permission_error=None)
    result = CheckTrafficPermission(fake)()
    assert result == {"ok": True, "error": ""}


def test_check_permission_available_but_denied() -> None:
    msg = "Fuer den Durchsatz aller Apps muss CERNIS PRO als Root gestartet werden."
    fake = FakeTrafficPermission(available=True, permission_error=msg)
    result = CheckTrafficPermission(fake)()
    assert result == {"ok": False, "error": msg}


def test_check_permission_not_available() -> None:
    fake = FakeTrafficPermission(available=False)
    result = CheckTrafficPermission(fake)()
    assert result["ok"] is False
    assert result["error"]  # nicht-leerer Grund


def test_check_permission_pass_throughs() -> None:
    fake = FakeTrafficPermission(available=True, permission_error="x")
    uc = CheckTrafficPermission(fake)
    assert uc.is_available() is True
    assert uc.check_permission() == "x"


# ── MeasureThroughput (zustandsfrei, kein Port) ──────────────────────────────


def _sample(key: str, sent: int, recv: int, ts: float) -> ConnSample:
    return ConnSample(key=key, bytes_sent=sent, bytes_received=recv, monotonic_ts=ts)


def test_measure_throughput_computes_rates_per_key() -> None:
    prev = [_sample("a", 1000, 2000, 10.0), _sample("b", 0, 0, 10.0)]
    curr = [_sample("a", 3000, 2500, 12.0), _sample("b", 200, 100, 12.0)]
    result = MeasureThroughput()(prev, curr)
    # a: sent (3000-1000)/2=1000, recv (2500-2000)/2=250
    assert result["a"] == (1000.0, 250.0)
    # b: sent 200/2=100, recv 100/2=50
    assert result["b"] == (100.0, 50.0)


def test_measure_throughput_only_paired_keys() -> None:
    prev = [_sample("shared", 0, 0, 10.0), _sample("gone", 0, 0, 10.0)]
    curr = [_sample("shared", 200, 0, 12.0), _sample("new", 999, 0, 12.0)]
    result = MeasureThroughput()(prev, curr)
    # nur 'shared' ist in beiden Messpunkten -> nur dieser key
    assert set(result) == {"shared"}
    assert result["shared"] == (100.0, 0.0)


def test_measure_throughput_empty() -> None:
    assert MeasureThroughput()([], []) == {}
    assert MeasureThroughput()([_sample("a", 0, 0, 1.0)], []) == {}
    assert MeasureThroughput()([], [_sample("a", 0, 0, 1.0)]) == {}
