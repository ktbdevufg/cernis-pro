"""Tests des PsutilTrafficAdapter -- reine Mapping-/Helfer-Funktionen + sync-Kern.

Prueft die L4-Zuordnung (SOCK_STREAM->tcp/SOCK_DGRAM->udp/Rest skip), die defensive
PID->Name-Aufloesung (psutil-Fehler -> None, wirft nie), die Endpoint-Abbildung
(leeres raddr -> None) und die status-Normalisierung. ``psutil`` wird gemockt (das
``psutil``-Modul selbst, das der Adapter im selben Namespace nutzt) -- kein echtes
Netz noetig (die Integration gegen echtes psutil deckt der Laufzeit-Smoke ab).
"""

import socket
from typing import Any, NamedTuple

import psutil
import pytest

from infrastructure.traffic_linux import (
    PsutilTrafficAdapter,
    _endpoint,
    _resolve_app_name,
)


class _Addr(NamedTuple):
    ip: str
    port: int


class _SConn(NamedTuple):
    fd: int
    family: int
    type: int
    laddr: object
    raddr: object
    status: str
    pid: int | None


def _sconn(
    type_: int = int(socket.SOCK_STREAM),
    laddr: object = _Addr("10.0.0.1", 1234),
    raddr: object = (),
    status: str = "ESTABLISHED",
    pid: int | None = None,
) -> _SConn:
    return _SConn(
        fd=-1, family=socket.AF_INET, type=type_, laddr=laddr, raddr=raddr, status=status, pid=pid
    )


# ── _endpoint ────────────────────────────────────────────────────────────────


def test_endpoint_maps_addr() -> None:
    ep = _endpoint(_Addr("1.2.3.4", 443))
    assert ep is not None
    assert ep.ip == "1.2.3.4"
    assert ep.port == 443


def test_endpoint_empty_raddr_is_none() -> None:
    # psutil liefert () fuer abwesende raddr (LISTEN/verbindungslos) -> None.
    assert _endpoint(()) is None


# ── _resolve_app_name (defensiv) ─────────────────────────────────────────────


def test_resolve_app_name_returns_name(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeProcess:
        def __init__(self, pid: int) -> None:
            self._pid = pid

        def name(self) -> str:
            return "firefox"

    monkeypatch.setattr(psutil, "Process", FakeProcess)
    assert _resolve_app_name(42) == "firefox"


def test_resolve_app_name_no_such_process_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_no_such(pid: int) -> Any:
        raise psutil.NoSuchProcess(pid)

    monkeypatch.setattr(psutil, "Process", raise_no_such)
    assert _resolve_app_name(42) is None


def test_resolve_app_name_access_denied_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_denied(pid: int) -> Any:
        raise psutil.AccessDenied(pid)

    monkeypatch.setattr(psutil, "Process", raise_denied)
    assert _resolve_app_name(42) is None


# ── L4-Mapping + sync-Kern ───────────────────────────────────────────────────


def test_sync_maps_tcp(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        psutil, "net_connections", lambda kind: [_sconn(type_=int(socket.SOCK_STREAM))]
    )
    conns = PsutilTrafficAdapter()._list_connections_sync()
    assert len(conns) == 1
    assert conns[0].l4 == "tcp"


def test_sync_maps_udp(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        psutil,
        "net_connections",
        lambda kind: [_sconn(type_=int(socket.SOCK_DGRAM), status="NONE")],
    )
    conns = PsutilTrafficAdapter()._list_connections_sync()
    assert len(conns) == 1
    assert conns[0].l4 == "udp"


def test_sync_skips_non_tcp_udp(monkeypatch: pytest.MonkeyPatch) -> None:
    # RAW-Socket (oder anderes) -> uebersprungen, nicht Teil der Per-App-Sicht.
    monkeypatch.setattr(
        psutil, "net_connections", lambda kind: [_sconn(type_=int(socket.SOCK_RAW))]
    )
    assert PsutilTrafficAdapter()._list_connections_sync() == []


def test_sync_normalizes_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(psutil, "net_connections", lambda kind: [_sconn(status="ESTABLISHED")])
    conns = PsutilTrafficAdapter()._list_connections_sync()
    assert conns[0].status == "established"


def test_sync_resolves_app_name_for_pid(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeProcess:
        def __init__(self, pid: int) -> None:
            pass

        def name(self) -> str:
            return "ssh"

    monkeypatch.setattr(psutil, "net_connections", lambda kind: [_sconn(pid=99)])
    monkeypatch.setattr(psutil, "Process", FakeProcess)
    conns = PsutilTrafficAdapter()._list_connections_sync()
    assert conns[0].pid == 99
    assert conns[0].app_name == "ssh"


def test_sync_no_pid_means_no_app_name(monkeypatch: pytest.MonkeyPatch) -> None:
    # rootless: fremde Verbindung ohne PID -> app_name None (None-Gruppe), nicht weg.
    monkeypatch.setattr(psutil, "net_connections", lambda kind: [_sconn(pid=None)])
    conns = PsutilTrafficAdapter()._list_connections_sync()
    assert len(conns) == 1
    assert conns[0].pid is None
    assert conns[0].app_name is None


def test_sync_stage1_fields_are_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(psutil, "net_connections", lambda kind: [_sconn()])
    conn = PsutilTrafficAdapter()._list_connections_sync()[0]
    assert conn.bytes_sent is None
    assert conn.bytes_received is None
    assert conn.send_rate_bps is None
    assert conn.recv_rate_bps is None


def test_sync_remote_endpoint_set_when_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        psutil, "net_connections", lambda kind: [_sconn(raddr=_Addr("8.8.8.8", 53))]
    )
    conn = PsutilTrafficAdapter()._list_connections_sync()[0]
    assert conn.remote is not None
    assert conn.remote.ip == "8.8.8.8"
