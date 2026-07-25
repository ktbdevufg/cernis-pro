"""Tests des PsutilTrafficAdapter -- reine Mapping-/Helfer-Funktionen + sync-Kern.

Prueft die L4-Zuordnung (SOCK_STREAM->tcp/SOCK_DGRAM->udp/Rest skip), die defensive
PID->Name-Aufloesung (psutil-Fehler -> None, wirft nie), die Endpoint-Abbildung
(leeres raddr -> None) und die status-Normalisierung. ``psutil`` wird gemockt (das
``psutil``-Modul selbst, das der Adapter im selben Namespace nutzt) -- kein echtes
Netz noetig (die Integration gegen echtes psutil deckt der Laufzeit-Smoke ab).
"""

import socket
import subprocess
from dataclasses import dataclass
from typing import Any, NamedTuple

import psutil
import pytest

from infrastructure.traffic_linux import (
    PsutilTrafficAdapter,
    ThroughputUnavailableError,
    _endpoint,
    _resolve_app_name,
    _run,
)


@dataclass
class _CompletedStub:
    """Minimaler Ersatz fuer ``subprocess.CompletedProcess`` (nur was ``_run`` liest)."""

    returncode: int
    stdout: str
    stderr: str


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


# ── Stufe 2: Scheitern ist ein Fehler, keine stille Null (S3) ────────────────
# Frueher schluckte ``_run`` JEDEN Fehler und lieferte "" -> [] . Damit sah ein
# fehlendes Werkzeug exakt so aus wie "null Bytes uebertragen". Diese Tests
# halten fest, dass der Fehlschlag benannt wird -- und dass eine echte Leermessung
# weiterhin ehrlich [] bleibt.


def test_run_wirft_wenn_werkzeug_fehlt(monkeypatch: pytest.MonkeyPatch) -> None:
    def fehlt(*_a: Any, **_k: Any) -> Any:
        raise FileNotFoundError(2, "No such file or directory", "ss")

    monkeypatch.setattr(subprocess, "run", fehlt)

    with pytest.raises(ThroughputUnavailableError) as exc:
        _run(["ss", "-tin"])
    assert "ss" in str(exc.value)


def test_run_wirft_bei_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def zu_langsam(*_a: Any, **_k: Any) -> Any:
        raise subprocess.TimeoutExpired(cmd="ss", timeout=5)

    monkeypatch.setattr(subprocess, "run", zu_langsam)

    with pytest.raises(ThroughputUnavailableError):
        _run(["ss", "-tin"])


def test_run_wirft_bei_fehlerstatus(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_a, **_k: _CompletedStub(returncode=2, stdout="", stderr="unbekannte Option"),
    )

    with pytest.raises(ThroughputUnavailableError) as exc:
        _run(["ss", "-tin"])
    assert "unbekannte Option" in str(exc.value)


def test_run_leeres_stdout_bei_erfolg_ist_kein_fehler(monkeypatch: pytest.MonkeyPatch) -> None:
    # Keine TCP-Sockets ist eine ECHTE Messung mit leerem Ergebnis, kein Fehlschlag.
    monkeypatch.setattr(
        subprocess, "run", lambda *_a, **_k: _CompletedStub(returncode=0, stdout="", stderr="")
    )

    assert _run(["ss", "-tin"]) == ""


def test_sample_throughput_sync_reicht_fehler_durch(monkeypatch: pytest.MonkeyPatch) -> None:
    # Der Fehler darf im Adapter nicht wieder zur leeren Liste eingeebnet werden.
    def fehlt(*_a: Any, **_k: Any) -> Any:
        raise FileNotFoundError(2, "No such file or directory", "ss")

    monkeypatch.setattr(subprocess, "run", fehlt)

    with pytest.raises(ThroughputUnavailableError):
        PsutilTrafficAdapter()._sample_throughput_sync()


def test_sample_throughput_sync_leer_ohne_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        subprocess, "run", lambda *_a, **_k: _CompletedStub(returncode=0, stdout="", stderr="")
    )

    assert PsutilTrafficAdapter()._sample_throughput_sync() == []


def test_sample_throughput_sync_liest_zaehler(monkeypatch: pytest.MonkeyPatch) -> None:
    # Echte ss -tin-Form: Socket-Zeile ohne Einzug, Detailzeile mit Einzug.
    ausgabe = (
        "State Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
        "ESTAB 0      0      10.0.0.5:51752     93.184.216.34:443\n"
        "\t cubic wscale:13,10 bytes_sent:239888 bytes_acked:237178 bytes_received:39089\n"
    )
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_a, **_k: _CompletedStub(returncode=0, stdout=ausgabe, stderr=""),
    )

    samples = PsutilTrafficAdapter()._sample_throughput_sync()

    assert len(samples) == 1
    assert samples[0].bytes_sent == 239888
    assert samples[0].bytes_received == 39089
