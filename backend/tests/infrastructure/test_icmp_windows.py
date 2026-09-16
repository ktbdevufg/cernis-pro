"""Tests fuer den nativen Windows-ICMP-Echo-Adapter (iphlpapi via ctypes).

Getestet wird die PLATTFORMUNABHAENGIGE Ablauflogik aus ``infrastructure.icmp_windows``
OHNE echte Windows-API und OHNE echtes Netz -- die ctypes-Schicht ist ueber Callables
gekapselt und wird hier gemockt. Alles laeuft deterministisch auch auf dem Linux-CI-Runner:

* ``_reply_to_result``: ``Status == 0`` (IP_SUCCESS) -> ``(True, rtt)``; jeder andere Status
  -> ``(False, -1.0)`` (RoundTripTime wird dann nicht als Messwert gewertet).
* ``_resolve_ipv4``: gescheiterte Namensaufloesung (``getaddrinfo`` wirft) -> ``None``.
* ``_perform_echo``: Erfolgsfall; Fehlerstatus -> Sentinel; Handle wird IMMER geschlossen
  (auch bei Fehlerstatus UND bei Exception im Sende-/Lese-Schritt); keine Antwort ->
  Sentinel; ungueltiges Handle -> Sentinel OHNE Schliessen.
* ``icmp_echo`` (async): gescheiterte Aufloesung -> ``(False, -1.0)``; Erfolg via gemocktem
  nativen Kern; Exception im Thread -> ``(False, -1.0)``. Async-Smokes via ``asyncio.run``
  (kein pytest-asyncio, Projektmuster).

Der echte ctypes-/iphlpapi-Kern (``_send_echo_native`` unter win32) braucht die Windows-API
und wird auf Linux gar nicht ausgefuehrt -- die Logik sitzt im herausgezogenen reinen
``_perform_echo``-Kern.
"""

import asyncio
import socket
import sys

import pytest

from infrastructure import icmp_windows
from infrastructure.icmp_windows import (
    _perform_echo,
    _reply_to_result,
    _resolve_ipv4,
    _send_echo_native,
    icmp_echo,
)

# ── _reply_to_result: Status/RoundTripTime -> (alive, rtt) ─────────────────


def test_reply_success_maps_status_zero_to_alive_with_rtt() -> None:
    # Status 0 (IP_SUCCESS) -> alive, RoundTripTime als float-ms.
    assert _reply_to_result(0, 7) == (True, 7.0)


def test_reply_zero_rtt_is_valid_when_status_success() -> None:
    # Sub-ms-Antwort: RoundTripTime 0 bei Erfolg ist ein gueltiger Messwert, kein Sentinel.
    assert _reply_to_result(0, 0) == (True, 0.0)


def test_reply_nonzero_status_is_unreachable() -> None:
    # Jeder Status != 0 -> (False, -1.0); RoundTripTime wird NICHT gewertet.
    assert _reply_to_result(11010, 42) == (False, -1.0)  # IP_REQ_TIMED_OUT


# ── _resolve_ipv4: Aufloesung ──────────────────────────────────────────────


def test_resolve_ipv4_returns_first_address(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_getaddrinfo(host: str, port: object, **kwargs: object) -> list[tuple[object, ...]]:
        return [(socket.AF_INET, None, None, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    assert _resolve_ipv4("example.test") == "93.184.216.34"


def test_resolve_ipv4_failure_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(host: str, port: object, **kwargs: object) -> list[tuple[object, ...]]:
        raise socket.gaierror("unresolvable")

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    assert _resolve_ipv4("does-not-resolve.invalid") is None


def test_resolve_ipv4_empty_result_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [])
    assert _resolve_ipv4("nothing.invalid") is None


# ── _perform_echo: Ablauf + Handle-Schluss (ctypes-Schicht gemockt) ────────


class _FakeApi:
    """Sammelt die gemockten API-Schritte und protokolliert das Schliessen des Handles."""

    def __init__(
        self,
        *,
        handle: object = "HANDLE",
        count: int | None = 1,
        reply: tuple[int, int] = (0, 5),
        send_raises: bool = False,
        read_raises: bool = False,
    ) -> None:
        self.handle = handle
        self.count = count
        self.reply = reply
        self.send_raises = send_raises
        self.read_raises = read_raises
        self.closed_with: list[object] = []

    def create_handle(self) -> object:
        return self.handle

    def send_echo(self, handle: object) -> int | None:
        if self.send_raises:
            raise OSError("send failed")
        return self.count

    def read_reply(self) -> tuple[int, int]:
        if self.read_raises:
            raise ValueError("bad reply")
        return self.reply

    def close_handle(self, handle: object) -> None:
        self.closed_with.append(handle)

    def run(self) -> tuple[bool, float]:
        return _perform_echo(self.create_handle, self.send_echo, self.read_reply, self.close_handle)


def test_perform_echo_success_returns_alive_and_rtt() -> None:
    api = _FakeApi(reply=(0, 5))
    assert api.run() == (True, 5.0)
    assert api.closed_with == ["HANDLE"]  # Handle geschlossen


def test_perform_echo_error_status_is_unreachable_but_handle_closed() -> None:
    # Status != 0 -> Sentinel; das Handle MUSS trotzdem geschlossen werden.
    api = _FakeApi(reply=(11010, 99))
    assert api.run() == (False, -1.0)
    assert api.closed_with == ["HANDLE"]


def test_perform_echo_no_answer_is_unreachable_but_handle_closed() -> None:
    # IcmpSendEcho liefert 0 (keine Antwort) -> Sentinel; Handle geschlossen.
    api = _FakeApi(count=0)
    assert api.run() == (False, -1.0)
    assert api.closed_with == ["HANDLE"]


def test_perform_echo_closes_handle_on_send_exception() -> None:
    # Exception im Sende-Schritt -> Handle wird im finally trotzdem geschlossen.
    api = _FakeApi(send_raises=True)
    with pytest.raises(OSError):
        api.run()
    assert api.closed_with == ["HANDLE"]


def test_perform_echo_closes_handle_on_read_exception() -> None:
    # Exception im Lese-Schritt -> Handle wird im finally trotzdem geschlossen.
    api = _FakeApi(read_raises=True)
    with pytest.raises(ValueError):
        api.run()
    assert api.closed_with == ["HANDLE"]


def test_perform_echo_invalid_handle_is_unreachable_without_close() -> None:
    # Falsy Handle (None) -> es wurde keines geoeffnet, also NICHT schliessen.
    api = _FakeApi(handle=None)
    assert api.run() == (False, -1.0)
    assert api.closed_with == []


# ── icmp_echo (async): Vertrag Ende-zu-Ende ────────────────────────────────


def test_icmp_echo_unresolvable_host_is_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    # Gescheiterte Aufloesung -> (False, -1.0), OHNE den nativen Kern zu rufen.
    monkeypatch.setattr(icmp_windows, "_resolve_ipv4", lambda host: None)

    def should_not_run(ipv4: str, timeout: float) -> tuple[bool, float]:
        raise AssertionError("nativer Kern darf bei gescheiterter Aufloesung nicht laufen")

    monkeypatch.setattr(icmp_windows, "_send_echo_native", should_not_run)
    assert asyncio.run(icmp_echo("nope.invalid", 1.0)) == (False, -1.0)


def test_icmp_echo_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(icmp_windows, "_resolve_ipv4", lambda host: "10.0.0.1")
    monkeypatch.setattr(icmp_windows, "_send_echo_native", lambda ipv4, timeout: (True, 3.0))
    assert asyncio.run(icmp_echo("host.test", 1.0)) == (True, 3.0)


def test_icmp_echo_swallows_thread_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    # Exception im nativen Kern (im Thread) -> vertraglicher Nicht-erreichbar-Zustand.
    monkeypatch.setattr(icmp_windows, "_resolve_ipv4", lambda host: "10.0.0.1")

    def boom(ipv4: str, timeout: float) -> tuple[bool, float]:
        raise RuntimeError("iphlpapi explodiert")

    monkeypatch.setattr(icmp_windows, "_send_echo_native", boom)
    assert asyncio.run(icmp_echo("host.test", 1.0)) == (False, -1.0)


# ── Nicht-Windows-Ersatz: gleicher Name, vertraglicher Leer-/Fehlzustand ───


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Auf Windows ruft _send_echo_native die echte iphlpapi -- hier nur der Ersatz.",
)
def test_send_echo_native_stub_is_unreachable_on_non_windows() -> None:
    # Der Nicht-Windows-Zweig bindet denselben Namen und liefert (False, -1.0).
    assert _send_echo_native("10.0.0.1", 1.0) == (False, -1.0)
