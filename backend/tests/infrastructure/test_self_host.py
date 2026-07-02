"""Tests von ``detect_self_host`` -- der psutil-basierten Eigenhost-Ermittlung.

Prueft: das primaere aktive Nicht-Loopback-Interface mit MAC + IPv4 wird
zurueckgegeben; das Loopback ``lo``/127.0.0.1 wird STRIKT ausgeschlossen; ein
inaktives (``isup=False``) Interface wird uebersprungen; fehlt MAC oder IPv4, ist
das Interface untauglich; wirft psutil, faellt es best-effort auf ``None`` zurueck.

``psutil`` wird gemockt (das Modul im Adapter-Namespace) -- kein echtes Netz noetig
(die Integration gegen echtes psutil deckt der Laufzeit-Smoke ab).
"""

import socket
from typing import NamedTuple

import psutil
import pytest

from infrastructure.self_host import detect_self_host


class _Addr(NamedTuple):
    family: int
    address: str


class _Stats(NamedTuple):
    isup: bool


_LINK = int(psutil.AF_LINK)
_INET = int(socket.AF_INET)


def _patch(
    monkeypatch: pytest.MonkeyPatch,
    if_addrs: dict[str, list[_Addr]],
    if_stats: dict[str, _Stats],
    hostname: str = "testhost",
) -> None:
    monkeypatch.setattr(psutil, "net_if_addrs", lambda: if_addrs)
    monkeypatch.setattr(psutil, "net_if_stats", lambda: if_stats)
    monkeypatch.setattr(socket, "gethostname", lambda: hostname)


def test_detect_primaeres_interface(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(
        monkeypatch,
        if_addrs={
            "eth0": [_Addr(_LINK, "00:0c:29:ec:b5:30"), _Addr(_INET, "172.18.1.156")],
        },
        if_stats={"eth0": _Stats(isup=True)},
        hostname="ubultsvm",
    )
    got = detect_self_host()
    assert got is not None
    assert got.mac == "00:0c:29:ec:b5:30"
    assert got.ip == "172.18.1.156"
    assert got.hostname == "ubultsvm"


def test_detect_loopback_strikt_ausgeschlossen(monkeypatch: pytest.MonkeyPatch) -> None:
    # lo traegt MAC + 127.0.0.1, wird aber per Namen UND per IP ausgeschlossen ->
    # nur eth0 zaehlt.
    _patch(
        monkeypatch,
        if_addrs={
            "lo": [_Addr(_LINK, "00:00:00:00:00:00"), _Addr(_INET, "127.0.0.1")],
            "eth0": [_Addr(_LINK, "AA:BB:CC:DD:EE:FF"), _Addr(_INET, "10.0.0.7")],
        },
        if_stats={"lo": _Stats(isup=True), "eth0": _Stats(isup=True)},
    )
    got = detect_self_host()
    assert got is not None
    assert got.ip == "10.0.0.7"


def test_detect_ueberspringt_inaktives_interface(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(
        monkeypatch,
        if_addrs={
            "eth0": [_Addr(_LINK, "AA:BB:CC:DD:EE:01"), _Addr(_INET, "10.0.0.1")],
            "eth1": [_Addr(_LINK, "AA:BB:CC:DD:EE:02"), _Addr(_INET, "10.0.0.2")],
        },
        if_stats={"eth0": _Stats(isup=False), "eth1": _Stats(isup=True)},
    )
    got = detect_self_host()
    assert got is not None
    assert got.ip == "10.0.0.2"


def test_detect_ohne_ipv4_ist_untauglich(monkeypatch: pytest.MonkeyPatch) -> None:
    # Nur eine Loopback-IPv4 auf dem einzigen Interface -> keine taugliche IP -> None.
    _patch(
        monkeypatch,
        if_addrs={"eth0": [_Addr(_LINK, "AA:BB:CC:DD:EE:01"), _Addr(_INET, "127.0.0.5")]},
        if_stats={"eth0": _Stats(isup=True)},
    )
    assert detect_self_host() is None


def test_detect_ohne_mac_ist_untauglich(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(
        monkeypatch,
        if_addrs={"eth0": [_Addr(_INET, "10.0.0.9")]},
        if_stats={"eth0": _Stats(isup=True)},
    )
    assert detect_self_host() is None


def test_detect_psutil_fehler_ist_none(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom() -> dict[str, list[_Addr]]:
        raise OSError("psutil kaputt")

    monkeypatch.setattr(psutil, "net_if_addrs", boom)
    assert detect_self_host() is None
