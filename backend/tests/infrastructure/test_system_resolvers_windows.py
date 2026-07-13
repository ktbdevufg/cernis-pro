"""Tests fuer den Windows-Zweig der System-Resolver-Ermittlung (nativer API-Pfad).

Getestet wird die PLATTFORMUNABHAENGIGE reine Kanonisier-/Dedup-Logik aus
``infrastructure.system_resolvers_windows`` OHNE echte Windows-API -- deterministisch
und auch auf dem Linux-CI-Runner lauffaehig:

* ``canonicalize_resolvers``: Loopback-Stub (``127.0.0.53`` u. jedes ``127.0.0.0/8`` / ``::1``)
  wird verworfen; echte IPv4- UND IPv6-Server bleiben; ungueltige Literale fallen still raus;
  stabil dedupliziert (erste Reihenfolge bewahrt); IPv6 wird kanonisiert.
* ``detect_windows_resolvers``: auf Nicht-Windows vertraglicher Leer-Zustand ``[]``.

Der ctypes-Kern (``_collect_raw_dns_addresses`` etc.) braucht echte Windows-API und steht
im ``sys.platform``-Guard -- er wird hier NICHT getestet (auf Linux gar nicht vorhanden),
die Logik sitzt im herausgezogenen reinen ``canonicalize_resolvers``-Kern.
"""

import sys

import pytest

from infrastructure.system_resolvers_windows import (
    canonicalize_resolvers,
    detect_windows_resolvers,
)

# ── canonicalize_resolvers: Loopback raus, echte Server bleiben ─────────────


def test_canonicalize_drops_systemd_like_loopback_keeps_real() -> None:
    # Auch auf Windows ist ein Loopback als Upstream-Resolver wertlos -> verworfen.
    raw = ["127.0.0.53", "192.168.1.1", "1.1.1.1"]
    assert canonicalize_resolvers(raw) == ["192.168.1.1", "1.1.1.1"]


def test_canonicalize_drops_all_loopback() -> None:
    raw = ["127.0.0.1", "::1", "8.8.8.8"]
    assert canonicalize_resolvers(raw) == ["8.8.8.8"]


def test_canonicalize_keeps_ipv4_and_ipv6() -> None:
    # IPv4 UND IPv6 werden gehalten, Reihenfolge bewahrt.
    raw = ["192.168.178.1", "fd00::1", "2001:4860:4860::8888"]
    assert canonicalize_resolvers(raw) == ["192.168.178.1", "fd00::1", "2001:4860:4860::8888"]


def test_canonicalize_ignores_invalid_literals() -> None:
    raw = ["nicht-eine-ip", "", "9.9.9.9"]
    assert canonicalize_resolvers(raw) == ["9.9.9.9"]


def test_canonicalize_dedupes_stable() -> None:
    # Mehrere Adapter melden denselben Server -> nur einmal, erste Reihenfolge gewinnt.
    raw = ["1.1.1.1", "8.8.8.8", "1.1.1.1"]
    assert canonicalize_resolvers(raw) == ["1.1.1.1", "8.8.8.8"]


def test_canonicalize_empty_is_valid() -> None:
    assert canonicalize_resolvers([]) == []


def test_canonicalize_canonicalizes_ipv6() -> None:
    # Nicht-kanonisches IPv6-Literal -> kanonische Form via ipaddress.
    raw = ["2001:0db8:0000:0000:0000:0000:0000:0001"]
    assert canonicalize_resolvers(raw) == ["2001:db8::1"]


def test_canonicalize_strips_ipv6_zone() -> None:
    # Eine etwaige Zone/Interface-Angabe (%eth0) wird abgeschnitten und die Adresse
    # kanonisiert (deckungsgleich zum Linux-Zweig).
    raw = ["fe80::1%12"]
    assert canonicalize_resolvers(raw) == ["fe80::1"]


# ── detect_windows_resolvers: Nicht-Windows-Leerpfad ───────────────────────


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Auf Windows ruft detect_windows_resolvers die echte API -- hier nur der Leerpfad.",
)
def test_detect_empty_on_non_windows() -> None:
    # Vertraglicher Leer-Zustand ausserhalb win32: [] (kein Fehler, kein None).
    assert detect_windows_resolvers() == []


# ── Windows-only: echter API-Aufruf (auf Linux-CI sauber uebersprungen) ────


@pytest.mark.skipif(
    sys.platform != "win32",
    reason="Braucht echte Windows-API (GetAdaptersAddresses) -- auf Nicht-Windows uebersprungen.",
)
def test_detect_returns_list_on_windows() -> None:
    result = detect_windows_resolvers()
    assert isinstance(result, list)
    for ip in result:
        assert isinstance(ip, str)
