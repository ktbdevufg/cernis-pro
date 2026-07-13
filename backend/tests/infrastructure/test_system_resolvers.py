"""Tests fuer die System-Resolver-Ermittlung ``infrastructure.system_resolvers`` (E2).

Kern der Behauptungen:

* ``parse_resolv_conf``: der systemd-resolved-Stub ``127.0.0.53`` (und jedes andere
  Loopback) wird verworfen, echte ``nameserver``-IPs bleiben; Kommentare/Muell ignoriert;
  stabil dedupliziert.
* ``parse_resolvectl_output``: parst eine vorgegebene Beispiel-Ausgabe (Current DNS Server
  + DNS Servers ueber Folgezeilen), verwirft Loopback, dedupliziert stabil.
* ``detect_system_resolvers``: nutzt den resolv.conf-Fallback gegen eine Test-Datei, wenn
  resolvectl leer ist; eine fehlende Datei liefert best-effort ``[]``.

Der Subprocess selbst wird NICHT live getestet (best-effort/Timeout-Verhalten); die Logik
sitzt in den herausgezogenen reinen Parse-Kernen.
"""

import asyncio
import sys
from pathlib import Path

import pytest

import infrastructure.system_resolvers as sysres
from infrastructure.system_resolvers import (
    detect_system_resolvers,
    parse_resolv_conf,
    parse_resolvectl_output,
)

# ── parse_resolv_conf: Loopback-Stub raus, echte Server bleiben ─────────────


def test_resolv_conf_drops_systemd_stub_keeps_real() -> None:
    content = (
        "# generiert von etwas\nnameserver 127.0.0.53\nnameserver 192.168.1.1\nnameserver 1.1.1.1\n"
    )
    assert parse_resolv_conf(content) == ["192.168.1.1", "1.1.1.1"]


def test_resolv_conf_drops_all_loopback() -> None:
    # Jedes Loopback (127.0.0.0/8, ::1) faellt raus -- nur echte Upstreams bleiben.
    content = "nameserver 127.0.0.1\nnameserver ::1\nnameserver 8.8.8.8\n"
    assert parse_resolv_conf(content) == ["8.8.8.8"]


def test_resolv_conf_ignores_comments_and_junk() -> None:
    content = (
        "; ein Kommentar\n"
        "\n"
        "search example.org\n"
        "options edns0\n"
        "nameserver nicht-eine-ip\n"
        "nameserver 9.9.9.9\n"
    )
    assert parse_resolv_conf(content) == ["9.9.9.9"]


def test_resolv_conf_dedupes_stable() -> None:
    content = "nameserver 1.1.1.1\nnameserver 8.8.8.8\nnameserver 1.1.1.1\n"
    assert parse_resolv_conf(content) == ["1.1.1.1", "8.8.8.8"]


def test_resolv_conf_empty_is_valid() -> None:
    assert parse_resolv_conf("") == []


def test_resolv_conf_canonicalizes_ipv6() -> None:
    # Nicht-kanonisches IPv6-Literal -> kanonische Form via ipaddress.
    content = "nameserver 2001:0db8:0000:0000:0000:0000:0000:0001\n"
    assert parse_resolv_conf(content) == ["2001:db8::1"]


# ── parse_resolvectl_output: Beispiel-Ausgabe ───────────────────────────────


def test_resolvectl_parses_current_and_servers() -> None:
    output = (
        "Global\n"
        "       Protocols: -LLMNR -mDNS\n"
        "Link 2 (eth0)\n"
        "    Current DNS Server: 192.168.1.1\n"
        "           DNS Servers: 192.168.1.1 1.1.1.1\n"
        "            DNS Domain: fritz.box\n"
    )
    # Current zuerst, dann die Server-Menge -- 192.168.1.1 nur einmal (stabil dedupliziert).
    assert parse_resolvectl_output(output) == ["192.168.1.1", "1.1.1.1"]


def test_resolvectl_continuation_lines() -> None:
    # "DNS Servers:" kann auf eingerueckten Folgezeilen (ohne ":") fortgesetzt werden.
    output = (
        "Link 2 (eth0)\n"
        "           DNS Servers: 1.1.1.1\n"
        "                        8.8.8.8\n"
        "                        9.9.9.9\n"
        "            DNS Domain: ~.\n"
    )
    assert parse_resolvectl_output(output) == ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


def test_resolvectl_drops_loopback_stub() -> None:
    output = "    Current DNS Server: 127.0.0.53\n           DNS Servers: 127.0.0.53 8.8.4.4\n"
    assert parse_resolvectl_output(output) == ["8.8.4.4"]


def test_resolvectl_empty_output_is_valid() -> None:
    assert parse_resolvectl_output("") == []


def test_resolvectl_strips_zone_from_link_local() -> None:
    # systemd haengt bei link-lokalen Adressen eine Zone an (fe80::1%eth0).
    output = "           DNS Servers: fe80::1%eth0\n"
    assert parse_resolvectl_output(output) == ["fe80::1"]


# ── detect_system_resolvers: resolvectl-Vorrang, Fallback, Leerzustand ──────
#
# Der resolvectl-Subprocess wird gemockt (kein Live-Aufruf -- Muster
# ``test_diagnostics_linux``/``test_resolver_dns_ptr``), damit die Wahl zwischen resolvectl
# und dem resolv.conf-Fallback deterministisch ist. Der Coroutine-Aufruf laeuft ueber
# ``asyncio.run`` (kein async-pytest-Plugin in diesem Repo).
#
# Diese drei Tests pruefen die LINUX-Selektionslogik (resolvectl vs. resolv.conf). Sie
# laufen auf JEDEM Host deterministisch, indem ``sys.platform`` zur Laufzeit auf ``"linux"``
# gepinnt wird -- auf einem echten Windows-Host wuerde ``detect_system_resolvers`` sonst in
# den nativen Windows-Zweig abbiegen und die echten Systemresolver liefern. Der
# Windows-Zweig selbst ist in ``test_system_resolvers_windows`` getestet.


def _force_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pinnt den Plattform-Guard von ``detect_system_resolvers`` zur Laufzeit auf Linux.

    ``sysres`` liest ``sys.platform`` zur Laufzeit; ``sys`` ist dasselbe Modulobjekt, das
    hier importiert ist -- ein Patch auf ``sys.platform`` wirkt daher auch dort. So laeuft
    die Linux-Selektionslogik auf jedem Host (auch echtem Windows) deterministisch.
    """
    monkeypatch.setattr(sys, "platform", "linux")


def _stub_resolvectl(monkeypatch: pytest.MonkeyPatch, result: list[str]) -> None:
    """Ersetzt den resolvectl-Weg durch eine Coroutine mit fixem Ergebnis."""

    async def _fake(_timeout: float) -> list[str]:
        return result

    monkeypatch.setattr(sysres, "_run_resolvectl", _fake)


def test_detect_prefers_resolvectl_over_fallback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Liefert resolvectl IPs, gewinnt es -- der resolv.conf-Fallback wird NICHT gelesen.
    _force_linux(monkeypatch)
    _stub_resolvectl(monkeypatch, ["1.1.1.1"])
    resolv = tmp_path / "resolv.conf"
    resolv.write_text("nameserver 8.8.8.8\n", encoding="utf-8")
    result = asyncio.run(detect_system_resolvers(resolv_conf_path=resolv))
    assert result == ["1.1.1.1"]


def test_detect_falls_back_to_resolv_conf(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # resolvectl leer -> der Fallback greift und liest die Test-Datei (Stub 127.0.0.53
    # verworfen, echter Server bleibt).
    _force_linux(monkeypatch)
    _stub_resolvectl(monkeypatch, [])
    resolv = tmp_path / "resolv.conf"
    resolv.write_text("nameserver 127.0.0.53\nnameserver 192.168.178.1\n", encoding="utf-8")
    result = asyncio.run(detect_system_resolvers(resolv_conf_path=resolv))
    assert result == ["192.168.178.1"]


def test_detect_missing_resolv_conf_is_empty(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # resolvectl leer UND Datei fehlt -> best-effort [] (leere Liste ist gueltig).
    _force_linux(monkeypatch)
    _stub_resolvectl(monkeypatch, [])
    missing = tmp_path / "nicht_da.conf"
    result = asyncio.run(detect_system_resolvers(resolv_conf_path=missing))
    assert result == []
