"""Tests der diagnostics-Adapter -- reine Parser + Tool-fehlt-Naht, kein echtes I/O.

Kein echter dig/traceroute-/Netz-/Subprocess-Aufruf: die reinen Parser-Helfer werden
gegen realistische ``dig``-/``traceroute``-Beispielausgaben geprueft (inkl. ``* * *``-
Timeout-Hops), und die Tool-fehlt-Naht wird ueber gemocktes ``shutil.which`` belegt
(``which`` None -> ``DiagnosticsToolMissing``). Die Subprocess-Aufrufe selbst sind
gemockt, wo der Adapter-Kern getestet wird.
"""

import asyncio
import os
import shutil

import pytest

from domain.diagnostics import DnsRecord
from infrastructure.diagnostics_linux import (
    DiagnosticsToolMissing,
    DigDnsResolver,
    LinuxPackageManagerDetector,
    LinuxTraceroutePermission,
    ShutilToolDetector,
    SystemTracerouteRunner,
    _parse_dig_answer,
    _parse_traceroute,
)

# ── dig-Parser (realistische Ausgaben) ────────────────────────────────────────

_DIG_A = "example.com.\t\t195\tIN\tA\t104.20.23.154\nexample.com.\t\t195\tIN\tA\t172.66.147.243\n"
_DIG_MX = "google.com.\t\t76\tIN\tMX\t10 smtp.google.com.\n"
_DIG_PTR = "1.1.1.1.in-addr.arpa.\t764\tIN\tPTR\tone.one.one.one.\n"
# Eine A-Abfrage, deren Antwort zusaetzlich eine CNAME-Begleitzeile enthaelt.
_DIG_A_WITH_CNAME = (
    "www.example.com.\t3600\tIN\tCNAME\texample.com.\nexample.com.\t\t195\tIN\tA\t104.20.23.154\n"
)


def test_parse_dig_answer_a_records() -> None:
    records = _parse_dig_answer(_DIG_A, "A")
    assert [r.value for r in records] == ["104.20.23.154", "172.66.147.243"]
    assert all(r.record_type == "A" for r in records)


def test_parse_dig_answer_mx_keeps_full_value() -> None:
    # Der MX-Wert ist Prioritaet + Host -- alles ab dem 5. Feld.
    records = _parse_dig_answer(_DIG_MX, "MX")
    assert records == [DnsRecord(record_type="MX", value="10 smtp.google.com.")]


def test_parse_dig_answer_ptr() -> None:
    records = _parse_dig_answer(_DIG_PTR, "PTR")
    assert [r.value for r in records] == ["one.one.one.one."]


def test_parse_dig_answer_ignores_wrong_type_line() -> None:
    # In einer A-Abfrage faellt die CNAME-Begleitzeile NICHT als A-Record durch.
    records = _parse_dig_answer(_DIG_A_WITH_CNAME, "A")
    assert [r.value for r in records] == ["104.20.23.154"]


def test_parse_dig_answer_empty_output() -> None:
    # Keine Antwort (NXDOMAIN/leer) -> leere Liste, kein Fehler.
    assert _parse_dig_answer("", "A") == []


def test_parse_dig_answer_skips_comment_and_malformed() -> None:
    output = ";; comment line\nshort line\nexample.com. 1 IN A 5.6.7.8\n"
    records = _parse_dig_answer(output, "A")
    assert [r.value for r in records] == ["5.6.7.8"]


# ── traceroute-Parser (inkl. Timeout-Hops) ────────────────────────────────────

_TRACEROUTE = (
    "traceroute to example.com (104.20.23.154), 30 hops max, 60 byte packets\n"
    " 1  fritzbox.mysticplace.de (172.18.0.1)  0.674 ms  0.650 ms  0.632 ms\n"
    " 2  46.128.193.1.dyn.pyur.net (46.128.193.1)  4.339 ms  4.321 ms  4.305 ms\n"
    " 3  * * *\n"
    " 4  109.104.59.156 (109.104.59.156)  13.413 ms  13.396 ms  13.380 ms\n"
)


def test_parse_traceroute_skips_header() -> None:
    hops = _parse_traceroute(_TRACEROUTE)
    # Die Kopfzeile (kein fuehrender int) ist kein Hop.
    assert [h.hop for h in hops] == [1, 2, 3, 4]


def test_parse_traceroute_prefers_ip_in_parens() -> None:
    hops = _parse_traceroute(_TRACEROUTE)
    assert hops[0].address == "172.18.0.1"
    assert hops[0].rtt_ms == 0.674


def test_parse_traceroute_timeout_hop_is_none() -> None:
    # Der ``* * *``-Hop antwortet nicht -> address/rtt_ms ehrlich None, NICHT weggelassen.
    timeout_hop = next(h for h in _parse_traceroute(_TRACEROUTE) if h.hop == 3)
    assert timeout_hop.address is None
    assert timeout_hop.rtt_ms is None


def test_parse_traceroute_empty_output() -> None:
    assert _parse_traceroute("") == []


def test_parse_traceroute_no_dns_address_uses_ip_token() -> None:
    # ``-n``-aehnliche Zeile ohne Klammer: erster Token ist die IP-Adresse.
    line = " 5  80.64.189.74  5.019 ms\n"
    hops = _parse_traceroute(line)
    assert hops[0].address == "80.64.189.74"
    assert hops[0].rtt_ms == 5.019


# ── Tool-fehlt-Naht (gemocktes shutil.which) ──────────────────────────────────


def test_resolve_dns_tool_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    with pytest.raises(DiagnosticsToolMissing) as exc_info:
        asyncio.run(DigDnsResolver().resolve("example.com", ["A"]))
    assert exc_info.value.tool == "dig"
    assert "dig" in exc_info.value.message


def test_traceroute_tool_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    with pytest.raises(DiagnosticsToolMissing) as exc_info:
        asyncio.run(SystemTracerouteRunner().run("example.com", False))
    assert exc_info.value.tool == "traceroute"


# ── Adapter-Kern mit gemocktem Subprocess (kein echtes Tool) ──────────────────


def test_resolve_dns_dedups_and_sorts(monkeypatch: pytest.MonkeyPatch) -> None:
    # which sagt "da", der dig-Aufruf liefert die A-Beispielausgabe (zweimal pro Typ-
    # Aufruf identisch -> dedup_records muss deduppen). Kein echtes dig.
    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/dig")
    monkeypatch.setattr("infrastructure.diagnostics_linux._run_dig", lambda _q, _t: _DIG_A)
    result = asyncio.run(DigDnsResolver().resolve("example.com", ["A"]))
    assert result.query == "example.com"
    assert result.requested_types == ("A",)
    # Zwei verschiedene A-Werte, aufsteigend sortiert.
    assert [r.value for r in result.records] == ["104.20.23.154", "172.66.147.243"]


def test_run_traceroute_reflects_privileged_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/sbin/traceroute")
    monkeypatch.setattr(
        "infrastructure.diagnostics_linux._run_traceroute", lambda _t, _p: _TRACEROUTE
    )
    result = asyncio.run(SystemTracerouteRunner().run("example.com", True))
    assert result.target == "example.com"
    assert result.privileged is True
    assert [h.hop for h in result.hops] == [1, 2, 3, 4]


# ── LinuxTraceroutePermission ─────────────────────────────────────────────────


def test_permission_is_available_true_when_binary_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/sbin/traceroute")
    assert LinuxTraceroutePermission().is_available() is True


def test_permission_is_available_false_when_binary_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    assert LinuxTraceroutePermission().is_available() is False


def test_permission_root_means_privileged_method(monkeypatch: pytest.MonkeyPatch) -> None:
    # geteuid 0 -> privilegierte Methode moeglich -> None (kein Hinweis noetig).
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    assert LinuxTraceroutePermission().check_permission() is None


def test_permission_non_root_gives_hint_without_install_cmd(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Nicht-Root -> Hinweis (kein stiller Fallback), KEIN distro-Install-Befehl (das ist 1b).
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    hint = LinuxTraceroutePermission().check_permission()
    assert hint is not None
    assert "Root" in hint
    assert "apt" not in hint and "dnf" not in hint


# ── Block 1b: ShutilToolDetector ──────────────────────────────────────────────


def test_tool_detector_available_when_binary_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/dig")
    assert ShutilToolDetector().is_available("dig") is True


def test_tool_detector_unavailable_when_binary_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    assert ShutilToolDetector().is_available("dig") is False


# ── Block 1b: LinuxPackageManagerDetector (Reihenfolge, erster gewinnt) ────────


def _which_only(*present: str) -> "object":
    """Baut ein ``shutil.which``-Stand-in, das nur die genannten Binaries 'findet'."""

    def _which(name: str) -> str | None:
        return f"/usr/bin/{name}" if name in present else None

    return _which


def test_package_manager_detect_first_in_order_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    # Sowohl dnf als auch yum da -> der frueher gelistete (dnf) gewinnt.
    monkeypatch.setattr(shutil, "which", _which_only("dnf", "yum"))
    assert LinuxPackageManagerDetector().detect() == "dnf"


def test_package_manager_detect_apt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", _which_only("apt"))
    assert LinuxPackageManagerDetector().detect() == "apt"


def test_package_manager_detect_pacman(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", _which_only("pacman"))
    assert LinuxPackageManagerDetector().detect() == "pacman"


def test_package_manager_detect_apt_beats_pacman(monkeypatch: pytest.MonkeyPatch) -> None:
    # apt steht vor pacman in der Reihenfolge -> apt gewinnt, egal welcher zuerst gefunden wird.
    monkeypatch.setattr(shutil, "which", _which_only("pacman", "apt"))
    assert LinuxPackageManagerDetector().detect() == "apt"


def test_package_manager_detect_none_when_no_manager(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shutil, "which", _which_only())
    assert LinuxPackageManagerDetector().detect() is None
